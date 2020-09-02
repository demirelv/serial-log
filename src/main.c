#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <fcntl.h>

#include <pthread.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>

#include <dirent.h>

#include "utils.h"
#include "config.h"
#include "serial.h"

#define TELOPT_TRANSMIT_BINARY      0  // Binary Transmission (RFC856)
#define TELOPT_ECHO                 1  // Echo (RFC857)
#define TELOPT_SGA					3  // Suppress Go Ahead (RFC858)
#define TELOPT_STATUS               5  // Status (RFC859)
#define TELOPT_TIMING_MARK          6  // Timing Mark (RFC860)
#define TELOPT_NAOCRD              10  // Output Carriage-Return Disposition (RFC652)
#define TELOPT_NAOHTS              11  // Output Horizontal Tab Stops (RFC653)
#define TELOPT_NAOHTD              12  // Output Horizontal Tab Stop Disposition (RFC654)
#define TELOPT_NAOFFD              13  // Output Formfeed Disposition (RFC655)
#define TELOPT_NAOVTS              14  // Output Vertical Tabstops (RFC656)
#define TELOPT_NAOVTD              15  // Output Vertical Tab Disposition (RFC657)
#define TELOPT_NAOLFD              16  // Output Linefeed Disposition (RFC658)
#define TELOPT_EXTEND_ASCII        17  // Extended ASCII (RFC698)
#define TELOPT_TERMINAL_TYPE       24  // Terminal Type (RFC1091)
#define TELOPT_NAWS                31  // Negotiate About Window Size (RFC1073)
#define TELOPT_TERMINAL_SPEED      32  // Terminal Speed (RFC1079)
#define TELOPT_LFLOW			   33  // Remote Flow Control (RFC1372)
#define TELOPT_LINEMODE            34  // Linemode (RFC1184)
#define TELOPT_AUTHENTICATION      37  // Authentication (RFC1416)

#define TELNET_WILL  251   // Will option code
#define TELNET_WONT  252   // Won't option code
#define TELNET_DO    253   // Do option code
#define TELNET_DONT  254   // Don't option code
#define TELNET_IAC   255   // Interpret as command

struct log {
	char *msg;
	char *date;
	int len;
	TAILQ_ENTRY(log) list;
};

typedef struct {
	int fd;
	char *serial_dev;
	unsigned last_dns_resolve;
	char *host;
	char *log_key;
	char file_name[256];
	int port;
	socklen_t alen;
	char *ftp_addr;
	FILE *file;
	char *file_path;
	int file_len;
	struct sockaddr *sa;
	struct log *point;
} remote_t;

struct client {
	int client;
	int remove;
	int level;
	int inited;
	char type[128];
	TAILQ_ENTRY(client) list;
};

static TAILQ_HEAD(log_list, log) log_list = TAILQ_HEAD_INITIALIZER(log_list);
static TAILQ_HEAD(client_list, client) client_list = TAILQ_HEAD_INITIALIZER(client_list);
static int gLogRecordCount = 0;
static int die = 0;
#define MAXLOGCOUNT 4096
#define MAX_BUF_SIZE 4096

static struct client *get_client(int client)
{
	struct client *cl;

	TAILQ_FOREACH(cl, &client_list, list) {
		if (cl->client == client)
			return cl;
	}
	return NULL;
}

static struct client *find_remove()
{
	struct client *cl;

	TAILQ_FOREACH(cl, &client_list, list) {
		if (cl->remove) {
			return cl;
		}
	}
	return NULL;
}

static int host2sockaddr(remote_t *rh)
{
	int rc;
	struct addrinfo *result = NULL;
	struct addrinfo *used_res;
	struct addrinfo hint;
	char *host = rh->host;
	struct sockaddr *r;

	memset(&hint, 0, sizeof(hint));
	hint.ai_family = AF_INET;
	hint.ai_socktype = SOCK_STREAM;
	hint.ai_flags = AI_CANONNAME;
	rc = getaddrinfo(host, NULL, &hint, &result);
	if (rc || !result) {
		return -1;
	}
	used_res = result;
	while (1) {
		if (used_res->ai_family == AF_INET)
			break;
		used_res = used_res->ai_next;
		if (!used_res) {
			used_res = result;
			freeaddrinfo(result);
			return -1;
		}
	}

	r = malloc(used_res->ai_addrlen);
	rh->alen = used_res->ai_addrlen;
	memcpy(r, used_res->ai_addr, used_res->ai_addrlen);
	rh->sa = r;

	set_nport(r, htons(rh->port));
	if (result)
		freeaddrinfo(result);
	return 0;
}

static int try_to_resolve_remote(remote_t *rh)
{
	int rc = 0;
	if (!rh->sa) {
		unsigned now = monotonic_sec();

		if ((now - rh->last_dns_resolve) < 2 * 60)
			return -1;
		rh->last_dns_resolve = now;
		if (host2sockaddr(rh)) {
			return -1;
		}
		printf("connected '%s' %d\n", rh->host, rh->port);
	}
	rc = socket(rh->sa->sa_family, SOCK_DGRAM, 0);
	if (rc == -1 && rh->sa) { // free for possible mem-leak issue AIRS4930-836
		free(rh->sa);
		rh->sa = NULL;
	}
	return rc;
}

static int remote_handle(remote_t *rh)
{
	struct log *log;

	if (rh->host == NULL || rh->port <= 0) {
		return 0;
	}

	if (rh->fd == -1) {
		rh->fd = try_to_resolve_remote(rh);
		if (rh->fd == -1)
			return -1;
	}

	for (log = rh->point == NULL ? TAILQ_FIRST(&log_list) : TAILQ_NEXT(rh->point, list); log; log = TAILQ_NEXT(log, list)) {
		char buffer[MAX_BUF_SIZE + 128];
		int len = 0;

		len = snprintf(buffer, sizeof(buffer) - 1, "<4>%s: %s\n\r", log->date, log->msg);
		if (sendto(rh->fd, buffer, len,
				MSG_DONTWAIT | MSG_NOSIGNAL,
				rh->sa, rh->alen) == -1
		) {
			switch (errno) {
			case ECONNRESET:
			case ENOTCONN:
			case EPIPE:
				debug("connection closed errno %d '%s'\n", errno, strerror(errno));
				close(rh->fd);
				rh->fd = -1;
				free(rh->sa);
				rh->sa = NULL;
				return 0;
			}
		}
		rh->point = log;
	}
	return 0;
}

static int client_handle(char *buffer, unsigned int len)
{
	struct client *cl, *n;
	int rc = 0;

	TAILQ_FOREACH_SAFE(cl, &client_list, list, n) {
		if (unix_write(cl->client, buffer, len)) {
			if (errno != EAGAIN)
				cl->remove = 1;
		}
	}
	return rc;
}

static int send_client_logs(struct client *cl)
{
	struct log *log;
	int rc = 0;

	for (log = TAILQ_FIRST(&log_list); log; log = TAILQ_NEXT(log, list)) {
		char buffer[MAX_BUF_SIZE + 128];
		int len = 0;

		len = snprintf(buffer, sizeof(buffer) - 1, "%s\n", log->msg);
		if (unix_write(cl->client, buffer, len)) {
			if (errno != EAGAIN)
				cl->remove = 1;
			else
				rc = 1;
			break;
		}
	}
	return rc;
}

static char *get_date(void)
{
	char date[128] = { 0 };
	time_t t;

	time(&t);

	strftime(date, sizeof(date), "%h %e %T", localtime(&t));
	return strdup(date);
}

static int send_iac(struct client *cl, unsigned char command, unsigned char option)
{
	unsigned char b[3];
	int rc = 0;

	b[0] = TELNET_IAC;
	b[1] = command;
	b[2] = option;

	rc = unix_write(cl->client, (char *)b, 3);
	if (rc) {
		if (errno != EAGAIN)
			cl->remove = 1;
	}
	return rc;
}

static void get_file_name(char *filename, char *key)
{
	char date[128] = { 0 };
	struct tm *ctime;
	time_t t;
	
	time(&t);
	ctime = localtime(&t);
	if (ctime == NULL) {
		snprintf(date, sizeof(date), "null");
		goto bail;
	}
	snprintf(date, sizeof(date), "%04d_%02d_%02d_%02d_%02d_%02d", ctime->tm_year + 1900, ctime->tm_mon + 1, ctime->tm_mday, ctime->tm_hour, ctime->tm_min, ctime->tm_sec);
bail:
	sprintf(filename, "log-%s_%s.txt", key, date);
	return;
}

static void save_file(struct log *log, remote_t *rh)
{

	if (rh->file_path == NULL)
		return;

	if (rh->file == NULL) {
		char file_name[512] = { 0 };

		get_file_name(rh->file_name, rh->log_key);
		snprintf(file_name, sizeof(file_name), "%s/active-%s", rh->file_path, rh->file_name);
		rh->file = fopen(file_name, "a+");
		rh->file_len = 0;
	}

	if (rh->file != NULL) {

		rh->file_len += fprintf(rh->file, "[%s]%s\n\r", log->date, log->msg);

		fflush(rh->file);
		if (rh->file_len > 1024 * 1024) {
			char cmd[1024];

			fclose(rh->file);
			snprintf(cmd, sizeof(cmd), "mv %s/active-%s %s/%s", rh->file_path, rh->file_name, rh->file_path, rh->file_name);
			if (system(cmd))
				printf("system ret fail '%s'\n", cmd);
			rh->file = NULL;
		} 
	}
}

static int log_add(char *msg, int len, remote_t *rh)
{
	struct log *log = NULL;

	log = (struct log *)malloc(sizeof(*log));
	if (!log) {
		debug("Failed to alloc log record\n");
		return -1;
	}

	memset(log, 0, sizeof(*log));
	log->msg = malloc(len + 1);
	log->date = get_date();
	log->len = len;
	memcpy(log->msg, msg, len);
	log->msg[len] = 0;
	TAILQ_INSERT_TAIL(&log_list, log, list);

	save_file(log, rh);

	if (gLogRecordCount < MAXLOGCOUNT) {
		gLogRecordCount++;
	} else {
		log = TAILQ_FIRST(&log_list);
		if (log) {
			if (rh->point != NULL && rh->point == log)
				rh->point = TAILQ_NEXT(log, list);
			TAILQ_REMOVE(&log_list, log, list);
			if (log->date)
				free(log->date);
			free(log->msg);
			free(log);
		}
	}
	return 0;
}

int tcp_server_init(int port)
{
	int server = -1;
	int optval = 1;
	struct sockaddr_in local_sock_addr;

	if ( (server = socket(AF_INET, SOCK_STREAM, 0)) < 0 ) {
		goto bail;
	}

	fcntl(server, F_SETFD, fcntl(server, F_GETFD,0) | FD_CLOEXEC);
	fcntl(server, F_SETFL, fcntl(server, F_GETFL,0) | O_NONBLOCK);

	bzero((char *) &local_sock_addr, sizeof(local_sock_addr));

	local_sock_addr.sin_family      = AF_INET;
	local_sock_addr.sin_addr.s_addr = INADDR_ANY;
	local_sock_addr.sin_port        = htons(port);

	optval = 1;
	if (setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof (optval)) < 0) {
		goto bail;
	}

	if (bind(server, (const struct sockaddr *) &local_sock_addr, sizeof(local_sock_addr)) == -1) {
		goto bail;
	}

	if (listen(server, 5) < 0) {
		goto bail;
	}

	optval = 1;
	if (setsockopt(server, SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof (optval)) < 0) {
		goto bail;
	}

	if (setsockopt(server, SOL_TCP, TCP_NODELAY, &optval, sizeof (optval)) < 0) {
		goto bail;
	}
	optval = 10;
	if (setsockopt(server, SOL_TCP, TCP_KEEPINTVL, &optval, sizeof (optval)) < 0) {
		goto bail;
	}
	optval = 10;
	if (setsockopt(server, SOL_TCP, TCP_KEEPIDLE, &optval, sizeof (optval)) < 0) {
		goto bail;
	}
	optval = 5;
	if (setsockopt(server, SOL_TCP, TCP_KEEPCNT, &optval, sizeof (optval)) < 0) {
		goto bail;
	}

	return server;
bail:
	if (server > -1) {
		close(server);
		server = -1;
	}
	return -1;
}

static int load_configs(const char *filename, remote_t *rh)
{
	if (read_config(filename)) {
		debug("read config fail '%s' \n", filename);
		goto bail;
	}

	rh->file_path = get_config("LOG_PATH");
	rh->host = get_config("HOST");
	rh->log_key = get_config_safe("LOG_KEY");
	rh->port = atoi(get_config_safe("PORT"));
	rh->serial_dev = get_config("SERIAL_DEV");
	rh->ftp_addr = get_config("FTP");
	return 0;
bail:
	return -1;
}

static void signal_handle(int signal)
{
	(void)signal;
	die = 1;
}

static void check_log_files(remote_t *rh)
{
	struct dirent *dir;
	DIR *d;

	if (rh == NULL || rh->file_path == NULL)
		return;

	d = opendir(rh->file_path);
	if (d == NULL) {
		debug("could not open dir path '%s' \n", rh->file_path);
		return;
	}

	while ((dir = readdir(d)) != NULL) {
		if (dir->d_type != DT_DIR) {
			char tmp[1024] = { 0 };

			if (strncmp("active-", dir->d_name, 7) == 0) {
				snprintf(tmp, sizeof(tmp), "mv %s/%s %s/%s", rh->file_path, dir->d_name, rh->file_path, (char *)&dir->d_name[7]);
				if (system(tmp)) {
					debug("could not run cmd '%s' \n", tmp);
				}
			}
		}
	}
	closedir(d);

	return;
}

static void* ftp_thread(void *arg)
{
	remote_t *rh = (remote_t *)arg;
	struct dirent *dir;
	DIR *d;

	if (rh == NULL || rh->file_path == NULL || rh->ftp_addr == NULL)
		return NULL;

	while (die) {
		sleep(10);

		d = opendir(rh->file_path);
		if (d == NULL) {
			printf("could not open dir path '%s' \n", rh->file_path);
			continue;
		}

		while ((dir = readdir(d)) != NULL) {
			if (dir->d_type != DT_DIR) {
				char tmp[512] = { 0 };
	
				if (strncmp("active-", dir->d_name, 7)) {
					snprintf(tmp, sizeof(tmp), "curl -T %s/%s %s", rh->file_path, dir->d_name, rh->ftp_addr);
					if (system(tmp) == 0) {
						snprintf(tmp, sizeof(tmp), "rm %s/%s", rh->file_path, dir->d_name);
						if (system(tmp))
							debug("could not run cmd '%s' \n", tmp);
					} else
						debug("could not run cmd '%s' \n", tmp);
				}
			}
		}
		closedir(d);
	}
	return NULL;
}

int main(int argc, char *argv[])
{
	fd_set rfds, afds;
	int serial = -1, server = -1, fd;
	char buffer[MAX_BUF_SIZE];
	int nfds = getdtablesize();
	int len;
	int timeout = 0;
	pthread_t thrd;
	int rc = 0;

	struct timeval tv;
	remote_t *rh = NULL;

	(void)argc;
	(void)argv;

	signal(SIGPIPE, SIG_IGN);
	signal(SIGHUP, SIG_IGN);
	signal(SIGINT, signal_handle);
	signal(SIGTERM, signal_handle);
	signal(SIGKILL, signal_handle);

	rh = malloc(sizeof(*rh));
	if (rh == NULL)
		goto bail;

	memset(rh, '\0', sizeof(*rh));
	rh->fd = -1;

	if (load_configs(argv[1], rh))
		goto bail;

	check_log_files(rh);

	rc = pthread_create(&thrd, NULL, &ftp_thread, rh);
	if (rc) {
		goto bail;
	}

	server = tcp_server_init(9955);
	if (server < 0) {
		goto bail;
	}

	FD_ZERO(&afds);
	FD_SET(server, &afds);

	debug("serial log started !\n");
	while (!die) {
		tv.tv_sec = timeout ? timeout : 10;
		tv.tv_usec = 0;
		timeout = 0;
		if (serial < 0) {
			timeout = 1;
			serial = open_serial(rh->serial_dev, 5);
			if (serial > -1) {
				debug("serial port opened '%s'\n", rh->serial_dev);
				FD_SET(serial, &afds);
				timeout = 0;
			} else
				debug("could not open serial port '%s'\n", rh->serial_dev);
		}
		bcopy((char *)&afds, (char *)&rfds, sizeof(rfds));
		if (select(nfds, &rfds, (fd_set *)0, (fd_set *)0,
				(struct timeval *)&tv) < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		if (serial > -1 && FD_ISSET(serial, &rfds)) {
			len = read_serial(serial, buffer, sizeof(buffer));
			if (len < 0) {
				debug("close serial port ret %d \n", len);
				FD_CLR(serial, &afds);
				close(serial);
				serial = -1;
				timeout = 1;
			} else if (len > 0) {
				client_handle(buffer, len);
				do {
					len = read_line(buffer, sizeof(buffer));
					if (len > 0) {
						log_add(buffer, len, rh);
					}
				} while(len > 0);
			}
		}
		if (FD_ISSET(server, &rfds)) {
			int client;
			struct sockaddr_un client_addr;
			socklen_t alen;

			alen = sizeof(client_addr);
			client = accept(server, (struct sockaddr *)&client_addr, &alen);
			if (!(client < 0)) {
				struct client *cl = malloc(sizeof(*cl));
				memset(cl, '\0', sizeof(*cl));
				cl->client = client;
				FD_SET(client, &afds);
				fcntl(client, F_SETFD, fcntl(client, F_GETFD, 0) | FD_CLOEXEC);
				fcntl(client, F_SETFL, fcntl(client, F_GETFL, 0) | O_NONBLOCK);
				TAILQ_INSERT_TAIL(&client_list, cl, list);
				send_client_logs(cl);

				send_iac(cl, TELNET_DO, TELOPT_ECHO);
				send_iac(cl, TELNET_DO, TELOPT_LFLOW);
				send_iac(cl, TELNET_WILL, TELOPT_ECHO);
				send_iac(cl, TELNET_WILL, TELOPT_SGA);
			}
		}
		for (fd = 0; fd < nfds; fd++) {
			if (fd != serial && fd != server && FD_ISSET(fd, &rfds)) {
				struct client *cl = get_client(fd);
				if (cl != NULL) {
					len = recv(fd, buffer, sizeof(buffer), 0);
					if (len < 1) {
						debug("recv failed ret=%d \n", len);
						TAILQ_REMOVE(&client_list, cl, list);
						free(cl);
						FD_CLR(fd, &afds);
						close(fd);
					} else {
						int rlen = 0;
						rlen = write_serial(serial, buffer, len);
						if (rlen != len) {
							debug("close serial port rlen = %d != %d \n", rlen, len);
							FD_CLR(serial, &afds);
							close(serial);
							serial = -1;
							timeout = 1;
						}
					}
				} else {
					close(fd);
					FD_CLR(fd, &afds);
				}
			}
		}

		remote_handle(rh);

		do {
			struct client *cl = find_remove(&client_list);
			if (cl == NULL)
				break;
			TAILQ_REMOVE(&client_list, cl, list);
			FD_CLR(cl->client, &afds);
			close(cl->client);
			free(cl);
		} while (1);
	}
bail:
	die = 1;
	pthread_join(thrd, NULL);
	if (server > -1)
		close(server);
	if (serial > -1)
		close(serial);
	if (rh != NULL) {
		if (rh->fd != -1) {
			close(rh->fd);
			rh->fd = -1;
			free(rh->sa);
			rh->sa = NULL;
		}
		if (rh->file != NULL) {
			char cmd[1024];

			fclose(rh->file);
			snprintf(cmd, sizeof(cmd), "mv %s/active-%s %s/%s ", rh->file_path, rh->file_name, rh->file_path, rh->file_name);
			if (system(cmd))
				debug("system ret fail '%s'\n", cmd);
		}
		free(rh);
	}
	free_config();

	return 0;
}
