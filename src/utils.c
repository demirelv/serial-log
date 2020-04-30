#include <ctype.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <time.h>

#include <netinet/in.h>

#include <sys/syscall.h>
# include <sys/klog.h>
#include <syslog.h>

#include "utils.h"

void set_nport(struct sockaddr *sa, unsigned port)
{
	if (sa->sa_family == AF_INET) {
		struct sockaddr_in *sin = (void *)sa;
		sin->sin_port = port;
		return;
	}
}

static void get_mono(struct timespec *ts)
{
	if (syscall(__NR_clock_gettime, CLOCK_MONOTONIC, ts))
		printf("clock_gettime(MONOTONIC) failed\n");
}

unsigned  monotonic_sec(void)
{
	struct timespec ts;
	get_mono(&ts);
	return ts.tv_sec;
}

int unix_write(int  fd, const char *buff, int len)
{
	int  ret, tlen = 0;
	do {
		ret = send(fd, &buff[tlen], len - tlen, 0);
		if (ret < 0 && (errno == EINTR))
			continue;
		if (ret < 0 && (errno == EAGAIN) && tlen != 0)
			continue;
		if (ret > 0)
			tlen += ret;
		else
			break;
	} while (tlen < len);

	if (tlen == len)
		return 0;
	return -1;
}
