#include <string.h>
#include <fcntl.h>
#include <termios.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>

#include "utils.h"

int open_serial(const char *dev, int timeout)
{
	int fd;
	struct termios tty;

	fd = open(dev, O_RDWR | O_NOCTTY | O_NDELAY);
	if (fd < 0) {
		return -1;
	}

	fcntl(fd, F_SETFD, fcntl(fd, F_GETFD, 0) | FD_CLOEXEC);
	fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);

	bzero(&tty, sizeof(tty));

	tty.c_cflag |= B115200;
	tty.c_cflag |= CS8; // 8 bits per byte (most common)
	tty.c_cflag |= CREAD | CLOCAL; // Turn on READ & ignore ctrl lines (CLOCAL = 1)

	tty.c_cc[VTIME] = timeout;
	tty.c_cc[VMIN] = 0;

	// Set in/out baud rate to be 115200
	cfsetispeed(&tty, B115200);
	cfsetospeed(&tty, B115200);

	tcflush(fd, TCIOFLUSH);
	tcsetattr(fd, TCSANOW, &tty);
	
	return fd;
}

int read_line(int fd, char *buffer, unsigned int size)
{
	int rc;
	static unsigned int p = 0;

	do {
		rc = TEMP_FAILURE_RETRY(read(fd, &buffer[p], 1));
		if (rc < 1) {
			if (errno == EAGAIN)
				return 0;
			else
				printf("rc %d errno %d '%s'\n", rc, errno, strerror(errno));
			return -1;
		}

		if (buffer[p] == '\n' || buffer[p] == '\r' || buffer[p] == '\0') {
			buffer[p] = '\0';
			break;
		}
		p++;
	} while (p < size - 1);
	rc = p;
	p = 0;
	return rc;
 }
