#include <string.h>
#include <fcntl.h>
#include <termios.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>

#include "utils.h"

static unsigned int wp = 0;
static unsigned int rp = 0;
static char serbuf[2048];

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

int read_line(char *buffer, unsigned int size)
{
	int rc = 0;

	for (;rp < wp; rp++) {
		if (serbuf[rp] == '\n' || serbuf[rp] == '\r' || serbuf[rp] == '\0') {
			if (rp && rp < size)
				memcpy(buffer, serbuf, rp);
			rc = rp < size ? rp : 0;
			rp++;
			if (rp < wp) {
				memmove(serbuf, &serbuf[rp], wp - rp);
			}
			wp -= rp;
			rp = 0;
			if (rc > 0)
				return rc;
		}
	}

	return rc;
 }

 int read_serial(int fd, char *buffer, unsigned int size)
{
	int rc;

	rc = TEMP_FAILURE_RETRY(read(fd, buffer, size));
	if (rc < 1) {
		debug("serial read rc %d errno %d '%s'\n", rc, errno, strerror(errno));
		return -1;
	}

	if (rc + wp < sizeof(serbuf)) {
		memcpy(&serbuf[wp], buffer, rc);
		wp += rc;
	} else {
		wp = 0;
		rp = 0;
	}

	return rc;
 }

int write_serial(int fd, const char *buffer, int len)
{
	int cur = 0;
	int written = 0;

	if (fd < 0 ) {
		return -1;
	}

	while (cur < len) {
		written = TEMP_FAILURE_RETRY(write(fd, buffer + cur, len - cur));
		if (written < 0) {
			return -1;
		}
		cur += written;
	}

	return cur;
}
