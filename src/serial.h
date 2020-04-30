#ifndef __SERIAL_H__
#define __SERIAL_H__

int open_serial(const char *dev, int timeout);
int read_line(int fd, char *buffer, unsigned int size);

#endif /* __SERIAL_H__ */