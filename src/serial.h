#ifndef __SERIAL_H__
#define __SERIAL_H__

int open_serial(const char *dev, int timeout);
int read_line(char *buffer, unsigned int size);
int write_serial(int fd, const char *buffer, int len);
 int read_serial(int fd, char *buffer, unsigned int size);
#endif /* __SERIAL_H__ */