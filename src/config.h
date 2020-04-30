
#ifndef __CONFIG_H__
#define __CONFIG_H__

void free_config(void);
char *get_config(const char *name);
char *get_config_safe(const char *name);
int read_config(const char *filename);

#endif /* __CONFIG_H__ */
