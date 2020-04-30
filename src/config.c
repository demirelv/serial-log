
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <sys/queue.h>

#include "utils.h"
#include "config.h"

static TAILQ_HEAD(config_list, cfg_element) config_list = TAILQ_HEAD_INITIALIZER(config_list);

typedef struct cfg_element {
	char *name;
	char *value;
	TAILQ_ENTRY(cfg_element) list;
} cfg_element_t;

static cfg_element_t *get_elem(const char *name)
{
	cfg_element_t *e = NULL;

	if (name == NULL)
		return NULL;

	TAILQ_FOREACH(e, &config_list, list) {
		if (!strcmp(e->name, name))
			return e;
	}

	return NULL;
}

static int add_elem(const char *name, const char *value)
{
	cfg_element_t *e = NULL;

	if (name == NULL || value == NULL)
		return -1;

	e = get_elem(name);
	if (e == NULL) {
		e = calloc(1, sizeof(cfg_element_t));
		if (e == NULL)
			return -1;
		e->name = strdup(name);
		e->value = NULL;
		TAILQ_INSERT_TAIL(&config_list, e, list);
	}

	if (e->value != NULL) {
		free(e->value);
		e->value = NULL;
	}
	e->value = strdup(value);

	return 0;
}

static void clear_space(char **p)
{
	char *n = *p;

	if (*n == 0)
		return;
	for(; *n == ' '; n++);
	*p = n;
	for(; *n; n++);
	n--;
	for(; *n == ' '; n--)
		*n = 0;
}

static int parse_elem(char *buf, char **name, char **value)
{
	char *n, *v;

	if (buf == NULL || name == NULL || value == NULL)
		return -1;

	for(n = buf; *n != 0 && *n != '\r' && *n != '\n' && *n != '#'; ++n);

	*n = 0;

	v = strchr(buf, '=');
	if (v == NULL)
		return -1;
	*v = 0;
	v++;
	*name = buf;
	*value = v;
	clear_space(name);
	clear_space(value);
	if (strlen(*name) == 0 || strlen(*value) == 0)
		return -1;

	return 0;
}

int read_config(const char *filename)
{
	FILE *fp  = NULL;
	int ret = -1;
	char buf[1024] = { 0 };
	char *name = NULL, *value = NULL;

	if (filename == NULL)
		goto bail;

	if ((fp = fopen(filename, "r")) == NULL) {
		goto bail;
	}
	while (!feof(fp)) {
		if (fgets(buf, sizeof(buf), fp) == NULL)
			continue;

		if (parse_elem(buf, &name, &value) != 0) {
			printf("could not parse '%s'\n", buf);
			continue;
		}
		if (add_elem(name, value) != 0) {
			printf("could not add '%s'='%s'\n", name, value);
			continue;
		}
	}

	ret = 0;
bail:
	if (fp != NULL)
		fclose(fp);
	return ret;
}

void free_config(void)
{
	cfg_element_t *e, *n;

	TAILQ_FOREACH_SAFE(e, &config_list, list, n) {
		TAILQ_REMOVE(&config_list, e, list);
		if (e->value != NULL)
			free(e->value);
		if (e->name != NULL)
			free(e->name);
		free(e);
	}
}

char *get_config(const char *name)
{
	cfg_element_t *e;

	e = get_elem(name);
	if (e != NULL)
		return e->value;
	return NULL;
}

char *get_config_safe(const char *name)
{
	char *value = get_config(name);

	if (value != NULL)
		return value;
	return "";
}
