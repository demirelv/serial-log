#ifndef __UTILS_H__
#define __UTILS_H__

#include <netdb.h>
#include <netinet/in.h>
#include <sys/un.h>

#include <sys/queue.h>

#define TEMP_FAILURE_RETRY(exp) ({		\
	typeof(exp) _rc;			\
	do {					\
		_rc = (exp);			\
	} while (_rc == -1 && errno == EINTR);	\
	_rc; })

#ifndef bzero
#define bzero(s, n) memset((s), '\0', (n))
#endif
#ifndef bcopy
#define bcopy(src, dest, n) memmove((dest), (src), (n))
#endif

#if !defined(TAILQ_FOREACH_SAFE)
#define TAILQ_FOREACH_SAFE(var, head, field, next)			\
	for ((var) = TAILQ_FIRST((head));				\
		(var) && ((next) = TAILQ_NEXT((var), field), 1);	\
		(var) = (next))
#endif

void set_nport(struct sockaddr *sa, unsigned port);
unsigned  monotonic_sec(void);
int unix_write(int  fd, const char *buff, int len);
#endif /* __UTILS_H__ */
