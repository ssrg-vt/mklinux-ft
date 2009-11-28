#ifndef __PERF_TRACE_EVENT_PERL_H
#define __PERF_TRACE_EVENT_PERL_H
#ifdef NO_LIBPERL
typedef int INTERP;
#define dSP
#define ENTER
#define SAVETMPS
#define PUTBACK
#define SPAGAIN
#define FREETMPS
#define LEAVE
#define SP
#define ERRSV
#define G_SCALAR		(0)
#define G_DISCARD		(0)
#define G_NOARGS		(0)
#define PUSHMARK(a)
#define SvTRUE(a)		(0)
#define XPUSHs(s)
#define sv_2mortal(a)
#define newSVpv(a,b)
#define newSVuv(a)
#define newSViv(a)
#define get_cv(a,b)		(0)
#define call_pv(a,b)		(0)
#define perl_alloc()		(0)
#define perl_construct(a)	(0)
#define perl_parse(a,b,c,d,e)	(0)
#define perl_run(a)		(0)
#define perl_destruct(a)	(0)
#define perl_free(a)		(0)
#else
#include <EXTERN.h>
#include <perl.h>
typedef PerlInterpreter * INTERP;
#endif

struct scripting_context {
	void *event_data;
};

#endif /* __PERF_TRACE_EVENT_PERL_H */
