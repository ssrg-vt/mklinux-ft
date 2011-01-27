#ifndef __PERF_EVLIST_H
#define __PERF_EVLIST_H 1

#include <linux/list.h>
#include "../perf.h"
#include "event.h"

struct pollfd;

#define PERF_EVLIST__HLIST_BITS 8
#define PERF_EVLIST__HLIST_SIZE (1 << PERF_EVLIST__HLIST_BITS)

struct perf_evlist {
	struct list_head entries;
	struct hlist_head heads[PERF_EVLIST__HLIST_SIZE];
	int		 nr_entries;
	int		 nr_fds;
	int		 mmap_len;
	event_t		 event_copy;
	struct perf_mmap *mmap;
	struct pollfd	 *pollfd;
};

struct perf_evsel;

struct perf_evlist *perf_evlist__new(void);
void perf_evlist__init(struct perf_evlist *evlist);
void perf_evlist__exit(struct perf_evlist *evlist);
void perf_evlist__delete(struct perf_evlist *evlist);

void perf_evlist__add(struct perf_evlist *evlist, struct perf_evsel *entry);
int perf_evlist__add_default(struct perf_evlist *evlist);

int perf_evlist__alloc_pollfd(struct perf_evlist *evlist, int ncpus, int nthreads);
void perf_evlist__add_pollfd(struct perf_evlist *evlist, int fd);

struct perf_evsel *perf_evlist__id2evsel(struct perf_evlist *evlist, u64 id);

event_t *perf_evlist__read_on_cpu(struct perf_evlist *self, int cpu);

#endif /* __PERF_EVLIST_H */
