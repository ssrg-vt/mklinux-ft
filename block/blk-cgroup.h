#ifndef _BLK_CGROUP_H
#define _BLK_CGROUP_H
/*
 * Common Block IO controller cgroup interface
 *
 * Based on ideas and code from CFQ, CFS and BFQ:
 * Copyright (C) 2003 Jens Axboe <axboe@kernel.dk>
 *
 * Copyright (C) 2008 Fabio Checconi <fabio@gandalf.sssup.it>
 *		      Paolo Valente <paolo.valente@unimore.it>
 *
 * Copyright (C) 2009 Vivek Goyal <vgoyal@redhat.com>
 * 	              Nauman Rafique <nauman@google.com>
 */

#include <linux/cgroup.h>

struct blkio_cgroup {
	struct cgroup_subsys_state css;
	unsigned int weight;
	spinlock_t lock;
	struct hlist_head blkg_list;
};

struct blkio_group {
	/* An rcu protected unique identifier for the group */
	void *key;
	struct hlist_node blkcg_node;
	unsigned short blkcg_id;
#ifdef CONFIG_DEBUG_BLK_CGROUP
	/* Store cgroup path */
	char path[128];
	/* How many times this group has been removed from service tree */
	unsigned long dequeue;
#endif
	/* The device MKDEV(major, minor), this group has been created for */
	dev_t   dev;

	/* total disk time and nr sectors dispatched by this group */
	unsigned long time;
	unsigned long sectors;
};

#define BLKIO_WEIGHT_MIN	100
#define BLKIO_WEIGHT_MAX	1000
#define BLKIO_WEIGHT_DEFAULT	500

#ifdef CONFIG_DEBUG_BLK_CGROUP
static inline char *blkg_path(struct blkio_group *blkg)
{
	return blkg->path;
}
void blkiocg_update_blkio_group_dequeue_stats(struct blkio_group *blkg,
				unsigned long dequeue);
#else
static inline char *blkg_path(struct blkio_group *blkg) { return NULL; }
static inline void blkiocg_update_blkio_group_dequeue_stats(
			struct blkio_group *blkg, unsigned long dequeue) {}
#endif

#ifdef CONFIG_BLK_CGROUP
extern struct blkio_cgroup blkio_root_cgroup;
extern struct blkio_cgroup *cgroup_to_blkio_cgroup(struct cgroup *cgroup);
extern void blkiocg_add_blkio_group(struct blkio_cgroup *blkcg,
			struct blkio_group *blkg, void *key, dev_t dev);
extern int blkiocg_del_blkio_group(struct blkio_group *blkg);
extern struct blkio_group *blkiocg_lookup_group(struct blkio_cgroup *blkcg,
						void *key);
void blkiocg_update_blkio_group_stats(struct blkio_group *blkg,
			unsigned long time, unsigned long sectors);
#else
static inline struct blkio_cgroup *
cgroup_to_blkio_cgroup(struct cgroup *cgroup) { return NULL; }

static inline void blkiocg_add_blkio_group(struct blkio_cgroup *blkcg,
			struct blkio_group *blkg, void *key, dev_t dev)
{
}

static inline int
blkiocg_del_blkio_group(struct blkio_group *blkg) { return 0; }

static inline struct blkio_group *
blkiocg_lookup_group(struct blkio_cgroup *blkcg, void *key) { return NULL; }
static inline void blkiocg_update_blkio_group_stats(struct blkio_group *blkg,
			unsigned long time, unsigned long sectors)
{
}
#endif
#endif /* _BLK_CGROUP_H */
