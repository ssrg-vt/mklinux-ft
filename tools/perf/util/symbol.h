#ifndef __PERF_SYMBOL
#define __PERF_SYMBOL 1

#include <linux/types.h>
#include <stdbool.h>
#include "types.h"
#include <linux/list.h>
#include <linux/rbtree.h>
#include "event.h"

#ifdef HAVE_CPLUS_DEMANGLE
extern char *cplus_demangle(const char *, int);

static inline char *bfd_demangle(void __used *v, const char *c, int i)
{
	return cplus_demangle(c, i);
}
#else
#ifdef NO_DEMANGLE
static inline char *bfd_demangle(void __used *v, const char __used *c,
				 int __used i)
{
	return NULL;
}
#else
#include <bfd.h>
#endif
#endif

/*
 * libelf 0.8.x and earlier do not support ELF_C_READ_MMAP;
 * for newer versions we can use mmap to reduce memory usage:
 */
#ifdef LIBELF_NO_MMAP
# define PERF_ELF_C_READ_MMAP ELF_C_READ
#else
# define PERF_ELF_C_READ_MMAP ELF_C_READ_MMAP
#endif

#ifndef DMGL_PARAMS
#define DMGL_PARAMS      (1 << 0)       /* Include function args */
#define DMGL_ANSI        (1 << 1)       /* Include const, volatile, etc */
#endif

struct symbol {
	struct rb_node	rb_node;
	u64		start;
	u64		end;
	char		name[0];
};

extern unsigned int symbol__priv_size;

static inline void *symbol__priv(struct symbol *self)
{
	return ((void *)self) - symbol__priv_size;
}

struct dso {
	struct list_head node;
	struct rb_root	 syms;
	struct symbol    *(*find_symbol)(struct dso *, u64 ip);
	u8		 adjust_symbols:1;
	u8		 slen_calculated:1;
	u8		 loaded:1;
	u8		 has_build_id:1;
	unsigned char	 origin;
	u8		 build_id[BUILD_ID_SIZE];
	u16		 long_name_len;
	const char	 *short_name;
	char	 	 *long_name;
	char		 name[0];
};

struct dso *dso__new(const char *name);
void dso__delete(struct dso *self);

struct symbol *dso__find_symbol(struct dso *self, u64 ip);

int dsos__load_modules(void);
int dsos__load_modules_sym(symbol_filter_t filter);
struct dso *dsos__findnew(const char *name);
int dso__load(struct dso *self, struct map *map, symbol_filter_t filter);
int dso__load_kernel_sym(struct dso *self, symbol_filter_t filter,
			 int use_modules);
void dsos__fprintf(FILE *fp);
size_t dsos__fprintf_buildid(FILE *fp);

size_t dso__fprintf_buildid(struct dso *self, FILE *fp);
size_t dso__fprintf(struct dso *self, FILE *fp);
char dso__symtab_origin(const struct dso *self);
void dso__set_build_id(struct dso *self, void *build_id);

int filename__read_build_id(const char *filename, void *bf, size_t size);
int sysfs__read_build_id(const char *filename, void *bf, size_t size);
bool dsos__read_build_ids(void);
int build_id__sprintf(u8 *self, int len, char *bf);

struct dso *dsos__load_kernel(void);
int load_kernel(symbol_filter_t filter, bool use_modules);

void symbol__init(unsigned int priv_size);

extern struct list_head dsos;
extern struct map *kernel_map;
extern struct dso *vdso;
extern const char *vmlinux_name;
#endif /* __PERF_SYMBOL */
