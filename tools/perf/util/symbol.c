#include "util.h"
#include "../perf.h"
#include "string.h"
#include "symbol.h"
#include "thread.h"

#include "debug.h"

#include <libelf.h>
#include <gelf.h>
#include <elf.h>
#include <sys/utsname.h>

const char *sym_hist_filter;

enum dso_origin {
	DSO__ORIG_KERNEL = 0,
	DSO__ORIG_JAVA_JIT,
	DSO__ORIG_FEDORA,
	DSO__ORIG_UBUNTU,
	DSO__ORIG_BUILDID,
	DSO__ORIG_DSO,
	DSO__ORIG_KMODULE,
	DSO__ORIG_NOT_FOUND,
};

static void dsos__add(struct dso *dso);
static struct dso *dsos__find(const char *name);

static struct rb_root kernel_maps;

static void dso__set_symbols_end(struct dso *self)
{
	struct rb_node *nd, *prevnd = rb_first(&self->syms);

	if (prevnd == NULL)
		return;

	for (nd = rb_next(prevnd); nd; nd = rb_next(nd)) {
		struct symbol *prev = rb_entry(prevnd, struct symbol, rb_node),
			      *curr = rb_entry(nd, struct symbol, rb_node);

		if (prev->end == prev->start)
			prev->end = curr->start - 1;
		prevnd = nd;
	}
}

static void kernel_maps__fixup_sym_end(void)
{
	struct map *prev, *curr;
	struct rb_node *nd, *prevnd = rb_first(&kernel_maps);

	if (prevnd == NULL)
		return;

	curr = rb_entry(prevnd, struct map, rb_node);
	dso__set_symbols_end(curr->dso);

	for (nd = rb_next(prevnd); nd; nd = rb_next(nd)) {
		prev = curr;
		curr = rb_entry(nd, struct map, rb_node);
		prev->end = curr->start - 1;
		dso__set_symbols_end(curr->dso);
	}
}

static struct symbol *symbol__new(u64 start, u64 len, const char *name,
				  unsigned int priv_size, int v)
{
	size_t namelen = strlen(name) + 1;
	struct symbol *self = calloc(1, priv_size + sizeof(*self) + namelen);

	if (!self)
		return NULL;

	if (v >= 2)
		printf("new symbol: %016Lx [%08lx]: %s, hist: %p\n",
			start, (unsigned long)len, name, self->hist);

	self->hist = NULL;
	self->hist_sum = 0;

	if (sym_hist_filter && !strcmp(name, sym_hist_filter))
		self->hist = calloc(sizeof(u64), len);

	if (priv_size) {
		memset(self, 0, priv_size);
		self = ((void *)self) + priv_size;
	}
	self->start = start;
	self->end   = len ? start + len - 1 : start;
	memcpy(self->name, name, namelen);

	return self;
}

static void symbol__delete(struct symbol *self, unsigned int priv_size)
{
	free(((void *)self) - priv_size);
}

static size_t symbol__fprintf(struct symbol *self, FILE *fp)
{
	return fprintf(fp, " %llx-%llx %s\n",
		       self->start, self->end, self->name);
}

struct dso *dso__new(const char *name, unsigned int sym_priv_size)
{
	struct dso *self = malloc(sizeof(*self) + strlen(name) + 1);

	if (self != NULL) {
		strcpy(self->name, name);
		self->long_name = self->name;
		self->short_name = self->name;
		self->syms = RB_ROOT;
		self->sym_priv_size = sym_priv_size;
		self->find_symbol = dso__find_symbol;
		self->slen_calculated = 0;
		self->origin = DSO__ORIG_NOT_FOUND;
	}

	return self;
}

static void dso__delete_symbols(struct dso *self)
{
	struct symbol *pos;
	struct rb_node *next = rb_first(&self->syms);

	while (next) {
		pos = rb_entry(next, struct symbol, rb_node);
		next = rb_next(&pos->rb_node);
		rb_erase(&pos->rb_node, &self->syms);
		symbol__delete(pos, self->sym_priv_size);
	}
}

void dso__delete(struct dso *self)
{
	dso__delete_symbols(self);
	if (self->long_name != self->name)
		free(self->long_name);
	free(self);
}

static void dso__insert_symbol(struct dso *self, struct symbol *sym)
{
	struct rb_node **p = &self->syms.rb_node;
	struct rb_node *parent = NULL;
	const u64 ip = sym->start;
	struct symbol *s;

	while (*p != NULL) {
		parent = *p;
		s = rb_entry(parent, struct symbol, rb_node);
		if (ip < s->start)
			p = &(*p)->rb_left;
		else
			p = &(*p)->rb_right;
	}
	rb_link_node(&sym->rb_node, parent, p);
	rb_insert_color(&sym->rb_node, &self->syms);
}

struct symbol *dso__find_symbol(struct dso *self, u64 ip)
{
	struct rb_node *n;

	if (self == NULL)
		return NULL;

	n = self->syms.rb_node;

	while (n) {
		struct symbol *s = rb_entry(n, struct symbol, rb_node);

		if (ip < s->start)
			n = n->rb_left;
		else if (ip > s->end)
			n = n->rb_right;
		else
			return s;
	}

	return NULL;
}

size_t dso__fprintf(struct dso *self, FILE *fp)
{
	size_t ret = fprintf(fp, "dso: %s\n", self->short_name);

	struct rb_node *nd;
	for (nd = rb_first(&self->syms); nd; nd = rb_next(nd)) {
		struct symbol *pos = rb_entry(nd, struct symbol, rb_node);
		ret += symbol__fprintf(pos, fp);
	}

	return ret;
}

static int maps__load_kallsyms(symbol_filter_t filter, int use_modules, int v)
{
	struct map *map = kernel_map;
	char *line = NULL;
	size_t n;
	FILE *file = fopen("/proc/kallsyms", "r");
	int count = 0;

	if (file == NULL)
		goto out_failure;

	while (!feof(file)) {
		u64 start;
		struct symbol *sym;
		int line_len, len;
		char symbol_type;
		char *module, *symbol_name;

		line_len = getline(&line, &n, file);
		if (line_len < 0)
			break;

		if (!line)
			goto out_failure;

		line[--line_len] = '\0'; /* \n */

		len = hex2u64(line, &start);

		len++;
		if (len + 2 >= line_len)
			continue;

		symbol_type = toupper(line[len]);
		/*
		 * We're interested only in code ('T'ext)
		 */
		if (symbol_type != 'T' && symbol_type != 'W')
			continue;

		symbol_name = line + len + 2;
		module = strchr(symbol_name, '\t');
		if (module) {
			char *module_name_end;

			if (!use_modules)
				continue;
			*module = '\0';
			module = strchr(module + 1, '[');
			if (!module)
				continue;
			module_name_end = strchr(module + 1, ']');
			if (!module_name_end)
				continue;
			*(module_name_end + 1) = '\0';
			if (strcmp(map->dso->name, module)) {
				map = kernel_maps__find_by_dso_name(module);
				if (!map) {
					fputs("/proc/{kallsyms,modules} "
					      "inconsistency!\n", stderr);
					return -1;
				}
			}
			start = map->map_ip(map, start);
		} else
			map = kernel_map;
		/*
		 * Well fix up the end later, when we have all sorted.
		 */
		sym = symbol__new(start, 0, symbol_name,
				  map->dso->sym_priv_size, v);

		if (sym == NULL)
			goto out_delete_line;

		if (filter && filter(map, sym))
			symbol__delete(sym, map->dso->sym_priv_size);
		else {
			dso__insert_symbol(map->dso, sym);
			count++;
		}
	}

	free(line);
	fclose(file);

	return count;

out_delete_line:
	free(line);
out_failure:
	return -1;
}

static size_t kernel_maps__fprintf(FILE *fp)
{
	size_t printed = fprintf(stderr, "Kernel maps:\n");
	struct rb_node *nd;

	printed += map__fprintf(kernel_map, fp);
	printed += dso__fprintf(kernel_map->dso, fp);

	for (nd = rb_first(&kernel_maps); nd; nd = rb_next(nd)) {
		struct map *pos = rb_entry(nd, struct map, rb_node);

		printed += map__fprintf(pos, fp);
		printed += dso__fprintf(pos->dso, fp);
	}

	return printed + fprintf(stderr, "END kernel maps\n");
}

static int dso__load_perf_map(struct dso *self, struct map *map,
			      symbol_filter_t filter, int v)
{
	char *line = NULL;
	size_t n;
	FILE *file;
	int nr_syms = 0;

	file = fopen(self->long_name, "r");
	if (file == NULL)
		goto out_failure;

	while (!feof(file)) {
		u64 start, size;
		struct symbol *sym;
		int line_len, len;

		line_len = getline(&line, &n, file);
		if (line_len < 0)
			break;

		if (!line)
			goto out_failure;

		line[--line_len] = '\0'; /* \n */

		len = hex2u64(line, &start);

		len++;
		if (len + 2 >= line_len)
			continue;

		len += hex2u64(line + len, &size);

		len++;
		if (len + 2 >= line_len)
			continue;

		sym = symbol__new(start, size, line + len,
				  self->sym_priv_size, v);

		if (sym == NULL)
			goto out_delete_line;

		if (filter && filter(map, sym))
			symbol__delete(sym, self->sym_priv_size);
		else {
			dso__insert_symbol(self, sym);
			nr_syms++;
		}
	}

	free(line);
	fclose(file);

	return nr_syms;

out_delete_line:
	free(line);
out_failure:
	return -1;
}

/**
 * elf_symtab__for_each_symbol - iterate thru all the symbols
 *
 * @self: struct elf_symtab instance to iterate
 * @idx: uint32_t idx
 * @sym: GElf_Sym iterator
 */
#define elf_symtab__for_each_symbol(syms, nr_syms, idx, sym) \
	for (idx = 0, gelf_getsym(syms, idx, &sym);\
	     idx < nr_syms; \
	     idx++, gelf_getsym(syms, idx, &sym))

static inline uint8_t elf_sym__type(const GElf_Sym *sym)
{
	return GELF_ST_TYPE(sym->st_info);
}

static inline int elf_sym__is_function(const GElf_Sym *sym)
{
	return elf_sym__type(sym) == STT_FUNC &&
	       sym->st_name != 0 &&
	       sym->st_shndx != SHN_UNDEF &&
	       sym->st_size != 0;
}

static inline int elf_sym__is_label(const GElf_Sym *sym)
{
	return elf_sym__type(sym) == STT_NOTYPE &&
		sym->st_name != 0 &&
		sym->st_shndx != SHN_UNDEF &&
		sym->st_shndx != SHN_ABS;
}

static inline const char *elf_sec__name(const GElf_Shdr *shdr,
					const Elf_Data *secstrs)
{
	return secstrs->d_buf + shdr->sh_name;
}

static inline int elf_sec__is_text(const GElf_Shdr *shdr,
					const Elf_Data *secstrs)
{
	return strstr(elf_sec__name(shdr, secstrs), "text") != NULL;
}

static inline const char *elf_sym__name(const GElf_Sym *sym,
					const Elf_Data *symstrs)
{
	return symstrs->d_buf + sym->st_name;
}

static Elf_Scn *elf_section_by_name(Elf *elf, GElf_Ehdr *ep,
				    GElf_Shdr *shp, const char *name,
				    size_t *idx)
{
	Elf_Scn *sec = NULL;
	size_t cnt = 1;

	while ((sec = elf_nextscn(elf, sec)) != NULL) {
		char *str;

		gelf_getshdr(sec, shp);
		str = elf_strptr(elf, ep->e_shstrndx, shp->sh_name);
		if (!strcmp(name, str)) {
			if (idx)
				*idx = cnt;
			break;
		}
		++cnt;
	}

	return sec;
}

#define elf_section__for_each_rel(reldata, pos, pos_mem, idx, nr_entries) \
	for (idx = 0, pos = gelf_getrel(reldata, 0, &pos_mem); \
	     idx < nr_entries; \
	     ++idx, pos = gelf_getrel(reldata, idx, &pos_mem))

#define elf_section__for_each_rela(reldata, pos, pos_mem, idx, nr_entries) \
	for (idx = 0, pos = gelf_getrela(reldata, 0, &pos_mem); \
	     idx < nr_entries; \
	     ++idx, pos = gelf_getrela(reldata, idx, &pos_mem))

/*
 * We need to check if we have a .dynsym, so that we can handle the
 * .plt, synthesizing its symbols, that aren't on the symtabs (be it
 * .dynsym or .symtab).
 * And always look at the original dso, not at debuginfo packages, that
 * have the PLT data stripped out (shdr_rel_plt.sh_type == SHT_NOBITS).
 */
static int dso__synthesize_plt_symbols(struct  dso *self, int v)
{
	uint32_t nr_rel_entries, idx;
	GElf_Sym sym;
	u64 plt_offset;
	GElf_Shdr shdr_plt;
	struct symbol *f;
	GElf_Shdr shdr_rel_plt, shdr_dynsym;
	Elf_Data *reldata, *syms, *symstrs;
	Elf_Scn *scn_plt_rel, *scn_symstrs, *scn_dynsym;
	size_t dynsym_idx;
	GElf_Ehdr ehdr;
	char sympltname[1024];
	Elf *elf;
	int nr = 0, symidx, fd, err = 0;

	fd = open(self->long_name, O_RDONLY);
	if (fd < 0)
		goto out;

	elf = elf_begin(fd, ELF_C_READ_MMAP, NULL);
	if (elf == NULL)
		goto out_close;

	if (gelf_getehdr(elf, &ehdr) == NULL)
		goto out_elf_end;

	scn_dynsym = elf_section_by_name(elf, &ehdr, &shdr_dynsym,
					 ".dynsym", &dynsym_idx);
	if (scn_dynsym == NULL)
		goto out_elf_end;

	scn_plt_rel = elf_section_by_name(elf, &ehdr, &shdr_rel_plt,
					  ".rela.plt", NULL);
	if (scn_plt_rel == NULL) {
		scn_plt_rel = elf_section_by_name(elf, &ehdr, &shdr_rel_plt,
						  ".rel.plt", NULL);
		if (scn_plt_rel == NULL)
			goto out_elf_end;
	}

	err = -1;

	if (shdr_rel_plt.sh_link != dynsym_idx)
		goto out_elf_end;

	if (elf_section_by_name(elf, &ehdr, &shdr_plt, ".plt", NULL) == NULL)
		goto out_elf_end;

	/*
	 * Fetch the relocation section to find the idxes to the GOT
	 * and the symbols in the .dynsym they refer to.
	 */
	reldata = elf_getdata(scn_plt_rel, NULL);
	if (reldata == NULL)
		goto out_elf_end;

	syms = elf_getdata(scn_dynsym, NULL);
	if (syms == NULL)
		goto out_elf_end;

	scn_symstrs = elf_getscn(elf, shdr_dynsym.sh_link);
	if (scn_symstrs == NULL)
		goto out_elf_end;

	symstrs = elf_getdata(scn_symstrs, NULL);
	if (symstrs == NULL)
		goto out_elf_end;

	nr_rel_entries = shdr_rel_plt.sh_size / shdr_rel_plt.sh_entsize;
	plt_offset = shdr_plt.sh_offset;

	if (shdr_rel_plt.sh_type == SHT_RELA) {
		GElf_Rela pos_mem, *pos;

		elf_section__for_each_rela(reldata, pos, pos_mem, idx,
					   nr_rel_entries) {
			symidx = GELF_R_SYM(pos->r_info);
			plt_offset += shdr_plt.sh_entsize;
			gelf_getsym(syms, symidx, &sym);
			snprintf(sympltname, sizeof(sympltname),
				 "%s@plt", elf_sym__name(&sym, symstrs));

			f = symbol__new(plt_offset, shdr_plt.sh_entsize,
					sympltname, self->sym_priv_size, v);
			if (!f)
				goto out_elf_end;

			dso__insert_symbol(self, f);
			++nr;
		}
	} else if (shdr_rel_plt.sh_type == SHT_REL) {
		GElf_Rel pos_mem, *pos;
		elf_section__for_each_rel(reldata, pos, pos_mem, idx,
					  nr_rel_entries) {
			symidx = GELF_R_SYM(pos->r_info);
			plt_offset += shdr_plt.sh_entsize;
			gelf_getsym(syms, symidx, &sym);
			snprintf(sympltname, sizeof(sympltname),
				 "%s@plt", elf_sym__name(&sym, symstrs));

			f = symbol__new(plt_offset, shdr_plt.sh_entsize,
					sympltname, self->sym_priv_size, v);
			if (!f)
				goto out_elf_end;

			dso__insert_symbol(self, f);
			++nr;
		}
	}

	err = 0;
out_elf_end:
	elf_end(elf);
out_close:
	close(fd);

	if (err == 0)
		return nr;
out:
	fprintf(stderr, "%s: problems reading %s PLT info.\n",
		__func__, self->long_name);
	return 0;
}

static int dso__load_sym(struct dso *self, struct map *map, const char *name,
			 int fd, symbol_filter_t filter, int kernel,
			 int kmodule, int v)
{
	Elf_Data *symstrs, *secstrs;
	uint32_t nr_syms;
	int err = -1;
	uint32_t idx;
	GElf_Ehdr ehdr;
	GElf_Shdr shdr;
	Elf_Data *syms;
	GElf_Sym sym;
	Elf_Scn *sec, *sec_strndx;
	Elf *elf;
	int nr = 0;

	elf = elf_begin(fd, ELF_C_READ_MMAP, NULL);
	if (elf == NULL) {
		if (v)
			fprintf(stderr, "%s: cannot read %s ELF file.\n",
				__func__, name);
		goto out_close;
	}

	if (gelf_getehdr(elf, &ehdr) == NULL) {
		if (v)
			fprintf(stderr, "%s: cannot get elf header.\n", __func__);
		goto out_elf_end;
	}

	sec = elf_section_by_name(elf, &ehdr, &shdr, ".symtab", NULL);
	if (sec == NULL) {
		sec = elf_section_by_name(elf, &ehdr, &shdr, ".dynsym", NULL);
		if (sec == NULL)
			goto out_elf_end;
	}

	syms = elf_getdata(sec, NULL);
	if (syms == NULL)
		goto out_elf_end;

	sec = elf_getscn(elf, shdr.sh_link);
	if (sec == NULL)
		goto out_elf_end;

	symstrs = elf_getdata(sec, NULL);
	if (symstrs == NULL)
		goto out_elf_end;

	sec_strndx = elf_getscn(elf, ehdr.e_shstrndx);
	if (sec_strndx == NULL)
		goto out_elf_end;

	secstrs = elf_getdata(sec_strndx, NULL);
	if (secstrs == NULL)
		goto out_elf_end;

	nr_syms = shdr.sh_size / shdr.sh_entsize;

	memset(&sym, 0, sizeof(sym));
	if (!kernel) {
		self->adjust_symbols = (ehdr.e_type == ET_EXEC ||
				elf_section_by_name(elf, &ehdr, &shdr,
						     ".gnu.prelink_undo",
						     NULL) != NULL);
	} else self->adjust_symbols = 0;

	elf_symtab__for_each_symbol(syms, nr_syms, idx, sym) {
		struct symbol *f;
		const char *elf_name;
		char *demangled;
		int is_label = elf_sym__is_label(&sym);
		const char *section_name;
		u64 sh_offset = 0;

		if (!is_label && !elf_sym__is_function(&sym))
			continue;

		sec = elf_getscn(elf, sym.st_shndx);
		if (!sec)
			goto out_elf_end;

		gelf_getshdr(sec, &shdr);

		if (is_label && !elf_sec__is_text(&shdr, secstrs))
			continue;

		section_name = elf_sec__name(&shdr, secstrs);

		if ((kernel || kmodule)) {
			if (strstr(section_name, ".init"))
				sh_offset = shdr.sh_offset;
		}

		if (self->adjust_symbols) {
			if (v >= 2)
				printf("adjusting symbol: st_value: %Lx sh_addr: %Lx sh_offset: %Lx\n",
					(u64)sym.st_value, (u64)shdr.sh_addr, (u64)shdr.sh_offset);

			sym.st_value -= shdr.sh_addr - shdr.sh_offset;
		}
		/*
		 * We need to figure out if the object was created from C++ sources
		 * DWARF DW_compile_unit has this, but we don't always have access
		 * to it...
		 */
		elf_name = elf_sym__name(&sym, symstrs);
		demangled = bfd_demangle(NULL, elf_name, DMGL_PARAMS | DMGL_ANSI);
		if (demangled != NULL)
			elf_name = demangled;

		f = symbol__new(sym.st_value + sh_offset, sym.st_size, elf_name,
				self->sym_priv_size, v);
		free(demangled);
		if (!f)
			goto out_elf_end;

		if (filter && filter(map, f))
			symbol__delete(f, self->sym_priv_size);
		else {
			dso__insert_symbol(self, f);
			nr++;
		}
	}

	err = nr;
out_elf_end:
	elf_end(elf);
out_close:
	return err;
}

#define BUILD_ID_SIZE 128

static char *dso__read_build_id(struct dso *self, int v)
{
	int i;
	GElf_Ehdr ehdr;
	GElf_Shdr shdr;
	Elf_Data *build_id_data;
	Elf_Scn *sec;
	char *build_id = NULL, *bid;
	unsigned char *raw;
	Elf *elf;
	int fd = open(self->long_name, O_RDONLY);

	if (fd < 0)
		goto out;

	elf = elf_begin(fd, ELF_C_READ_MMAP, NULL);
	if (elf == NULL) {
		if (v)
			fprintf(stderr, "%s: cannot read %s ELF file.\n",
				__func__, self->long_name);
		goto out_close;
	}

	if (gelf_getehdr(elf, &ehdr) == NULL) {
		if (v)
			fprintf(stderr, "%s: cannot get elf header.\n", __func__);
		goto out_elf_end;
	}

	sec = elf_section_by_name(elf, &ehdr, &shdr, ".note.gnu.build-id", NULL);
	if (sec == NULL)
		goto out_elf_end;

	build_id_data = elf_getdata(sec, NULL);
	if (build_id_data == NULL)
		goto out_elf_end;
	build_id = malloc(BUILD_ID_SIZE);
	if (build_id == NULL)
		goto out_elf_end;
	raw = build_id_data->d_buf + 16;
	bid = build_id;

	for (i = 0; i < 20; ++i) {
		sprintf(bid, "%02x", *raw);
		++raw;
		bid += 2;
	}
	if (v >= 2)
		printf("%s(%s): %s\n", __func__, self->long_name, build_id);
out_elf_end:
	elf_end(elf);
out_close:
	close(fd);
out:
	return build_id;
}

char dso__symtab_origin(const struct dso *self)
{
	static const char origin[] = {
		[DSO__ORIG_KERNEL] =   'k',
		[DSO__ORIG_JAVA_JIT] = 'j',
		[DSO__ORIG_FEDORA] =   'f',
		[DSO__ORIG_UBUNTU] =   'u',
		[DSO__ORIG_BUILDID] =  'b',
		[DSO__ORIG_DSO] =      'd',
		[DSO__ORIG_KMODULE] =  'K',
	};

	if (self == NULL || self->origin == DSO__ORIG_NOT_FOUND)
		return '!';
	return origin[self->origin];
}

int dso__load(struct dso *self, struct map *map, symbol_filter_t filter, int v)
{
	int size = PATH_MAX;
	char *name = malloc(size), *build_id = NULL;
	int ret = -1;
	int fd;

	if (!name)
		return -1;

	self->adjust_symbols = 0;

	if (strncmp(self->name, "/tmp/perf-", 10) == 0) {
		ret = dso__load_perf_map(self, map, filter, v);
		self->origin = ret > 0 ? DSO__ORIG_JAVA_JIT :
					 DSO__ORIG_NOT_FOUND;
		return ret;
	}

	self->origin = DSO__ORIG_FEDORA - 1;

more:
	do {
		self->origin++;
		switch (self->origin) {
		case DSO__ORIG_FEDORA:
			snprintf(name, size, "/usr/lib/debug%s.debug",
				 self->long_name);
			break;
		case DSO__ORIG_UBUNTU:
			snprintf(name, size, "/usr/lib/debug%s",
				 self->long_name);
			break;
		case DSO__ORIG_BUILDID:
			build_id = dso__read_build_id(self, v);
			if (build_id != NULL) {
				snprintf(name, size,
					 "/usr/lib/debug/.build-id/%.2s/%s.debug",
					build_id, build_id + 2);
				free(build_id);
				break;
			}
			self->origin++;
			/* Fall thru */
		case DSO__ORIG_DSO:
			snprintf(name, size, "%s", self->long_name);
			break;

		default:
			goto out;
		}

		fd = open(name, O_RDONLY);
	} while (fd < 0);

	ret = dso__load_sym(self, map, name, fd, filter, 0, 0, v);
	close(fd);

	/*
	 * Some people seem to have debuginfo files _WITHOUT_ debug info!?!?
	 */
	if (!ret)
		goto more;

	if (ret > 0) {
		int nr_plt = dso__synthesize_plt_symbols(self, v);
		if (nr_plt > 0)
			ret += nr_plt;
	}
out:
	free(name);
	if (ret < 0 && strstr(self->name, " (deleted)") != NULL)
		return 0;
	return ret;
}

struct map *kernel_map;

static void kernel_maps__insert(struct map *map)
{
	maps__insert(&kernel_maps, map);
}

struct symbol *kernel_maps__find_symbol(u64 ip, struct map **mapp)
{
	/*
	 * We can't have kernel_map in kernel_maps because it spans an address
	 * space that includes the modules. The right way to fix this is to
	 * create several maps, so that we don't have overlapping ranges with
	 * modules. For now lets look first on the kernel dso.
	 */
	struct map *map = maps__find(&kernel_maps, ip);
	struct symbol *sym;

	if (map) {
		ip = map->map_ip(map, ip);
		sym = map->dso->find_symbol(map->dso, ip);
	} else {
		map = kernel_map;
		sym = map->dso->find_symbol(map->dso, ip);
	}

	if (mapp)
		*mapp = map;

	return sym;
}

struct map *kernel_maps__find_by_dso_name(const char *name)
{
	struct rb_node *nd;

	for (nd = rb_first(&kernel_maps); nd; nd = rb_next(nd)) {
		struct map *map = rb_entry(nd, struct map, rb_node);

		if (map->dso && strcmp(map->dso->name, name) == 0)
			return map;
	}

	return NULL;
}

static int dso__load_module_sym(struct dso *self, struct map *map,
				symbol_filter_t filter, int v)
{
	int err = 0, fd = open(self->long_name, O_RDONLY);

	if (fd < 0) {
		if (v)
			fprintf(stderr, "%s: cannot open %s\n",
				__func__, self->long_name);
		return err;
	}

	err = dso__load_sym(self, map, self->long_name, fd, filter, 0, 1, v);
	close(fd);

	return err;
}

static int dsos__load_modules_sym_dir(char *dirname,
				      symbol_filter_t filter, int v)
{
	struct dirent *dent;
	int nr_symbols = 0, err;
	DIR *dir = opendir(dirname);

	if (!dir) {
		if (v)
			fprintf(stderr, "%s: cannot open %s dir\n", __func__,
				dirname);
		return -1;
	}

	while ((dent = readdir(dir)) != NULL) {
		char path[PATH_MAX];

		if (dent->d_type == DT_DIR) {
			if (!strcmp(dent->d_name, ".") ||
			    !strcmp(dent->d_name, ".."))
				continue;

			snprintf(path, sizeof(path), "%s/%s",
				 dirname, dent->d_name);
			err = dsos__load_modules_sym_dir(path, filter, v);
			if (err < 0)
				goto failure;
		} else {
			char *dot = strrchr(dent->d_name, '.'),
			     dso_name[PATH_MAX];
			struct map *map;
			struct rb_node *last;

			if (dot == NULL || strcmp(dot, ".ko"))
				continue;
			snprintf(dso_name, sizeof(dso_name), "[%.*s]",
				 (int)(dot - dent->d_name), dent->d_name);

			strxfrchar(dso_name, '-', '_');
			map = kernel_maps__find_by_dso_name(dso_name);
			if (map == NULL)
				continue;

			snprintf(path, sizeof(path), "%s/%s",
				 dirname, dent->d_name);

			map->dso->long_name = strdup(path);
			if (map->dso->long_name == NULL)
				goto failure;

			err = dso__load_module_sym(map->dso, map, filter, v);
			if (err < 0)
				goto failure;
			last = rb_last(&map->dso->syms);
			if (last) {
				struct symbol *sym;
				sym = rb_entry(last, struct symbol, rb_node);
				map->end = map->start + sym->end;
			}
		}
		nr_symbols += err;
	}

	return nr_symbols;
failure:
	closedir(dir);
	return -1;
}

static int dsos__load_modules_sym(symbol_filter_t filter, int v)
{
	struct utsname uts;
	char modules_path[PATH_MAX];

	if (uname(&uts) < 0)
		return -1;

	snprintf(modules_path, sizeof(modules_path), "/lib/modules/%s/kernel",
		 uts.release);

	return dsos__load_modules_sym_dir(modules_path, filter, v);
}

/*
 * Constructor variant for modules (where we know from /proc/modules where
 * they are loaded) and for vmlinux, where only after we load all the
 * symbols we'll know where it starts and ends.
 */
static struct map *map__new2(u64 start, struct dso *dso)
{
	struct map *self = malloc(sizeof(*self));

	if (self != NULL) {
		self->start = start;
		/*
		 * Will be filled after we load all the symbols
		 */
		self->end = 0;

		self->pgoff = 0;
		self->dso = dso;
		self->map_ip = map__map_ip;
		RB_CLEAR_NODE(&self->rb_node);
	}
	return self;
}

static int dsos__load_modules(unsigned int sym_priv_size)
{
	char *line = NULL;
	size_t n;
	FILE *file = fopen("/proc/modules", "r");
	struct map *map;

	if (file == NULL)
		return -1;

	while (!feof(file)) {
		char name[PATH_MAX];
		u64 start;
		struct dso *dso;
		char *sep;
		int line_len;

		line_len = getline(&line, &n, file);
		if (line_len < 0)
			break;

		if (!line)
			goto out_failure;

		line[--line_len] = '\0'; /* \n */

		sep = strrchr(line, 'x');
		if (sep == NULL)
			continue;

		hex2u64(sep + 1, &start);

		sep = strchr(line, ' ');
		if (sep == NULL)
			continue;

		*sep = '\0';

		snprintf(name, sizeof(name), "[%s]", line);
		dso = dso__new(name, sym_priv_size);

		if (dso == NULL)
			goto out_delete_line;

		map = map__new2(start, dso);
		if (map == NULL) {
			dso__delete(dso);
			goto out_delete_line;
		}

		dso->origin = DSO__ORIG_KMODULE;
		kernel_maps__insert(map);
		dsos__add(dso);
	}

	free(line);
	fclose(file);

	return 0;

out_delete_line:
	free(line);
out_failure:
	return -1;
}

static int dso__load_vmlinux(struct dso *self, struct map *map,
			     const char *vmlinux,
			     symbol_filter_t filter, int v)
{
	int err, fd = open(vmlinux, O_RDONLY);

	if (fd < 0)
		return -1;

	err = dso__load_sym(self, map, self->long_name, fd, filter, 1, 0, v);

	close(fd);

	return err;
}

int dsos__load_kernel(const char *vmlinux, unsigned int sym_priv_size,
		      symbol_filter_t filter, int v, int use_modules)
{
	int err = -1;
	struct dso *dso = dso__new(vmlinux, sym_priv_size);

	if (dso == NULL)
		return -1;

	dso->short_name = "[kernel]";
	kernel_map = map__new2(0, dso);
	if (kernel_map == NULL)
		goto out_delete_dso;

	kernel_map->map_ip = vdso__map_ip;

	if (use_modules && dsos__load_modules(sym_priv_size) < 0) {
		fprintf(stderr, "Failed to load list of modules in use! "
				"Continuing...\n");
		use_modules = 0;
	}

	if (vmlinux) {
		err = dso__load_vmlinux(dso, kernel_map, vmlinux, filter, v);
		if (err > 0 && use_modules) {
			int syms = dsos__load_modules_sym(filter, v);

			if (syms < 0)
				fprintf(stderr, "Failed to read module symbols!"
					" Continuing...\n");
			else
				err += syms;
		}
	}

	if (err <= 0)
		err = maps__load_kallsyms(filter, use_modules, v);

	if (err > 0) {
		struct rb_node *node = rb_first(&dso->syms);
		struct symbol *sym = rb_entry(node, struct symbol, rb_node);
		/*
		 * Now that we have all sorted out, just set the ->end of all
		 * symbols that still don't have it.
		 */
		dso__set_symbols_end(dso);
		kernel_maps__fixup_sym_end();

		kernel_map->start = sym->start;
		node = rb_last(&dso->syms);
		sym = rb_entry(node, struct symbol, rb_node);
		kernel_map->end = sym->end;

		dso->origin = DSO__ORIG_KERNEL;
		/*
		 * XXX See kernel_maps__find_symbol comment
		 * kernel_maps__insert(kernel_map)
		 */
		dsos__add(dso);

		if (v > 0)
			kernel_maps__fprintf(stderr);
	}

	return err;

out_delete_dso:
	dso__delete(dso);
	return -1;
}

LIST_HEAD(dsos);
struct dso	*vdso;

const char	*vmlinux_name = "vmlinux";
int		modules;

static void dsos__add(struct dso *dso)
{
	list_add_tail(&dso->node, &dsos);
}

static struct dso *dsos__find(const char *name)
{
	struct dso *pos;

	list_for_each_entry(pos, &dsos, node)
		if (strcmp(pos->name, name) == 0)
			return pos;
	return NULL;
}

struct dso *dsos__findnew(const char *name)
{
	struct dso *dso = dsos__find(name);
	int nr;

	if (dso)
		return dso;

	dso = dso__new(name, 0);
	if (!dso)
		goto out_delete_dso;

	nr = dso__load(dso, NULL, NULL, verbose);
	if (nr < 0) {
		eprintf("Failed to open: %s\n", name);
		goto out_delete_dso;
	}
	if (!nr)
		eprintf("No symbols found in: %s, maybe install a debug package?\n", name);

	dsos__add(dso);

	return dso;

out_delete_dso:
	dso__delete(dso);
	return NULL;
}

void dsos__fprintf(FILE *fp)
{
	struct dso *pos;

	list_for_each_entry(pos, &dsos, node)
		dso__fprintf(pos, fp);
}

int load_kernel(void)
{
	if (dsos__load_kernel(vmlinux_name, 0, NULL, verbose, modules) <= 0)
		return -1;

	vdso = dso__new("[vdso]", 0);
	if (!vdso)
		return -1;

	dsos__add(vdso);

	return 0;
}

void symbol__init(void)
{
	elf_version(EV_CURRENT);
}
