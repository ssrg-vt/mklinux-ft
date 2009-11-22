#include "builtin.h"
#include "perf.h"

#include "util/util.h"
#include "util/cache.h"
#include "util/symbol.h"
#include "util/thread.h"
#include "util/header.h"

#include "util/parse-options.h"
#include "util/trace-event.h"

#include "util/debug.h"
#include "util/data_map.h"

#include <linux/rbtree.h>

struct alloc_stat;
typedef int (*sort_fn_t)(struct alloc_stat *, struct alloc_stat *);

static char const		*input_name = "perf.data";

static struct perf_header	*header;
static u64			sample_type;

static int			alloc_flag;
static int			caller_flag;

sort_fn_t			alloc_sort_fn;
sort_fn_t			caller_sort_fn;

static int			alloc_lines = -1;
static int			caller_lines = -1;

static char			*cwd;
static int			cwdlen;

struct alloc_stat {
	union {
		struct {
			char	*name;
			u64	call_site;
		};
		u64	ptr;
	};
	u64	bytes_req;
	u64	bytes_alloc;
	u32	hit;

	struct rb_node node;
};

static struct rb_root root_alloc_stat;
static struct rb_root root_alloc_sorted;
static struct rb_root root_caller_stat;
static struct rb_root root_caller_sorted;

static unsigned long total_requested, total_allocated;

struct raw_event_sample {
	u32 size;
	char data[0];
};

static int
process_comm_event(event_t *event, unsigned long offset, unsigned long head)
{
	struct thread *thread = threads__findnew(event->comm.pid);

	dump_printf("%p [%p]: PERF_RECORD_COMM: %s:%d\n",
		(void *)(offset + head),
		(void *)(long)(event->header.size),
		event->comm.comm, event->comm.pid);

	if (thread == NULL ||
	    thread__set_comm(thread, event->comm.comm)) {
		dump_printf("problem processing PERF_RECORD_COMM, skipping event.\n");
		return -1;
	}

	return 0;
}

static void insert_alloc_stat(unsigned long ptr,
			      int bytes_req, int bytes_alloc)
{
	struct rb_node **node = &root_alloc_stat.rb_node;
	struct rb_node *parent = NULL;
	struct alloc_stat *data = NULL;

	if (!alloc_flag)
		return;

	while (*node) {
		parent = *node;
		data = rb_entry(*node, struct alloc_stat, node);

		if (ptr > data->ptr)
			node = &(*node)->rb_right;
		else if (ptr < data->ptr)
			node = &(*node)->rb_left;
		else
			break;
	}

	if (data && data->ptr == ptr) {
		data->hit++;
		data->bytes_req += bytes_req;
		data->bytes_alloc += bytes_req;
	} else {
		data = malloc(sizeof(*data));
		data->ptr = ptr;
		data->hit = 1;
		data->bytes_req = bytes_req;
		data->bytes_alloc = bytes_alloc;

		rb_link_node(&data->node, parent, node);
		rb_insert_color(&data->node, &root_alloc_stat);
	}
}

static void insert_caller_stat(unsigned long call_site,
			      int bytes_req, int bytes_alloc)
{
	struct rb_node **node = &root_caller_stat.rb_node;
	struct rb_node *parent = NULL;
	struct alloc_stat *data = NULL;

	if (!caller_flag)
		return;

	while (*node) {
		parent = *node;
		data = rb_entry(*node, struct alloc_stat, node);

		if (call_site > data->call_site)
			node = &(*node)->rb_right;
		else if (call_site < data->call_site)
			node = &(*node)->rb_left;
		else
			break;
	}

	if (data && data->call_site == call_site) {
		data->hit++;
		data->bytes_req += bytes_req;
		data->bytes_alloc += bytes_req;
	} else {
		data = malloc(sizeof(*data));
		data->call_site = call_site;
		data->hit = 1;
		data->bytes_req = bytes_req;
		data->bytes_alloc = bytes_alloc;

		rb_link_node(&data->node, parent, node);
		rb_insert_color(&data->node, &root_caller_stat);
	}
}

static void process_alloc_event(struct raw_event_sample *raw,
				struct event *event,
				int cpu __used,
				u64 timestamp __used,
				struct thread *thread __used,
				int node __used)
{
	unsigned long call_site;
	unsigned long ptr;
	int bytes_req;
	int bytes_alloc;

	ptr = raw_field_value(event, "ptr", raw->data);
	call_site = raw_field_value(event, "call_site", raw->data);
	bytes_req = raw_field_value(event, "bytes_req", raw->data);
	bytes_alloc = raw_field_value(event, "bytes_alloc", raw->data);

	insert_alloc_stat(ptr, bytes_req, bytes_alloc);
	insert_caller_stat(call_site, bytes_req, bytes_alloc);

	total_requested += bytes_req;
	total_allocated += bytes_alloc;
}

static void process_free_event(struct raw_event_sample *raw __used,
			       struct event *event __used,
			       int cpu __used,
			       u64 timestamp __used,
			       struct thread *thread __used)
{
}

static void
process_raw_event(event_t *raw_event __used, void *more_data,
		  int cpu, u64 timestamp, struct thread *thread)
{
	struct raw_event_sample *raw = more_data;
	struct event *event;
	int type;

	type = trace_parse_common_type(raw->data);
	event = trace_find_event(type);

	if (!strcmp(event->name, "kmalloc") ||
	    !strcmp(event->name, "kmem_cache_alloc")) {
		process_alloc_event(raw, event, cpu, timestamp, thread, 0);
		return;
	}

	if (!strcmp(event->name, "kmalloc_node") ||
	    !strcmp(event->name, "kmem_cache_alloc_node")) {
		process_alloc_event(raw, event, cpu, timestamp, thread, 1);
		return;
	}

	if (!strcmp(event->name, "kfree") ||
	    !strcmp(event->name, "kmem_cache_free")) {
		process_free_event(raw, event, cpu, timestamp, thread);
		return;
	}
}

static int
process_sample_event(event_t *event, unsigned long offset, unsigned long head)
{
	u64 ip = event->ip.ip;
	u64 timestamp = -1;
	u32 cpu = -1;
	u64 period = 1;
	void *more_data = event->ip.__more_data;
	struct thread *thread = threads__findnew(event->ip.pid);

	if (sample_type & PERF_SAMPLE_TIME) {
		timestamp = *(u64 *)more_data;
		more_data += sizeof(u64);
	}

	if (sample_type & PERF_SAMPLE_CPU) {
		cpu = *(u32 *)more_data;
		more_data += sizeof(u32);
		more_data += sizeof(u32); /* reserved */
	}

	if (sample_type & PERF_SAMPLE_PERIOD) {
		period = *(u64 *)more_data;
		more_data += sizeof(u64);
	}

	dump_printf("%p [%p]: PERF_RECORD_SAMPLE (IP, %d): %d/%d: %p period: %Ld\n",
		(void *)(offset + head),
		(void *)(long)(event->header.size),
		event->header.misc,
		event->ip.pid, event->ip.tid,
		(void *)(long)ip,
		(long long)period);

	if (thread == NULL) {
		pr_debug("problem processing %d event, skipping it.\n",
			 event->header.type);
		return -1;
	}

	dump_printf(" ... thread: %s:%d\n", thread->comm, thread->pid);

	process_raw_event(event, more_data, cpu, timestamp, thread);

	return 0;
}

static int sample_type_check(u64 type)
{
	sample_type = type;

	if (!(sample_type & PERF_SAMPLE_RAW)) {
		fprintf(stderr,
			"No trace sample to read. Did you call perf record "
			"without -R?");
		return -1;
	}

	return 0;
}

static struct perf_file_handler file_handler = {
	.process_sample_event	= process_sample_event,
	.process_comm_event	= process_comm_event,
	.sample_type_check	= sample_type_check,
};

static int read_events(void)
{
	register_idle_thread();
	register_perf_file_handler(&file_handler);

	return mmap_dispatch_perf_file(&header, input_name, 0, 0,
				       &cwdlen, &cwd);
}

static double fragmentation(unsigned long n_req, unsigned long n_alloc)
{
	if (n_alloc == 0)
		return 0.0;
	else
		return 100.0 - (100.0 * n_req / n_alloc);
}

static void __print_result(struct rb_root *root, int n_lines, int is_caller)
{
	struct rb_node *next;

	printf("\n ------------------------------------------------------------------------------\n");
	if (is_caller)
		printf(" Callsite          |");
	else
		printf(" Alloc Ptr         |");
	printf(" Total_alloc/Per |  Total_req/Per  |  Hit   | Fragmentation\n");
	printf(" ------------------------------------------------------------------------------\n");

	next = rb_first(root);

	while (next && n_lines--) {
		struct alloc_stat *data;

		data = rb_entry(next, struct alloc_stat, node);

		printf(" %-16p  | %8llu/%-6lu | %8llu/%-6lu | %6lu | %8.3f%%\n",
		       is_caller ? (void *)(unsigned long)data->call_site :
				   (void *)(unsigned long)data->ptr,
		       (unsigned long long)data->bytes_alloc,
		       (unsigned long)data->bytes_alloc / data->hit,
		       (unsigned long long)data->bytes_req,
		       (unsigned long)data->bytes_req / data->hit,
		       (unsigned long)data->hit,
		       fragmentation(data->bytes_req, data->bytes_alloc));

		next = rb_next(next);
	}

	if (n_lines == -1)
		printf(" ...               | ...             | ...             | ...    | ...   \n");

	printf(" ------------------------------------------------------------------------------\n");
}

static void print_summary(void)
{
	printf("\nSUMMARY\n=======\n");
	printf("Total bytes requested: %lu\n", total_requested);
	printf("Total bytes allocated: %lu\n", total_allocated);
	printf("Total bytes wasted on internal fragmentation: %lu\n",
	       total_allocated - total_requested);
	printf("Internal fragmentation: %f%%\n",
	       fragmentation(total_requested, total_allocated));
}

static void print_result(void)
{
	if (caller_flag)
		__print_result(&root_caller_sorted, caller_lines, 1);
	if (alloc_flag)
		__print_result(&root_alloc_sorted, alloc_lines, 0);
	print_summary();
}

static void sort_insert(struct rb_root *root, struct alloc_stat *data,
			sort_fn_t sort_fn)
{
	struct rb_node **new = &(root->rb_node);
	struct rb_node *parent = NULL;

	while (*new) {
		struct alloc_stat *this;
		int cmp;

		this = rb_entry(*new, struct alloc_stat, node);
		parent = *new;

		cmp = sort_fn(data, this);

		if (cmp > 0)
			new = &((*new)->rb_left);
		else
			new = &((*new)->rb_right);
	}

	rb_link_node(&data->node, parent, new);
	rb_insert_color(&data->node, root);
}

static void __sort_result(struct rb_root *root, struct rb_root *root_sorted,
			  sort_fn_t sort_fn)
{
	struct rb_node *node;
	struct alloc_stat *data;

	for (;;) {
		node = rb_first(root);
		if (!node)
			break;

		rb_erase(node, root);
		data = rb_entry(node, struct alloc_stat, node);
		sort_insert(root_sorted, data, sort_fn);
	}
}

static void sort_result(void)
{
	__sort_result(&root_alloc_stat, &root_alloc_sorted, alloc_sort_fn);
	__sort_result(&root_caller_stat, &root_caller_sorted, caller_sort_fn);
}

static int __cmd_kmem(void)
{
	setup_pager();
	read_events();
	sort_result();
	print_result();

	return 0;
}

static const char * const kmem_usage[] = {
	"perf kmem [<options>] {record}",
	NULL
};


static int ptr_cmp(struct alloc_stat *l, struct alloc_stat *r)
{
	if (l->ptr < r->ptr)
		return -1;
	else if (l->ptr > r->ptr)
		return 1;
	return 0;
}

static int callsite_cmp(struct alloc_stat *l, struct alloc_stat *r)
{
	if (l->call_site < r->call_site)
		return -1;
	else if (l->call_site > r->call_site)
		return 1;
	return 0;
}

static int hit_cmp(struct alloc_stat *l, struct alloc_stat *r)
{
	if (l->hit < r->hit)
		return -1;
	else if (l->hit > r->hit)
		return 1;
	return 0;
}

static int bytes_cmp(struct alloc_stat *l, struct alloc_stat *r)
{
	if (l->bytes_alloc < r->bytes_alloc)
		return -1;
	else if (l->bytes_alloc > r->bytes_alloc)
		return 1;
	return 0;
}

static int frag_cmp(struct alloc_stat *l, struct alloc_stat *r)
{
	double x, y;

	x = fragmentation(l->bytes_req, l->bytes_alloc);
	y = fragmentation(r->bytes_req, r->bytes_alloc);

	if (x < y)
		return -1;
	else if (x > y)
		return 1;
	return 0;
}

static int parse_sort_opt(const struct option *opt __used,
			  const char *arg, int unset __used)
{
	sort_fn_t sort_fn;

	if (!arg)
		return -1;

	if (strcmp(arg, "ptr") == 0)
		sort_fn = ptr_cmp;
	else if (strcmp(arg, "call_site") == 0)
		sort_fn = callsite_cmp;
	else if (strcmp(arg, "hit") == 0)
		sort_fn = hit_cmp;
	else if (strcmp(arg, "bytes") == 0)
		sort_fn = bytes_cmp;
	else if (strcmp(arg, "frag") == 0)
		sort_fn = frag_cmp;
	else
		return -1;

	if (caller_flag > alloc_flag)
		caller_sort_fn = sort_fn;
	else
		alloc_sort_fn = sort_fn;

	return 0;
}

static int parse_stat_opt(const struct option *opt __used,
			  const char *arg, int unset __used)
{
	if (!arg)
		return -1;

	if (strcmp(arg, "alloc") == 0)
		alloc_flag = (caller_flag + 1);
	else if (strcmp(arg, "caller") == 0)
		caller_flag = (alloc_flag + 1);
	else
		return -1;
	return 0;
}

static int parse_line_opt(const struct option *opt __used,
			  const char *arg, int unset __used)
{
	int lines;

	if (!arg)
		return -1;

	lines = strtoul(arg, NULL, 10);

	if (caller_flag > alloc_flag)
		caller_lines = lines;
	else
		alloc_lines = lines;

	return 0;
}

static const struct option kmem_options[] = {
	OPT_STRING('i', "input", &input_name, "file",
		   "input file name"),
	OPT_CALLBACK(0, "stat", NULL, "<alloc>|<caller>",
		     "stat selector, Pass 'alloc' or 'caller'.",
		     parse_stat_opt),
	OPT_CALLBACK('s', "sort", NULL, "key",
		     "sort by key: ptr, call_site, hit, bytes, frag",
		     parse_sort_opt),
	OPT_CALLBACK('l', "line", NULL, "num",
		     "show n lins",
		     parse_line_opt),
	OPT_END()
};

static const char *record_args[] = {
	"record",
	"-a",
	"-R",
	"-M",
	"-f",
	"-c", "1",
	"-e", "kmem:kmalloc",
	"-e", "kmem:kmalloc_node",
	"-e", "kmem:kfree",
	"-e", "kmem:kmem_cache_alloc",
	"-e", "kmem:kmem_cache_alloc_node",
	"-e", "kmem:kmem_cache_free",
};

static int __cmd_record(int argc, const char **argv)
{
	unsigned int rec_argc, i, j;
	const char **rec_argv;

	rec_argc = ARRAY_SIZE(record_args) + argc - 1;
	rec_argv = calloc(rec_argc + 1, sizeof(char *));

	for (i = 0; i < ARRAY_SIZE(record_args); i++)
		rec_argv[i] = strdup(record_args[i]);

	for (j = 1; j < (unsigned int)argc; j++, i++)
		rec_argv[i] = argv[j];

	return cmd_record(i, rec_argv, NULL);
}

int cmd_kmem(int argc, const char **argv, const char *prefix __used)
{
	symbol__init(0);

	argc = parse_options(argc, argv, kmem_options, kmem_usage, 0);

	if (argc && !strncmp(argv[0], "rec", 3))
		return __cmd_record(argc, argv);
	else if (argc)
		usage_with_options(kmem_usage, kmem_options);

	if (!alloc_sort_fn)
		alloc_sort_fn = bytes_cmp;
	if (!caller_sort_fn)
		caller_sort_fn = bytes_cmp;

	return __cmd_kmem();
}

