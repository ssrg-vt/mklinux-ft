/*
 * trace_ksym.c - Kernel Symbol Tracer
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * Copyright (C) IBM Corporation, 2009
 */

#include <linux/kallsyms.h>
#include <linux/uaccess.h>
#include <linux/debugfs.h>
#include <linux/ftrace.h>
#include <linux/module.h>
#include <linux/fs.h>

#include "trace_output.h"
#include "trace_stat.h"
#include "trace.h"

/* For now, let us restrict the no. of symbols traced simultaneously to number
 * of available hardware breakpoint registers.
 */
#define KSYM_TRACER_MAX HBP_NUM

#define KSYM_TRACER_OP_LEN 3 /* rw- */
#define KSYM_FILTER_ENTRY_LEN (KSYM_NAME_LEN + KSYM_TRACER_OP_LEN + 1)

static struct trace_array *ksym_trace_array;

static unsigned int ksym_filter_entry_count;
static unsigned int ksym_tracing_enabled;

static HLIST_HEAD(ksym_filter_head);

static DEFINE_MUTEX(ksym_tracer_mutex);

#ifdef CONFIG_PROFILE_KSYM_TRACER

#define MAX_UL_INT 0xffffffff

void ksym_collect_stats(unsigned long hbp_hit_addr)
{
	struct hlist_node *node;
	struct trace_ksym *entry;

	rcu_read_lock();
	hlist_for_each_entry_rcu(entry, node, &ksym_filter_head, ksym_hlist) {
		if ((entry->ksym_addr == hbp_hit_addr) &&
		    (entry->counter <= MAX_UL_INT)) {
			entry->counter++;
			break;
		}
	}
	rcu_read_unlock();
}
#endif /* CONFIG_PROFILE_KSYM_TRACER */

void ksym_hbp_handler(struct hw_breakpoint *hbp, struct pt_regs *regs)
{
	struct ring_buffer_event *event;
	struct trace_array *tr;
	struct trace_ksym *entry;
	int pc;

	if (!ksym_tracing_enabled)
		return;

	tr = ksym_trace_array;
	pc = preempt_count();

	event = trace_buffer_lock_reserve(tr, TRACE_KSYM,
							sizeof(*entry), 0, pc);
	if (!event)
		return;

	entry = ring_buffer_event_data(event);
	strlcpy(entry->ksym_name, hbp->info.name, KSYM_SYMBOL_LEN);
	entry->ksym_hbp = hbp;
	entry->ip = instruction_pointer(regs);
	strlcpy(entry->p_name, current->comm, TASK_COMM_LEN);
#ifdef CONFIG_PROFILE_KSYM_TRACER
	ksym_collect_stats(hbp->info.address);
#endif /* CONFIG_PROFILE_KSYM_TRACER */

	trace_buffer_unlock_commit(tr, event, 0, pc);
}

/* Valid access types are represented as
 *
 * rw- : Set Read/Write Access Breakpoint
 * -w- : Set Write Access Breakpoint
 * --- : Clear Breakpoints
 * --x : Set Execution Break points (Not available yet)
 *
 */
static int ksym_trace_get_access_type(char *access_str)
{
	int pos, access = 0;

	for (pos = 0; pos < KSYM_TRACER_OP_LEN; pos++) {
		switch (access_str[pos]) {
		case 'r':
			access += (pos == 0) ? 4 : -1;
			break;
		case 'w':
			access += (pos == 1) ? 2 : -1;
			break;
		case '-':
			break;
		default:
			return -EINVAL;
		}
	}

	switch (access) {
	case 6:
		access = HW_BREAKPOINT_RW;
		break;
	case 2:
		access = HW_BREAKPOINT_WRITE;
		break;
	case 0:
		access = 0;
	}

	return access;
}

/*
 * There can be several possible malformed requests and we attempt to capture
 * all of them. We enumerate some of the rules
 * 1. We will not allow kernel symbols with ':' since it is used as a delimiter.
 *    i.e. multiple ':' symbols disallowed. Possible uses are of the form
 *    <module>:<ksym_name>:<op>.
 * 2. No delimiter symbol ':' in the input string
 * 3. Spurious operator symbols or symbols not in their respective positions
 * 4. <ksym_name>:--- i.e. clear breakpoint request when ksym_name not in file
 * 5. Kernel symbol not a part of /proc/kallsyms
 * 6. Duplicate requests
 */
static int parse_ksym_trace_str(char *input_string, char **ksymname,
							unsigned long *addr)
{
	char *delimiter = ":";
	int ret;

	ret = -EINVAL;
	*ksymname = strsep(&input_string, delimiter);
	*addr = kallsyms_lookup_name(*ksymname);

	/* Check for malformed request: (2), (1) and (5) */
	if ((!input_string) ||
		(strlen(input_string) != (KSYM_TRACER_OP_LEN + 1)) ||
			(*addr == 0))
		goto return_code;
	ret = ksym_trace_get_access_type(input_string);

return_code:
	return ret;
}

int process_new_ksym_entry(char *ksymname, int op, unsigned long addr)
{
	struct trace_ksym *entry;
	int ret;

	if (ksym_filter_entry_count >= KSYM_TRACER_MAX) {
		printk(KERN_ERR "ksym_tracer: Maximum limit:(%d) reached. No"
		" new requests for tracing can be accepted now.\n",
			KSYM_TRACER_MAX);
		return -ENOSPC;
	}

	entry = kzalloc(sizeof(struct trace_ksym), GFP_KERNEL);
	if (!entry)
		return -ENOMEM;

	entry->ksym_hbp = kzalloc(sizeof(struct hw_breakpoint), GFP_KERNEL);
	if (!entry->ksym_hbp) {
		kfree(entry);
		return -ENOMEM;
	}

	entry->ksym_hbp->info.name = ksymname;
	entry->ksym_hbp->info.type = op;
	entry->ksym_addr = entry->ksym_hbp->info.address = addr;
#ifdef CONFIG_X86
	entry->ksym_hbp->info.len = HW_BREAKPOINT_LEN_4;
#endif
	entry->ksym_hbp->triggered = (void *)ksym_hbp_handler;

	ret = register_kernel_hw_breakpoint(entry->ksym_hbp);
	if (ret < 0) {
		printk(KERN_INFO "ksym_tracer request failed. Try again"
					" later!!\n");
		kfree(entry->ksym_hbp);
		kfree(entry);
		return -EAGAIN;
	}
	hlist_add_head_rcu(&(entry->ksym_hlist), &ksym_filter_head);
	ksym_filter_entry_count++;

	return 0;
}

static ssize_t ksym_trace_filter_read(struct file *filp, char __user *ubuf,
						size_t count, loff_t *ppos)
{
	struct trace_ksym *entry;
	struct hlist_node *node;
	char buf[KSYM_FILTER_ENTRY_LEN * KSYM_TRACER_MAX];
	ssize_t ret, cnt = 0;

	mutex_lock(&ksym_tracer_mutex);

	hlist_for_each_entry(entry, node, &ksym_filter_head, ksym_hlist) {
		cnt += snprintf(&buf[cnt], KSYM_FILTER_ENTRY_LEN - cnt, "%s:",
				entry->ksym_hbp->info.name);
		if (entry->ksym_hbp->info.type == HW_BREAKPOINT_WRITE)
			cnt += snprintf(&buf[cnt], KSYM_FILTER_ENTRY_LEN - cnt,
								"-w-\n");
		else if (entry->ksym_hbp->info.type == HW_BREAKPOINT_RW)
			cnt += snprintf(&buf[cnt], KSYM_FILTER_ENTRY_LEN - cnt,
								"rw-\n");
	}
	ret = simple_read_from_buffer(ubuf, count, ppos, buf, strlen(buf));
	mutex_unlock(&ksym_tracer_mutex);

	return ret;
}

static ssize_t ksym_trace_filter_write(struct file *file,
					const char __user *buffer,
						size_t count, loff_t *ppos)
{
	struct trace_ksym *entry;
	struct hlist_node *node;
	char *input_string, *ksymname = NULL;
	unsigned long ksym_addr = 0;
	int ret, op, changed = 0;

	/* Ignore echo "" > ksym_trace_filter */
	if (count == 0)
		return 0;

	input_string = kzalloc(count, GFP_KERNEL);
	if (!input_string)
		return -ENOMEM;

	if (copy_from_user(input_string, buffer, count)) {
		kfree(input_string);
		return -EFAULT;
	}

	ret = op = parse_ksym_trace_str(input_string, &ksymname, &ksym_addr);
	if (ret < 0) {
		kfree(input_string);
		return ret;
	}

	mutex_lock(&ksym_tracer_mutex);

	ret = -EINVAL;
	hlist_for_each_entry(entry, node, &ksym_filter_head, ksym_hlist) {
		if (entry->ksym_addr == ksym_addr) {
			/* Check for malformed request: (6) */
			if (entry->ksym_hbp->info.type != op)
				changed = 1;
			else
				goto err_ret;
			break;
		}
	}
	if (changed) {
		unregister_kernel_hw_breakpoint(entry->ksym_hbp);
		entry->ksym_hbp->info.type = op;
		if (op > 0) {
			ret = register_kernel_hw_breakpoint(entry->ksym_hbp);
			if (ret == 0) {
				ret = count;
				goto unlock_ret_path;
			}
		}
		ksym_filter_entry_count--;
		hlist_del_rcu(&(entry->ksym_hlist));
		synchronize_rcu();
		kfree(entry->ksym_hbp);
		kfree(entry);
		ret = count;
		goto err_ret;
	} else {
		/* Check for malformed request: (4) */
		if (op == 0)
			goto err_ret;
		ret = process_new_ksym_entry(ksymname, op, ksym_addr);
		if (ret)
			goto err_ret;
	}
	ret = count;
	goto unlock_ret_path;

err_ret:
	kfree(input_string);

unlock_ret_path:
	mutex_unlock(&ksym_tracer_mutex);
	return ret;
}

static const struct file_operations ksym_tracing_fops = {
	.open		= tracing_open_generic,
	.read		= ksym_trace_filter_read,
	.write		= ksym_trace_filter_write,
};

static void ksym_trace_reset(struct trace_array *tr)
{
	struct trace_ksym *entry;
	struct hlist_node *node, *node1;

	ksym_tracing_enabled = 0;

	mutex_lock(&ksym_tracer_mutex);
	hlist_for_each_entry_safe(entry, node, node1, &ksym_filter_head,
								ksym_hlist) {
		unregister_kernel_hw_breakpoint(entry->ksym_hbp);
		ksym_filter_entry_count--;
		hlist_del_rcu(&(entry->ksym_hlist));
		synchronize_rcu();
		/* Free the 'input_string' only if reset
		 * after startup self-test
		 */
#ifdef CONFIG_FTRACE_SELFTEST
		if (strncmp(entry->ksym_hbp->info.name, KSYM_SELFTEST_ENTRY,
					strlen(KSYM_SELFTEST_ENTRY)) != 0)
#endif /* CONFIG_FTRACE_SELFTEST*/
			kfree(entry->ksym_hbp->info.name);
		kfree(entry->ksym_hbp);
		kfree(entry);
	}
	mutex_unlock(&ksym_tracer_mutex);
}

static int ksym_trace_init(struct trace_array *tr)
{
	int cpu, ret = 0;

	for_each_online_cpu(cpu)
		tracing_reset(tr, cpu);
	ksym_tracing_enabled = 1;
	ksym_trace_array = tr;

	return ret;
}

static void ksym_trace_print_header(struct seq_file *m)
{

	seq_puts(m,
		 "#       TASK-PID      CPU#      Symbol         Type    "
		 "Function         \n");
	seq_puts(m,
		 "#          |           |          |              |         "
		 "|            \n");
}

static enum print_line_t ksym_trace_output(struct trace_iterator *iter)
{
	struct trace_entry *entry = iter->ent;
	struct trace_seq *s = &iter->seq;
	struct trace_ksym *field;
	char str[KSYM_SYMBOL_LEN];
	int ret;

	if (entry->type != TRACE_KSYM)
		return TRACE_TYPE_UNHANDLED;

	trace_assign_type(field, entry);

	ret = trace_seq_printf(s, "%-15s %-5d %-3d %-20s ", field->p_name,
				entry->pid, iter->cpu, field->ksym_name);
	if (!ret)
		return TRACE_TYPE_PARTIAL_LINE;

	switch (field->ksym_hbp->info.type) {
	case HW_BREAKPOINT_WRITE:
		ret = trace_seq_printf(s, " W  ");
		break;
	case HW_BREAKPOINT_RW:
		ret = trace_seq_printf(s, " RW ");
		break;
	default:
		return TRACE_TYPE_PARTIAL_LINE;
	}

	if (!ret)
		return TRACE_TYPE_PARTIAL_LINE;

	sprint_symbol(str, field->ip);
	ret = trace_seq_printf(s, "%-20s\n", str);
	if (!ret)
		return TRACE_TYPE_PARTIAL_LINE;

	return TRACE_TYPE_HANDLED;
}

struct tracer ksym_tracer __read_mostly =
{
	.name		= "ksym_tracer",
	.init		= ksym_trace_init,
	.reset		= ksym_trace_reset,
#ifdef CONFIG_FTRACE_SELFTEST
	.selftest	= trace_selftest_startup_ksym,
#endif
	.print_header   = ksym_trace_print_header,
	.print_line	= ksym_trace_output
};

__init static int init_ksym_trace(void)
{
	struct dentry *d_tracer;
	struct dentry *entry;

	d_tracer = tracing_init_dentry();
	ksym_filter_entry_count = 0;

	entry = debugfs_create_file("ksym_trace_filter", 0644, d_tracer,
				    NULL, &ksym_tracing_fops);
	if (!entry)
		pr_warning("Could not create debugfs "
			   "'ksym_trace_filter' file\n");

	return register_tracer(&ksym_tracer);
}
device_initcall(init_ksym_trace);


#ifdef CONFIG_PROFILE_KSYM_TRACER
static int ksym_tracer_stat_headers(struct seq_file *m)
{
	seq_printf(m, "   Access type    ");
	seq_printf(m, "            Symbol                     Counter     \n");
	return 0;
}

static int ksym_tracer_stat_show(struct seq_file *m, void *v)
{
	struct hlist_node *stat = v;
	struct trace_ksym *entry;
	int access_type = 0;
	char fn_name[KSYM_NAME_LEN];

	entry = hlist_entry(stat, struct trace_ksym, ksym_hlist);

	if (entry->ksym_hbp)
		access_type = entry->ksym_hbp->info.type;

	switch (access_type) {
	case HW_BREAKPOINT_WRITE:
		seq_printf(m, "     W     ");
		break;
	case HW_BREAKPOINT_RW:
		seq_printf(m, "     RW    ");
		break;
	default:
		seq_printf(m, "     NA    ");
	}

	if (lookup_symbol_name(entry->ksym_addr, fn_name) >= 0)
		seq_printf(m, "               %s                 ", fn_name);
	else
		seq_printf(m, "               <NA>                ");

	seq_printf(m, "%15lu\n", entry->counter);
	return 0;
}

static void *ksym_tracer_stat_start(struct tracer_stat *trace)
{
	return &(ksym_filter_head.first);
}

static void *
ksym_tracer_stat_next(void *v, int idx)
{
	struct hlist_node *stat = v;

	return stat->next;
}

static struct tracer_stat ksym_tracer_stats = {
	.name = "ksym_tracer",
	.stat_start = ksym_tracer_stat_start,
	.stat_next = ksym_tracer_stat_next,
	.stat_headers = ksym_tracer_stat_headers,
	.stat_show = ksym_tracer_stat_show
};

__init static int ksym_tracer_stat_init(void)
{
	int ret;

	ret = register_stat_tracer(&ksym_tracer_stats);
	if (ret) {
		printk(KERN_WARNING "Warning: could not register "
				    "ksym tracer stats\n");
		return 1;
	}

	return 0;
}
fs_initcall(ksym_tracer_stat_init);
#endif /* CONFIG_PROFILE_KSYM_TRACER */
