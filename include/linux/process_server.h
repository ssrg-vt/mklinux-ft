/*********************
 * process server header
 * dkatz
 *********************/

#include <linux/sched.h>
#include <asm/ptrace.h>

#ifndef _PROCESS_SERVER_H
#define _PROCESS_SERVER_H

#define PROCESS_SERVER_CLONE_SUCCESS 0
#define PROCESS_SERVER_CLONE_FAIL 1


/*
 * Migration hook.
 */
int process_server_do_migration(struct task_struct* task, int cpu);
void process_server_do_return_disposition(void);

/*
 * Utilities for other modules to hook
 * into the process server.
 */
int process_server_import_address_space(unsigned long* ip, unsigned long *sp, struct pt_regs* regs);
int process_server_notify_delegated_subprocess_starting(pid_t pid, pid_t remote_pid, int remote_cpu);
int process_server_do_exit(void);
int process_server_do_group_exit(void);
int process_server_notify_mmap(struct file *file, unsigned long addr,
                                unsigned long len, unsigned long prot,
                                unsigned long flags, unsigned long pgoff);
int process_server_notify_munmap(struct mm_struct *mm, unsigned long start, size_t len);
int process_server_try_handle_mm_fault(struct mm_struct *mm, struct vm_area_struct *vma,
                                unsigned long address, unsigned int flags,
                                struct vm_area_struct **vma_out,
                                unsigned long error_code);
int process_server_do_munmap(struct mm_struct* mm, 
                                struct vm_area_struct *vma,
                                unsigned long start, 
                                unsigned long len);
void process_server_do_mprotect(struct task_struct* task,
                                unsigned long addr,
                                size_t len,
                                unsigned long prot);
int process_server_dup_task(struct task_struct* orig, struct task_struct* task);
unsigned long process_server_do_mmap_pgoff(struct file *file, unsigned long addr,
                                           unsigned long len, unsigned long prot,
                                           unsigned long flags, unsigned long pgoff);
#endif // _PROCESS_SERVER_H
