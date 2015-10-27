/*
 * Define dmp_syscall_table
 * Reorganized from include/asm-x86/unistd_64.h
 * "S" is the conservative estimate
 *
 * TODO: The MOT should not be updated while in parallel mode. System calls
 *   that return file descriptors (such as open, openat, socket, accept, etc.)
 *   add fds to the MOT before returning to userspace. These are currently
 *   marked with "S" to ensure they are always executed in serial mode. However,
 *   this is probably too conservative, and should be looked at again to reduce
 *   the amount of unnecessary serialization.
 */

/* IO */

[__NR_read]		= FILE_READ,
[__NR_write]		= FILE_WRITE,
[__NR_open]		= FDTABLE | FSINFO_READ | S,
[__NR_openat]		= FDTABLE | FSINFO_READ | S,
[__NR_close]		= FDTABLE | FILE_WRITE | S,
[__NR_stat]		= FSINFO_READ,
[__NR_fstat]		= FD,
[__NR_lstat]		= FSINFO_READ,
[__NR_lseek]		= FD,

[__NR_ioctl]		= S,
[__NR_pread64]		= FILE_READ,
[__NR_pwrite64]		= FILE_WRITE,
[__NR_readv]		= FILE_READ,
[__NR_writev]		= FILE_WRITE,
[__NR_access]		= FSINFO_READ,
[__NR_pipe]		= FDTABLE | NOSLEEP | S,

[__NR_dup]		= FDTABLE | NOSLEEP | S,
[__NR_dup2]		= FDTABLE | SPECIAL | S,

[__NR_sendfile]		= S,
[__NR_socket]		= FDTABLE | S,
[__NR_connect]		= FD,
[__NR_accept]		= FD | FDTABLE | S,
[__NR_sendto]		= FILE_WRITE,
[__NR_sendmsg]		= FILE_WRITE,
[__NR_recvfrom]		= FILE_READ,
[__NR_recvmsg]		= FILE_READ,

[__NR_bind]		= FD,
[__NR_listen]		= NOSLEEP | FD,
[__NR_getsockname]	= FD,
[__NR_getpeername]	= FD,
[__NR_socketpair]	= FDTABLE | S,
[__NR_setsockopt]	= FD,
[__NR_getsockopt]	= FD,

[__NR_fcntl]		= FDTABLE | FD,
[__NR_flock]		= FD,
[__NR_fsync]		= FD,
[__NR_fdatasync]	= FD,
[__NR_truncate]		= S,
[__NR_ftruncate]	= FILE_WRITE,
[__NR_getdents]		= FD,
[__NR_getcwd]		= FSINFO_READ,

[__NR_chdir]		= FSINFO_WRITE,
[__NR_fchdir]		= FSINFO_WRITE | FD,
[__NR_rename]		= S,
[__NR_renameat]		= S,
[__NR_mknod]		= S,
[__NR_mknodat]		= S,
[__NR_mkdir]		= FSINFO_READ,
[__NR_mkdirat]		= FSINFO_READ | FD,
[__NR_rmdir]		= FSINFO_READ,
[__NR_creat]		= FSINFO_READ | S,
[__NR_link]		= S,
[__NR_linkat]		= S,
[__NR_unlink]		= S,
[__NR_unlinkat]		= S,

[__NR_symlink]		= FSINFO_READ,
[__NR_symlinkat]	= FSINFO_READ | FD,
[__NR_readlink]		= FSINFO_READ,
[__NR_readlinkat]	= FSINFO_READ | FD,
[__NR_chmod]		= S,
[__NR_fchmod]		= S,
[__NR_fchmodat]		= S,
[__NR_chown]		= S,
[__NR_fchown]		= S,
[__NR_fchownat]		= S,
[__NR_lchown]		= S,

[__NR_umask]		= FSINFO_WRITE,
[__NR_utime]		= S,
[__NR_utimes]		= S,
[__NR_futimesat]	= S,

[__NR_ustat]		= FSINFO_READ,
[__NR_statfs]		= FSINFO_READ,
[__NR_fstatfs]		= FSINFO_READ,
[__NR_sysfs]		= FSINFO_READ,

[__NR_chroot]		= FSINFO_WRITE,
[__NR_sync]		= P,

[__NR_splice]		= S,
[__NR_vmsplice]		= S,
[__NR_tee]		= S,

/* IO: Polling */

[__NR_select]		= S,
[__NR_poll]		= S,
[__NR_ppoll]		= S,
[__NR_pselect6]		= S,

[__NR_epoll_create]	= S,
[__NR_epoll_ctl]	= S,
[__NR_epoll_ctl_old]	= S,
[__NR_epoll_wait]	= S,
[__NR_epoll_wait_old]	= S,
[__NR_epoll_pwait]	= S,

[__NR_signalfd]		= S,
[__NR_eventfd]		= S,

/* VM */

[__NR_brk]		= MM | NOSLEEP,

[__NR_mmap]		= MM | NOSLEEP,
[__NR_mprotect]		= MM | NOSLEEP,
[__NR_munmap]		= MM | NOSLEEP,
[__NR_mremap]		= MM | NOSLEEP,
[__NR_msync]		= P,
[__NR_madvise]		= MM | NOSLEEP,  /* semantic effect in some cases */
[__NR_mincore]		= P | NOSLEEP,  /* intrinsically nondet */

[__NR_mlock]		= S | NOSLEEP,  /* no semantic effect, but mutates ptes? */
[__NR_munlock]		= S | NOSLEEP,  /* no semantic effect, but mutates ptes? */
[__NR_mlockall]		= S | NOSLEEP,  /* no semantic effect, but mutates ptes? */
[__NR_munlockall]	= S | NOSLEEP,  /* no semantic effect, but mutates ptes? */

[__NR_remap_file_pages]	= S,

/* SYS V IPC */
// TODO: don't serialize as many of these

[__NR_shmget]		= S,
[__NR_shmat]		= S,
[__NR_shmctl]		= S,
[__NR_shmdt]		= S,

[__NR_semget]		= S,
[__NR_semop]		= S,
[__NR_semctl]		= S,

[__NR_msgget]		= S,
[__NR_msgsnd]		= S,
[__NR_msgrcv]		= S,
[__NR_msgctl]		= S,

[__NR_mbind]		= S,
[__NR_set_mempolicy]	= S,
[__NR_get_mempolicy]	= S,

/* Signals */

[__NR_clone]		= S | NOSLEEP,
[__NR_fork]		= S | NOSLEEP,
[__NR_vfork]		= S | NOSLEEP,
[__NR_execve]		= S | NOSLEEP,
[__NR_exit]		= S | NOSLEEP,
[__NR_exit_group]	= S | NOSLEEP,
[__NR_unshare]		= S | NOSLEEP,

[__NR_rt_sigaction]	= P,
[__NR_rt_sigprocmask]	= S,
/* may return to kernel code (e.g. if a syscall was interrupted) */
/* TODO: don't need to serialize this if retrning to user-mode */
[__NR_rt_sigreturn]	= S,	// XXX: SPECIAL?
[__NR_rt_sigpending]	= S,
[__NR_rt_sigtimedwait]	= S,
[__NR_rt_sigqueueinfo]	= S,
[__NR_rt_sigsuspend]	= S,
[__NR_sigaltstack]	= S,

[__NR_kill]		= P | NOSLEEP,
[__NR_tkill]		= P | NOSLEEP,
[__NR_tgkill]		= P | NOSLEEP,
[__NR_alarm]		= S,

[__NR_waitid]		= P,  /* read-only (TODO: ?) */
[__NR_wait4]		= P,  /* read-only (TODO: ?) */
[__NR_pause]		= P,  /* read-only (TODO: ?) */
[__NR_nanosleep]	= P,  /* read-only (TODO: ?) */

[__NR_getitimer]	= P,  /* read-only (TODO: ?) */
[__NR_setitimer]	= S,

/* PIDs */

[__NR_getpid]		= P | NOSLEEP,  /* read-only */
[__NR_gettid]		= P | NOSLEEP,  /* read-only */
[__NR_getuid]		= P | NOSLEEP,  /* read-only */
[__NR_getgid]		= P | NOSLEEP,  /* read-only */
[__NR_getpgid]		= P | NOSLEEP,  /* read-only */
[__NR_getsid]		= P | NOSLEEP,  /* read-only */
[__NR_geteuid]		= P | NOSLEEP,  /* read-only */
[__NR_getegid]		= P | NOSLEEP,  /* read-only */
[__NR_getppid]		= P | NOSLEEP,  /* read-only */
[__NR_getpgrp]		= P | NOSLEEP,  /* read-only */
[__NR_getresuid]	= P | NOSLEEP,  /* read-only */
[__NR_getresgid]	= P | NOSLEEP,  /* read-only */
[__NR_getgroups]	= P | NOSLEEP,  /* read-only */

[__NR_setuid]		= S,
[__NR_setgid]		= S,
[__NR_setpgid]		= S,
[__NR_setsid]		= S,
[__NR_setreuid]		= S,
[__NR_setregid]		= S,
[__NR_setresuid]	= S,
[__NR_setresgid]	= S,
[__NR_setgroups]	= S,
[__NR_set_tid_address]	= S,

[__NR_setfsuid]		= S,
[__NR_setfsgid]		= S,

[__NR_capget]		= P,  /* read-only (TODO: ?) */
[__NR_capset]		= S,

/* Time */
[__NR_settimeofday]	= P | NOSLEEP,  /* intrinsically nondet */
[__NR_gettimeofday]	= P | NOSLEEP,  /* intrinsically nondet */
[__NR_times]		= P | NOSLEEP,  /* intrinsically nondet */
[__NR_time]		= P | NOSLEEP,  /* intrinsically nondet */

[__NR_clock_settime]	= P | NOSLEEP,  /* intrinsically nondet */
[__NR_clock_gettime]	= P | NOSLEEP,  /* intrinsically nondet */
[__NR_clock_getres]	= P | NOSLEEP,  /* intrinsically nondet */
[__NR_clock_nanosleep]	= P | NOSLEEP,  /* intrinsically nondet */

/* Misc */

[__NR_restart_syscall]	= S,  /* TODO: don't serialize this */
[__NR_futex]		= S,  /* TODO: don't serialize this */ 
[__NR_set_robust_list]	= S | NOSLEEP,  /* TODO: revisit */
[__NR_get_robust_list]	= S | NOSLEEP,  /* TODO: revisit */

[__NR_shutdown]		= S,
[__NR_reboot]		= S,

[__NR_uname]		= P,  /* read-only */
[__NR_ptrace]		= P,  /* TODO: revisit */

[__NR_setrlimit]	= S | NOSLEEP,
[__NR_getrlimit]	= P | NOSLEEP,  /* read-only (TODO: ?) */
[__NR_getrusage]	= P | NOSLEEP,  /* read-only (TODO: ?) */
[__NR_sysinfo]		= P | NOSLEEP,  /* intrinsically nondet */
[__NR_syslog]		= P,  /* intrinsically nondet */

[__NR_uselib]		= S,
[__NR_personality]	= S,

[__NR_set_thread_area]	= P,  /* thread-local */
[__NR_get_thread_area]	= P,  /* thread-local */

[__NR_getpriority]	= P | NOSLEEP,  /* no semantic effect */
[__NR_setpriority]	= P | NOSLEEP,  /* no semantic effect */
[__NR_sched_yield]	= P | NOSLEEP,  /* no semantic effect */
[__NR_sched_setparam]	= P | NOSLEEP,  /* no semantic effect */
[__NR_sched_getparam]	= P | NOSLEEP,  /* no semantic effect */
[__NR_sched_setaffinity]= P | NOSLEEP,  /* no semantic effect */
[__NR_sched_getaffinity]= P | NOSLEEP,  /* no semantic effect */
[__NR_sched_setscheduler]	= P,  /* no semantic effect */
[__NR_sched_getscheduler]	= P,  /* no semantic effect */
[__NR_sched_get_priority_max]	= P,  /* no semantic effect */
[__NR_sched_get_priority_min]	= P,  /* no semantic effect */
[__NR_sched_rr_get_interval]	= P,  /* no semantic effect */

/* No clue what these do */
/* A lot of these are probably "superuser only" types */

[__NR_vhangup]		= S,
[__NR_modify_ldt]	= S,
[__NR_pivot_root]	= S,
[__NR__sysctl]		= S,
[__NR_prctl]		= S,
[__NR_arch_prctl]	= S,
[__NR_adjtimex]		= S,
[__NR_acct]		= S,

[__NR_swapon]		= S,
[__NR_swapoff]		= S,

[__NR_mount]		= S,
[__NR_umount2]		= S,

[__NR_sethostname]	= S,
[__NR_setdomainname]	= S,

[__NR_iopl]		= S,
[__NR_ioperm]		= S,

[__NR_create_module]	= S,
[__NR_init_module]	= S,
[__NR_delete_module]	= S,
[__NR_get_kernel_syms]	= S,
[__NR_query_module]	= S,

[__NR_quotactl]		= S,
[__NR_nfsservctl]	= S,
[__NR_getpmsg]		= S,
[__NR_putpmsg]		= S,

[__NR_afs_syscall]	= S,
[__NR_tuxcall]		= S,
[__NR_security]		= S,

[__NR_readahead]	= S,
[__NR_setxattr]		= S,
[__NR_lsetxattr]	= S,
[__NR_fsetxattr]	= S,
[__NR_getxattr]		= S,
[__NR_lgetxattr]	= S,
[__NR_fgetxattr]	= S,
[__NR_listxattr]	= S,
[__NR_llistxattr]	= S,
[__NR_flistxattr]	= S,
[__NR_removexattr]	= S,
[__NR_lremovexattr]	= S,
[__NR_fremovexattr]	= S,

[__NR_io_setup]		= S,
[__NR_io_destroy]	= S,
[__NR_io_getevents]	= S,
[__NR_io_submit]	= S,
[__NR_io_cancel]	= S,
[__NR_lookup_dcookie]	= S,

[__NR_getdents64]	= S,
[__NR_semtimedop]	= S,
[__NR_fadvise64]	= S,

[__NR_timer_create]	= S,
[__NR_timer_settime]	= S,
[__NR_timer_gettime]	= S,
[__NR_timer_getoverrun]	= S,
[__NR_timer_delete]	= S,

[__NR_vserver]		= S,
[__NR_mq_open]		= S,
[__NR_mq_unlink]	= S,
[__NR_mq_timedsend]	= S,
[__NR_mq_timedreceive]	= S,
[__NR_mq_notify]	= S,
[__NR_mq_getsetattr]	= S,
[__NR_kexec_load]	= S,
[__NR_add_key]		= S,
[__NR_request_key]	= S,
[__NR_keyctl]		= S,
[__NR_ioprio_set]	= S,
[__NR_ioprio_get]	= S,
[__NR_inotify_init]	= S,
[__NR_inotify_add_watch]= S,
[__NR_inotify_rm_watch]	= S,
[__NR_migrate_pages]	= S,
[__NR_newfstatat]	= S,
[__NR_faccessat]	= S,

[__NR_sync_file_range]	= S,
[__NR_move_pages]	= S,
[__NR_utimensat]	= S,
[__NR_fallocate]	= S,
