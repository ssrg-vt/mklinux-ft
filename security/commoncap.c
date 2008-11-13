/* Common capabilities, needed by capability.o and root_plug.o
 *
 *	This program is free software; you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation; either version 2 of the License, or
 *	(at your option) any later version.
 *
 */

#include <linux/capability.h>
#include <linux/audit.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/security.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/pagemap.h>
#include <linux/swap.h>
#include <linux/skbuff.h>
#include <linux/netlink.h>
#include <linux/ptrace.h>
#include <linux/xattr.h>
#include <linux/hugetlb.h>
#include <linux/mount.h>
#include <linux/sched.h>
#include <linux/prctl.h>
#include <linux/securebits.h>

int cap_netlink_send(struct sock *sk, struct sk_buff *skb)
{
	NETLINK_CB(skb).eff_cap = current_cap();
	return 0;
}

int cap_netlink_recv(struct sk_buff *skb, int cap)
{
	if (!cap_raised(NETLINK_CB(skb).eff_cap, cap))
		return -EPERM;
	return 0;
}

EXPORT_SYMBOL(cap_netlink_recv);

/*
 * NOTE WELL: cap_capable() cannot be used like the kernel's capable()
 * function.  That is, it has the reverse semantics: cap_capable()
 * returns 0 when a task has a capability, but the kernel's capable()
 * returns 1 for this case.
 */
int cap_capable(struct task_struct *tsk, int cap, int audit)
{
	/* Derived from include/linux/sched.h:capable. */
	if (cap_raised(tsk->cred->cap_effective, cap))
		return 0;
	return -EPERM;
}

int cap_settime(struct timespec *ts, struct timezone *tz)
{
	if (!capable(CAP_SYS_TIME))
		return -EPERM;
	return 0;
}

int cap_ptrace_may_access(struct task_struct *child, unsigned int mode)
{
	/* Derived from arch/i386/kernel/ptrace.c:sys_ptrace. */
	if (cap_issubset(child->cred->cap_permitted,
			 current->cred->cap_permitted))
		return 0;
	if (capable(CAP_SYS_PTRACE))
		return 0;
	return -EPERM;
}

int cap_ptrace_traceme(struct task_struct *parent)
{
	if (cap_issubset(current->cred->cap_permitted,
			 parent->cred->cap_permitted))
		return 0;
	if (has_capability(parent, CAP_SYS_PTRACE))
		return 0;
	return -EPERM;
}

int cap_capget (struct task_struct *target, kernel_cap_t *effective,
		kernel_cap_t *inheritable, kernel_cap_t *permitted)
{
	struct cred *cred = target->cred;

	/* Derived from kernel/capability.c:sys_capget. */
	*effective   = cred->cap_effective;
	*inheritable = cred->cap_inheritable;
	*permitted   = cred->cap_permitted;
	return 0;
}

#ifdef CONFIG_SECURITY_FILE_CAPABILITIES

static inline int cap_inh_is_capped(void)
{
	/*
	 * Return 1 if changes to the inheritable set are limited
	 * to the old permitted set. That is, if the current task
	 * does *not* possess the CAP_SETPCAP capability.
	 */
	return (cap_capable(current, CAP_SETPCAP, SECURITY_CAP_AUDIT) != 0);
}

static inline int cap_limit_ptraced_target(void) { return 1; }

#else /* ie., ndef CONFIG_SECURITY_FILE_CAPABILITIES */

static inline int cap_inh_is_capped(void) { return 1; }
static inline int cap_limit_ptraced_target(void)
{
	return !capable(CAP_SETPCAP);
}

#endif /* def CONFIG_SECURITY_FILE_CAPABILITIES */

int cap_capset_check(const kernel_cap_t *effective,
		     const kernel_cap_t *inheritable,
		     const kernel_cap_t *permitted)
{
	const struct cred *cred = current->cred;

	if (cap_inh_is_capped()
	    && !cap_issubset(*inheritable,
			     cap_combine(cred->cap_inheritable,
					 cred->cap_permitted))) {
		/* incapable of using this inheritable set */
		return -EPERM;
	}
	if (!cap_issubset(*inheritable,
			   cap_combine(cred->cap_inheritable,
				       cred->cap_bset))) {
		/* no new pI capabilities outside bounding set */
		return -EPERM;
	}

	/* verify restrictions on target's new Permitted set */
	if (!cap_issubset (*permitted,
			   cap_combine (cred->cap_permitted,
					cred->cap_permitted))) {
		return -EPERM;
	}

	/* verify the _new_Effective_ is a subset of the _new_Permitted_ */
	if (!cap_issubset (*effective, *permitted)) {
		return -EPERM;
	}

	return 0;
}

void cap_capset_set(const kernel_cap_t *effective,
		    const kernel_cap_t *inheritable,
		    const kernel_cap_t *permitted)
{
	struct cred *cred = current->cred;

	cred->cap_effective   = *effective;
	cred->cap_inheritable = *inheritable;
	cred->cap_permitted   = *permitted;
}

static inline void bprm_clear_caps(struct linux_binprm *bprm)
{
	cap_clear(bprm->cap_post_exec_permitted);
	bprm->cap_effective = false;
}

#ifdef CONFIG_SECURITY_FILE_CAPABILITIES

int cap_inode_need_killpriv(struct dentry *dentry)
{
	struct inode *inode = dentry->d_inode;
	int error;

	if (!inode->i_op || !inode->i_op->getxattr)
	       return 0;

	error = inode->i_op->getxattr(dentry, XATTR_NAME_CAPS, NULL, 0);
	if (error <= 0)
		return 0;
	return 1;
}

int cap_inode_killpriv(struct dentry *dentry)
{
	struct inode *inode = dentry->d_inode;

	if (!inode->i_op || !inode->i_op->removexattr)
	       return 0;

	return inode->i_op->removexattr(dentry, XATTR_NAME_CAPS);
}

static inline int bprm_caps_from_vfs_caps(struct cpu_vfs_cap_data *caps,
					  struct linux_binprm *bprm)
{
	unsigned i;
	int ret = 0;

	if (caps->magic_etc & VFS_CAP_FLAGS_EFFECTIVE)
		bprm->cap_effective = true;
	else
		bprm->cap_effective = false;

	CAP_FOR_EACH_U32(i) {
		__u32 permitted = caps->permitted.cap[i];
		__u32 inheritable = caps->inheritable.cap[i];

		/*
		 * pP' = (X & fP) | (pI & fI)
		 */
		bprm->cap_post_exec_permitted.cap[i] =
			(current->cred->cap_bset.cap[i] & permitted) |
			(current->cred->cap_inheritable.cap[i] & inheritable);

		if (permitted & ~bprm->cap_post_exec_permitted.cap[i]) {
			/*
			 * insufficient to execute correctly
			 */
			ret = -EPERM;
		}
	}

	/*
	 * For legacy apps, with no internal support for recognizing they
	 * do not have enough capabilities, we return an error if they are
	 * missing some "forced" (aka file-permitted) capabilities.
	 */
	return bprm->cap_effective ? ret : 0;
}

int get_vfs_caps_from_disk(const struct dentry *dentry, struct cpu_vfs_cap_data *cpu_caps)
{
	struct inode *inode = dentry->d_inode;
	__u32 magic_etc;
	unsigned tocopy, i;
	int size;
	struct vfs_cap_data caps;

	memset(cpu_caps, 0, sizeof(struct cpu_vfs_cap_data));

	if (!inode || !inode->i_op || !inode->i_op->getxattr)
		return -ENODATA;

	size = inode->i_op->getxattr((struct dentry *)dentry, XATTR_NAME_CAPS, &caps,
				   XATTR_CAPS_SZ);
	if (size == -ENODATA || size == -EOPNOTSUPP) {
		/* no data, that's ok */
		return -ENODATA;
	}
	if (size < 0)
		return size;

	if (size < sizeof(magic_etc))
		return -EINVAL;

	cpu_caps->magic_etc = magic_etc = le32_to_cpu(caps.magic_etc);

	switch ((magic_etc & VFS_CAP_REVISION_MASK)) {
	case VFS_CAP_REVISION_1:
		if (size != XATTR_CAPS_SZ_1)
			return -EINVAL;
		tocopy = VFS_CAP_U32_1;
		break;
	case VFS_CAP_REVISION_2:
		if (size != XATTR_CAPS_SZ_2)
			return -EINVAL;
		tocopy = VFS_CAP_U32_2;
		break;
	default:
		return -EINVAL;
	}

	CAP_FOR_EACH_U32(i) {
		if (i >= tocopy)
			break;
		cpu_caps->permitted.cap[i] = le32_to_cpu(caps.data[i].permitted);
		cpu_caps->inheritable.cap[i] = le32_to_cpu(caps.data[i].inheritable);
	}
	return 0;
}

/* Locate any VFS capabilities: */
static int get_file_caps(struct linux_binprm *bprm)
{
	struct dentry *dentry;
	int rc = 0;
	struct cpu_vfs_cap_data vcaps;

	bprm_clear_caps(bprm);

	if (!file_caps_enabled)
		return 0;

	if (bprm->file->f_vfsmnt->mnt_flags & MNT_NOSUID)
		return 0;

	dentry = dget(bprm->file->f_dentry);

	rc = get_vfs_caps_from_disk(dentry, &vcaps);
	if (rc < 0) {
		if (rc == -EINVAL)
			printk(KERN_NOTICE "%s: get_vfs_caps_from_disk returned %d for %s\n",
				__func__, rc, bprm->filename);
		else if (rc == -ENODATA)
			rc = 0;
		goto out;
	}

	rc = bprm_caps_from_vfs_caps(&vcaps, bprm);

out:
	dput(dentry);
	if (rc)
		bprm_clear_caps(bprm);

	return rc;
}

#else
int cap_inode_need_killpriv(struct dentry *dentry)
{
	return 0;
}

int cap_inode_killpriv(struct dentry *dentry)
{
	return 0;
}

static inline int get_file_caps(struct linux_binprm *bprm)
{
	bprm_clear_caps(bprm);
	return 0;
}
#endif

int cap_bprm_set_security (struct linux_binprm *bprm)
{
	int ret;

	ret = get_file_caps(bprm);

	if (!issecure(SECURE_NOROOT)) {
		/*
		 * To support inheritance of root-permissions and suid-root
		 * executables under compatibility mode, we override the
		 * capability sets for the file.
		 *
		 * If only the real uid is 0, we do not set the effective
		 * bit.
		 */
		if (bprm->e_uid == 0 || current_uid() == 0) {
			/* pP' = (cap_bset & ~0) | (pI & ~0) */
			bprm->cap_post_exec_permitted = cap_combine(
				current->cred->cap_bset,
				current->cred->cap_inheritable);
			bprm->cap_effective = (bprm->e_uid == 0);
			ret = 0;
		}
	}

	return ret;
}

void cap_bprm_apply_creds (struct linux_binprm *bprm, int unsafe)
{
	struct cred *cred = current->cred;

	if (bprm->e_uid != cred->uid || bprm->e_gid != cred->gid ||
	    !cap_issubset(bprm->cap_post_exec_permitted,
			  cred->cap_permitted)) {
		set_dumpable(current->mm, suid_dumpable);
		current->pdeath_signal = 0;

		if (unsafe & ~LSM_UNSAFE_PTRACE_CAP) {
			if (!capable(CAP_SETUID)) {
				bprm->e_uid = cred->uid;
				bprm->e_gid = cred->gid;
			}
			if (cap_limit_ptraced_target()) {
				bprm->cap_post_exec_permitted = cap_intersect(
					bprm->cap_post_exec_permitted,
					cred->cap_permitted);
			}
		}
	}

	cred->suid = cred->euid = cred->fsuid = bprm->e_uid;
	cred->sgid = cred->egid = cred->fsgid = bprm->e_gid;

	/* For init, we want to retain the capabilities set
	 * in the init_task struct. Thus we skip the usual
	 * capability rules */
	if (!is_global_init(current)) {
		cred->cap_permitted = bprm->cap_post_exec_permitted;
		if (bprm->cap_effective)
			cred->cap_effective = bprm->cap_post_exec_permitted;
		else
			cap_clear(cred->cap_effective);
	}

	/*
	 * Audit candidate if current->cap_effective is set
	 *
	 * We do not bother to audit if 3 things are true:
	 *   1) cap_effective has all caps
	 *   2) we are root
	 *   3) root is supposed to have all caps (SECURE_NOROOT)
	 * Since this is just a normal root execing a process.
	 *
	 * Number 1 above might fail if you don't have a full bset, but I think
	 * that is interesting information to audit.
	 */
	if (!cap_isclear(cred->cap_effective)) {
		if (!cap_issubset(CAP_FULL_SET, cred->cap_effective) ||
		    (bprm->e_uid != 0) || (cred->uid != 0) ||
		    issecure(SECURE_NOROOT))
			audit_log_bprm_fcaps(bprm, &cred->cap_permitted,
					     &cred->cap_effective);
	}

	cred->securebits &= ~issecure_mask(SECURE_KEEP_CAPS);
}

int cap_bprm_secureexec (struct linux_binprm *bprm)
{
	const struct cred *cred = current->cred;

	if (cred->uid != 0) {
		if (bprm->cap_effective)
			return 1;
		if (!cap_isclear(bprm->cap_post_exec_permitted))
			return 1;
	}

	return (cred->euid != cred->uid ||
		cred->egid != cred->gid);
}

int cap_inode_setxattr(struct dentry *dentry, const char *name,
		       const void *value, size_t size, int flags)
{
	if (!strcmp(name, XATTR_NAME_CAPS)) {
		if (!capable(CAP_SETFCAP))
			return -EPERM;
		return 0;
	} else if (!strncmp(name, XATTR_SECURITY_PREFIX,
		     sizeof(XATTR_SECURITY_PREFIX) - 1)  &&
	    !capable(CAP_SYS_ADMIN))
		return -EPERM;
	return 0;
}

int cap_inode_removexattr(struct dentry *dentry, const char *name)
{
	if (!strcmp(name, XATTR_NAME_CAPS)) {
		if (!capable(CAP_SETFCAP))
			return -EPERM;
		return 0;
	} else if (!strncmp(name, XATTR_SECURITY_PREFIX,
		     sizeof(XATTR_SECURITY_PREFIX) - 1)  &&
	    !capable(CAP_SYS_ADMIN))
		return -EPERM;
	return 0;
}

/* moved from kernel/sys.c. */
/* 
 * cap_emulate_setxuid() fixes the effective / permitted capabilities of
 * a process after a call to setuid, setreuid, or setresuid.
 *
 *  1) When set*uiding _from_ one of {r,e,s}uid == 0 _to_ all of
 *  {r,e,s}uid != 0, the permitted and effective capabilities are
 *  cleared.
 *
 *  2) When set*uiding _from_ euid == 0 _to_ euid != 0, the effective
 *  capabilities of the process are cleared.
 *
 *  3) When set*uiding _from_ euid != 0 _to_ euid == 0, the effective
 *  capabilities are set to the permitted capabilities.
 *
 *  fsuid is handled elsewhere. fsuid == 0 and {r,e,s}uid!= 0 should 
 *  never happen.
 *
 *  -astor 
 *
 * cevans - New behaviour, Oct '99
 * A process may, via prctl(), elect to keep its capabilities when it
 * calls setuid() and switches away from uid==0. Both permitted and
 * effective sets will be retained.
 * Without this change, it was impossible for a daemon to drop only some
 * of its privilege. The call to setuid(!=0) would drop all privileges!
 * Keeping uid 0 is not an option because uid 0 owns too many vital
 * files..
 * Thanks to Olaf Kirch and Peter Benie for spotting this.
 */
static inline void cap_emulate_setxuid (int old_ruid, int old_euid,
					int old_suid)
{
	struct cred *cred = current->cred;

	if ((old_ruid == 0 || old_euid == 0 || old_suid == 0) &&
	    (cred->uid != 0 && cred->euid != 0 && cred->suid != 0) &&
	    !issecure(SECURE_KEEP_CAPS)) {
		cap_clear (cred->cap_permitted);
		cap_clear (cred->cap_effective);
	}
	if (old_euid == 0 && cred->euid != 0) {
		cap_clear (cred->cap_effective);
	}
	if (old_euid != 0 && cred->euid == 0) {
		cred->cap_effective = cred->cap_permitted;
	}
}

int cap_task_post_setuid (uid_t old_ruid, uid_t old_euid, uid_t old_suid,
			  int flags)
{
	struct cred *cred = current->cred;

	switch (flags) {
	case LSM_SETID_RE:
	case LSM_SETID_ID:
	case LSM_SETID_RES:
		/* Copied from kernel/sys.c:setreuid/setuid/setresuid. */
		if (!issecure (SECURE_NO_SETUID_FIXUP)) {
			cap_emulate_setxuid (old_ruid, old_euid, old_suid);
		}
		break;
	case LSM_SETID_FS:
		{
			uid_t old_fsuid = old_ruid;

			/* Copied from kernel/sys.c:setfsuid. */

			/*
			 * FIXME - is fsuser used for all CAP_FS_MASK capabilities?
			 *          if not, we might be a bit too harsh here.
			 */

			if (!issecure (SECURE_NO_SETUID_FIXUP)) {
				if (old_fsuid == 0 && cred->fsuid != 0) {
					cred->cap_effective =
						cap_drop_fs_set(
							cred->cap_effective);
				}
				if (old_fsuid != 0 && cred->fsuid == 0) {
					cred->cap_effective =
						cap_raise_fs_set(
						    cred->cap_effective,
						    cred->cap_permitted);
				}
			}
			break;
		}
	default:
		return -EINVAL;
	}

	return 0;
}

#ifdef CONFIG_SECURITY_FILE_CAPABILITIES
/*
 * Rationale: code calling task_setscheduler, task_setioprio, and
 * task_setnice, assumes that
 *   . if capable(cap_sys_nice), then those actions should be allowed
 *   . if not capable(cap_sys_nice), but acting on your own processes,
 *   	then those actions should be allowed
 * This is insufficient now since you can call code without suid, but
 * yet with increased caps.
 * So we check for increased caps on the target process.
 */
static int cap_safe_nice(struct task_struct *p)
{
	if (!cap_issubset(p->cred->cap_permitted,
			  current->cred->cap_permitted) &&
	    !capable(CAP_SYS_NICE))
		return -EPERM;
	return 0;
}

int cap_task_setscheduler (struct task_struct *p, int policy,
			   struct sched_param *lp)
{
	return cap_safe_nice(p);
}

int cap_task_setioprio (struct task_struct *p, int ioprio)
{
	return cap_safe_nice(p);
}

int cap_task_setnice (struct task_struct *p, int nice)
{
	return cap_safe_nice(p);
}

/*
 * called from kernel/sys.c for prctl(PR_CABSET_DROP)
 * done without task_capability_lock() because it introduces
 * no new races - i.e. only another task doing capget() on
 * this task could get inconsistent info.  There can be no
 * racing writer bc a task can only change its own caps.
 */
static long cap_prctl_drop(unsigned long cap)
{
	if (!capable(CAP_SETPCAP))
		return -EPERM;
	if (!cap_valid(cap))
		return -EINVAL;
	cap_lower(current->cred->cap_bset, cap);
	return 0;
}

#else
int cap_task_setscheduler (struct task_struct *p, int policy,
			   struct sched_param *lp)
{
	return 0;
}
int cap_task_setioprio (struct task_struct *p, int ioprio)
{
	return 0;
}
int cap_task_setnice (struct task_struct *p, int nice)
{
	return 0;
}
#endif

int cap_task_prctl(int option, unsigned long arg2, unsigned long arg3,
		   unsigned long arg4, unsigned long arg5, long *rc_p)
{
	struct cred *cred = current_cred();
	long error = 0;

	switch (option) {
	case PR_CAPBSET_READ:
		if (!cap_valid(arg2))
			error = -EINVAL;
		else
			error = !!cap_raised(cred->cap_bset, arg2);
		break;
#ifdef CONFIG_SECURITY_FILE_CAPABILITIES
	case PR_CAPBSET_DROP:
		error = cap_prctl_drop(arg2);
		break;

	/*
	 * The next four prctl's remain to assist with transitioning a
	 * system from legacy UID=0 based privilege (when filesystem
	 * capabilities are not in use) to a system using filesystem
	 * capabilities only - as the POSIX.1e draft intended.
	 *
	 * Note:
	 *
	 *  PR_SET_SECUREBITS =
	 *      issecure_mask(SECURE_KEEP_CAPS_LOCKED)
	 *    | issecure_mask(SECURE_NOROOT)
	 *    | issecure_mask(SECURE_NOROOT_LOCKED)
	 *    | issecure_mask(SECURE_NO_SETUID_FIXUP)
	 *    | issecure_mask(SECURE_NO_SETUID_FIXUP_LOCKED)
	 *
	 * will ensure that the current process and all of its
	 * children will be locked into a pure
	 * capability-based-privilege environment.
	 */
	case PR_SET_SECUREBITS:
		if ((((cred->securebits & SECURE_ALL_LOCKS) >> 1)
		     & (cred->securebits ^ arg2))                  /*[1]*/
		    || ((cred->securebits & SECURE_ALL_LOCKS
			 & ~arg2))                                    /*[2]*/
		    || (arg2 & ~(SECURE_ALL_LOCKS | SECURE_ALL_BITS)) /*[3]*/
		    || (cap_capable(current, CAP_SETPCAP, SECURITY_CAP_AUDIT) != 0)) { /*[4]*/
			/*
			 * [1] no changing of bits that are locked
			 * [2] no unlocking of locks
			 * [3] no setting of unsupported bits
			 * [4] doing anything requires privilege (go read about
			 *     the "sendmail capabilities bug")
			 */
			error = -EPERM;  /* cannot change a locked bit */
		} else {
			cred->securebits = arg2;
		}
		break;
	case PR_GET_SECUREBITS:
		error = cred->securebits;
		break;

#endif /* def CONFIG_SECURITY_FILE_CAPABILITIES */

	case PR_GET_KEEPCAPS:
		if (issecure(SECURE_KEEP_CAPS))
			error = 1;
		break;
	case PR_SET_KEEPCAPS:
		if (arg2 > 1) /* Note, we rely on arg2 being unsigned here */
			error = -EINVAL;
		else if (issecure(SECURE_KEEP_CAPS_LOCKED))
			error = -EPERM;
		else if (arg2)
			cred->securebits |= issecure_mask(SECURE_KEEP_CAPS);
		else
			cred->securebits &= ~issecure_mask(SECURE_KEEP_CAPS);
		break;

	default:
		/* No functionality available - continue with default */
		return 0;
	}

	/* Functionality provided */
	*rc_p = error;
	return 1;
}

void cap_task_reparent_to_init (struct task_struct *p)
{
	struct cred *cred = p->cred;

	cap_set_init_eff(cred->cap_effective);
	cap_clear(cred->cap_inheritable);
	cap_set_full(cred->cap_permitted);
	p->cred->securebits = SECUREBITS_DEFAULT;
}

int cap_syslog (int type)
{
	if ((type != 3 && type != 10) && !capable(CAP_SYS_ADMIN))
		return -EPERM;
	return 0;
}

int cap_vm_enough_memory(struct mm_struct *mm, long pages)
{
	int cap_sys_admin = 0;

	if (cap_capable(current, CAP_SYS_ADMIN, SECURITY_CAP_NOAUDIT) == 0)
		cap_sys_admin = 1;
	return __vm_enough_memory(mm, pages, cap_sys_admin);
}

