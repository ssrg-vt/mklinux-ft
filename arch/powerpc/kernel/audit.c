#include <linux/init.h>
#include <linux/types.h>
#include <linux/audit.h>
#include <asm/unistd.h>

static unsigned dir_class[] = {
#include <asm-generic/audit_dir_write.h>
~0U
};

static unsigned read_class[] = {
#include <asm-generic/audit_read.h>
~0U
};

static unsigned write_class[] = {
#include <asm-generic/audit_write.h>
~0U
};

static unsigned chattr_class[] = {
#include <asm-generic/audit_change_attr.h>
~0U
};

static int __init audit_classes_init(void)
{
#ifdef CONFIG_PPC64
	extern __u32 ppc32_dir_class[];
	extern __u32 ppc32_write_class[];
	extern __u32 ppc32_read_class[];
	extern __u32 ppc32_chattr_class[];
	audit_register_class(AUDIT_CLASS_WRITE_32, ppc32_write_class);
	audit_register_class(AUDIT_CLASS_READ_32, ppc32_read_class);
	audit_register_class(AUDIT_CLASS_DIR_WRITE_32, ppc32_dir_class);
	audit_register_class(AUDIT_CLASS_CHATTR_32, ppc32_chattr_class);
#endif
	audit_register_class(AUDIT_CLASS_WRITE, write_class);
	audit_register_class(AUDIT_CLASS_READ, read_class);
	audit_register_class(AUDIT_CLASS_DIR_WRITE, dir_class);
	audit_register_class(AUDIT_CLASS_CHATTR, chattr_class);
	return 0;
}

__initcall(audit_classes_init);
