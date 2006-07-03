#include <linux/init.h>
#include <linux/types.h>
#include <linux/audit.h>
#include <asm/unistd.h>

static unsigned dir_class[] = {
#include <asm-generic/audit_dir_write.h>
~0U
};

static unsigned chattr_class[] = {
#include <asm-generic/audit_change_attr.h>
~0U
};

static int __init audit_classes_init(void)
{
	audit_register_class(AUDIT_CLASS_DIR_WRITE, dir_class);
	audit_register_class(AUDIT_CLASS_CHATTR, chattr_class);
	return 0;
}

__initcall(audit_classes_init);
