#undef __powerpc64__
#include <asm/unistd.h>

unsigned ppc32_dir_class[] = {
#include <asm-generic/audit_dir_write.h>
~0U
};

unsigned ppc32_chattr_class[] = {
#include <asm-generic/audit_change_attr.h>
~0U
};
