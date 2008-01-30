#ifndef _ASM_X86_ASM_H
#define _ASM_X86_ASM_H

#ifdef CONFIG_X86_32
/* 32 bits */

# define _ASM_PTR	" .long "
# define _ASM_ALIGN	" .balign 4 "
# define _ASM_MOV_UL	" movl "

#else
/* 64 bits */

# define _ASM_PTR	" .quad "
# define _ASM_ALIGN	" .balign 8 "
# define _ASM_MOV_UL	" movq "

#endif /* CONFIG_X86_32 */

#endif /* _ASM_X86_ASM_H */
