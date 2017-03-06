#include <xtf/extable.h>
#include <xtf/asm_macros.h>
#include <xen/arch-x86/xen.h>

#include <arch/idt.h>
#include <arch/page.h>
#include <arch/processor.h>
#include <arch/segment.h>

#ifdef __i386__
# define REG  edx
# define REG8 dl
#else
# define REG  rdi
# define REG8 dil
#endif

.macro GEN_SINGLE name, type, force=0

ENTRY(stub_\name)

        xor %eax, %eax

#ifdef __i386__
        mov 4(%esp), %REG
#endif

        .ifnc \type, X
        .if \force
        _ASM_XEN_FEP
        .endif
        .endif

.Lstub_\name\()_fault:

        .ifc \type, R
        /* Read (and trash) the pointer. */
        mov (%REG), %REG8
        .endif

        .ifc \type, I
        /* Load %fs with the selector in %REG.  Causes implicit GDT/LDT access. */
        mov %REG, %fs
        .endif

        .ifc \type, W
        /* Write `ret` to the pointer. */
        movb $0xc3, (%REG)
        .endif

        .ifc \type, X
        /* Call the pointer. */

        .if \force
        /* If FORCE, move the pointer to include the force emulation prefix. */
        sub $5, %REG
        .endif

        call *%REG
        .endif

.Lstub_\name\()_fixup:
        ret

ENDFUNC(stub_\name)

        .ifnc \type, X
        _ASM_EXTABLE_HANDLER(.Lstub_\name\()_fault, \
                             .Lstub_\name\()_fixup, \
                             ex_check_pf)
        .endif
.endm

GEN_SINGLE read     R
GEN_SINGLE implicit I
GEN_SINGLE write    W
GEN_SINGLE exec     X
GEN_SINGLE force_read     R 1
GEN_SINGLE force_implicit I 1
GEN_SINGLE force_write    W 1
GEN_SINGLE force_exec     X 1

.pushsection .text.user, "ax", @progbits

GEN_SINGLE read_user     R
GEN_SINGLE implicit_user I
GEN_SINGLE write_user    W
GEN_SINGLE exec_user     X
GEN_SINGLE force_read_user     R 1
GEN_SINGLE force_implicit_user I 1
GEN_SINGLE force_write_user    W 1
GEN_SINGLE force_exec_user     X 1

.popsection
