#include <arch/idt.h>
#include <arch/page.h>
#include <arch/processor.h>
#include <arch/segment.h>
#include <xtf/asm_macros.h>
#include <arch/msr-index.h>

    .align  16
    .code32

ENTRY(handle_external_int)
    SAVE_ALL
    call pt_interrupt_handler
    RESTORE_ALL
    iret
