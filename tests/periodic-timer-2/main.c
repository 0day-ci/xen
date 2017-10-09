/**
 * @file tests/periodic-timer/main.c
 * @ref test-periodic-timer
 *
 * @page test-periodic-timer periodic-timer
 *
 * @todo Docs for test-periodic-timer
 *
 * @see tests/periodic-timer/main.c
 */
#include <xtf.h>
#include <arch/barrier.h>
#include <arch/idt.h>
#include <xtf/asm_macros.h>
#include <arch/msr-index.h>

#define COUNTER_FREQ    1193181
#define MAX_PIT_HZ      COUNTER_FREQ
#define MIN_PIT_HZ      18
#define PIT_CTRL_PORT   0x43
#define PIT_CHANNEL0    0x40

#define IOAPIC_REGSEL   ((uint32_t *)0xfec00000)
#define IOAPIC_IOWIN    ((uint32_t *)0xfec00010)

#define AP_START_EIP 0x1000UL
extern char ap_boot_start[], ap_boot_end[];

asm (
    "    .text                       \n"
    "    .code16                     \n"
    "ap_boot_start: .code16          \n"
    "    mov   %cs,%ax               \n"
    "    mov   %ax,%ds               \n"
    "    lgdt  gdt_desr-ap_boot_start\n"
    "    xor   %ax, %ax              \n"
    "    inc   %ax                   \n"
    "    lmsw  %ax                   \n"
    "    ljmpl $0x08,$1f             \n"
    "gdt_desr:                       \n"
    "    .word gdt_end - gdt - 1     \n"
    "    .long gdt                   \n"
    "ap_boot_end: .code32            \n"
    "1:  mov   $0x10,%eax            \n"
    "    mov   %eax,%ds              \n"
    "    mov   %eax,%es              \n"
    "    mov   %eax,%ss              \n"
    "    movl  $stack_top,%esp       \n"
    "    movl  %esp,%ebp             \n"
    "    call  test_ap_main          \n"
    "1:  hlt                         \n"
    "    jmp  1b                     \n"
    "                                \n"
    "    .align 8                    \n"
    "gdt:                            \n"
    "    .quad 0x0000000000000000    \n"
    "    .quad 0x00cf9a000000ffff    \n" /* 0x08: Flat code segment */
    "    .quad 0x00cf92000000ffff    \n" /* 0x10: Flat data segment */
    "gdt_end:                        \n"
    "                                \n"
    "    .bss                        \n"
    "    .align    8                 \n"
    "stack:                          \n"
    "    .skip    0x4000             \n"
    "stack_top:                      \n"
    "    .text                       \n"
    );

const char test_title[] = "Test periodic-timer-2";

int init_pit(int freq)
{
    uint16_t reload;

    if ( (freq < MIN_PIT_HZ) || (freq > MAX_PIT_HZ) ) 
        return -1;

    reload = COUNTER_FREQ / freq;

    asm volatile("cli");
    outb(0x34, PIT_CTRL_PORT);
    outb(reload & 0xff, PIT_CHANNEL0);
    outb(reload >> 8, PIT_CHANNEL0);
    asm volatile("sti");
    return 0;
}

struct ioapic_entry {
    union {
        struct {
            uint32_t vector : 8,
                     dlm    : 3,
                     dm     : 1,
                     dls    : 1,
                     pol    : 1,
                     irr    : 1,
                     tri    : 1,
                     mask   : 1,
                     rsvd1  : 15;
            uint32_t rsvd2  : 24,
                     dest   : 8;
        } fields;
        struct {
            uint32_t lo;
            uint32_t hi;
        } bits;
    };
} __attribute__ ((packed));

void writel(uint32_t data, uint32_t *addr)
{
    *addr = data;
}

#define readl(data, addr) (data) = *(addr)

int write_IOAPIC_entry(struct ioapic_entry *ent, int pin)
{
    asm volatile("cli");
    writel(0x11 + 2*pin, IOAPIC_REGSEL); 
    writel(ent->bits.hi, IOAPIC_IOWIN);
    wmb();
    writel(0x10 + 2*pin, IOAPIC_REGSEL); 
    writel(ent->bits.lo, IOAPIC_IOWIN);
    wmb();
    asm volatile("sti");
    return 0;
}

void handle_external_int(void);

#define rdmsr(msr, val1, val2) \
    __asm__ __volatile__("rdmsr" \
            : "=a" (val1), "=d" (val2) \
            : "c" (msr))

#define wrmsr(msr, val1, val2) \
    __asm__ __volatile__("wrmsr" \
            : \
            : "c" (msr), "a" (val1), "d" (val2))

static inline void wrmsrl(unsigned int msr, uint64_t val)
{
    uint32_t lo, hi;
    lo = (uint32_t)val;
    hi = (uint32_t)(val >> 32);
    wrmsr(msr, lo, hi);
}

#define APIC_BASE_ADDR_MASK 0xfffff000
#define APIC_BASE_ADDR(a) (a & APIC_BASE_ADDR_MASK)
#define APIC_BASE_MSR 0x1b
#define APIC_GLOBAL_ENABLE_MASK 0x800
#define APIC_EOI 0xB0
#define APIC_SVR 0xF0
#define APIC_SOFT_ENABLE_MASK 0x100

uint32_t apic_base_addr;

void enable_lapic(void)
{
    uint32_t lo, hi;
    uint64_t apic_base_msr;
    uint32_t svr;
    rdmsr(APIC_BASE_MSR, lo, hi);
    apic_base_msr = lo | ((uint64_t) hi <<32);
    apic_base_addr = APIC_BASE_ADDR(apic_base_msr);
    wrmsrl(APIC_BASE_MSR, apic_base_msr | APIC_GLOBAL_ENABLE_MASK);
    readl(svr, (uint32_t *)(apic_base_addr + APIC_SVR)); 
    writel(svr | APIC_SOFT_ENABLE_MASK, (uint32_t *)(apic_base_addr + APIC_SVR));
}

void ack_APIC_irq(unsigned long apic_base)
{
    writel(0, (uint32_t *)(apic_base + APIC_EOI));
}

uint32_t lapic_read(uint32_t reg)
{
    return *(volatile uint32_t *)(apic_base_addr + reg);
}

void lapic_write(uint32_t reg, uint32_t val)
{
    *(volatile uint32_t *)(apic_base_addr + reg) = val;
}

#define APIC_ICR 0x300
#define APIC_ICR2 0x310
#define APIC_ICR_BUSY 0x01000
#define APIC_DM_INIT 0x500
#define APIC_DM_STARTUP 0x600

static inline void cpu_relax(void)
{
    asm volatile ( "rep; nop" ::: "memory" );
}

static void lapic_wait_ready(void)
{
    while ( lapic_read(APIC_ICR) & APIC_ICR_BUSY )
        cpu_relax();
}

void pt_interrupt_handler(void)
{
    ack_APIC_irq(apic_base_addr);
}

static void boot_cpu(int cpu)
{
    unsigned int icr2 = (cpu * 2) << 24;
    lapic_wait_ready();
    lapic_write(APIC_ICR2, icr2);
    lapic_write(APIC_ICR, APIC_DM_INIT);
    lapic_wait_ready();
    lapic_write(APIC_ICR2, icr2);
    lapic_write(APIC_ICR, APIC_DM_STARTUP | (AP_START_EIP >> 12));
    lapic_wait_ready();
    lapic_write(APIC_ICR2, icr2);
    lapic_write(APIC_ICR, APIC_DM_STARTUP | (AP_START_EIP >> 12));
    lapic_wait_ready();
}

static void send_ipi(int cpu, uint8_t vector)
{
    unsigned int icr2 = (cpu * 2) << 24;
    lapic_wait_ready();
    lapic_write(APIC_ICR2, icr2);
    lapic_write(APIC_ICR, vector);
    lapic_wait_ready();
}

void smp_initialize(void)
{
    memcpy((void*)AP_START_EIP, ap_boot_start,
           ap_boot_end - ap_boot_start); 
    boot_cpu(1);
}

struct ioapic_entry ent;
void test_main(void)
{
    struct xtf_idte idte = 
    {
        .addr = (unsigned long)handle_external_int,
        .cs = __KERN_CS,
        .dpl = 0,
    };

    /* setup idt entry */
    xtf_set_idte(0x30, &idte);
    xtf_set_idte(0x38, &idte);

    //asm volatile(".byte 0xcd,0x30\n");

    memset(&ent, 0, sizeof(ent));
    ent.fields.vector = 0x38;
    write_IOAPIC_entry(&ent, 2);
    enable_lapic();

    printk("activate cpu1\n");
    smp_initialize();
    init_pit(1000);

    while (1)
        cpu_relax();

    xtf_success(NULL);
}

void test_ap_main(void)
{
    struct ioapic_entry ent2;
    memcpy(&ent2, &ent, sizeof(ent2));
    ent2.fields.vector = 0x38;
    ent2.fields.mask = 1;
    while (1)
    {
        write_IOAPIC_entry(&ent2, 2);
        send_ipi(0, 0x30);
        write_IOAPIC_entry(&ent, 2);
    }
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
