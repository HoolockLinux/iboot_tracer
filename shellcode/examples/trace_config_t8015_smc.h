#ifndef TRACE_CONFIG_H
#define TRACE_CONFIG_H

#include "common.h"

// Specify bit [35:25] of the address to trace as bit [15:4]
// This will cause access to 0x20a000000 - 0x20c000000,
// 0x236000000 - 0x238000000 to be emulated.
static const u16 trace_config[] = {
    0x2360,
};

// Specify which addresses where access is actually printed.
// Specify bit [35:4] of the start of the whitelist as bit [31:0]
// Second member is the size
// Combined with the above this casues accesses to
// 0x20a110000 - 0x20a111000 to actually be printed.
static const struct whitelist_range whitelist_addr[] = {
    {0x23680000, 0x20000}, // SMC Mailbox
    {0x23600010, 0x100}, // SMC CPU Control
};

#define HAVE_TRACE_HOOK

#define RTKIT_MSG1_EP       GENMASK(7, 0)
#define SMC_MSG_TYPE        GENMASK(7, 0)
#define SMC_MSG_TYPE_READ   0x10
#define SMC_MSG_TYPE_WRITE  0x11
#define SMC_WRITE_SIZE      GENMASK(23, 16)
#define SMC_RESULT_VALUE    GENMASK(63, 32)
#define SMC_RESULT_SIZE     GENMASK(31, 16)
#define SMC_RESULT_ID       GENMASK(15, 8)
#define SMC_RESULT_RESULT   GENMASK(7, 0)
#define SMC_SHMEM_RESULT    0x19

static void read_mem(volatile uint32_t *shmem, uint16_t cnt)
{
    for (uint16_t i = 0; i < cnt; i++) {
        uart_putchar('M');
        uart_putchar(':');
        uart_put64(shmem[i]);
        uart_putchar('\n');
    }
}

// Log SMC shared memory
static void trace_hook(uint64_t vaddr, bool isWrite, uint64_t width, uint64_t *val)
{
    // only interested mbox messages
    if (width != 4)
        return;

    if (vaddr != 0x236808800 && vaddr != 0x236808830)
        return;

    uint8_t size;

    // in rtkit 11 and 12 smc endpoint is 0x20, in 10 it is 0x6
    uint8_t ep = FIELD_GET(RTKIT_MSG1_EP, val[1]);
    if (ep != 0x20) return;
    
    if (vaddr == 0x236808800) // A2I
    {
        if (!isWrite) return;

        uint8_t type = FIELD_GET(SMC_MSG_TYPE, val[0]);
        if (type != SMC_MSG_TYPE_WRITE) // for READ commands we handle the SMCResult
            return;

        size = FIELD_GET(SMC_WRITE_SIZE, val[0]);
        if (size == 0) // shmem not used
            return;

    } else { // I2A
        if (isWrite) return;

        uint8_t result = FIELD_GET(SMC_RESULT_RESULT, val[0]);
        if (result == 0x19) {
            V->trace_hook_var[0] = val[0] >> 8; // smc shmem
            uart_putchar('S');
            uart_putchar(':');
            uart_put64(V->trace_hook_var[0]);
            uart_putchar('\n');
            return;
        }

        size = FIELD_GET(SMC_RESULT_SIZE, val[0]);
        if (size <= 4) // shmem not used
            return;
    }

    read_mem((volatile uint32_t*)V->trace_hook_var[0], (ALIGN_UP(size, 4)) / 4);
}

#endif
