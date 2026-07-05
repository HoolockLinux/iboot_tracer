#ifndef TRACE_CONFIG_H
#define TRACE_CONFIG_H

#include "common.h"

static const u16 trace_config[] = {
	0x2080, // ANS1
	0x2082, // ANS1
	0x2084, // ANS1
	0x2088, // ANS1
	0x208a, // ANS1
	0x208c, // ANS1
	0x208e, // ANS1
};
static const struct whitelist_range whitelist_addr[] = {
	{0x20800000, 0x200000},
	{0x20820000, 0x200000},
	{0x20840000, 0x200000},
	{0x20880000, 0x200000},
	{0x208a0000, 0x200000},
	{0x208c0000, 0x200000},
	{0x208e0000, 0x200000},
};

#define HAVE_TRACE_HOOK

void udelay(u32 d)
{
    u64 delay = ((u64)d) * __builtin_arm_rsr64("CNTFRQ_EL0") / 1000000;
    u64 val = __builtin_arm_rsr64("CNTPCT_EL0");
    while ((__builtin_arm_rsr64("CNTPCT_EL0") - val) < delay)
        ;
    sysop("isb");
}

INTERNAL static void uart_put4(u8 h)
{
    if (h < 10)
         uart_putchar('0' + h);      // 0-9
    else
        uart_putchar('a' + h - 10); // a-f
}

INTERNAL static void uart_put8(u8 b)
{
    u8 lo = b & 0xf;
    u8 hi = (b >> 4) & 0xf;

    uart_put4(hi);
    uart_put4(lo);
}

INTERNAL static void uart_putmem32(u8 *mem)
{
    for (int i = 0; i < 4; i++)
        uart_put8(mem[i]);
}

INTERNAL static void uart_dumpline(u8 *mem)
{
    uart_putchar('0');
    uart_putchar('x');
    uart_put64((u64)mem);
    uart_putchar('\t');

    for (int i = 0; i < 16; i++) {
       uart_putmem32(mem);
       mem += 4;
       uart_putchar(' ');
    }
    uart_putchar('\n');
}

INTERNAL void dump(u64 val, u8 c)
{
	u8 nsid = (val >> 4) & 0xf;
	if (nsid > 8) {
		uart_putchar('!');
		return ;
	}

	for (int i = 0; i < 40; i++)
		uart_putchar(c);
	uart_putchar('\n');

	u8 *dma_buf = (u8*)V->trace_hook_var[0] + nsid * 2240;
	for (int i = 0; i < 35; i++) {
		uart_dumpline(dma_buf);
		dma_buf += 64;
	}

	for (int i = 0; i < 40; i++)
		uart_putchar(c);
	uart_putchar('\n');

}


static void trace_hook(uint64_t vaddr, bool isWrite, uint64_t width, uint64_t *val)
{
	if (!isWrite || vaddr != 0x208041010 || width != 3)
		return;

	if ((val[0] >> 56) != 0x20)
		return;

	// "Using paddr 0x87020a000, setbase message 0x00087020a0001180"
	if ((val[0] & 0xff0000000000ffff) == 0x2000000000001180)
	{
		V->trace_hook_var[0] = ((val[0] >> 16) & 0xfffffffff);
	}

	if ((val[0] & 0xff0000000000000f) != 0x2000000000000003)
		return;

	if (!V->trace_hook_var[0])
		return;

	udelay(100000);
        sysop("dmb oshld");
	dump(*val, '-');
}

void pre_write_hook(uint64_t vaddr, uint64_t *val)
{
	if (vaddr != 0x208041010)
		return;

	if ((val[0] >> 56) != 0x20)
		return;

	if ((val[0] & 0xff0000000000000f) != 0x2000000000000003)
		return;

	if (!V->trace_hook_var[0])
		return;

	uart_putchar('\n');
	dump(*val, '*');
}

#endif
