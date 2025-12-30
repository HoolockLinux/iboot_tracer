#include "common.h"

#define ULCON    0x000
#define UCON     0x004
#define UFCON    0x008
#define UMCON    0x00c
#define UTRSTAT  0x010
#define UFSTAT   0x018
#define UTXH     0x020
#define URXH     0x024
#define UBRDIV   0x028
#define UFRACVAL 0x02c

#define UTRSTAT_TXBE     BIT(1)

void uart_init(void)
{
    write32(V->uart_base + ULCON, 0x3);
    write32(V->uart_base  + UCON, 0x5c85);
    write32(V->uart_base  + UFCON, 0x0);
    write32(V->uart_base  + UMCON, 0x0);
    write32(V->uart_base  + UBRDIV, 0xc);
}

INTERNAL static void uart_putbyte(u8 c)
{
    if (!V->uart_base )
        return;

    if (!(V->payload_flags & PAYLOAD_FLAG_ENABLE_UART))
        return;

    while (!(read32(V->uart_base  + UTRSTAT) & UTRSTAT_TXBE))
        ;

    write32(V->uart_base  + UTXH, c);
}

void uart_putchar(u8 c)
{
    if (c == '\n')
        uart_putbyte('\r');

    uart_putbyte(c);
}

void uart_put64(u64 num)
{
    if (num == 0) {
        uart_putchar('0');
        return;
    }
    u8 digits[16];
    int digit_count = 0;

    while (num > 0) {
        digits[digit_count++] = num & 0xF;
        num >>= 4;
    }

    for (int i = digit_count - 1; i >= 0; i--) {
        if (digits[i] < 10)
            uart_putchar('0' + digits[i]);      // 0-9
        else
            uart_putchar('a' + (digits[i] - 10)); // a-f
    }
}

