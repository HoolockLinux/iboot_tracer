#ifndef T8012_H
#define T8012_H

#include <stdint.h>
#include <stdbool.h>
#include "../common.h"

#define UART_BASE_T8012 0x20a600000
#define UART_PMGR_REGISTER_T8012 0x20e080200

INTERNAL static bool address_is_blacklisted_t8012(uint64_t addr)
{
    // need to be like this because we are misaligned
    if (addr > 0x212e00000 && addr <= 0x212e80000)
        return true;

    return false;
}

#endif
