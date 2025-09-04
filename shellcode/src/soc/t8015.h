#ifndef T8015_H
#define T8015_H

#include <stdint.h>
#include <stdbool.h>
#include "../common.h"

#define UART_BASE_T8015 0x22e600000
#define UART_PMGR_REGISTER_T8015 0x2320801e8

INTERNAL static bool address_is_blacklisted_t8015(uint64_t addr)
{
    // need to be like this because we are misaligned
    if (addr > 0x236e00000 && addr <= 0x236e40000)
        return true;

    return false;
}

#endif
