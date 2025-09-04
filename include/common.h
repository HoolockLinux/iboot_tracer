#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>
#include <stddef.h>

extern uint64_t iboot_base;
extern uint8_t *iboot_buf;
extern size_t iboot_len;
extern uint8_t *payload_buf;
extern uint8_t *payload_var;
extern uint32_t payload_bin_len;
extern uint32_t *ttbr0;

extern unsigned char *payload_bin;

static inline uint64_t iboot_ptr_to_pa(void* ptr)
{
    return iboot_base + ((uintptr_t)ptr - (uintptr_t)iboot_buf);
}

static inline void* iboot_pa_to_ptr(uint64_t pa)
{
    return (void*)((uintptr_t)iboot_buf + (uintptr_t)(pa - iboot_base));
}

#endif
