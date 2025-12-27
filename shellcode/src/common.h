#ifndef COMMON_H
#define COMMON_H

#include <stddef.h>
#include <stdint.h>

#define PAYLOAD_VARIABLES_SIZE 0x40

typedef __uint128_t uint128_t;
typedef uint8_t             u8;
typedef uint16_t            u16;
typedef uint32_t            u32;
typedef uint64_t            u64;
typedef int64_t             s64;
typedef int32_t             s32;

struct __attribute__((packed)) payload_variables {
    uint16_t payload_flags;
    uint16_t chipid;
    uint32_t reserved1;
    uint64_t ttbr0;
    uint64_t uart_pmgr_reg;
    uint64_t uart_base;
    char reserved[0x20];
};

extern uint16_t get_chipid(void);

static_assert(sizeof(struct payload_variables) == PAYLOAD_VARIABLES_SIZE, "Unexpected struct payload_variable size");
extern struct payload_variables* V;

#define EXT(n, b) (((s32)(((u32)(n)) << (32 - (b)))) >> (32 - (b)))
#define CHECK_RN                                                                                   \
    if (Rn == 31)                                                                                  \
    return 1
#define BIT(x)                 (1UL << (x))
#define PAGE_SIZE       0x4000
#define CACHE_LINE_SIZE 64
#define CACHE_LINE_LOG2 6
#define sysop(op) __asm__ volatile(op ::: "memory")
#define GENMASK(msb, lsb)      ((BIT((msb + 1) - (lsb)) - 1) << (lsb))
#define _FIELD_LSB(field)      ((field) & ~(field - 1))
#define FIELD_PREP(field, val) (((val) * (_FIELD_LSB(field))) & (field))
#define FIELD_GET(field, val)  (((val) & (field)) / _FIELD_LSB(field))

#define PAYLOAD_FLAG_ENABLE_UART    BIT(0)
#define INTERNAL __attribute__((visibility("internal")))

#define PTE_VALID           BIT(0)
#define PTE_UNPRIV_ACCESS   BIT(6)

/* Trace with TransFault (slow) instead of No-UnPriv-Access (fast) */
#define TRACE_CONFIG_FLAG_FAULT BIT(62)
/* Output address block */
#define TRACE_CONFIG_OAB        GENMASK(47, 0) // 25

static u8 read8(u64 addr)
{
    u32 data;
    __asm__ volatile("ldrb\t%w0, [%1]" : "=r"(data) : "r"(addr) : "memory");
    return data;
}
static u16 read16(u64 addr)
{
    u32 data;
    __asm__ volatile("ldrh\t%w0, [%1]" : "=r"(data) : "r"(addr) : "memory");
    return data;
}
static u32 read32(u64 addr)
{
    u32 data;
    __asm__ volatile("ldr\t%w0, [%1]" : "=r"(data) : "r"(addr) : "memory");
    return data;
}
static u64 read64(u64 addr)
{
    u64 data;
    __asm__ volatile("ldr\t%0, [%1]" : "=r"(data) : "r"(addr) : "memory");
    return data;
}
static void write64(u64 addr, u64 data)
{
    __asm__ volatile("str\t%0, [%1]" : : "r"(data), "r"(addr) : "memory");
}
static void write32(u64 addr, u32 data)
{
    __asm__ volatile("str\t%w0, [%1]" : : "r"(data), "r"(addr) : "memory");
}
static void write16(u64 addr, u16 data)
{
    __asm__ volatile("strh\t%w0, [%1]" : : "r"(data), "r"(addr) : "memory");
}
static void write8(u64 addr, u8 data)
{
    __asm__ volatile("strb\t%w0, [%1]" : : "r"(data), "r"(addr) : "memory");
}

static inline u64 set64(u64 addr, u64 set)
{
    u64 data;
    __asm__ volatile("ldr\t%0, [%1]\n"
                     "\torr\t%0, %0, %2\n"
                     "\tstr\t%0, [%1]"
                     : "=&r"(data)
                     : "r"(addr), "r"(set)
                     : "memory");
    return data;
}

static inline u64 clear64(u64 addr, u64 clear)
{
    u64 data;
    __asm__ volatile("ldr\t%0, [%1]\n"
                     "\tbic\t%0, %0, %2\n"
                     "\tstr\t%0, [%1]"
                     : "=&r"(data)
                     : "r"(addr), "r"(clear)
                     : "memory");
    return data;
}


#endif
