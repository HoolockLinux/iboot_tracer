#include "common.h"
#include "soc.h"
#include <stddef.h>

#if __has_include("trace_config.h")
#include "trace_config.h"
#else
static const u64 trace_config[] = {};
#endif

/*
 * Payload CANNOT have any global variables
 * Only functions allowed in global context
 * cannot use va arg for some reason
 */ 

#define ALIGN_UP(x, a)   (((x) + ((a) - 1)) & ~((a) - 1))
#define ALIGN_DOWN(x, a) ((x) & ~((a) - 1))
#define L2_ENTRY_SIZE 0x2000000
#define L2_TTE(addr) (V->ttbr0 + (addr / L2_ENTRY_SIZE)*sizeof(uint64_t))
#define CORRUPT_TTE(addr) clear64((uint64_t)L2_TTE(addr), PTE_VALID)
#define FIX_TTE(addr) set64((uint64_t)L2_TTE(addr), PTE_VALID)
// this works because most of iboot runs in EL0
#define NO_UNPRIV_ACCESS_TTE(addr) clear64((uint64_t)L2_TTE(addr), PTE_UNPRIV_ACCESS)

struct arm_exception_frame64 {
	uint64_t	regs[29];	// x0-x28
	uint64_t	fp;
	uint64_t	lr;
	uint64_t	sp;		
	uint32_t	spsr;
	uint32_t	reserved0;		
	uint64_t	pc;
	uint64_t	far;
	uint32_t	esr;
	uint32_t	reserved1;
	uint64_t	reserved2;	// stp requires multiple of 16 in imm field
	uint64_t	reserved3;	// stp requires multiple of 16 in imm field
	union {
		uint128_t	q;
		uint64_t	d;
		uint32_t	s;
	} vregs[32];			// v0-v31
	uint32_t	fpsr;
	uint32_t	reserved4;
	uint32_t	fpcr;
	uint32_t	reserved5;
};// from iboot

static int emulate_store(struct arm_exception_frame64 *ctx, u32 insn, u64 *val, u64 *width, u64 *vaddr);
static int emulate_load(struct arm_exception_frame64 *ctx, u32 insn, u64 far_addr, u64 *width, u64 *vaddr, u64* val);

#define ESR_EC_SHIFT			26
#define ESR_EC_MASK			(0x3F << ESR_EC_SHIFT)
#define ESR_EC(x)			((x & ESR_EC_MASK) >> ESR_EC_SHIFT)
#define ESR_ISS_MASK			0x01FFFFFF
#define ESR_ISS(x)			(x & ESR_ISS_MASK)

#define ISS_DA_WNR_SHIFT			6
#define ISS_DA_WNR				(0x1 << ISS_DA_WNR_SHIFT)
#define ISS_DA_FSC_MASK				0x2F
#define ISS_DA_FSC(x)				(x & ISS_DA_FSC_MASK)
#define FSC_TRANSLATION_FAULT_L2    0x06
#define FSC_TRANSLATION_FAULT_L3    0x07

#define PMGR_PS_ACTUAL  0xf0
#define PMGR_PS_ACTIVE  0xf

void uart_init();
void uart_putchar(u8 c);
void uart_put64(u64 num);
#define O(c) uart_putchar(c);

#define panic(c) { O('P'); O(':'); O(c); while(1);}

INTERNAL static void *memset(void *s, int c, unsigned long n)
{
    unsigned char *p = (unsigned char *)s;

    while (n--) {
        *p++ = (unsigned char)c;
    }

    return s;
}

INTERNAL static void flush_tlbs()
{
    sysop("dsb ishst");
    sysop("tlbi vmalle1is");
    sysop("dsb ish");
    sysop("isb");
}

INTERNAL static uint64_t virt_to_phys(uint64_t vaddr) {
    __asm__ volatile("at\tS1E1R, %0" : : "r"(vaddr) : "memory");

    uint64_t par = __builtin_arm_rsr64("par_el1");
    if (par & 0x1) {
        return 0xFFFFFFFFFFFFFFFF;
    }
    uint64_t phys_addr = (par & 0xFFFFFFFFF000ULL) | (vaddr & 0xFFFULL);

    return phys_addr;
}

INTERNAL static u64 read_by_width(u64 addr, u64 *width)
{
    switch (*width) {
        case 0:
            return (u64)read8(addr);
        case 1:
            return (u64)read16(addr);
        case 2:
            return (u64)read32(addr);
        default:
            return read64(addr);
    }
    
}

void* arm64_data_abort_exception(struct arm_exception_frame64 *frame)
{
    u32 esr_iss = ESR_ISS(frame->esr);
	u64 width=0;
	u64 vaddr=0;
	u64 val[2]={0,0};
	u32 insn = read32(frame->pc);
    u64 addr = frame->far;
    u8 isWite=0, isTransFault=0;

    if(ISS_DA_FSC(esr_iss) == FSC_TRANSLATION_FAULT_L2 || ISS_DA_FSC(esr_iss) == FSC_TRANSLATION_FAULT_L3 )
    {   // traslation fault
        isWite=!(insn & BIT(22));
        isTransFault=1;
        FIX_TTE(ALIGN_DOWN(addr, L2_ENTRY_SIZE));
        flush_tlbs();
    }
    else // permission fault
        isWite=esr_iss & ISS_DA_WNR;

    V->payload_flags |= PAYLOAD_FLAG_ENABLE_UART;
    bool blacklisted = false;
    switch (V->chipid) {
        case 0x8012:
            blacklisted = address_is_blacklisted_t8012(addr);
            break;
        case 0x8015:
            blacklisted = address_is_blacklisted_t8015(addr);
            break;
        default:
            break;
    }

    if (addr == V->uart_pmgr_reg || (addr > V->uart_base && addr < (V->uart_base + 0x1000)))
        blacklisted = true;

    if (blacklisted)
        V->payload_flags &= ~PAYLOAD_FLAG_ENABLE_UART;

    if(!isWite)
    {
        if(addr == 0) panic('0');
        if (emulate_load(frame, insn, addr, &width, &vaddr, val))
            panic('L');
        uart_put64(frame->pc);O(':');
        O('R');O(' ');uart_put64(addr);O('@');uart_put64(virt_to_phys(addr));
        O('=');uart_put64(val[0]);
        O('-');uart_put64(width);
        if (width == 4) {
            if(vaddr == addr){
                O('|');uart_put64(addr+8);O('@');uart_put64(virt_to_phys(addr+8));
                O('=');uart_put64(val[1]);
                O('-');uart_put64(width);
            }
            else panic('A');
        }
        else if (width > 4) {
            O('!');uart_put64(width);
            O('!');uart_put64(vaddr);
            O('!');uart_put64(val[0]);
            O('!');uart_put64(val[1]);
            panic('B');
        }
        O('\n');
    }
    else
    {
        if (emulate_store(frame, insn, val, &width, &vaddr))
            panic('S');
        uart_put64(frame->pc);O(':');
        O('W');O(' ');uart_put64(addr);O('@');uart_put64(virt_to_phys(addr));
        O('=');uart_put64(val[0]);
        O('-');uart_put64(width);
        if (width == 0)
            write8(addr, val[0]);
        else if (width == 1)
            write16(addr, val[0]);
        else if (width == 2)
            write32(addr, val[0]);
        else if (width == 3)
            write64(addr, val[0]);
        else if (width == 4) {
            if(vaddr == addr){
                O('|');uart_put64(addr+8);O('@');uart_put64(virt_to_phys(addr+8));
                O('=');uart_put64(val[1]);
                O('-');uart_put64(width);
            }
            else panic('C');
            write64(vaddr, val[0]);
            write64(vaddr+8, val[1]);
        }
        else {
            O('!');uart_put64(width);
            O('!');uart_put64(vaddr);
            O('!');uart_put64(val[0]);
            O('!');uart_put64(val[1]);
            panic('D');
        }
        O('\n');
    }
    if(isTransFault)
    {
        CORRUPT_TTE(ALIGN_DOWN(addr, L2_ENTRY_SIZE));
        flush_tlbs();
    }
    V->payload_flags |= PAYLOAD_FLAG_ENABLE_UART;
    frame->pc += 4;
    return frame;
}

INTERNAL static int emulate_store(struct arm_exception_frame64 *ctx, u32 insn, u64 *val, u64 *width, u64 *vaddr)
{
    u64 Rt = insn & 0x1f;
    u64 Rn = (insn >> 5) & 0x1f;
    u64 imm9 = EXT((insn >> 12) & 0x1ff, 9);
    u64 imm7 = EXT((insn >> 15) & 0x7f, 7);
    u64 *regs = ctx->regs;

    *width = insn >> 30;
    u64 backup_xzr = regs[31];
    regs[31] = 0;// xzr

    u64 mask = 0xffffffffffffffffUL;

    if (*width < 3)
        mask = (1UL << (8 << *width)) - 1;

    if ((insn & 0x3fe00400) == 0x38000400) {
        // STRx (immediate) Pre/Post-index
        CHECK_RN;
        regs[Rn] += imm9;
        *val = regs[Rt] & mask;
    } else if ((insn & 0x3fc00000) == 0x39000000) {
        // STRx (immediate) Unsigned offset
        *val = regs[Rt] & mask;
    } else if ((insn & 0x3fe04c00) == 0x38204800) {
        // STRx (register)
        *val = regs[Rt] & mask;
    } else if ((insn & 0xfec00000) == 0x28000000) {
        // ST[N]P (Signed offset, 32-bit)
        *vaddr = regs[Rn] + (imm7 * 4);
        u64 Rt2 = (insn >> 10) & 0x1f;
        *val = (regs[Rt] & 0xffffffff) | (regs[Rt2] << 32);
        *width = 3;
    } else if ((insn & 0xfec00000) == 0xa8000000) {
        // ST[N]P (Signed offset, 64-bit)
        *vaddr = regs[Rn] + (imm7 * 8);
        u64 Rt2 = (insn >> 10) & 0x1f;
        *val = regs[Rt];
        val[1] = regs[Rt2];
        *width = 4;
    } else if ((insn & 0xfec00000) == 0xa8800000) {
        // ST[N]P (immediate, 64-bit, pre/post-index)
        CHECK_RN;
        *vaddr = regs[Rn] + ((insn & BIT(24)) ? (imm7 * 8) : 0);
        regs[Rn] += (imm7 * 8);
        u64 Rt2 = (insn >> 10) & 0x1f;
        *val = regs[Rt];
        val[1] = regs[Rt2];
        *width = 4;
    } else if ((insn & 0x3fe00c00) == 0x38000000) {
        // STURx (unscaled)
        *val = regs[Rt] & mask;
    } else if ((insn & 0xffffffe0) == 0xd50b7420) {
        // DC ZVA
        *vaddr = regs[Rt];
        memset(val, 0, CACHE_LINE_SIZE);
        *width = CACHE_LINE_LOG2;
    } else if ((insn & 0x3ffffc00) == 0x089ffc00) {
        // STL  qR*
        *val = regs[Rt] & mask;
    } else {
        return 1;
    }
    regs[31] = backup_xzr;
    return 0;
}

INTERNAL static int emulate_load(struct arm_exception_frame64 *ctx, u32 insn, u64 far_addr, u64 *width, u64 *vaddr, u64* val)
{
    u64 Rt = insn & 0x1f;
    u64 Rn = (insn >> 5) & 0x1f;
    u64 imm9 = EXT((insn >> 12) & 0x1ff, 9);
    u64 imm7 = EXT((insn >> 15) & 0x7f, 7);
    u64 *regs = ctx->regs;

    *width = insn >> 30;

    if ((insn & 0x3fe00400) == 0x38400400) {
        // LDRx (immediate) Pre/Post-index
        CHECK_RN;
        regs[Rn] += imm9;
        val[0] = regs[Rt] = read_by_width(far_addr, width);
    } else if ((insn & 0x3fc00000) == 0x39400000) {
        // LDRx (immediate) Unsigned offset
        val[0] = regs[Rt] = read_by_width(far_addr, width);
    } else if ((insn & 0x3fa00400) == 0x38800400) {
        // LDRSx (immediate) Pre/Post-index
        CHECK_RN;
        regs[Rn] += imm9;
        val[0] = regs[Rt] = (s64)EXT(read_by_width(far_addr, width), 8 << *width);
        if (insn & (1 << 22))
            regs[Rt] &= 0xffffffff;
    } else if ((insn & 0x3fa00000) == 0x39800000) {
        // LDRSx (immediate) Unsigned offset
        val[0] = regs[Rt] = (s64)EXT(read_by_width(far_addr, width), 8 << *width);
        if (insn & (1 << 22))
            regs[Rt] &= 0xffffffff;
    } else if ((insn & 0x3fe04c00) == 0x38604800) {
        // LDRx (register)
        regs[Rt] = read_by_width(far_addr, width);
    } else if ((insn & 0x3fa04c00) == 0x38a04800) {
        // LDRSx (register)
        val[0] = regs[Rt] = (s64)EXT(read_by_width(far_addr, width), 8 << *width);
        if (insn & (1 << 22))
            regs[Rt] &= 0xffffffff;
    } else if ((insn & 0x3fe00c00) == 0x38400000) {
        // LDURx (unscaled)
        val[0] = regs[Rt] = read_by_width(far_addr, width);
    } else if ((insn & 0x3fa00c00) == 0x38a00000) {
        // LDURSx (unscaled)
        val[0] = regs[Rt] = (s64)EXT(read_by_width(far_addr, width), (8 << *width));
        if (insn & (1 << 22))
            regs[Rt] &= 0xffffffff;
    } else if ((insn & 0xfec00000) == 0x28400000) {
        // LD[N]P (Signed offset, 32-bit)
        *width = 3;
        *vaddr = regs[Rn] + (imm7 * 4);
        u64 Rt2 = (insn >> 10) & 0x1f;
        val[0] = regs[Rt] = read_by_width(far_addr, width) & 0xffffffff;
        val[1] = regs[Rt2] = read_by_width(far_addr, width) >> 32;
    } else if ((insn & 0xfec00000) == 0xa8400000) {
        // LD[N]P (Signed offset, 64-bit)
        *width = 4;
        *vaddr = regs[Rn] + (imm7 * 8);
        u64 Rt2 = (insn >> 10) & 0x1f;
        val[0] = regs[Rt] = read_by_width(far_addr, width);
        val[1] = regs[Rt2] = read_by_width(far_addr+8, width);
    } else if ((insn & 0xfec00000) == 0xa8c00000) {
        // LDP (pre/post-increment, 64-bit)
        *width = 4;
        *vaddr = regs[Rn] + ((insn & BIT(24)) ? (imm7 * 8) : 0);
        regs[Rn] += imm7 * 8;
        u64 Rt2 = (insn >> 10) & 0x1f;
        val[0] = regs[Rt] = read_by_width(far_addr, width);
        val[0] = regs[Rt2] = read_by_width(far_addr+8, width);
    }
    else {
        return -1;
    }
    return 0;
}

// runs with MMU off
uint64_t payload_init(uint64_t* ttbr0)
{
    memset(V, 0, PAYLOAD_VARIABLES_SIZE);
    V->payload_flags |= PAYLOAD_FLAG_ENABLE_UART;
    V->chipid = get_chipid();
    switch (V->chipid) {
        case 0x8010:
            V->uart_base = UART_BASE_T8010;
            V->uart_pmgr_reg = UART_PMGR_REGISTER_T8010;
            break;
        case 0x8011:
            V->uart_base = UART_BASE_T8011;
            V->uart_pmgr_reg = UART_PMGR_REGISTER_T8011;
            break;
        case 0x8012:
            V->uart_base = UART_BASE_T8012;
            V->uart_pmgr_reg = UART_PMGR_REGISTER_T8012;
            break;
        case 0x8015:
            V->uart_base = UART_BASE_T8015;
            V->uart_pmgr_reg = UART_PMGR_REGISTER_T8015;
            break;
        default:
            while (1);
    }

    if((read32(V->uart_pmgr_reg) & PMGR_PS_ACTUAL) != PMGR_PS_ACTIVE) {
        write32(V->uart_pmgr_reg, 0xa0f);
        uart_init();
    }
    
    V->ttbr0 = (uint64_t)ttbr0;

    for (uint8_t i = 0; i < sizeof(trace_config)/sizeof(u64); i++) {
        if (trace_config[i] & TRACE_CONFIG_FLAG_FAULT)
            CORRUPT_TTE(FIELD_GET(TRACE_CONFIG_OAB, trace_config[i]));
        else
            NO_UNPRIV_ACCESS_TTE(FIELD_GET(TRACE_CONFIG_OAB, trace_config[i]));
    }

    __builtin_arm_wsr64("ttbr0_el1", (uint64_t)ttbr0);
    sysop("isb");
    return (uint64_t)ttbr0; // 0x180000000
}
