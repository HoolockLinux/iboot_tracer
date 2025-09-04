#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <inttypes.h>
#include "patches/exception.h"
#include "patches/chipid.h"
#include "asm/arm64.h"
#include "common.h"

#define REG_LR 30

int assemble_adr(uint32_t *from, uint32_t *to, uint32_t reg, uint32_t *out) {
    if (reg & ~0x1f) {
        printf("%s: invalid register\n", __func__);
        return -1;
    }

    uint64_t from_pa = iboot_ptr_to_pa(from);
    uint64_t to_pa = iboot_ptr_to_pa(to);

    int64_t diff = (int64_t)to_pa - (int64_t)from_pa;
    if (diff > 0xfffff || diff < -0xfffff) {
        printf("%s: diff too large 0x%" PRIx64" -> 0x%" PRIx64 "\n", __func__, from_pa, to_pa);
        return -1;
    }

    uint32_t immlo = diff & 0x3;
    uint32_t immhi = diff >> 2;

    out[0] = 0x10000000 | ((immlo << 29) & 0x3) | ((immhi & 0x7ffff) << 5) | reg;
    printf("%s: adr 0x%x: 0x%llx -> 0x%llx\n", __func__, out[0], from_pa, to_pa);
    return 0;
}

int shellcode_patch(void)
{
    printf("%s: payload text at 0x%" PRIx64 "\n", __func__, iboot_ptr_to_pa(payload_buf));
    memcpy(payload_buf, &payload_bin, payload_bin_len);

    uint32_t *shc = (uint32_t*)payload_buf;
    uint32_t insn;

    /* DATA_ABORT_PANIC_CALL */
    if (assemble_adr(&shc[7], sync_panic, REG_LR, &insn)) {
        printf("%s: could not assemble shellcode (DATA_ABORT_PANIC_CALL)\n", __func__);
        return -1;
    }

    shc[7] = insn;

    /* EXCEPTION_EL1_ERET */
    if (assemble_adr(&shc[10], el1_eret, REG_LR, &insn)) {
        printf("%s: could not assemble shellcode (EXCEPTION_EL1_ERET)\n", __func__);
        return -1;
    }

    shc[10] = insn;

    shc[12] = arm64_branch(&shc[12], get_chipid, false);
    printf("%s: payload's get_chipid() to iboot's get_chipid(): 0x%" PRIx64 " -> 0x%" PRIx64 "\n", __func__, iboot_ptr_to_pa(&shc[12]), iboot_ptr_to_pa(get_chipid));

    *ttbr0 = arm64_branch(ttbr0, &shc[13], false);
    printf("%s: iboot's write_ttbr0() to payload's init_payload(): 0x%" PRIx64 " -> 0x%" PRIx64 "\n", __func__, iboot_ptr_to_pa(ttbr0), iboot_ptr_to_pa(&shc[13]));

    *(uint64_t*)&shc[14] = iboot_ptr_to_pa(payload_var);
    printf("%s: payload variables at 0x%" PRIx64 " with ptr 0x%" PRIx64 "\n", __func__, iboot_ptr_to_pa(payload_var), iboot_ptr_to_pa(&shc[14]));

    return 0;
}
