#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <inttypes.h>
#include "plooshfinder.h"
#include "plooshfinder32.h"
#include "patches/platform_init_mmu.h"
#include "asm/arm64.h"
#include "common.h"

#define PAYLOAD_VARIABLES_SIZE 0x40

uint32_t *ttbr0;
uint8_t *payload_var;
#define ALIGN_UP(x, a)   (((x) + ((a) - 1)) & ~((a) - 1))

int32_t adr_off(uint32_t* insn) {
    uint32_t immhi = (*insn >> 5) & 0x7ffff;
    uint32_t immlo = (*insn >> 29) & 0x3;
    return pf_signextend_32(immhi << 2 | immlo, 21);
}

void *iboot_follow_xref(void *buf, uint32_t *stream) {
    // this is marked as void * so it can be casted to a different type later
    if (!pf_maskmatch32(stream[0], 0x90000000, 0x9f000000)) {
        printf("%s: is not adrp!\n", __func__);
        return 0;
    } else if (!pf_maskmatch32(stream[1], 0x91000000, 0xff800000)) {
        printf("%s: is not add!\n", __func__);
        return 0;
    }

    int64_t adrp_addr = pf_adrp_offset(stream[0]);
    uint32_t add_offset = (stream[1] >> 10) & 0xfff;

    uint64_t stream_va = iboot_ptr_to_pa(stream);
    uint64_t stream_addr = stream_va & ~0xfffUL;
    uint64_t followed_addr = stream_addr + adrp_addr + add_offset;

    return iboot_pa_to_ptr(followed_addr);
}


bool patch_platform_init_mmu(struct pf_patch_t *patch, uint32_t *stream) {
    // search backwards for adr xN, iboot_base
    uint32_t *adr = NULL;
    uint32_t *insn = stream - 2;
    uint8_t i = 0;

    while (i < 0x40 && !adr) {
        i++;
        if (!pf_maskmatch32(*(--insn), 0x10000000,0x9f000000)) // adr
            continue;

        int32_t off = adr_off(insn);

        if (iboot_ptr_to_pa((char*)insn + off) != iboot_base)
            continue;

        adr = insn;
    }

    if (!adr) {
        printf("%s: failed to find adr xN, iboot_base (0x%" PRIx64 ")\n", __func__, iboot_ptr_to_pa(stream));
        return false;
    }

    uint32_t *adr2 = pf_find_next(adr+1, 5, 0x10000001, 0x9f00001f); // adr x1, ...

    if (!adr2) {
        printf("%s: failed to find adr x1, text_end (0x%" PRIx64 ")\n", __func__, iboot_ptr_to_pa(adr));
        return false;
    }

    uint32_t *text_end = adr2 + (adr_off(adr2) >> 2);
    uint64_t text_end_pa = ALIGN_UP(iboot_ptr_to_pa(text_end), 4);
    uint64_t text_end_pa_aligned = ALIGN_UP(text_end_pa, 0x4000);
    size_t payload_max_len = text_end_pa_aligned - text_end_pa;

    uint32_t *adr3 = pf_find_next(adr2+1, 10, 0x10000000, 0x9f000000); // adr
    if (!adr3) {
        printf("%s: failed to find adr xN, data_start (0x%" PRIx64 ")\n", __func__, iboot_ptr_to_pa(adr2));
        return false;
    }

    uint32_t *adr3_dest = adr3 + (adr_off(adr3) >> 2);

    if (iboot_ptr_to_pa(adr3_dest) != text_end_pa_aligned) {
        printf("adr3_dest not match aligned text end! 0x%llx != 0x%llx (0x%" PRIx64 ")\n", iboot_ptr_to_pa(adr3_dest), text_end_pa_aligned, iboot_ptr_to_pa(adr3));
        return false;
    }

    uint32_t *adrp = pf_find_next(adr3, 5, 0x90000000, 0x9f000000); // adrp
    uint32_t *data_end = NULL;

    if (adrp) {
        data_end = iboot_follow_xref(iboot_buf, adrp);
    } else {
        // maybe it's an adr?
        uint32_t *adr4 = pf_find_next(adr3+1, 10, 0x10000000, 0x9f000000); // adr
        if (adr4)
            data_end = adr4 + (adr_off(adr4) >> 2);
        else {
            printf("%s: failed to find data_end xref adr3=0x%llx\n", __func__, iboot_ptr_to_pa(adr3));
            return false;
        }
    }

    uint64_t data_end_pa = ALIGN_UP(iboot_ptr_to_pa(data_end), 8);
    uint64_t data_end_pa_aligned = ALIGN_UP(data_end_pa, 0x4000);
    size_t payload_var_max_len = data_end_pa_aligned - data_end_pa;

    printf("%s: %zd bytes available to payload\n", __func__, payload_max_len);
    if (payload_bin_len > payload_max_len) {
        printf("payload too large: %" PRIu32 " > %zd\n", payload_bin_len, payload_max_len);
        return false;
    }

    printf("%s: %zd bytes available to payload variables\n", __func__, payload_var_max_len);
    if (0x20 > payload_var_max_len) {
        printf("payload variable too large: %" PRIu32 "> %zd\n", PAYLOAD_VARIABLES_SIZE, payload_var_max_len);
        return false;
    }

    payload_buf = (uint8_t*)iboot_pa_to_ptr(text_end_pa);
    payload_var = (uint8_t*)iboot_pa_to_ptr(data_end_pa);
    return true;
}

bool patch_write_ttbr0(struct pf_patch_t *patch, uint32_t *stream) {
    printf("%s: Found write_ttbr0 = 0x%" PRIx64 "\n", __func__, iboot_ptr_to_pa(&stream[0]));
    ttbr0 = stream; 
    return true;
}

void platform_init_mmu_patch(void) {
    // for t8015
    uint32_t pim_t8015_matches[] = {
        0xaa1003e0, // mov x0, x{16-31}
        0xaa1003e1, // mox x1, x{16-31}
        0x94000000, // bl ... maps Normal RX
        0xd2c00040, // mov x0, #0x200000000
        0x52a00001, // mov x1, ... 
        0x94000000, // bl ... maps IO RW
    };

    uint32_t pim_t8015_masks[] = {
        0xfff0ffff,
        0xfff0ffff,
        0xfc000000,
        0xffffffff,
        0xffe0001f,
        0xfc000000,
    };

    struct pf_patch_t platform_init_mmu_t8015 = pf_construct_patch(pim_t8015_matches, pim_t8015_masks, sizeof(pim_t8015_matches) / sizeof(uint32_t), (void*)patch_platform_init_mmu);

    // for t8010 and t8011
    uint32_t pim_t8010_matches[] = {
        0xd2c00040, // mov x0, #0x2_0000_0000 ; io_base
        0x52a00001, // mov w1, ...; io_size
        0x94000000, // bl ; maps IO RW
        0xd2c000c0, // mov x0, #0x6_0000_0000 ; pcie_base
        0x52a00001, // mov w1, ...; pcie_size
        0x94000000, // bl ; maps IO RW

    };

    uint32_t pim_t8010_masks[] = {
        0xffffffff,
        0xffe0001f,
        0xfc000000,
        0xffffffff,
        0xffe0001f,
        0xfc000000,
    };

    struct pf_patch_t platform_init_mmu_t8010 = pf_construct_patch(pim_t8010_matches, pim_t8010_masks, sizeof(pim_t8010_matches) / sizeof(uint32_t), (void*)patch_platform_init_mmu);

    // for t8012
    uint32_t pim_t8012_matches[] = {
        0xd2c00040, // mov x0, #0x2_0000_0000 ; io_base
        0xd2c000a1, // mov x1, #0x5_0000_0000 ; io_size
        0x94000000, // bl ; maps IO RW
    };

    uint32_t pim_t8012_masks[] = {
        0xffffffff,
        0xffffffff,
        0xfc000000,
    };

    struct pf_patch_t platform_init_mmu_t8012 = pf_construct_patch(pim_t8012_matches, pim_t8012_masks, sizeof(pim_t8012_matches) / sizeof(uint32_t), (void*)patch_platform_init_mmu);


    // match entire function
    uint32_t write_ttbr0_matches[] = {
        0xd5182000, // msr ttbr0_el1, x0
        0xd5033fdf, // isb
        0xd65f03c0, // ret
    };

    uint32_t write_ttbr0_masks[] = {
        0xffffffff,
        0xffffffff,
        0xffffffff,
    };

    struct pf_patch_t write_ttbr0 = pf_construct_patch(write_ttbr0_matches, write_ttbr0_masks, sizeof(write_ttbr0_matches) / sizeof(uint32_t), (void*)patch_write_ttbr0);

    struct pf_patch_t patches[] = {
        platform_init_mmu_t8010,
        platform_init_mmu_t8012,
        platform_init_mmu_t8015,
        write_ttbr0,
    };

    struct pf_patchset_t patchset = pf_construct_patchset(patches, sizeof(patches) / sizeof(struct pf_patch_t), (void *) pf_find_maskmatch32);

    pf_patchset_emit(iboot_buf, iboot_len, patchset);
}
