#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <inttypes.h>
#include "plooshfinder.h"
#include "plooshfinder32.h"
#include "patches/exception.h"
#include "asm/arm64.h"
#include "common.h"

uint32_t *sync_panic;
uint32_t *el1_eret;

bool patch_exception(struct pf_patch_t *patch, uint32_t *stream) {
    uint32_t *adr = pf_find_next(stream, 6, 0x10000001,0x9f00001f); // adr x2, ...

    if (!adr) {
        printf("%s: failed to find adr\n", __func__);
        return false;
    }

    if (adr[1] != nop || !pf_maskmatch32(adr[2], 0x14000000, 0x7c000000)) {
        printf("%s: Unexpected instruction after adr (0x%" PRIx64 ")\n", __func__, iboot_ptr_to_pa(adr));
        return false;
    }

    sync_panic = pf_follow_branch(iboot_buf, &adr[2]);
    printf("%s: found arm_synchronous_exception = 0x%llx\n", __func__, iboot_ptr_to_pa(sync_panic));

    // call our payload handler instead of arm_synchronous_exception

    adr[1] = 0xa8c17bfd; // ldp x29, x30, [sp], #0x10
    adr[2] = arm64_branch(&adr[2], payload_buf, false);
    printf("%s: iboot's arm_synchronous_exception() to payload's payload_init(): 0x%" PRIx64 " -> 0x%" PRIx64"\n", __func__, iboot_ptr_to_pa(&adr[2]), iboot_ptr_to_pa(payload_buf));

    return true;
}

bool patch_eret(struct pf_patch_t *patch, uint32_t *stream) {
    printf("%s: Found el1_eret = 0x%" PRIx64 "\n", __func__, iboot_ptr_to_pa(stream));
    el1_eret = stream;

    return true;
}

void exception_patch(void) {
    uint32_t exc_sync_matches[] = {
        0x12006101, // and w1, w8, #0x1ffffff
        0xa8c17bfd, // ldp x29, x30, [sp], #0x10
    };

    uint32_t exc_sync_masks[] = {
        0xffffffff,
        0xffffffff,
    };

    struct pf_patch_t sync_exception = pf_construct_patch(exc_sync_matches, exc_sync_masks, sizeof(exc_sync_matches) / sizeof(uint32_t), (void*)patch_exception);

    uint32_t el1_eret_matches[] = {
        0xd50041bf, // msr PSTATE.SP, #0x1
        0x58000001, // ldr x1, ...
        0x9100003f, // mov sp, x1
        0xd50040bf, // msr PSTATE.SP, #0x0
    };

    uint32_t el1_eret_masks[] = {
        0xffffffff,
        0xff00001f,
        0xffffffff,
        0xffffffff,
    };

    struct pf_patch_t el1_eret = pf_construct_patch(el1_eret_matches, el1_eret_masks, sizeof(el1_eret_matches) / sizeof(uint32_t), (void*)patch_eret);


    struct pf_patch_t patches[] = {
        sync_exception,
        el1_eret,
    };

    struct pf_patchset_t patchset = pf_construct_patchset(patches, sizeof(patches) / sizeof(struct pf_patch_t), (void *) pf_find_maskmatch32);

    pf_patchset_emit(iboot_buf, iboot_len, patchset);
}

