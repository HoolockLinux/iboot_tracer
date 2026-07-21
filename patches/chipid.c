#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <inttypes.h>
#include "plooshfinder.h"
#include "plooshfinder32.h"
#include "patches/chipid.h"
#include "asm/arm64.h"
#include "common.h"

int32_t adr_off(uint32_t* insn);

uint8_t *get_chipid, *get_boardid;

bool patch_chipid(struct pf_patch_t *patch, uint32_t *stream, uint8_t func_off) {
    char *str = ((char*)stream + (adr_off(stream)));
    if (strcmp(str, "chip-id") == 0) {
        get_chipid = (uint8_t*)pf_follow_branch(iboot_buf, &stream[func_off]);

        printf("%s: found chipid = 0x%" PRIx64 "\n", __func__, iboot_ptr_to_pa(get_chipid));
        return true;
    } else if (strcmp(str, "board-id") == 0) {
        get_boardid = (uint8_t*)pf_follow_branch(iboot_buf, &stream[func_off]);

        printf("%s: found boardid = 0x%" PRIx64 "\n", __func__, iboot_ptr_to_pa(get_boardid));
        return true;
    }
    return false;
}

bool patch_chipid_12(struct pf_patch_t *patch, uint32_t *stream) {
    return patch_chipid(patch, stream, 9);
}

bool patch_chipid_15(struct pf_patch_t *patch, uint32_t *stream) {
    return patch_chipid(patch, stream, 4);
}

void chipid_patch(void) {
    uint32_t chipid_matches[] = {
        0x10000008, // adr x8, "chip-id" / "board-id"
        0xd503201f, // nop
        0x94000000, // bl
        0x34000000, // cbz w0, ...
        0x94000000, // bl get_chipid / get_boardid
    };

    uint32_t chipid_masks[] = {
        0x9f00001f,
        0xffffffff,
        0xfc000000,
        0xff00001f,
        0xfc000000,
    };

    struct pf_patch_t chipid = pf_construct_patch(chipid_matches, chipid_masks, sizeof(chipid_matches) / sizeof(uint32_t), (void*)patch_chipid_15);

    uint32_t chipid_matches12[] = {
        0x10000008, // adr x8, "chip-id" / "board-id"
        0xd503201f, // nop
        0xf90003e8, // str x8, [sp, ...]
        0xf94003e0, // ldr x0, [sp, ...]
        0x910003e1, // add x1, sp, ...
        0x910003e2, // add x2, sp, ...
        0x910003e3, // add x3, sp, ...
        0x94000000, // bl
        0x34000000, // cbz x0, ...
        0x94000000, // bl get_chipid / get_boardid
    };

    uint32_t chipid_masks12[] = {
        0x9f00001f,
        0xffffffff,
        0xffc003ff,
        0xffc003ff,
        0xffc003ff,
        0xffc003ff,
        0xffc003ff,
        0xfc000000,
        0xff00001f,
        0xfc000000,
    };

    struct pf_patch_t chipid_12 = pf_construct_patch(chipid_matches12, chipid_masks12, sizeof(chipid_matches12) / sizeof(uint32_t), (void*)patch_chipid_12);

    struct pf_patch_t patches[] = {
        chipid,
        chipid_12,
    };

    struct pf_patchset_t patchset = pf_construct_patchset(patches, sizeof(patches) / sizeof(struct pf_patch_t), (void *) pf_find_maskmatch32);

    pf_patchset_emit(iboot_buf, iboot_len, patchset);
}

