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

uint8_t *get_chipid;

bool patch_chipid(struct pf_patch_t *patch, uint32_t *stream) {
    char *str = ((char*)stream + (adr_off(stream)));
    if (strcmp(str, "chip-id"))
        return false;

    get_chipid = (uint8_t*)pf_follow_branch(iboot_buf, &stream[4]);

    printf("%s: found chipid = %" PRIx64 "\n", __func__, iboot_ptr_to_pa(get_chipid));
    return true;
}

void chipid_patch(void) {
    uint32_t chipid_matches[] = {
        0x10000008, // adr x8, "chip-id"
        0xd503201f, // nop
        0x94000000, // bl
        0x34000000, // cbz w0, ...
        0x94000000, // bl get_chipid
    };

    uint32_t chipid_masks[] = {
        0x9f00001f,
        0xffffffff,
        0xfc000000,
        0xff00001f,
        0xfc000000,
    };

    struct pf_patch_t chipid = pf_construct_patch(chipid_matches, chipid_masks, sizeof(chipid_matches) / sizeof(uint32_t), (void*)patch_chipid);

    struct pf_patch_t patches[] = {
        chipid,
    };

    struct pf_patchset_t patchset = pf_construct_patchset(patches, sizeof(patches) / sizeof(struct pf_patch_t), (void *) pf_find_maskmatch32);

    pf_patchset_emit(iboot_buf, iboot_len, patchset);
}

