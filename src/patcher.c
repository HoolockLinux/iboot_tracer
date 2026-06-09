#ifdef __gnu_linux__
#define _GNU_SOURCE 
#endif

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include "common.h"
#include "plooshfinder.h"
#include "patches/platform_init_mmu.h"
#include "patches/chipid.h"
#include "patches/exception.h"
#include "patches/shellcode.h"


uint64_t payload_start, payload_end;
uint64_t iboot_base;
uint8_t* payload_buf;
uint8_t *iboot_buf;
size_t iboot_len;

int patch_iboot(void) {
    printf("starting ibootpatch3\n");

    uint32_t *ldr = pf_find_next((uint32_t *)iboot_buf, 10, 0x58000001, 0xff00001f);
    if (!ldr) {
        printf("%s: failed to find initial ldr!\n", __func__);
        return -1;
    }

    uint32_t ldr_off = (ldr[0] >> 5) & 0x7ffff; // uint32_t takes care of << 2
    uint64_t *iboot_base_p = (uint64_t *)(ldr + ldr_off);

    iboot_base = iboot_base_p[0];
    uint64_t iboot_end = iboot_base_p[1];

    printf("%s: iboot_base = 0x%" PRIx64 "\n", __func__, iboot_base);
    printf("%s: iboot_end = 0x%" PRIx64 "\n", __func__, iboot_end);

    if (iboot_base >= iboot_end) {
        printf("iboot_end is not bigger than iboot_base!\n");
        return -1;
    }

    payload_start = (iboot_end + 0x3fff & ~0x3fff);
    payload_end = payload_start + 0x4000;

    iboot_buf = realloc(iboot_buf, payload_end - iboot_base);
    if (!iboot_buf) {
        printf("realloc iboot_buf failed!\n");
        return -1;
    }

    chipid_patch();

    if (!get_chipid) {
        printf("could not find get_chipid() function\n");
        return -1;
    }

    if (!get_boardid) {
        printf("could not find get_boardid() function\n");
        return -1;
    }

    platform_init_mmu_patch();

    if (!payload_buf) {
        printf("could not find payload buffer\n");
        return -1;
    }

    if (!payload_var) {
        printf("could not find payload variable buffer\n");
        return -1;
    }

    if (!ttbr0) {
        printf("could not find write_ttbr0\n");
        return -1;
    }

    exception_patch();

    if (!sync_panic) {
        printf("could not find sync_panic\n");
        return -1;
    }

    if (!el1_eret) {
        printf("could not find el1_eret\n");
        return -1;
    }

    shellcode_patch();

    return 0;
}

int main(int argc, char **argv) {
    FILE *fp = NULL;

    if (argc < 3) {
        printf("Usage: %s <input iboot> <patched iboot>\n", argv[0]);
        return 0;
    }

    fp = fopen(argv[1], "rb");
    if (!fp) {
        printf("Failed to open iboot!\n");
        return -1;
    }

    fseek(fp, 0, SEEK_END);
    iboot_len = ftell(fp);
    fseek(fp, 0, SEEK_SET);


    if (iboot_len < 0x4000) {
        printf("iBoot too small\n");
        fclose(fp);
        return -1;
    }

    iboot_buf = (void *) malloc(iboot_len);
    if (!iboot_buf) {
        printf("Out of memory while allocating region for iboot!\n");
        fclose(fp);
        return -1;
    }

    fread(iboot_buf, 1, iboot_len, fp);
    fclose(fp);

    int retval = patch_iboot();

    if (retval) {
        printf("patchfinding failed!\n");
        return retval;
    }

    fp = fopen(argv[2], "wb");
    if(!fp) {
        printf("Failed to open output file!\n");
        free(iboot_buf);
        return -1;
    }
    
    fwrite(iboot_buf, 1, iboot_len, fp);
    fflush(fp);
    fclose(fp);

    free(iboot_buf);

    return retval;
}
