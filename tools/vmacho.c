// SPDX-License-Identifier: Unlicense
// refer to: https://github.com/Siguza/misc

#define _CRT_SECURE_NO_WARNINGS
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>              // fopen, fclose, ftell, fseek, fflush, fprintf, stdin, stdout, stderr
#include <stdlib.h>             // malloc, free
#include <string.h>             // memset, strcmp, strerror
#include <inttypes.h>

#define LOG(str, ...) do { fprintf(stderr, str "\n", ##__VA_ARGS__); } while(0)

#define MH_MAGIC            0xfeedface
#define MH_MAGIC_64         0xfeedfacf
#define LC_SEGMENT          0x1
#define LC_SEGMENT_64       0x19
#define SEC_TYPE_MASK       0x000000ff
#define SEC_TYPE_ZEROFILL   0x1

typedef uint32_t vm_prot_t;

typedef struct
{
    uint32_t magic;
    uint32_t cputype;
    uint32_t cpusubtype;
    uint32_t filetype;
    uint32_t ncmds;
    uint32_t sizeofcmds;
    uint32_t flags;
} mach_hdr32_t;

typedef struct
{
    uint32_t magic;
    uint32_t cputype;
    uint32_t cpusubtype;
    uint32_t filetype;
    uint32_t ncmds;
    uint32_t sizeofcmds;
    uint32_t flags;
    uint32_t reserved;
} mach_hdr64_t;

typedef struct
{
    uint32_t cmd;
    uint32_t cmdsize;
} mach_lc_t;

typedef struct
{
    uint32_t  cmd;
    uint32_t  cmdsize;
    char      segname[16];
    uint32_t  vmaddr;
    uint32_t  vmsize;
    uint32_t  fileoff;
    uint32_t  filesize;
    vm_prot_t maxprot;
    vm_prot_t initprot;
    uint32_t  nsects;
    uint32_t  flags;
} mach_seg32_t;

typedef struct
{
    uint32_t  cmd;
    uint32_t  cmdsize;
    char      segname[16];
    uint64_t  vmaddr;
    uint64_t  vmsize;
    uint64_t  fileoff;
    uint64_t  filesize;
    vm_prot_t maxprot;
    vm_prot_t initprot;
    uint32_t  nsects;
    uint32_t  flags;
} mach_seg64_t;

typedef struct
{
    char sectname[16];
    char segname[16];
    uint32_t addr;
    uint32_t size;
    uint32_t offset;
    uint32_t align;
    uint32_t reloff;
    uint32_t nreloc;
    uint32_t flags;
    uint32_t reserved[2];
} mach_sect32_t;

typedef struct
{
    char sectname[16];
    char segname[16];
    uint64_t addr;
    uint64_t size;
    uint32_t offset;
    uint32_t align;
    uint32_t reloff;
    uint32_t nreloc;
    uint32_t flags;
    uint32_t reserved[3];
} mach_sect64_t;

typedef enum
{
    Mode_Binary,
    Mode_HeadlessArray,
    Mode_NamedArray,
} vmacho_mode_t;

uint64_t text_sect_off;
size_t text_sect_size;

// 0 = success
// 1 = not a segment
// N = fatal error
static int get_mapped_segment_range(mach_lc_t *cmd, bool use_sections, uint64_t *mapbase, uint64_t *mapoff, uint64_t *mapsize, uint64_t *vmbase, uint64_t *vmsize)
{
    uint64_t lowest    = ~0,
             highest   =  0,
             offset    =  0,
             vmlowest  = ~0,
             vmhighest =  0;
    if(cmd->cmd == LC_SEGMENT)
    {
        mach_seg32_t *seg = (mach_seg32_t*)cmd;
        uint32_t vmaddr   = seg->vmaddr,
                 vmsize   = seg->vmsize,
                 fileoff  = seg->fileoff,
                 filesize = seg->filesize;
        if(!use_sections)
        {
            lowest    = vmaddr;
            highest   = vmaddr + filesize;
            offset    = fileoff;
            vmlowest  = vmaddr;
            vmhighest = vmaddr + vmsize;
        }
        else
        {
            for(uint32_t i = 0, max = seg->nsects; i < max; ++i)
            {
                mach_sect32_t *sec = (mach_sect32_t*)(seg + 1) + i;
                uint32_t lo = sec->addr,
                         hi = lo + sec->size;
                if(hi < lo || lo < vmaddr || hi > vmaddr + vmsize)
                {
                    return 2;
                }
                if((sec->flags & SEC_TYPE_MASK) != SEC_TYPE_ZEROFILL)
                {
                    if(hi > vmaddr + filesize)
                    {
                        return 2;
                    }
                    if(lo < lowest)
                    {
                        lowest = lo;
                    }
                    if(hi > highest)
                    {
                        highest = hi;
                    }
                }
                if(lo < vmlowest)
                {
                    vmlowest = lo;
                }
                if(hi > vmhighest)
                {
                    vmhighest = hi;
                }
            }
            // Zero mapped sections
            if(lowest > highest)
            {
                lowest  = vmaddr;
                highest = vmaddr;
                offset  = 0;
            }
            else
            {
                offset = fileoff + (lowest - vmaddr);
            }
            if(vmlowest > vmhighest)
            {
                vmlowest  = vmaddr;
                vmhighest = vmaddr;
            }
        }
    }
    else if(cmd->cmd == LC_SEGMENT_64)
    {
        mach_seg64_t *seg = (mach_seg64_t*)cmd;
        uint64_t vmaddr   = seg->vmaddr,
                 vmsize   = seg->vmsize,
                 fileoff  = seg->fileoff,
                 filesize = seg->filesize;
        if(!use_sections)
        {
            lowest    = vmaddr;
            highest   = vmaddr + filesize;
            offset    = fileoff;
            vmlowest  = vmaddr;
            vmhighest = vmaddr + vmsize;
        }
        else
        {
            for(uint32_t i = 0, max = seg->nsects; i < max; ++i)
            {
                mach_sect64_t *sec = (mach_sect64_t*)(seg + 1) + i;
                uint64_t lo = sec->addr,
                         hi = lo + sec->size;
                if(hi < lo || lo < vmaddr || hi > vmaddr + vmsize)
                {
                    return 2;
                }
                if((sec->flags & SEC_TYPE_MASK) != SEC_TYPE_ZEROFILL)
                {
                    if(hi > vmaddr + filesize)
                    {
                        return 2;
                    }
                    if(lo < lowest)
                    {
                        lowest = lo;
                    }
                    if(hi > highest)
                    {
                        highest = hi;
                    }
                }
                if(lo < vmlowest)
                {
                    vmlowest = lo;
                }
                if(hi > vmhighest)
                {
                    vmhighest = hi;
                }

                if (!strcmp(sec->segname, "__TEXT") && !strcmp(sec->sectname, "__text"))  {
                    if (seg->fileoff > sec->offset) {
                        printf("error parsing section\n");
                        return 2;
                    }
                    text_sect_off = sec->offset - seg->fileoff;
                    text_sect_size = sec->size;
                }
            }
            // Zero mapped sections
            if(lowest > highest)
            {
                lowest  = vmaddr;
                highest = vmaddr;
                offset  = 0;
            }
            else
            {
                offset = fileoff + (lowest - vmaddr);
            }
            if(vmlowest > vmhighest)
            {
                vmlowest  = vmaddr;
                vmhighest = vmaddr;
            }
        }
    }
    else
    {
        return 1;
    }
    *mapbase = lowest;
    *mapoff  = offset;
    *mapsize = highest - lowest;
    if(vmbase) *vmbase = vmlowest;
    if(vmsize) *vmsize = vmhighest - vmlowest;
    return 0;
}

int64_t sxt64(int64_t val, uint8_t bits) {
    val = (uint64_t) val << (64 - bits);
    val >>= 64 - bits;

    return val;
}

int text_fixup_pass(void* __dst, void* __src, size_t size, uint64_t vmaddr)
{
    if (!text_sect_size)
        return -1;

    if (text_sect_off > size) {
        printf("error parsing section info\n");
        return -1;
    }

    memcpy(__dst, __src, text_sect_off);

    uint32_t *src_text_sect = __src + text_sect_off;
    uint32_t *dst_text_sect = __dst + text_sect_off;

    uint32_t sz4 = text_sect_size / sizeof(uint32_t);

    if ((uintptr_t)(src_text_sect) & 4) {
        printf("__text section is misaligned\n");
        return -1;
    }

    for (uint32_t i = 0; i < sz4; i++) {
        if ((src_text_sect[i] & 0x9f000000) != 0x90000000) {
            dst_text_sect[i] = src_text_sect[i];
            continue;
        }

        if ((i + 1) == sz4) {
            printf("can't have adrp at end of file\n");
            return -1;
        }

        uint8_t reg = src_text_sect[i] & 0x1f;
        uint32_t add = 0x91000000 | reg << 5 | reg;

        if ((src_text_sect[i+1] & 0xffc003ff) != add) {
            printf("can't have stray adrp\n");
            return -1;
        }

        int64_t immhi = (((uint64_t)src_text_sect[i] >> 5) & 0x7ffffULL) << 2;
        uint64_t immlo = ((uint64_t)src_text_sect[i] >> 29) & 0x3ULL;

        uint64_t pc = vmaddr + text_sect_off + i * sizeof(uint32_t);

        int64_t adrp_off = sxt64((immhi | immlo) << 12, 33);
        uint64_t add_off = (src_text_sect[i+1] >> 10) & 0xfff;

        uint64_t dest = ((uint64_t)(pc + adrp_off) & ~UINT64_C(0xfff)) + add_off;

        int64_t adr_off = dest - pc;

        if (adr_off > 0xfffff || adr_off < -0xfffff) {
            printf("can't have adrp, and too far for adr\n");
            return -1;
        }

        uint32_t adr_immlo = adr_off & 0x3;
        int32_t adr_immhi = adr_off >> 2;

        dst_text_sect[i] = 0x10000000 | ((adr_immlo << 29) & 0x3) | ((adr_immhi & 0x7ffff) << 5) | reg;
        dst_text_sect[i+1] = 0xd503201f; // nop

        printf("fixup adr at 0x%" PRIx64 ": 0x%x\n", pc ,dst_text_sect[i]);

        i += 1; // the normal loop already adds 1
    }

    void *__src_tail = __src + text_sect_off + text_sect_size;
    void *__dst_tail = __dst + text_sect_off + text_sect_size;
    size_t tail_size = size - text_sect_off - text_sect_size;

    memcpy(__dst_tail, __src_tail, tail_size);

    return 0;
}

int main(int argc, const char **argv)
{
    int retval = -1;
    void *file = NULL,
         *mem  = NULL;
    size_t flen = 0,
           mlen = 0,
           fmax = 0,
           smax = 0;
    FILE *infile  = NULL,
         *outfile = NULL;
    vmacho_mode_t mode = Mode_Binary;
    const char *oflags = "wbx",
               *aname  = NULL;
    bool use_sections  = true;
    int r;

    int aoff = 1;
    for(; aoff < argc; ++aoff)
    {
        if(argv[aoff][0] != '-' || argv[aoff][1] == '\0')
        {
            break;
        }
        int curoff = aoff;
        for(size_t i = 1; argv[curoff][i] != '\0'; ++i)
        {
            char c = argv[curoff][i];
            switch(c)
            {
                case 'c':
                    mode = Mode_HeadlessArray;
                    break;
                case 'C':
                    if(argc - aoff < 4) // Don't want curoff here
                    {
                        LOG("-%c requires an argument", c);
                        goto out;
                    }
                    mode = Mode_NamedArray;
                    aname = argv[++aoff];
                    break;
                case 'f':
                    oflags = "wb";
                    break;
                case 'm':
                case 'M':
                    if(argc - aoff < 4) // Don't want curoff here
                    {
                        LOG("-%c requires an argument", c);
                        goto out;
                    }
                    const char *num = argv[++aoff];
                    char *end = NULL;
                    unsigned long long l = strtoull(num, &end, 0);
                    if(*num == '\0' || *end != '\0')
                    {
                        LOG("Invalid argument to -%c: %s", c, num);
                        goto out;
                    }
                    if(c == 'm')
                        fmax = (size_t)l;
                    else
                        smax = (size_t)l;
                    break;
                case 's':
                    use_sections = false;
                    break;
                default:
                    LOG("Bad option: -%c", c);
                    goto out;
            }
        }
    }
    if(argc - aoff != 2)
    {
        fprintf(stderr, "Usage: %s [-cf] [-C name] [-m max] [-M max] in out\n"
                        "    -c      Output as headless C array\n"
                        "    -C name Output as named C array\n"
                        "    -f      Force (overwrite existing files)\n"
                        "    -m max  Enforce max size of bytes for total file mapping\n"
                        "    -M max  Enforce max size of bytes for total runtime size\n"
                        "    -s      Use only segments for mapping, ignore sections\n"
                        , argv[0]);
        goto out;
    }

    infile = strcmp(argv[aoff], "-") == 0 ? stdin : fopen(argv[aoff], "rb");
    if(!infile)
    {
        LOG("fopen(%s): %s", argv[aoff], strerror(errno));
        goto out;
    }
    long cur = ftell(infile);
    if(cur < 0)
    {
        LOG("ftell(cur): %s", strerror(errno));
        goto out;
    }
    r = fseek(infile, 0, SEEK_END);
    if(r != 0)
    {
        LOG("fseek(end): %s", strerror(errno));
        goto out;
    }
    long end = ftell(infile);
    if(end < 0)
    {
        LOG("ftell(end): %s", strerror(errno));
        goto out;
    }
    flen = (size_t)(end - cur);
    r = fseek(infile, cur, SEEK_SET);
    if(r != 0)
    {
        LOG("fseek(cur): %s", strerror(errno));
        goto out;
    }

    if(flen < sizeof(uint32_t))
    {
        LOG("File too short for magic.");
        goto out;
    }
    file = malloc(flen);
    if(!file)
    {
        LOG("malloc(file): %s", strerror(errno));
        goto out;
    }
    if(fread(file, 1, flen, infile) != flen)
    {
        LOG("fread: %s", strerror(errno));
        goto out;
    }

    uintptr_t ufile = (uintptr_t)file;
    uint32_t magic = *(uint32_t*)file;
    mach_lc_t *lcs = NULL;
    uint32_t sizeofcmds = 0;
    if(magic == MH_MAGIC)
    {
        mach_hdr32_t *hdr = file;
        if(flen < sizeof(*hdr) + hdr->sizeofcmds)
        {
            LOG("File too short for load commands.");
            goto out;
        }
        lcs = (mach_lc_t*)(hdr + 1);
        sizeofcmds = hdr->sizeofcmds;
    }
    else if(magic == MH_MAGIC_64)
    {
        mach_hdr64_t *hdr = file;
        if(flen < sizeof(*hdr) + hdr->sizeofcmds)
        {
            LOG("File too short for load commands.");
            goto out;
        }
        lcs = (mach_lc_t*)(hdr + 1);
        sizeofcmds = hdr->sizeofcmds;
    }
    else
    {
        LOG("Bad magic: %08llx", (unsigned long long)magic);
        goto out;
    }

    uint64_t lowest    = ~0,
             highest   =  0,
             vmlowest  = ~0,
             vmhighest =  0;
    for(mach_lc_t *cmd = lcs, *end = (mach_lc_t*)((uintptr_t)cmd + sizeofcmds); cmd < end; cmd = (mach_lc_t*)((uintptr_t)cmd + cmd->cmdsize))
    {
        if((uintptr_t)cmd + sizeof(*cmd) > (uintptr_t)end || (uintptr_t)cmd + cmd->cmdsize > (uintptr_t)end || (uintptr_t)cmd + cmd->cmdsize < (uintptr_t)cmd)
        {
            LOG("Bad LC: 0x%llx", (unsigned long long)((uintptr_t)cmd - ufile));
            goto out;
        }

        uint64_t vmaddr  = 0,
                 fileoff = 0,
                 size    = 0,
                 vmbase  = 0,
                 vmsize  = 0;
        r = get_mapped_segment_range(cmd, use_sections, &vmaddr, &fileoff, &size, &vmbase, &vmsize);
        switch(r)
        {
            case 0:
                break;
            case 1:
                continue;
            default:
                LOG("get_mapped_segment_range returned error: %d", r);
                goto out;
        }
        if(vmsize)
        {
            if(vmbase < vmlowest)
                vmlowest = vmbase;
            if(vmbase + vmsize > vmhighest)
                vmhighest = vmbase + vmsize;
        }
        if(!size)
        {
            continue;
        }
        uint64_t off = fileoff + size;
        if(off > flen || off < fileoff)
        {
            LOG("Bad segment: 0x%llx", (unsigned long long)((uintptr_t)cmd - ufile));
            goto out;
        }

        uint64_t start = vmaddr;
        if(start < lowest)
        {
            lowest = start;
        }
        uint64_t end = start + size;
        if(end > highest)
        {
            highest = end;
        }
    }
    if(highest < lowest)
    {
        LOG("Bad memory layout, lowest: 0x%llx, highest: 0x%llx", (unsigned long long)lowest, (unsigned long long)highest);
        goto out;
    }
    mlen = (size_t)(highest - lowest);
    if(fmax > 0 && mlen > fmax)
    {
        LOG("Filemap size is too large: max 0x%zx, have 0x%zx", fmax, mlen);
        goto out;
    }
    if(smax > 0 && (vmhighest - vmlowest) > smax)
    {
        LOG("Runtime size is too large: max 0x%zx, have 0x%zx", smax, (size_t)(vmhighest - vmlowest));
        goto out;
    }
    mem = malloc(mlen);
    if(!mem)
    {
        LOG("malloc: %s", strerror(errno));
        goto out;
    }
    memset(mem, 0, mlen);
    for(mach_lc_t *cmd = lcs, *end = (mach_lc_t*)((uintptr_t)cmd + sizeofcmds); cmd < end; cmd = (mach_lc_t*)((uintptr_t)cmd + cmd->cmdsize))
    {
        uint64_t vmaddr  = 0,
                 fileoff = 0,
                 size    = 0;
        r = get_mapped_segment_range(cmd, use_sections, &vmaddr, &fileoff, &size, NULL, NULL);
        switch(r)
        {
            case 0:
                break;
            case 1:
                continue;
            default:
                LOG("get_mapped_segment_range returned error: %d", r);
                goto out;
        }
        if(!size)
        {
            continue;
        }
        if (!strcmp(((mach_seg64_t*)cmd)->segname, "__TEXT")) {
            r = text_fixup_pass((void*)((uintptr_t)mem + (vmaddr - lowest)), (void*)(ufile + fileoff), size, vmaddr);
            if (r) {
                LOG("text fixup failed!");
                goto out;
            }
        }
        else
            memcpy((void*)((uintptr_t)mem + (vmaddr - lowest)), (void*)(ufile + fileoff), size);
    }

    outfile = strcmp(argv[aoff + 1], "-") == 0 ? stdout : fopen(argv[aoff + 1], oflags);
    if(!outfile)
    {
        LOG("fopen(%s): %s", argv[aoff + 1], strerror(errno));
        goto out;
    }

    if(mode == Mode_Binary)
    {
        if(fwrite(mem, 1, mlen, outfile) != mlen)
        {
            LOG("fwrite: %s", strerror(errno));
            goto out;
        }
    }
    else
    {
        r = 0;
        if(mode == Mode_NamedArray)
        {
            r = fprintf(outfile, "unsigned char %s[] = {\n", aname);
        }
        if(r >= 0)
        {
            uint8_t *u = mem;
            for(size_t i = 0; i < mlen; ++i)
            {
                r = fprintf(outfile, "%s0x%02x,%c", i % 0x10 == 0 ? "    " : "", u[i], (i % 0x10 == 0xf || i == mlen - 1) ? '\n' : ' ');
                if(r < 0) break;
            }
        }
        if(mode == Mode_NamedArray && r >= 0)
        {
            r = fprintf(outfile, "};\n");
        }
        if(r < 0)
        {
            LOG("fprintf: %s", strerror(errno));
            goto out;
        }
    }
    fflush(outfile); // In case of stdout

    LOG("Done, base address: 0x%llx", (unsigned long long)lowest);
    retval = 0;

out:;
    if(outfile && outfile != stdout) fclose(outfile);
    if(mem) free(mem);
    if(file) free(file);
    if(infile && infile != stdin) fclose(infile);
    return retval;
}
