.section __TEXT,__text
.global _entry
.globl _V
.globl _get_chipid
.globl _get_boardid
.balign 16

#define ESR_EC_DABORT_EL0 0x24
#define ESR_EC_DABORT_EL1 0x25

_entry:
    ldr     w8, [x0,#0x118]
    and     w8, w8, #0xfc000000
    lsr     w8, w8, #0x1a
    //w8 is current esr_ec
    cmp     w8, #ESR_EC_DABORT_EL0
    b.eq     custom_handler
    cmp     w8, #ESR_EC_DABORT_EL1
    b.eq     custom_handler

    adr lr, #0 // gets patched by patcher to DATA_ABORT_PANIC_CALL
    ret

_get_boardid:
    b . // patched to iboot's get_boardid function

custom_handler:
    adr lr, #0 // gets patched by patcher to EXCEPTION_EL1_ERET
    b       _arm64_data_abort_exception

_get_chipid:
    b . // patched to iboot's get_chipid function

write_ttbr0:
    b _payload_init

// payload variables
_V:
    .quad 0x4141414141414140
