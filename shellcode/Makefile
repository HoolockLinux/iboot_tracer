OS != uname -s
ifeq ($(OS),Darwin)
LD_FOR_TARGET != xcrun --find ld-classic
OTOOL = otool
else
LD_FOR_TARGET ?= cctools-ld
OTOOL         ?= llvm-otool
endif
CC_FOR_TARGET ?= clang -target aarch64-darwin-none
AS_FOR_TARGET ?= $(CC_FOR_TARGET)
HEADERS = $(wildcard src/*.h)
CFLAGS_FOR_TARGET ?= -std=gnu23 -fvisibility=hidden -fno-stack-protector -fno-exceptions -nostdlib -ffreestanding -mgeneral-regs-only -flto=full -Oz
ASFLAGS_FOR_TARGET ?= $(CFLAGS_FOR_TARGET)
LDFLAGS_FOR_TARGET ?= -Wl,-preload -Wl,-e,_entry -Wl,-order_file,sym_order.txt -flto=full -fvisibility=hidden --ld-path="$(LD_FOR_TARGET)"
OBJS = payload.o entry.o uart.o

PAYLOAD_SUPPORTED_SOCS ?= S8000 S8001 S8003 T8010 T8011 T8012 T8015

CFLAGS_FOR_TARGET += $(patsubst %,-DHAVE_SOC_%,$(PAYLOAD_SUPPORTED_SOCS))

export OTOOL

all: dirs $(OBJDIR)/payload.bin.o

dirs:
	@mkdir -p $(OBJDIR)
	@mkdir -p $(OBJDIR)/shellcode

$(OBJDIR)/shellcode/%.o: src/%.S
	$(AS_FOR_TARGET) $(ASFLAGS_FOR_TARGET) -c -o $@ $<

$(OBJDIR)/shellcode/%.o: src/%.c $(HEADERS)
	$(CC_FOR_TARGET) $(CFLAGS_FOR_TARGET) -c -o $@ $<

$(OBJDIR)/shellcode/entry.o: src/entry.S
	$(AS_FOR_TARGET) $(ASFLAGS_FOR_TARGET) -c -o $@ $<

payload.macho: $(patsubst %.o,$(OBJDIR)/shellcode/%.o, $(OBJS))
	$(CC_FOR_TARGET) $(CFLAGS_FOR_TARGET) $(LDFLAGS_FOR_TARGET) -o $@ $^
	./checkPayload.sh $@

payload.bin: payload.macho
	../tools/vmacho -fM 0x2000 $^ $@

payload.bin.c: payload.bin
	echo '#include <stdint.h>' > $@
	xxd -iC $^ | sed -e 's/unsigned int/uint32_t/' -e 's/unsigned char/uint8_t/' >> $@

$(OBJDIR)/payload.bin.o: payload.bin.c
	$(CC) $(CFLAGS) -c -o $@ $^

clean:
	rm -f payload.bin.c payload.bin payload.macho

.PHONY: all dirs clean
