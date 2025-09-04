ROOT != pwd
PLATFORM_SRC = $(wildcard patches/*)
SRC = $(wildcard src/*)
OBJDIR = $(ROOT)/obj
PLATFORM_OBJS = $(patsubst patches/%,$(OBJDIR)/patches/%,$(PLATFORM_SRC:.c=.o))
OBJS = $(patsubst src/%,$(OBJDIR)/%,$(SRC:.c=.o)) $(PLATFORM_OBJS)
PLOOSHFINDER = plooshfinder/libplooshfinder.a
INCLDIRS = -I./include -I./plooshfinder/include

LDFLAGS ?=
LDFLAGS += -L./plooshfinder
CFLAGS ?= -O2 -g -Wall -Wextra -Wno-unused-parameter -Wno-unused-variable
CC_FOR_BUILD = cc
CC := clang
LIBS = -lplooshfinder

export OBJDIR CC CFLAGS

.PHONY: $(PLOOSHFINDER) all

all: submodules dirs tools/vmacho $(PLOOSHFINDER) $(OBJS) ibootpatch3

submodules:
	@git submodule update --init --remote --recursive || true

dirs:
	@mkdir -p $(OBJDIR)
	@mkdir -p $(OBJDIR)/patches

clean:
	@rm -rf ibootpatch3 obj tools/vmacho
	@$(MAKE) -C plooshfinder clean
	@$(MAKE) -C shellcode clean

ibootpatch3: $(OBJS) $(PLOOSHFINDER) shellcode
	$(CC) $(CFLAGS) $(LDFLAGS) $(LIBS) $(INCLDIRS) $(OBJS) $(OBJDIR)/payload.bin.o -o $@

$(OBJDIR)/%.o: src/%.c
	$(CC) $(CFLAGS) $(INCLDIRS) -c -o $@ $<

$(OBJDIR)/patches/%.o: patches/%.c
	$(CC) $(CFLAGS) $(INCLDIRS) -c -o $@ $<

shellcode:
	$(MAKE) -C shellcode all

tools/vmacho: tools/vmacho.c
	$(CC_FOR_BUILD) $(CFLAGS_FOR_BUILD) $(LDFLAGS_FOR_BUILD) -o $@ $<

$(PLOOSHFINDER):
	$(MAKE) -C plooshfinder all

.PHONY: all dirs shellcode clean
