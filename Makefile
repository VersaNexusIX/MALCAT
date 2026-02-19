CC      := gcc
ARCH    := $(shell uname -m)
TARGET  := malcat

CFLAGS  := -O2 -Wall -Wextra -Wno-unused-variable -Wno-unused-const-variable -Isrc -lm

ifeq ($(ARCH),aarch64)
    ASM_SRC  := asm/engine.s
    ASM_OBJ  := build/engine.o
    C_SRCS   := src/bridge.c src/main.c
    USE_ASM  := 1
else ifeq ($(ARCH),arm64)
    ASM_SRC  := asm/engine.s
    ASM_OBJ  := build/engine.o
    C_SRCS   := src/bridge.c src/main.c
    USE_ASM  := 1
else
    $(info [INFO] Not on ARM64 — using portable C stub)
    ASM_OBJ  :=
    C_SRCS   := src/engine_stub.c src/bridge.c src/main.c
    USE_ASM  := 0
endif

.PHONY: all clean run

all: build/. $(TARGET)

build/.:
	@mkdir -p build

ifdef USE_ASM
ifeq ($(USE_ASM),1)
$(ASM_OBJ): $(ASM_SRC)
	as -march=armv8-a+fp+simd -o $@ $<

$(TARGET): $(ASM_OBJ) $(C_SRCS)
	$(CC) $(CFLAGS) $(ASM_OBJ) $(C_SRCS) -o $@
else
$(TARGET): $(C_SRCS)
	$(CC) $(CFLAGS) $(C_SRCS) -o $@
endif
else
$(TARGET): $(C_SRCS)
	$(CC) $(CFLAGS) $(C_SRCS) -o $@
endif

run: all
	./$(TARGET)

clean:
	rm -rf build $(TARGET)
