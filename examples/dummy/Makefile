CC      ?= gcc
CFLAGS  ?= -O0 -g
TARGET   = dummy
UNAME   := $(shell uname -s)

all: $(TARGET)

# heapscope reads /proc/<pid>/mem, so the target has to be a Linux ELF. On macOS
# this rule would happily build a Mach-O binary instead, and the mistake only
# surfaces later as a confusing failure to find the heap. Refuse it here, where
# the message can say what to do about it. `make clean` still works either way.
$(TARGET): dummy.c
ifeq ($(UNAME),Linux)
	$(CC) $(CFLAGS) -o $@ $<
else
	@echo "error: $(TARGET) is a Linux-only target, and this is $(UNAME)." >&2
	@echo "       heapscope reads /proc/<pid>/mem, so a Mach-O binary is no use." >&2
	@echo "       Build it on Linux, or inside a Linux container. make is not" >&2
	@echo "       needed for a single file, gcc is enough:" >&2
	@echo "         gcc -O0 -g -o $(TARGET) $(TARGET).c" >&2
	@exit 1
endif

clean:
	rm -rf $(TARGET) $(TARGET).dSYM

.PHONY: all clean
