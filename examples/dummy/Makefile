CC      ?= gcc
CFLAGS  ?= -O0 -g
TARGET   = dummy

all: $(TARGET)

$(TARGET): dummy.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET)

.PHONY: all clean
