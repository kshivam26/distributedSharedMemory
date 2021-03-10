CC = gcc
CFLAGS += -g -O2 -Wall
LDFLAGS +=  -pthread

SRC_FILES = $(wildcard *.c)

EXE_FILES = $(SRC_FILES:.c=)

all: $(EXE_FILES)
%:%.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<

clean:
	rm -f $(EXE_FILES)

.PHONY: all clean

