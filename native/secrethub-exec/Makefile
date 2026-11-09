CC ?= cc
CFLAGS ?= -O2
CFLAGS += -std=c99 -Wall -Wextra -Werror
PREFIX ?= /usr/local
DESTDIR ?=

BIN = secrethub-exec

.PHONY: all test install clean

all: $(BIN)

$(BIN): secrethub-exec.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ secrethub-exec.c

test: $(BIN)
	sh test/run-tests.sh ./$(BIN)

install: $(BIN)
	mkdir -p $(DESTDIR)$(PREFIX)/bin
	cp $(BIN) $(DESTDIR)$(PREFIX)/bin/$(BIN)
	chmod 0755 $(DESTDIR)$(PREFIX)/bin/$(BIN)

clean:
	rm -f $(BIN)
