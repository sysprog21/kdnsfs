KDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
MODDIR := $(PWD)/src
BUILD_DIR ?= /tmp/kdnsfs-build
.DEFAULT_GOAL := all
DNS_SERVER := $(BUILD_DIR)/dns-server
PUBLISHER := $(BUILD_DIR)/publisher
PUBLISHER_STORE := $(BUILD_DIR)/publisher-store
HOSTCC ?= cc
HOSTCFLAGS ?= -Wall -Wextra -Werror -g

C_SOURCES := $(wildcard src/*.c src/*.h tests/*.c tools/*.c)
SH_SOURCES := $(wildcard tests/*.sh)

.PHONY: all modules publisher dns-server clean check indent

all: modules publisher

modules:
	mkdir -p $(BUILD_DIR)
	$(MAKE) -C $(KDIR) M=$(MODDIR) MO=$(BUILD_DIR) modules

publisher: $(PUBLISHER)
	mkdir -p $(PUBLISHER_STORE)

$(PUBLISHER): tools/publisher.c Makefile
	mkdir -p $(PUBLISHER_STORE)
	$(HOSTCC) $(HOSTCFLAGS) -DDNSFS_PUBLISHER_STORE=\"$(PUBLISHER_STORE)\" -o $@ $<

dns-server: $(DNS_SERVER)

$(DNS_SERVER): tests/dns-server.c
	mkdir -p $(BUILD_DIR)
	$(HOSTCC) $(HOSTCFLAGS) -o $@ $<

clean:
	mkdir -p $(BUILD_DIR)
	$(MAKE) -C $(KDIR) M=$(MODDIR) MO=$(BUILD_DIR) clean
	rm -f $(DNS_SERVER) $(PUBLISHER)

# Full-coverage suite: build, userspace parser fuzz, mount, behavior, dmesg.
# Linux-only; the script rejects non-Linux hosts. Run it inside the Lima VM.
check:
	./tests/driver.sh

# Format C sources (clang-format v20, .clang-format config) and shell.
# .ci/clang-format.sh auto-detects the v20 binary by name or --version; the
# version is fixed because newer clang-format differs on compound-literal
# spacing, and .ci/check-format.sh enforces the same in CI.
indent:
	CF=$$(.ci/clang-format.sh) && $$CF -i --style=file $(C_SOURCES)
	shfmt -i 4 -fn -w $(SH_SOURCES)
