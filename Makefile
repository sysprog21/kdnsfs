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

$(PUBLISHER): Makefile
	mkdir -p $(PUBLISHER_STORE)
	printf '%s\n' '#!/bin/sh' \
		'set -eu' \
		'root="$(PUBLISHER_STORE)"' \
		'case "$$1" in' \
		'put)' \
		'python3 - "$$root" "$$2" "$${3:-}" <<'"'"'PY'"'"'' \
		'import os, re, sys' \
		'def valid(label):' \
		'    if label == "index":' \
		'        return False' \
		'    if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label):' \
		'        return False' \
		'    d1 = label.find("-")' \
		'    d2 = label.find("-", d1 + 1) if d1 != -1 else -1' \
		'    if d1 >= 1 and label[0] == "e" and d2 != -1 and d2 != d1 + 1 and d2 + 1 < len(label):' \
		'        if int(label[d1 + 1:d2], 36) % 180 == 0:' \
		'            return False' \
		'    return True' \
		'root, label, hex_payload = sys.argv[1:]' \
		'if not valid(label):' \
		'    raise SystemExit(1)' \
		'path = os.path.join(root, label)' \
		'tmp = f"{path}.tmp"' \
		'with open(tmp, "wb") as f:' \
		'    f.write(bytes.fromhex(hex_payload))' \
		'    f.flush()' \
		'    os.fsync(f.fileno())' \
		'os.replace(tmp, path)' \
		'PY' \
		';;' \
		'del)' \
		'python3 - "$$root" "$$2" <<'"'"'PY'"'"'' \
		'import os, re, sys' \
		'def valid(label):' \
		'    if label == "index":' \
		'        return False' \
		'    if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label):' \
		'        return False' \
		'    d1 = label.find("-")' \
		'    d2 = label.find("-", d1 + 1) if d1 != -1 else -1' \
		'    if d1 >= 1 and label[0] == "e" and d2 != -1 and d2 != d1 + 1 and d2 + 1 < len(label):' \
		'        if int(label[d1 + 1:d2], 36) % 180 == 0:' \
		'            return False' \
		'    return True' \
		'root, label = sys.argv[1:]' \
		'if not valid(label):' \
		'    raise SystemExit(1)' \
		'try:' \
		'    os.unlink(os.path.join(root, label))' \
		'except FileNotFoundError:' \
		'    pass' \
		'PY' \
		';;' \
		'*)' \
		'exit 1' \
		';;' \
		'esac' > $@
	chmod +x $@

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
