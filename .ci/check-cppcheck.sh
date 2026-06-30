#!/usr/bin/env bash

# Static analysis on the parser only. parser.c is the one TU that compiles in
# userspace (the __KERNEL__ shim), so cppcheck sees a complete translation
# unit; main.c/dns.c are pure kernel and would only yield missing-header noise.

set -e -u -o pipefail

timeout 120 cppcheck \
    -Isrc \
    --platform=unix64 \
    --enable=warning \
    --max-configs=1 --error-exitcode=1 --inline-suppr \
    --suppress=checkersReport --suppress=unmatchedSuppression \
    --suppress=missingIncludeSystem --suppress=noValidConfiguration \
    --suppress=normalCheckLevelMaxBranches \
    --suppress=preprocessorErrorDirective \
    -D_GNU_SOURCE -D__linux__ \
    src/parser.c
