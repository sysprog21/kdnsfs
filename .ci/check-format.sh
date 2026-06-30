#!/usr/bin/env bash
# Diff every tracked C source against clang-format-20 output. The binary is
# resolved by .ci/clang-format.sh (version-pinned; see Makefile 'indent').
# Override the binary with CLANG_FORMAT=<path>.
set -u -o pipefail

CLANG_FORMAT=$("$(dirname "$0")/clang-format.sh") || exit 1

ret=0
while IFS= read -r -d '' file; do
    expected=$(mktemp)
    "$CLANG_FORMAT" "$file" >"$expected" 2>/dev/null
    if ! diff -u -p --label="$file" --label="expected coding style" "$file" "$expected"; then
        ret=1
    fi
    rm -f "$expected"
done < <(git ls-files -z -- '*.c' '*.h')

exit $ret
