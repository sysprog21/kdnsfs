#!/usr/bin/env bash
# Resolve a clang-format binary pinned to major version 20. The style is
# version-sensitive (newer releases differ on compound-literal spacing), so
# both 'make indent' and .ci/check-format.sh format against exactly v20.
# Probe $CLANG_FORMAT first, then common binary names; print the match on
# stdout. Exit 1 if no version-20 clang-format is installed.
set -u

want=20
for cand in "${CLANG_FORMAT:-}" clang-format-20 clang-format; do
    [ -n "$cand" ] || continue
    command -v "$cand" >/dev/null 2>&1 || continue
    major=$("$cand" --version 2>/dev/null | grep -oE '[0-9]+' | head -1)
    if [ "$major" = "$want" ]; then
        echo "$cand"
        exit 0
    fi
done

echo "error: clang-format $want not found (install it or set CLANG_FORMAT)" >&2
exit 1
