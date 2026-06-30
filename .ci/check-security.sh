#!/usr/bin/env bash

# Reject unsafe libc functions, hardcoded secrets, and hardening opt-outs in
# the kernel module sources -- the trust boundary that parses untrusted DNS
# wire data. Comment lines are ignored.

set -u -o pipefail

failed=0

banned='(^|[^[:alnum:]_])(gets|sprintf|vsprintf|strcpy|stpcpy|strcat|atoi|atol|atoll|atof|mktemp|tmpnam|tempnam)[[:space:]]*\('
secrets='(password|secret|api_key|private_key|token)[[:space:]]*=[[:space:]]*"[^"]+'
dangerous_pp='#[[:space:]]*(undef|define)[[:space:]]+((_FORTIFY_SOURCE[[:space:]]+0)|(__SSP__))'
comment_only='^[[:space:]]*(//|/\*|\*|\*/)'

while IFS= read -r -d '' f; do
    code=$(grep -vE "$comment_only" "$f")

    if echo "$code" | grep -qE "$banned"; then
        echo "Banned function in $f:"
        grep -nE "$banned" "$f" | grep -vE "$comment_only"
        failed=1
    fi
    if echo "$code" | grep -iqE "$secrets"; then
        echo "Possible hardcoded secret in $f:"
        grep -inE "$secrets" "$f" | grep -vE "$comment_only"
        failed=1
    fi
    if echo "$code" | grep -qE "$dangerous_pp"; then
        echo "Dangerous preprocessor directive in $f:"
        grep -nE "$dangerous_pp" "$f" | grep -vE "$comment_only"
        failed=1
    fi
done < <(git ls-files -z -- 'src/*.c' 'src/*.h')

if [ $failed -eq 0 ]; then
    echo "Security checks passed."
fi

exit $failed
