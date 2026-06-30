#!/usr/bin/env bash

# Every tracked text source must end with a trailing newline.

set -e -u -o pipefail

ret=0
while IFS= read -rd '' f; do
    if file --mime-encoding "$f" | grep -qv binary; then
        if [ -n "$(tail -c1 < "$f")" ]; then
            echo "Warning: No newline at end of file $f"
            ret=1
        fi
    fi
done < <(git ls-files -z -- '*.c' '*.h' '*.sh')

exit $ret
