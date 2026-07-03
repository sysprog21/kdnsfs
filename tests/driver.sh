#!/bin/sh
set -eu

if [ "$(uname -s)" != "Linux" ]; then
    echo "tests/driver.sh must run inside Linux" >&2
    exit 1
fi

repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
mnt=${TMPDIR:-/tmp}/dnsfs-test.$$
build_dir=${BUILD_DIR:-/tmp/kdnsfs-build}
cc=${CC:-cc}
dns_pid=
dns_pids=
dns_port=$((20000 + ($$ % 20000)))
dns_tcp_port=$((40000 + ($$ % 10000)))
dns_nx_port=$((30000 + ($$ % 10000)))
dns_expire_port=$((45000 + ($$ % 5000)))
dns_async_port=$((44000 + ($$ % 5000)))
dns_ttl0_port=$((43000 + ($$ % 5000)))
dns_nx_expire_port=$((25000 + ($$ % 5000)))
dns_parallel_port=$((35000 + ($$ % 5000)))
dns_eviction_port=$((39000 + ($$ % 5000)))
dns_reclaim_port=$((31000 + ($$ % 5000)))
dns_rcode_port=$((28000 + ($$ % 5000)))
dns_bad_txid_port=$((27000 + ($$ % 5000)))
dns_failover_port=$((26000 + ($$ % 5000)))
dns_bad_rdata_port=$((24000 + ($$ % 5000)))
dns_storage_port=$((23000 + ($$ % 5000)))
dns_bad_index_port=$((22000 + ($$ % 5000)))
dns_publisher_port=$((29000 + ($$ % 5000)))
dns_multi_port=$((21000 + ($$ % 5000)))
dns_signal_port=$((46000 + ($$ % 3000)))
dns_count=${TMPDIR:-/tmp}/dnsfs-count.$$
parallel_dir=${TMPDIR:-/tmp}/dnsfs-parallel.$$
storage_out=${TMPDIR:-/tmp}/dnsfs-storage.$$
publisher_dir=${TMPDIR:-/tmp}/dnsfs-publisher.$$
publisher=${TMPDIR:-/tmp}/dnsfs-publisher.$$
storage_entries="big
private
empty
sub
huge
writable
specialmode
badmode
badmeta
badepoch
badcrc
badfilecrc
shortchunk
badchunktext
badchunkb64
missing
epochflip
pin"
# Default (no args/env) runs light and fast: incremental build, small load loop.
# THOROUGH=1 restores the heavy pass (clean rebuild, 1M fuzz, 100x load loop);
# FUZZ_RUNS / LOAD_ITERS still override either mode individually.
thorough=${THOROUGH:-0}
if [ "$thorough" = 1 ]; then
    fuzz_runs=${FUZZ_RUNS:-1000000}
    load_iters=${LOAD_ITERS:-100}
else
    fuzz_runs=${FUZZ_RUNS:-0}
    load_iters=${LOAD_ITERS:-5}
fi

log()
{
    echo ">> $*" >&2
}

# Compile a userspace helper and fail loudly if the compiler produced nothing (a
# silent no-output cc otherwise surfaces as a confusing "not found" later).
build_helper()
{
    out=$1
    shift
    log "compile ${out##*/}"
    "$cc" "$@" -o "$out"
    if [ ! -x "$out" ]; then
        echo "build failed: '$cc' did not produce $out" >&2
        echo "  cc resolves to: $(command -v "$cc" 2>/dev/null || echo MISSING)" >&2
        echo "  retry with a known-good compiler, e.g. CC=gcc $0" >&2
        exit 1
    fi
}

cleanup()
{
    set +e
    sudo umount "$mnt" 2>/dev/null
    sudo rmmod dnsfs 2>/dev/null
    kill $dns_pids 2>/dev/null
    rm -f "$dns_count"
    rm -f "$storage_out"
    rm -f /tmp/dnsfs-fuzz-parser /tmp/dnsfs-mount-no-source /tmp/dnsfs-check-d-type /tmp/dnsfs-dns-server
    rm -f "$publisher"
    rm -rf "$parallel_dir"
    sudo rm -rf "$publisher_dir"
    rmdir "$mnt" 2>/dev/null
}
trap cleanup EXIT INT TERM

wire_queries()
{
    if [ ! -r /proc/fs/dnsfs/wire_queries ]; then
        echo "missing /proc/fs/dnsfs/wire_queries" >&2
        exit 1
    fi
    cat /proc/fs/dnsfs/wire_queries
}

record_refreshes()
{
    if [ ! -r /proc/fs/dnsfs/record_refreshes ]; then
        echo "missing /proc/fs/dnsfs/record_refreshes" >&2
        exit 1
    fi
    cat /proc/fs/dnsfs/record_refreshes
}

drop_dns_pid()
{
    drop=$1
    keep=

    for pid in $dns_pids; do
        if [ "$pid" != "$drop" ]; then
            keep="$keep $pid"
        fi
    done
    dns_pids=$keep
}

expect_delta()
{
    before=$1
    after=$2
    want=$3
    context=$4
    if [ "$((after - before))" != "$want" ]; then
        echo "unexpected query delta ($context): $((after - before)), want $want" >&2
        exit 1
    fi
}

expect_delta_between()
{
    before=$1
    after=$2
    min=$3
    max=$4
    context=$5
    delta=$((after - before))

    if [ "$delta" -lt "$min" ] || [ "$delta" -gt "$max" ]; then
        echo "unexpected query delta ($context): $delta, want $min..$max" >&2
        exit 1
    fi
}

expect_equal()
{
    got=$1
    want=$2
    context=$3

    if [ "$got" != "$want" ]; then
        echo "unexpected value ($context): $got, want $want" >&2
        exit 1
    fi
}

expect_not_exists()
{
    path=$1
    context=$2

    if [ -e "$path" ]; then
        echo "unexpected path exists ($context): $path" >&2
        exit 1
    fi
}

expect_dns_count()
{
    want=$1
    context=$2

    if [ ! -r "$dns_count" ]; then
        echo "missing DNS query count ($context)" >&2
        exit 1
    fi
    got=$(cat "$dns_count")
    if [ "$got" != "$want" ]; then
        echo "unexpected DNS query count ($context): $got, want $want" >&2
        exit 1
    fi
}

expect_open_errno()
{
    python3 - "$1" "$2" <<'PY'
import errno
import os
import sys

path = sys.argv[1]
want = getattr(errno, sys.argv[2])
try:
    fd = os.open(path, os.O_RDONLY)
except OSError as exc:
    if exc.errno == want:
        raise SystemExit(0)
    raise SystemExit(f"{path}: got errno {exc.errno}, expected {want}")
else:
    os.close(fd)
    raise SystemExit(f"{path}: open unexpectedly succeeded")
PY
}

expect_create_errno()
{
    python3 - "$@" <<'PY'
import errno
import os
import sys

path = sys.argv[1]
wants = {getattr(errno, name) for name in sys.argv[2:]}
try:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
except OSError as exc:
    if exc.errno in wants:
        raise SystemExit(0)
    raise SystemExit(f"{path}: got errno {exc.errno}, expected one of {sorted(wants)}")
else:
    os.close(fd)
    os.unlink(path)
    raise SystemExit(f"{path}: create unexpectedly succeeded")
PY
}

expect_readlink_errno()
{
    python3 - "$1" "$2" <<'PY'
import errno
import os
import sys

path = sys.argv[1]
want = getattr(errno, sys.argv[2])
try:
    os.readlink(path)
except OSError as exc:
    if exc.errno == want:
        raise SystemExit(0)
    raise SystemExit(f"{path}: got errno {exc.errno}, expected {want}")
else:
    raise SystemExit(f"{path}: readlink unexpectedly succeeded")
PY
}

expect_read_errno()
{
    python3 - "$1" "$2" <<'PY'
import errno
import os
import sys

path = sys.argv[1]
want = getattr(errno, sys.argv[2])
try:
    with open(path, "rb", buffering=0) as f:
        f.read()
except OSError as exc:
    if exc.errno == want:
        raise SystemExit(0)
    raise SystemExit(f"{path}: got errno {exc.errno}, expected {want}")
else:
    raise SystemExit(f"{path}: read unexpectedly succeeded")
PY
}

expect_list_errno()
{
    python3 - "$1" "$2" <<'PY'
import errno
import os
import sys

path = sys.argv[1]
want = getattr(errno, sys.argv[2])
try:
    os.listdir(path)
except OSError as exc:
    if exc.errno == want:
        raise SystemExit(0)
    raise SystemExit(f"{path}: got errno {exc.errno}, expected {want}")
else:
    raise SystemExit(f"{path}: list unexpectedly succeeded")
PY
}

expect_file_content()
{
    path=$1
    want=$2
    context=$3
    got=$(cat "$path")

    if [ "$got" != "$want" ]; then
        echo "unexpected file content ($context): $path" >&2
        printf 'got:\n%s\nwant:\n%s\n' "$got" "$want" >&2
        exit 1
    fi
}

expect_storage_payload()
{
    python3 - "$1" "$2" <<'PY'
import sys

path = sys.argv[1]
context = sys.argv[2]
want = bytes(i % 251 for i in range(1980))
got = open(path, "rb").read()
if got != want:
    raise SystemExit(f"storage payload mismatch: {context}")
PY
}

expect_storage_stat()
{
    python3 - "$1" "$2" "$3" "$4" <<'PY'
import os
import stat
import sys

path = sys.argv[1]
want_size = int(sys.argv[2])
want_mode = int(sys.argv[3], 8)
context = sys.argv[4]
st = os.stat(path)
if st.st_size != want_size:
    raise SystemExit(f"unexpected storage size ({context}): {st.st_size}")
if stat.S_IMODE(st.st_mode) != want_mode:
    raise SystemExit(f"unexpected storage mode ({context}): {stat.S_IMODE(st.st_mode):o}")
if int(st.st_mtime) != 1700000000:
    raise SystemExit(f"unexpected storage mtime ({context}): {int(st.st_mtime)}")
PY
}

expect_cached_record()
{
    record=$1
    want=$2
    count=$3
    context=$4
    got=$(cat "$mnt/$record")

    if [ "$got" != "$want" ]; then
        echo "unexpected $record output ($context)" >&2
        printf 'got:\n%s\nwant:\n%s\n' "$got" "$want" >&2
        exit 1
    fi
    got=$(cat "$mnt/$record")
    if [ "$got" != "$want" ]; then
        echo "unexpected cached $record output ($context)" >&2
        printf 'got:\n%s\nwant:\n%s\n' "$got" "$want" >&2
        exit 1
    fi
    expect_dns_count "$count" "$context"
}

# Two small reads of one open file, asserting how many page-cache refreshes they
# trigger. The open refreshes once; while the cache stays fresh neither read
# refreshes again, so a cacheable answer advances the counter by 1. A
# non-cacheable (ttl=0) answer forces a refresh on every read, the pre-fastpath
# behavior, so its expected delta is 3.
expect_small_read_refresh()
{
    path=$1
    context=$2
    expected=$3

    refresh_before=$(record_refreshes)
    python3 - "$path" <<'PY'
import os
import sys

with open(sys.argv[1], "rb", buffering=0) as f:
    if os.read(f.fileno(), 4) != b"dnsf":
        raise SystemExit("first small read mismatch")
    if os.read(f.fileno(), 4) != b"s li":
        raise SystemExit("second small read mismatch")
PY
    refresh_after=$(record_refreshes)
    expect_delta "$refresh_before" "$refresh_after" "$expected" "$context"
}

expect_multi_record()
{
    flag=$1
    record=$2
    context=$3
    want=$4

    start_dns "$dns_multi_port" "$flag" --count-file "$dns_count"
    rm -f "$dns_count"
    mount_dnsfs -o nameserver=127.0.0.1,port="$dns_multi_port",timeout=250,retries=1 example.org
    got=$(cat "$mnt/$record")
    if [ "$got" != "$want" ]; then
        echo "unexpected $record output ($context)" >&2
        printf 'got:\n%s\nwant:\n%s\n' "$got" "$want" >&2
        exit 1
    fi
    expect_dns_count 1 "$context"
    unmount_dnsfs
    stop_dns
}

wait_dns()
{
    python3 - "$1" "${2:-127.0.0.1}" <<'PY'
import socket
import sys
import time

port = int(sys.argv[1])
host = sys.argv[2]
deadline = time.time() + 5
while time.time() < deadline:
    try:
        with socket.create_connection((host, port), timeout=0.1):
            raise SystemExit(0)
    except OSError:
        time.sleep(0.02)
raise SystemExit(f"DNS test server not ready on {host}:{port}")
PY
}

start_dns()
{
    start_dns_port=$1
    shift
    log "dns server :$start_dns_port $*"
    /tmp/dnsfs-dns-server "$start_dns_port" "$@" &
    dns_pid=$!
    dns_pids="$dns_pids $dns_pid"
    wait_dns "$start_dns_port"
}

stop_dns()
{
    kill "$dns_pid"
    drop_dns_pid "$dns_pid"
    dns_pid=
}

mount_dnsfs()
{
    log "mount $*"
    sudo insmod "$build_dir/dnsfs.ko"
    sudo mount -t dnsfs "$@" "$mnt"
}

expect_mount_fail()
{
    context=$1
    shift
    if sudo mount -t dnsfs "$@" "$mnt" 2>/dev/null; then
        echo "$context unexpectedly succeeded" >&2
        exit 1
    fi
}

unmount_dnsfs()
{
    sudo umount "$mnt"
    sudo rmmod dnsfs
}

# Build the module + userspace helpers, run the parser self-test, and prep the
# mount point. THOROUGH forces a clean rebuild; otherwise the build is
# incremental.
prepare()
{
    cd "$repo"

    log "build module (thorough=$thorough)"
    if [ "$thorough" = 1 ]; then
        make clean
    fi
    make
    expect_equal "$(modinfo -F license "$build_dir/dnsfs.ko")" "GPL" "module license"
    expect_equal "$(modinfo -F author "$build_dir/dnsfs.ko")" "National Cheng Kung University, Taiwan" "module author"
    build_helper /tmp/dnsfs-fuzz-parser -Wall -Wextra -Werror \
        -fsanitize=address,undefined -g tests/test-parser.c src/parser.c
    build_helper /tmp/dnsfs-mount-no-source -Wall -Wextra -Werror -g \
        tools/dns-mount.c
    build_helper /tmp/dnsfs-check-d-type -Wall -Wextra -Werror -g \
        tools/check-d-type.c
    build_helper /tmp/dnsfs-dns-server -Wall -Wextra -Werror -g \
        tests/dns-server.c
    # Redirect stdin from /dev/null: the harness reads stdin first (corpus
    # mode), so without this it blocks waiting for EOF on an interactive
    # terminal.
    log "parser self-test"
    /tmp/dnsfs-fuzz-parser </dev/null
    if [ "$fuzz_runs" -gt 0 ]; then
        log "parser fuzz ($fuzz_runs runs)"
        /tmp/dnsfs-fuzz-parser "$fuzz_runs" </dev/null
    fi

    mkdir "$mnt"
    sudo dmesg -C 2>/dev/null || true
}

# Live records cache + presentation for every record type, plus the proc
# counter.
test_live_records()
{
    start_dns "$dns_port" --count-file "$dns_count" --expect-do=1

    mount_dnsfs -o "nameserver=127.0.0.2;127.0.0.1",port="$dns_port",timeout=250,retries=1,dnssec example.org
    wire_before=$(wire_queries)
    expect_cached_record TXT "dnsfs live" 1 "TXT cache"
    expect_small_read_refresh "$mnt/TXT" "TXT small-read cache" 1
    expect_cached_record A "192.0.2.1" 2 "A cache"
    expect_cached_record AAAA "2001:db8::1" 3 "AAAA cache"
    expect_cached_record MX "10 mail.example.org." 4 "MX cache"
    expect_cached_record NS "ns.example.org." 5 "NS cache"
    expect_cached_record SOA "ns.example.org. hostmaster.example.org. 1 3600 600 604800 60" 6 "SOA cache"
    expect_cached_record DS "12345 8 2 DEADBEEF" 7 "DS cache"
    expect_cached_record DNSKEY "257 3 8 3q2+7w==" 8 "DNSKEY cache"
    expect_equal "$(readlink "$mnt/CNAME")" "target" "live CNAME readlink"
    expect_file_content "$mnt/CNAME/TXT" "dnsfs live" "CNAME target"
    expect_dns_count 10 "CNAME target"
    wire_after=$(wire_queries)
    expect_delta "$wire_before" "$wire_after" 20 proc-counter
    unmount_dnsfs
    stop_dns
}

# Eight concurrent cold reads collapse to a single resolver query (coalescing).
test_parallel_herd()
{
    start_dns "$dns_parallel_port" --count-file "$dns_count" --expect-do=0
    rm -f "$dns_count"
    mkdir "$parallel_dir"
    mount_dnsfs -o nameserver=127.0.0.1,port="$dns_parallel_port",timeout=250,retries=1 example.org
    i=0
    cat_pids=
    while [ "$i" -lt 8 ]; do
        i=$((i + 1))
        cat "$mnt/TXT" >"$parallel_dir/$i" &
        cat_pids="$cat_pids $!"
    done
    for pid in $cat_pids; do
        wait "$pid"
    done
    i=0
    while [ "$i" -lt 8 ]; do
        i=$((i + 1))
        expect_file_content "$parallel_dir/$i" "dnsfs live" "parallel herd $i"
    done
    expect_dns_count 1 "parallel herd"
    i=0
    cat_pids=
    while [ "$i" -lt 8 ]; do
        i=$((i + 1))
        cat "$mnt/TXT" >"$parallel_dir/warm-$i" &
        cat_pids="$cat_pids $!"
    done
    for pid in $cat_pids; do
        wait "$pid"
    done
    i=0
    while [ "$i" -lt 8 ]; do
        i=$((i + 1))
        expect_file_content "$parallel_dir/warm-$i" "dnsfs live" "parallel cached $i"
    done
    expect_dns_count 1 "parallel cached"
    unmount_dnsfs
    stop_dns
    rm -rf "$parallel_dir"
}

# Filling past the cache cap evicts the oldest entry (re-query on next read).
test_cache_eviction()
{
    start_dns "$dns_eviction_port" --count-file "$dns_count"
    rm -f "$dns_count"
    mount_dnsfs -o nameserver=127.0.0.1,port="$dns_eviction_port",timeout=250,retries=1 example.org
    i=0
    while [ "$i" -lt 65 ]; do
        expect_file_content "$mnt/e$i/TXT" "dnsfs live" "cache fill $i"
        i=$((i + 1))
    done
    expect_dns_count 65 "cache fill"
    expect_file_content "$mnt/e0/TXT" "dnsfs live" "cache eviction"
    expect_dns_count 66 "cache eviction"
    unmount_dnsfs
    stop_dns
}

# drop_caches drops the DNS cache entry; the next read re-queries the resolver.
test_cache_reclaim()
{
    start_dns "$dns_reclaim_port" --count-file "$dns_count"
    rm -f "$dns_count"
    mount_dnsfs -o nameserver=127.0.0.1,port="$dns_reclaim_port",timeout=250,retries=1 example.org
    expect_file_content "$mnt/TXT" "dnsfs live" "cache reclaim first read"
    expect_dns_count 1 "cache reclaim fill"
    sudo sh -c 'echo 3 > /proc/sys/vm/drop_caches'
    expect_file_content "$mnt/TXT" "dnsfs live" "cache reclaim reread"
    expect_dns_count 2 "cache reclaim reread"
    unmount_dnsfs
    stop_dns
}

# Positive-TTL expiry + open-fd refresh. Slow (sleeps past a 1s TTL): THOROUGH
# only.
test_positive_ttl()
{
    [ "$thorough" = 1 ] || return 0
    start_dns "$dns_expire_port" --ttl1 --count-file "$dns_count"
    rm -f "$dns_count"
    mount_dnsfs -o nameserver=127.0.0.1,port="$dns_expire_port",timeout=250,retries=1 example.org
    expect_file_content "$mnt/TXT" "dnsfs live" "positive TTL first read"
    expect_file_content "$mnt/TXT" "dnsfs live" "positive TTL cached read"
    expect_dns_count 1 "positive TTL hit"
    sleep 2
    expect_file_content "$mnt/TXT" "dnsfs live" "positive TTL refresh"
    expect_dns_count 2 "positive TTL expiry"
    exec 3<"$mnt/TXT"
    got=$(cat <&3)
    if [ "$got" != "dnsfs live" ]; then
        echo "unexpected open fd read before TTL expiry" >&2
        printf 'got:\n%s\nwant:\ndnsfs live\n' "$got" >&2
        exit 1
    fi
    expect_dns_count 2 "open fd cache hit"
    sleep 2
    python3 - "$mnt/TXT" <<'PY'
import os
import sys

fd = 3
os.lseek(fd, 0, os.SEEK_SET)
data = os.read(fd, 1024).decode().strip()
if data != "dnsfs live":
    raise SystemExit(f"unexpected fd read: {data!r}")
PY
    expect_dns_count 3 "open fd TTL refresh"
    exec 3<&-
    unmount_dnsfs
    stop_dns
}

test_async_ttl_refresh()
{
    [ "$thorough" = 1 ] || return 0
    start_dns "$dns_async_port" --ttl1 --delay-ms=900 --count-file "$dns_count"
    rm -f "$dns_count"
    mount_dnsfs -o nameserver=127.0.0.1,port="$dns_async_port",timeout=1500,retries=1 example.org
    expect_file_content "$mnt/TXT" "dnsfs live" "async TTL first read"
    expect_dns_count 1 "async TTL fill"
    sleep 2
    python3 - "$mnt/TXT" <<'PY'
import pathlib
import sys
import time

start = time.monotonic()
got = pathlib.Path(sys.argv[1]).read_text().strip()
elapsed = time.monotonic() - start
if got != "dnsfs live":
    raise SystemExit(f"unexpected async TTL read: {got!r}")
if elapsed > 0.5:
    raise SystemExit(f"expired read blocked for refresh: {elapsed:.3f}s")
PY
    expect_dns_count 2 "async TTL background refresh"
    unmount_dnsfs
    stop_dns

    start_dns "$dns_ttl0_port" --ttl1 --ttl0-after=1 --count-file "$dns_count"
    rm -f "$dns_count"
    mount_dnsfs -o nameserver=127.0.0.1,port="$dns_ttl0_port",timeout=250,retries=1 example.org
    expect_file_content "$mnt/TXT" "dnsfs live" "async TTL0 first read"
    expect_dns_count 1 "async TTL0 fill"
    sleep 2
    expect_file_content "$mnt/TXT" "dnsfs live" "async TTL0 stale read"
    python3 - "$dns_count" <<'PY'
import pathlib
import sys
import time

path = pathlib.Path(sys.argv[1])
deadline = time.time() + 2
while time.time() < deadline:
    if path.exists() and int(path.read_text() or "0") >= 2:
        raise SystemExit(0)
    time.sleep(0.02)
raise SystemExit("background TTL0 refresh did not reach DNS")
PY
    before=$(cat "$dns_count")
    expect_file_content "$mnt/TXT" "dnsfs live" "async TTL0 recache"
    after=$(cat "$dns_count")
    if [ "$after" -le "$before" ]; then
        echo "TTL0 refresh left stale cache entry live" >&2
        exit 1
    fi
    unmount_dnsfs
    stop_dns

    start_dns "$dns_ttl0_port" --ttl0 --count-file "$dns_count"
    rm -f "$dns_count"
    mount_dnsfs -o nameserver=127.0.0.1,port="$dns_ttl0_port",timeout=250,retries=1 example.org
    expect_small_read_refresh "$mnt/TXT" "TTL0 small-read refresh" 3
    unmount_dnsfs
    stop_dns
}

# A signal must abort a read blocked on a slow resolver promptly, not wait out
# the whole query (E1). The resolver delays every answer 3s; a cat is
# interrupted ~0.3s in and must die from the signal well before that, proving
# the foreground waiter no longer falls into an uninterruptible wait after the
# signal.
test_signal_interrupt()
{
    start_dns "$dns_signal_port" --delay-ms=3000 --count-file "$dns_count"
    rm -f "$dns_count"
    mount_dnsfs -o nameserver=127.0.0.1,port="$dns_signal_port",timeout=5000,retries=1 example.org
    python3 - "$mnt/TXT" "$dns_count" <<'PY'
import pathlib
import signal
import subprocess
import sys
import time

path = sys.argv[1]
count_file = pathlib.Path(sys.argv[2])
proc = subprocess.Popen(["cat", path],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
# The fixture bumps the count before its 3s delay, so count>=1 proves the worker
# already sent the wire query and cat is parked in the interruptible wait -- a
# fixed sleep could race and signal cat before it ever blocks in the kernel.
deadline = time.monotonic() + 2.0
while time.monotonic() < deadline:
    try:
        if int(count_file.read_text().strip() or "0") >= 1:
            break
    except (FileNotFoundError, ValueError):
        pass
    time.sleep(0.01)
else:
    proc.kill()
    raise SystemExit("resolver never saw the query; cat never blocked")
start = time.monotonic()
proc.send_signal(signal.SIGINT)
try:
    proc.wait(timeout=2.0)
except subprocess.TimeoutExpired:
    proc.kill()
    raise SystemExit("interrupted read did not return (blocked >2s on the query)")
elapsed = time.monotonic() - start
if elapsed > 1.0:
    raise SystemExit(f"interrupted read returned slowly: {elapsed:.3f}s")
if proc.returncode != -signal.SIGINT:
    raise SystemExit(f"cat exit {proc.returncode}, expected SIGINT termination")
PY
    unmount_dnsfs
    stop_dns
}

# A truncated UDP response forces a TCP retry (exactly two transport queries).
test_tcp_fallback()
{
    start_dns "$dns_tcp_port" --truncate-udp --count-file "$dns_count"
    rm -f "$dns_count"
    mount_dnsfs -o nameserver=127.0.0.1,port="$dns_tcp_port",timeout=250,retries=1 example.org
    expect_file_content "$mnt/TXT" "dnsfs live" "TCP fallback"
    expect_dns_count 2 "TCP fallback"
    unmount_dnsfs
    stop_dns
}

# Multi-answer presentation: one line per RR for every multi-valued record type.
test_multi_record()
{
    expect_multi_record --multi-a A "multi-A presentation" "192.0.2.1
192.0.2.2"
    expect_multi_record --multi-aaaa AAAA "multi-AAAA presentation" "2001:db8::1
2001:db8::2"
    expect_multi_record --multi-mx MX "multi-MX presentation" "10 mail.example.org.
20 mail2.example.org."
    expect_multi_record --multi-ns NS "multi-NS presentation" "ns.example.org.
ns2.example.org."
    expect_multi_record --multi-ds DS "multi-DS presentation" "12345 8 2 DEADBEEF
12346 8 2 CAFEBABE"
    expect_multi_record --multi-dnskey DNSKEY "multi-DNSKEY presentation" "257 3 8 3q2+7w==
256 3 8 yv66vg=="
    expect_multi_record --multi-soa SOA "multi-SOA presentation" "ns.example.org. hostmaster.example.org. 1 3600 600 604800 60
ns2.example.org. hostmaster.example.org. 2 7200 1200 604800 60"
}

# DNS storage: listing, metadata, multi-chunk assembly, integrity, epoch retry.
test_storage()
{
    start_dns "$dns_storage_port" --storage --ttl1 --count-file "$dns_count"
    rm -f "$dns_count"
    mount_dnsfs -o nameserver=127.0.0.1,port="$dns_storage_port",timeout=250,retries=1,storage example.org
    python3 - "$mnt" "$storage_entries" <<'PY'
import os
import sys

names = set(os.listdir(sys.argv[1]))
for name in sys.argv[2].splitlines():
    if name not in names:
        raise SystemExit(f"missing storage listing entry: {name}")
PY
    DNSFS_GETDENTS_BUF=128 /tmp/dnsfs-check-d-type "$mnt" $storage_entries
    expect_dns_count 1 "storage readdir"
    expect_storage_stat "$mnt/big" 1980 444 "pre-open"
    expect_dns_count 2 "storage metadata stat"
    expect_open_errno "$mnt/absent" ENOENT
    expect_storage_stat "$mnt/private" 1980 400 "metadata mode"
    wire_before=$(cat "$dns_count")
    cat "$mnt/private" >"$storage_out"
    wire_after=$(cat "$dns_count")
    expect_delta "$wire_before" "$wire_after" 11 private-storage-chunks
    expect_storage_payload "$storage_out" "private metadata mode"
    wire_before=$(cat "$dns_count")
    expect_equal "$(wc -c <"$mnt/empty")" "0" "empty storage size"
    wire_after=$(cat "$dns_count")
    expect_delta "$wire_before" "$wire_after" 1 empty-storage-metadata
    for invalid_storage_case in \
        "huge EFBIG" \
        "writable EINVAL" \
        "specialmode EINVAL" \
        "badmode EINVAL" \
        "badmeta EINVAL" \
        "badepoch EINVAL"; do
        set -- $invalid_storage_case
        expect_open_errno "$mnt/$1" "$2"
    done
    wire_before=$(cat "$dns_count")
    cat "$mnt/big" >"$storage_out"
    wire_after=$(cat "$dns_count")
    expect_delta_between "$wire_before" "$wire_after" 11 12 storage-chunks
    expect_storage_payload "$storage_out" "initial read"
    cat "$mnt/BiG" >"$storage_out"
    expect_storage_payload "$storage_out" "mixed-case storage read"
    expect_storage_stat "$mnt/big" 1980 444 "after read"
    sudo sh -c 'echo 3 > /proc/sys/vm/drop_caches'
    cat "$mnt/big" >"$storage_out"
    expect_storage_payload "$storage_out" "after drop_caches"
    for bad_storage_read in badcrc badfilecrc shortchunk badchunktext badchunkb64 missing; do
        expect_read_errno "$mnt/$bad_storage_read" EIO
    done
    cat "$mnt/epochflip" >"$storage_out"
    expect_storage_payload "$storage_out" "after epoch retry"
    wire_before=$(cat "$dns_count")
    exec 4<"$mnt/pin"
    sleep 2
    cat <&4 >"$storage_out"
    exec 4<&-
    wire_after=$(cat "$dns_count")
    expect_delta "$wire_before" "$wire_after" 12 open-pinned-storage
    expect_storage_payload "$storage_out" "open-pinned metadata"
    python3 - "$mnt/sub" <<'PY'
import os
import sys

names = set(os.listdir(sys.argv[1]))
if "nested" not in names:
    raise SystemExit("missing nested storage listing entry")
PY
    cat "$mnt/sub/nested" >"$storage_out"
    expect_storage_payload "$storage_out" "nested storage file"
    cat "$mnt/Sub/NeStEd" >"$storage_out"
    expect_storage_payload "$storage_out" "mixed-case nested storage file"
    unmount_dnsfs
    stop_dns
}

# A duplicate index fails readdir EIO; an uppercase (malformed) index fails
# EINVAL.
test_storage_bad_index()
{
    start_dns "$dns_bad_index_port" --storage --bad-storage-index
    mount_dnsfs -o nameserver=127.0.0.1,port="$dns_bad_index_port",timeout=250,retries=1,storage example.org
    expect_list_errno "$mnt" EIO
    unmount_dnsfs
    stop_dns

    start_dns "$((dns_bad_index_port + 1))" --storage --malformed-storage-index
    mount_dnsfs -o nameserver=127.0.0.1,port="$((dns_bad_index_port + 1))",timeout=250,retries=1,storage example.org
    expect_list_errno "$mnt" EINVAL
    unmount_dnsfs
    stop_dns
}

test_storage_publisher()
{
    publisher_dir="$build_dir/publisher-store"
    sudo rm -rf "$publisher_dir"
    mkdir -p "$publisher_dir"
    cat >"$publisher" <<EOF
#!/bin/sh
set -eu
root='$publisher_dir'
case "\$1" in
put)
    python3 - "\$root" "\$2" "\${3:-}" <<'PY'
import os
import re
import sys

def valid(label):
    if label == "index":
        return False
    if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label):
        return False
    d1 = label.find("-")
    d2 = label.find("-", d1 + 1) if d1 != -1 else -1
    if d1 >= 1 and label[0] == "e" and d2 != -1 and d2 != d1 + 1 and d2 + 1 < len(label):
        if int(label[d1 + 1:d2], 36) % 180 == 0:
            return False
    return True

root, label, hex_payload = sys.argv[1:]
if not valid(label):
    raise SystemExit(1)
path = os.path.join(root, label)
tmp = f"{path}.tmp"
with open(tmp, "wb") as f:
    f.write(bytes.fromhex(hex_payload))
    f.flush()
    os.fsync(f.fileno())
os.replace(tmp, path)
PY
    ;;
del)
    python3 - "\$root" "\$2" <<'PY'
import os
import re
import sys

def valid(label):
    if label == "index":
        return False
    if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label):
        return False
    d1 = label.find("-")
    d2 = label.find("-", d1 + 1) if d1 != -1 else -1
    if d1 >= 1 and label[0] == "e" and d2 != -1 and d2 != d1 + 1 and d2 + 1 < len(label):
        if int(label[d1 + 1:d2], 36) % 180 == 0:
            return False
    return True

root, label = sys.argv[1:]
if not valid(label):
    raise SystemExit(1)
try:
    os.unlink(os.path.join(root, label))
except FileNotFoundError:
    pass
PY
    ;;
*)
    exit 1
    ;;
esac
EOF
    chmod +x "$publisher"
    start_dns "$dns_publisher_port" --serve-dir="$publisher_dir" --ttl1 --count-file "$dns_count"
    rm -f "$dns_count"
    python3 - "$dns_publisher_port" "$publisher_dir" <<'PY'
import os
import socket
import sys
import time

port = int(sys.argv[1])
root = sys.argv[2]

def put(label, data, want=b"OK\n"):
    with socket.create_connection(("127.0.0.1", port), timeout=2) as s:
        s.sendall(f"PUT {label} {len(data)}\n".encode() + data)
        got = s.recv(64)
    if got != want:
        raise SystemExit(f"PUT {label!r}: got {got!r}, want {want!r}")

def dns_txt(qname):
    msg = bytearray(b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00")
    for part in qname.split("."):
        if part:
            msg.append(len(part))
            msg.extend(part.encode())
    msg.extend(b"\x00\x00\x10\x00\x01")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(2)
        s.sendto(msg, ("127.0.0.1", port))
        resp = s.recv(4096)
    rcode = resp[3] & 0x0f
    if rcode == 3:
        return None
    if rcode:
        raise SystemExit(f"{qname}: rcode {rcode}")
    off = 12
    while resp[off]:
        off += resp[off] + 1
    off += 5
    off += 2 + 2 + 2 + 4
    rdlen = int.from_bytes(resp[off:off + 2], "big")
    off += 2
    rdata = resp[off:off + rdlen]
    return rdata[1:1 + rdata[0]].decode()

put("alpha", b"first")
epoch1 = dns_txt("alpha.example.org.").split()[4]
if dns_txt(f"{epoch1}-0-alpha.example.org.") is None:
    raise SystemExit("initial published chunk missing")
time.sleep(0.01)
put("alpha", b"second")
epoch2 = dns_txt("alpha.example.org.").split()[4]
if epoch1 == epoch2:
    raise SystemExit("publisher did not rotate epoch")
if dns_txt(f"{epoch1}-0-alpha.example.org.") is not None:
    raise SystemExit("old published chunk still reachable")
put("../bad", b"x", b"ERR EINVAL\n")
put("paged", bytes(i % 251 for i in range(9000)))
if open(os.path.join(root, "alpha"), "rb").read() != b"second":
    raise SystemExit("publisher overwrite did not persist")
if os.path.exists(os.path.join(root, "bad")):
    raise SystemExit("publisher accepted traversal name")
PY
    mount_dnsfs -o nameserver=127.0.0.1,port="$dns_publisher_port",timeout=250,retries=1,storage example.org
    rm -f "$dns_count"
    expect_create_errno "$mnt/readonly" EACCES EROFS
    wire_before=$(cat "$dns_count")
    dd if="$mnt/paged" of="$storage_out" bs=1 count=1 status=none
    wire_after=$(cat "$dns_count")
    expect_delta_between "$wire_before" "$wire_after" 20 32 "range-only storage first page"
    unmount_dnsfs

    # The generated publisher under BUILD_DIR handles writes for the local
    # validation workflow when explicitly selected.
    mount_dnsfs -o nameserver=127.0.0.1,publisher="$build_dir/publisher",port="$dns_publisher_port",timeout=250,retries=1,storage example.org
    sudo rm -f "$build_dir/publisher-store/defaultpub"
    printf 'default\n' | sudo tee "$mnt/defaultpub" >/dev/null
    expect_file_content "$build_dir/publisher-store/defaultpub" "default" "generated publisher put"
    sudo rm "$mnt/defaultpub"
    if [ -e "$build_dir/publisher-store/defaultpub" ]; then
        echo "generated publisher did not delete file" >&2
        exit 1
    fi
    unmount_dnsfs
    bad64=$(printf '%64s' '' | tr ' ' a)
    for bad_label in Bad a_b -bad bad- "$bad64" e-0-file index; do
        if "$build_dir/publisher" put "$bad_label" 78 2>/dev/null; then
            echo "generated publisher accepted invalid label: $bad_label" >&2
            exit 1
        fi
        if [ -e "$build_dir/publisher-store/$bad_label" ]; then
            echo "generated publisher persisted invalid label: $bad_label" >&2
            exit 1
        fi
        : >"$build_dir/publisher-store/$bad_label"
        if "$build_dir/publisher" del "$bad_label" 2>/dev/null; then
            echo "generated publisher deleted invalid label: $bad_label" >&2
            exit 1
        fi
        rm -f "$build_dir/publisher-store/$bad_label"
    done

    mount_dnsfs -o "nameserver=127.0.0.1;192.0.2.1",publisher="$publisher",port="$dns_publisher_port",timeout=250,retries=1,storage example.org
    printf 'publisher\n' | sudo tee "$mnt/via-publisher" >/dev/null
    expect_file_content "$publisher_dir/via-publisher" "publisher" "publisher put"
    sudo rm "$mnt/via-publisher"
    if [ -e "$publisher_dir/via-publisher" ]; then
        echo "publisher did not delete file" >&2
        exit 1
    fi
    unmount_dnsfs

    mount_dnsfs -o nameserver=127.0.0.1,publisher="$publisher",port="$dns_publisher_port",timeout=250,retries=1,storage example.org
    expect_file_content "$mnt/alpha" "second" "published storage read"
    sudo sh -c ": > '$mnt/touched'"
    if [ ! -f "$publisher_dir/touched" ]; then
        echo "touch did not publish file" >&2
        exit 1
    fi
    sudo python3 - "$mnt/rwfile" <<'PY'
import os
import sys

path = sys.argv[1]
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
os.write(fd, b"abcdef")
os.fsync(fd)
os.close(fd)
fd = os.open(path, os.O_RDWR)
os.lseek(fd, 2, os.SEEK_SET)
os.write(fd, b"XY")
os.fsync(fd)
os.close(fd)
if open(path, "rb").read() != b"abXYef":
    raise SystemExit("same-mount partial overwrite mismatch")

path = sys.argv[1] + "-samefd"
fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_TRUNC, 0o644)
os.write(fd, b"abcdef")
os.fsync(fd)
os.lseek(fd, 2, os.SEEK_SET)
os.write(fd, b"ZZ")
os.fsync(fd)
os.lseek(fd, 0, os.SEEK_SET)
if os.read(fd, 6) != b"abZZef":
    raise SystemExit("same-fd fsync/write/read mismatch")
os.close(fd)
PY
    unmount_dnsfs

    mount_dnsfs -o nameserver=127.0.0.1,publisher="$publisher",port="$dns_publisher_port",timeout=250,retries=1,storage example.org
    expect_file_content "$mnt/rwfile" "abXYef" "second-mount written storage read"
    expect_file_content "$mnt/rwfile-samefd" "abZZef" "second-mount same-fd fsync/write read"
    sudo rm "$mnt/rwfile"
    if [ -e "$publisher_dir/rwfile" ]; then
        echo "rm did not remove published file" >&2
        exit 1
    fi
    expect_open_errno "$mnt/rwfile" ENOENT
    unmount_dnsfs
    stop_dns
}

# B7 writeback regression: a publisher failure must surface on fsync (EIO),
# leave the dirty file intact and unpublished, and not poison the retry that
# succeeds once the publisher recovers.
test_writeback_retry()
{
    flaky_store="$build_dir/flaky-store"
    flaky_pub="$build_dir/flaky-publisher"
    sudo rm -rf "$flaky_store"
    mkdir -p "$flaky_store"
    # put: if the arm marker exists, consume it and fail BEFORE writing so the
    # store keeps the previous version; otherwise write the raw payload.
    cat >"$flaky_pub" <<EOF
#!/bin/sh
set -eu
root='$flaky_store'
case "\$1" in
put)
    if [ -e "\$root/.failnext" ]; then
        rm -f "\$root/.failnext"
        exit 1
    fi
    python3 - "\$root" "\$2" "\${3:-}" <<'PY'
import os, sys
root, label, hex_payload = sys.argv[1:]
with open(os.path.join(root, label), "wb") as f:
    f.write(bytes.fromhex(hex_payload))
PY
    ;;
del)
    rm -f "\$root/\$2"
    ;;
*)
    exit 1
    ;;
esac
EOF
    chmod +x "$flaky_pub"
    start_dns "$dns_publisher_port" --serve-dir="$flaky_store" --ttl1 --count-file "$dns_count"
    mount_dnsfs -o nameserver=127.0.0.1,publisher="$flaky_pub",port="$dns_publisher_port",timeout=250,retries=1,storage example.org
    sudo python3 - "$mnt/retryf" "$flaky_store/retryf" "$flaky_store/.failnext" <<'PY'
import errno, os, sys

path, store, marker = sys.argv[1:]

fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
os.write(fd, b"one")
os.fsync(fd)
os.close(fd)
if open(store, "rb").read() != b"one":
    raise SystemExit("initial publish did not persist")

# Overwrite, arm the publisher to fail, and expect fsync to surface EIO.
fd = os.open(path, os.O_RDWR)
os.lseek(fd, 0, os.SEEK_SET)
os.write(fd, b"two")
open(marker, "w").close()
try:
    os.fsync(fd)
except OSError as exc:
    if exc.errno != errno.EIO:
        raise SystemExit(f"fsync got errno {exc.errno}, expected EIO")
else:
    raise SystemExit("fsync unexpectedly succeeded while publisher failing")
# Dirty state intact and unpublished: the store still holds the old version.
if open(store, "rb").read() != b"one":
    raise SystemExit("failed publish corrupted the stored file")

# Retry on the same fd now that the publisher recovered: must succeed and the
# earlier write_err must not poison it.
os.fsync(fd)
if open(store, "rb").read() != b"two":
    raise SystemExit("retry did not publish the dirty file")
os.fsync(fd)  # third fsync: clean state, still returns success
os.close(fd)
PY
    unmount_dnsfs
    mount_dnsfs -o nameserver=127.0.0.1,publisher="$flaky_pub",port="$dns_publisher_port",timeout=250,retries=1,storage example.org
    expect_file_content "$mnt/retryf" "two" "writeback retry persisted"
    unmount_dnsfs
    stop_dns
    sudo rm -rf "$flaky_store"
}

# NXDOMAIN reads are negatively cached: two failing reads, one resolver query.
test_negative_cache()
{
    start_dns "$dns_nx_port" --nxdomain --count-file "$dns_count"
    rm -f "$dns_count"
    mount_dnsfs -o nameserver=127.0.0.1,port="$dns_nx_port",timeout=250,retries=1 example.org
    expect_open_errno "$mnt/TXT" ENOENT
    expect_open_errno "$mnt/TXT" ENOENT
    expect_dns_count 1 "negative cache"
    unmount_dnsfs
    stop_dns
}

# Negative-cache TTL expiry. Slow (sleeps past a 1s TTL): THOROUGH only.
test_negative_ttl()
{
    [ "$thorough" = 1 ] || return 0
    start_dns "$dns_nx_expire_port" --nxdomain --ttl1 --count-file "$dns_count"
    rm -f "$dns_count"
    mount_dnsfs -o nameserver=127.0.0.1,port="$dns_nx_expire_port",timeout=250,retries=1 example.org
    expect_open_errno "$mnt/TXT" ENOENT
    expect_open_errno "$mnt/TXT" ENOENT
    expect_dns_count 1 "negative TTL hit"
    sleep 2
    expect_open_errno "$mnt/TXT" ENOENT
    expect_dns_count 2 "negative TTL expiry"
    unmount_dnsfs
    stop_dns
}

# DNS rcode -> errno mapping through the live read path.
test_rcode_mapping()
{
    for rcode_case in "1 EINVAL" "2 EIO" "5 EACCES"; do
        set -- $rcode_case
        rcode_port=$((dns_rcode_port + $1))
        start_dns "$rcode_port" --rcode="$1"
        mount_dnsfs -o nameserver=127.0.0.1,port="$rcode_port",timeout=250,retries=1 example.org
        expect_open_errno "$mnt/TXT" "$2"
        unmount_dnsfs
        stop_dns
    done
}

# Malformed RDATA for each record type surfaces as EIO (readlink for CNAME).
test_bad_rdata()
{
    for bad_rdata_case in \
        "0 --bad-a-rdlength A open" \
        "1 --bad-aaaa-rdlength AAAA open" \
        "2 --bad-mx-rdata MX open" \
        "3 --bad-ns-rdata NS open" \
        "4 --bad-soa-rdata SOA open" \
        "5 --bad-dnskey-rdata DNSKEY open" \
        "6 --bad-ds-rdata DS open" \
        "7 --bad-txt-rdata TXT open" \
        "8 --bad-cname-rdata CNAME readlink"; do
        set -- $bad_rdata_case
        bad_rdata_port=$((dns_bad_rdata_port + $1))
        start_dns "$bad_rdata_port" "$2"
        mount_dnsfs -o nameserver=127.0.0.1,port="$bad_rdata_port",timeout=250,retries=1 example.org
        if [ "$4" = readlink ]; then
            expect_readlink_errno "$mnt/$3" EIO
        else
            expect_open_errno "$mnt/$3" EIO
        fi
        unmount_dnsfs
        stop_dns
    done
}

# Mismatched txid/qname/qtype/qclass/source-port responses are dropped
# (ETIMEDOUT).
test_bad_response()
{
    for bad_response_case in "1 --bad-txid" "2 --bad-qname" "3 --bad-qtype" "4 --bad-qclass" "5 --wrong-source-port"; do
        set -- $bad_response_case
        bad_response_port=$((dns_bad_txid_port + $1))
        start_dns "$bad_response_port" "$2"
        mount_dnsfs -o nameserver=127.0.0.1,port="$bad_response_port",timeout=250,retries=1 example.org
        expect_open_errno "$mnt/TXT" ETIMEDOUT
        unmount_dnsfs
        stop_dns
    done
}

# retries=2 doubles the bad-txid attempts before ETIMEDOUT.
test_retries()
{
    start_dns "$((dns_bad_txid_port + 6))" --bad-txid --count-file "$dns_count"
    rm -f "$dns_count"
    mount_dnsfs -o nameserver=127.0.0.1,port="$((dns_bad_txid_port + 6))",timeout=250,retries=2 example.org
    expect_open_errno "$mnt/TXT" ETIMEDOUT
    expect_dns_count 10 "retries option"
    unmount_dnsfs
    stop_dns
}

# Failover from a bad first resolver to a valid second resolver.
test_failover()
{
    /tmp/dnsfs-dns-server "$dns_failover_port" --bind=127.0.0.2 --bad-txid &
    bad_dns_pid=$!
    dns_pids="$dns_pids $bad_dns_pid"
    /tmp/dnsfs-dns-server "$dns_failover_port" --bind=127.0.0.1 &
    good_dns_pid=$!
    dns_pids="$dns_pids $good_dns_pid"
    wait_dns "$dns_failover_port" 127.0.0.2
    wait_dns "$dns_failover_port" 127.0.0.1
    mount_dnsfs -o "nameserver=127.0.0.2;127.0.0.1",port="$dns_failover_port",timeout=250,retries=1 example.org
    expect_file_content "$mnt/TXT" "dnsfs live" "resolver failover"
    unmount_dnsfs
    kill "$bad_dns_pid" "$good_dns_pid"
    drop_dns_pid "$bad_dns_pid"
    drop_dns_pid "$good_dns_pid"
}

# A short timeout against a silent resolver maps to ETIMEDOUT.
test_timeout()
{
    mount_dnsfs -o nameserver=127.0.0.1,port="$dns_port",timeout=50,retries=1 example.org
    expect_open_errno "$mnt/TXT" ETIMEDOUT
    unmount_dnsfs
}

# Synthetic (no-resolver) namespace: mapping, modes, magic, CNAME, name limits.
# Leaves the module loaded on exit for test_mount_validation.
test_synthetic()
{
    mount_dnsfs example.org.
    expect_file_content "$mnt/TXT" "TXT example.org. synthetic" "dotted synthetic source"
    unmount_dnsfs

    mount_dnsfs example.org
    expect_equal "$(stat -f -c %t "$mnt")" "444e5346" "filesystem magic"
    expect_equal "$(stat -f -c %s "$mnt")" "$(getconf PAGE_SIZE)" "filesystem block size"
    expect_equal "$(stat -c %a "$mnt")" "555" "root mode"
    expect_equal "$(stat -c %a "$mnt/TXT")" "444" "record file mode"
    expect_file_content "$mnt/TXT" "TXT example.org. synthetic" "synthetic root TXT"
    expect_file_content "$mnt/miek/a/TXT" "TXT a.miek.example.org. synthetic" "synthetic nested TXT"
    expect_file_content "$mnt/MiEk/a/TXT" "TXT a.miek.example.org. synthetic" "mixed-case synthetic TXT"
    expect_file_content "$mnt/miek/a/A" "A a.miek.example.org. synthetic" "synthetic nested A"
    python3 - "$mnt/miek/a" <<'PY'
import os
import sys

want = {"A", "AAAA", "TXT", "MX", "NS", "SOA", "DS", "DNSKEY", "CNAME"}
got = set(os.listdir(sys.argv[1]))
if got != want:
    raise SystemExit(f"unexpected synthetic listing: {sorted(got)}")
PY
    expect_equal "$(readlink "$mnt/miek/a/CNAME")" "target" "synthetic CNAME readlink"
    expect_file_content "$mnt/miek/a/CNAME/TXT" "TXT target.a.miek.example.org. synthetic" "synthetic CNAME target"
    expect_open_errno "$mnt/miek/a/BOGUS" ENOENT
    long_label=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    expect_open_errno "$mnt/$long_label/TXT" ENAMETOOLONG
    long_name=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    expect_open_errno "$mnt/$long_name/TXT" ENAMETOOLONG
    sudo umount "$mnt"
}

# Invalid mount sources, options, and zone names are all rejected before mount.
# Assumes the module is already loaded (by test_synthetic); unloads it at the
# end.
test_mount_validation()
{
    sudo /tmp/dnsfs-mount-no-source
    for invalid_mount_case in \
        "unknown mount option|-o|unknown=1|example.org" \
        "empty nameserver|-o|nameserver=|example.org" \
        "invalid nameserver|-o|nameserver=not-an-ip|example.org" \
        "trailing nameserver separator|-o|nameserver=127.0.0.1;|example.org" \
        "consecutive nameserver separators|-o|nameserver=127.0.0.1;;127.0.0.2|example.org" \
        "too many nameservers|-o|nameserver=127.0.0.1;127.0.0.2;127.0.0.3;127.0.0.4;127.0.0.5|example.org" \
        "zero DNS port|-o|port=0|example.org" \
        "oversized DNS port|-o|port=70000|example.org" \
        "zero DNS timeout|-o|timeout=0|example.org" \
        "zero DNS retries|-o|retries=0|example.org" \
        "empty publisher|-o|publisher=|example.org" \
        "relative publisher|-o|publisher=publisher|example.org"; do
        old_ifs=$IFS
        IFS='|'
        set -- $invalid_mount_case
        IFS=$old_ifs
        context=$1
        arg1=$2
        arg2=$3
        source=$4
        expect_mount_fail "$context" "$arg1" "$arg2" "$source"
    done
    undotted_max_zone=$(printf '%255s' '' | tr ' ' a)
    overlong_zone_label=$(printf '%64s' '' | tr ' ' a)
    for invalid_zone_case in \
        "undotted max DNS zone|$undotted_max_zone" \
        "overlong DNS zone label|$overlong_zone_label.example.org" \
        "root DNS zone|." \
        "empty DNS zone label|example..org" \
        "double trailing DNS zone dot|example.org.." \
        "uppercase DNS zone label|Example.org" \
        "underscore DNS zone label|bad_name.example.org" \
        "leading hyphen DNS zone label|bad.-example.org" \
        "trailing hyphen DNS zone label|bad-.example.org"; do
        old_ifs=$IFS
        IFS='|'
        set -- $invalid_zone_case
        IFS=$old_ifs
        context=$1
        source=$2
        expect_mount_fail "$context" "$source"
    done
    sudo rmmod dnsfs
}

# Repeated mount/unmount/load/unload stress; verifies proc cleanup at the end.
test_load_loop()
{
    log "load/unload loop ($load_iters iterations)"
    i=0
    while [ "$i" -lt "$load_iters" ]; do
        i=$((i + 1))
        mount_dnsfs example.org
        expect_file_content "$mnt/TXT" "TXT example.org. synthetic" "load loop $i"
        unmount_dnsfs
    done
    expect_not_exists /proc/fs/dnsfs "proc cleanup after load loop"
}

check_dmesg()
{
    if sudo dmesg | grep -Ei 'WARNING:|BUG:|Oops|general protection fault'; then
        exit 1
    fi
}

prepare
test_live_records
test_parallel_herd
test_cache_eviction
test_cache_reclaim
test_positive_ttl
test_async_ttl_refresh
test_signal_interrupt
test_tcp_fallback
test_multi_record
test_storage
test_storage_bad_index
test_storage_publisher
test_writeback_retry
test_negative_cache
test_negative_ttl
test_rcode_mapping
test_bad_rdata
test_bad_response
test_retries
test_failover
test_timeout
# test_synthetic leaves the module loaded; test_mount_validation unloads it.
test_synthetic
test_mount_validation
test_load_loop
check_dmesg

echo "dnsfs smoke test passed"
