# kdnsfs: DNS as a Linux kernel filesystem

`kdnsfs` is a teaching Linux kernel module. The module and mount filesystem type
are named `dnsfs`.

The core idea:

> A filesystem is fundamentally a namespace abstraction, not a storage
> abstraction.

DNS already is a distributed, delegated, cached namespace. `dnsfs` exposes that
namespace through Linux VFS so students can `cd`, `ls`, `cat`, and observe how
ordinary DNS concepts line up with filesystem concepts.

| DNS concept | Filesystem concept |
| --- | --- |
| zone, for example `example.org.` | mount root |
| label, for example `www` | directory |
| resource record, for example `TXT` | regular file |
| `CNAME` | symlink |
| `NXDOMAIN` | `ENOENT` / negative dentry |
| TTL | cache lifetime |
| TXT records in storage mode | file bytes |

This is not trying to make DNS a good disk. It is trying to make filesystem
internals, DNS resolution, TTL caching, negative dentries, page cache behavior,
and usermode helpers visible through one coherent experiment.

## Live Learning Loop

Build and run inside Linux only. Do not build, load, mount, or test the module
on macOS; use Lima or another Linux VM.

```sh
make
sudo insmod /tmp/kdnsfs-build/dnsfs.ko
sudo mkdir -p /mnt/dnsfs
```

Mount against generated synthetic records:

```sh
sudo mount -t dnsfs example.org /mnt/dnsfs
cat /mnt/dnsfs/TXT
cat /mnt/dnsfs/miek/a/TXT
readlink /mnt/dnsfs/CNAME
```

Mount against a real recursive resolver:

```sh
sudo umount /mnt/dnsfs
sudo mount -t dnsfs \
  -o nameserver=1.1.1.1,port=53,timeout=2000,retries=2 \
  example.org /mnt/dnsfs
cat /mnt/dnsfs/TXT
```

Watch the kernel internals while operating on the mount:

```sh
sudo python3 tools/dnsfs-vis.py
```

`dnsfs-vis.py` is an ANSI TUI over live procfs/debugfs state. It shows mounts,
wire-query counters, record-refresh counters, per-mount resolver config,
in-flight query state, and the TTL cache. Keys: `j/k` select a mount, `h/l`
select a sample path, `t` reads that path, `w` runs a bounded burst of real
dnsfs file operations, `r` refreshes, `q` quits.

For scripts or logs:

```sh
sudo python3 tools/dnsfs-vis.py --once
```

## Namespace Mapping

Mounting pins one DNS zone as the root:

```sh
sudo mount -t dnsfs example.org /mnt/dnsfs
```

Paths under the mount are reversed into DNS names under that zone. Record types
are uppercase leaf files:

```text
/mnt/dnsfs/TXT         -> TXT example.org.
/mnt/dnsfs/A           -> A   example.org.
/mnt/dnsfs/miek/a/TXT  -> TXT a.miek.example.org.
/mnt/dnsfs/miek/a/A    -> A   a.miek.example.org.
/mnt/dnsfs/CNAME       -> symlink to target
```

DNS is not generally enumerable, so normal directories list only `.`/`..` and
the reserved record-type files. Storage mode adds an index record for files it
publishes.

DNS errors map to ordinary errno values:

| DNS result | errno |
| --- | --- |
| `NXDOMAIN` | `ENOENT` |
| `SERVFAIL` | `EIO` |
| `REFUSED` | `EACCES` |
| `FORMERR` | `EINVAL` |
| timeout | `ETIMEDOUT` |

Avoid local stubs such as `127.0.0.53` for live-mode demos. They often return
`TTL=0` or rate-limit repeated queries, hiding the cache behavior this project is
designed to teach.

## Storage Mode

Remote DNS mounts are read-only unless storage mode names a publisher:

```sh
sudo mount -t dnsfs \
  -o storage,nameserver=127.0.0.1,port=5354,publisher=/tmp/kdnsfs-build/publisher \
  example.org /mnt/dnsfs
```

In storage mode, file bytes are carried in TXT records:

- `index.<zone>` lists published files.
- `<file>.<zone>` stores metadata: `size mode mtime chunk_count epoch crc32c`.
- `<epoch>-<base36offset>-<file>.<zone>` stores one chunk as
  `<crc32c> <base64-payload>`.
- Chunks are 180 raw bytes so their base64 payload fits in one DNS TXT string.

CRC32c detects corruption, not forgery. Authenticity still needs DNSSEC or a
trusted resolver. EOF comes from metadata, not from `NXDOMAIN`, because missing
chunks may be caused by loss, cache poisoning, or stale data.

### Local Publishing

`make` builds one userhelper at `/tmp/kdnsfs-build/publisher`. Without
`/etc/dnsfs/nsupdate.conf`, it writes to `/tmp/kdnsfs-build/publisher-store`.
The bundled test DNS server can serve that directory:

```sh
make dns-server
/tmp/kdnsfs-build/dns-server 5354 --serve-dir=/tmp/kdnsfs-build/publisher-store &
dns_pid=$!

sudo mount -t dnsfs \
  -o storage,nameserver=127.0.0.1,port=5354,publisher=/tmp/kdnsfs-build/publisher \
  example.org /mnt/dnsfs

printf 'hello world\n' | sudo tee /mnt/dnsfs/hello >/dev/null
cat /mnt/dnsfs/hello
sudo rm /mnt/dnsfs/hello

sudo umount /mnt/dnsfs
kill "$dns_pid"
```

### Real DNS Publishing

The same `/tmp/kdnsfs-build/publisher` can publish to an authoritative DNS
server that accepts RFC 2136 dynamic updates. Add one config file:

```sh
sudo install -d -m 0755 /etc/dnsfs /var/lib/dnsfs-nsupdate
sudo install -m 0644 tools/publisher.conf.example /etc/dnsfs/nsupdate.conf
sudo editor /etc/dnsfs/nsupdate.conf
```

Set `zone=`, `server=`, and optional `key=`. The server must be authoritative
for the zone; a recursive resolver like `1.1.1.1` cannot accept writes.

Then keep using the same helper:

```sh
sudo mount -t dnsfs \
  -o storage,nameserver=1.1.1.1,port=53,publisher=/tmp/kdnsfs-build/publisher \
  your.zone /mnt/dnsfs
```

The kernel still never mutates DNS directly. Writes go through the userspace
publisher via `call_usermodehelper()` as:

```text
publisher put <label> <hex-payload>
publisher del <label>
```

## Architecture

```text
untrusted DNS bytes
        |
        v
parser.c   allocation-free wire/storage decoder; builds in userspace for fuzzing
        |
        v
dns.c      resolver engine, UDP/TCP socket I/O, TTL cache, query kthread
        |
        v
main.c     VFS glue: mount, dentries, inodes, file ops, storage writeback

dnsfs.h    shared structs and cross-translation-unit contracts
```

Important boundaries:

- `parser.c` is the trust boundary. It validates DNS wire bytes, storage
  metadata, chunk names, base64 payloads, and CRC32c.
- `dns.c` owns resolver I/O and cache mutation. A per-mount kthread performs
  network work so VFS readers do not block in atomic contexts.
- `main.c` maps paths to FQDNs, exposes records as files/symlinks, and commits
  storage writes through the userhelper.
- Cache entries use TTL as object lifetime. Debug counters and debugfs expose
  the moving parts for `dnsfs-vis.py`.

## Kernel Concepts in Practice

These are the kernel concepts dnsfs is meant to make concrete. Each one is
small enough to inspect in one sitting, then observe live with `dnsfs-vis.py`.

### Synchronization and RCU

Hot cache reads use `dnsfs_cache_lookup_rcu()` so VFS read paths can inspect
immutable cache entries without taking `query_lock`. Writers still serialize
table/list mutation with `cfg->query_lock`; removed entries are freed only after
an RCU grace period.

```text
reader                         writer/kthread                  RCU callback
------                         --------------                  ------------
rcu_read_lock()
lookup entry E
read E fields                  mutex_lock(query_lock)
                               remove E from hash/list
                               call_rcu(E, free_rcu)
                               mutex_unlock(query_lock)
still reading E
rcu_read_unlock()
                               grace period passes --------->  kfree(E)
```

Student prompts:
- Why must an RCU reader avoid blocking on non-preemptible kernels?
- Why does the writer need a mutex while the reader does not?
- What fields in `struct dnsfs_cache_entry` must stay immutable for the RCU
  fast path to be correct?

### Kernel Networking and kthreads

dnsfs does not call a userspace resolver. `dnsfs_query_thread()` owns resolver
socket I/O, while VFS paths enqueue work and wait for completion. This keeps
sleeping network operations out of contexts where VFS code may not safely block.

```text
VFS read / lookup
      |
      v
enqueue dnsfs_query_request
      |
      v
dnsfs_query_thread
      |
      +--> dnsfs_query_udp_once() -> kernel_sendmsg() / kernel_recvmsg()
      |
      +--> dnsfs_query_tcp()      -> kernel_connect() + stream I/O
      |
      v
complete waiters and publish cache entry
```

Student prompts:
- Trigger TCP fallback with the test resolver's truncated UDP response and trace
  the path from UDP `TC` to `dnsfs_query_tcp()`.
- Compare UDP datagrams with TCP connection setup in kernel socket code.
- Watch duplicate readers coalesce into fewer wire queries with
  `/proc/fs/dnsfs/wire_queries`.

### User-Kernel Boundaries

dnsfs crosses the user/kernel boundary in three visible places:

- `fs_context`: mount options such as `nameserver=`, `storage`, and
  `publisher=`.
- procfs/debugfs: counters and per-mount internals consumed by `dnsfs-vis.py`.
- `call_usermodehelper()`: storage writes invoke the publisher as
  `publisher put <label> <hex>` or `publisher del <label>`.

```text
VFS write/fsync
      |
      v
dnsfs storage commit
      |
      v
call_usermodehelper()
      |
      v
publisher put <label> <hex-payload>
      |
      v
exit status becomes writeback success/failure
```

Student prompts:
- Audit why `publisher=` must be an absolute path.
- Check how arguments are passed as `argv[]`, not through a shell.
- Explain why DNS provider credentials belong in the userspace publisher, not
  in the kernel module.

### VFS Lifecycle and Page Cache Coherence

Mounting creates an `fs_context`, then a `super_block`; dnsfs stores per-mount
state in `sb->s_fs_info` as `struct dnsfs_config`.

```text
struct fs_context
       |
       v
struct super_block  --->  struct dnsfs_config
       |
       v
root dentry
       |
       v
root inode
```

Record reads go through `dnsfs_record_read_iter()`. When a DNS TTL expires or a
refresh changes a cache generation, dnsfs invalidates matching page-cache pages
with `invalidate_mapping_pages()` so file contents and resolver cache do not
diverge.

Student prompts:
- Trace one `cat /mnt/dnsfs/TXT` from dentry lookup to page-cache fill.
- Observe `record_refreshes` while repeatedly reading the same file before and
  after TTL expiry.
- Explain why metadata cache expiry and page-cache invalidation must be linked.

## Testing

Run tests inside Linux:

```sh
make check
THOROUGH=1 make check
```

Useful manual checks:

```sh
grep -w dnsfs /proc/filesystems
findmnt -t dnsfs
cat /proc/fs/dnsfs/wire_queries
cat /proc/fs/dnsfs/record_refreshes
sudo dmesg -w
```

The parser can be fuzzed in userspace:

```sh
cc -Wall -Wextra -Werror -fsanitize=address,undefined -g \
  -o /tmp/dnsfs-parser tests/test-parser.c src/parser.c
/tmp/dnsfs-parser 1000000
```

## Non-goals

- No DNS UPDATE, TSIG, provider API token, DoH, or DoT logic in the kernel.
- No claim that DNS is a practical general-purpose storage layer.
- No AXFR-style global DNS browsing.
- No macOS build/test path for the kernel module.

## Further Reading

- Ben Cox, *DNS filesystem: true cloud storage (DNSFS)*:
  <https://blog.benjojo.co.uk/post/dns-filesystem-true-cloud-storage-dnsfs>
- Linux kernel `Documentation/filesystems/vfs.rst` and `path-lookup.rst`.
- Plan 9 namespace papers for the broader "everything is a file" lineage.
- RFC 1034 / 1035 for DNS, RFC 2308 for negative caching, RFC 2136 for dynamic
  DNS update, RFC 6891 for EDNS(0), and RFC 4033-4035 for DNSSEC.

## License

GPL-2.0-only. See [`LICENSE`](LICENSE). Source files carry SPDX identifiers and
the module declares `MODULE_LICENSE("GPL")`.
