# dnsfs — a filesystem backed by DNS

`dnsfs` is a Linux kernel module that mounts DNS as a filesystem. Remote
resolvers are read-only; a storage mount that explicitly names a userspace
publisher (`-o storage,publisher=…`) is read-write (see below). It is a teaching
project: each stage introduces one kernel subsystem (VFS, kernel sockets, the
page cache, kthreads, memory reclaim) through one coherent idea.

> A filesystem is fundamentally a *namespace* abstraction, not a *storage* one.

DNS is already a hierarchical, delegated, cached namespace. `dnsfs` exposes it
through the VFS so you can `cd`, `ls`, and `cat` it:

| DNS concept            | Filesystem concept            |
| ---------------------- | ----------------------------- |
| zone (`example.org.`)  | the mount root                |
| label (`www`)          | a directory                   |
| resource record (`A`)  | a file, in zone-presentation form |
| `CNAME`                | a symlink                     |
| `NXDOMAIN`             | `ENOENT` / a negative dentry  |
| TTL                    | cache lifetime of an object   |
| TXT records            | raw bytes of a stored file (storage mode) |

## The namespace mapping

Mounting pins the root to a single zone — it is a mountable filesystem, not a
global DNS browser:

```sh
sudo mount -t dnsfs example.org /mnt        # / is now example.org.
```

A path is the DNS name *under that zone*, with the labels reversed and
lower-cased. Record types are upper-case leaf files; the content is the
zone-presentation form, one resource record per line:

```
/mnt
├── TXT                      # TXT of example.org.        -> "dnsfs live"
├── A                        # A   of example.org.        -> "192.0.2.1"
├── MX                       #                            -> "10 mail.example.org."
├── SOA  NS  DS  DNSKEY  AAAA
├── CNAME -> target          # a symlink, not a file
└── miek/
    └── a/                   # path miek/a  ==  a.miek.example.org.
        ├── TXT
        └── A
```

So `/mnt/miek/a/TXT` issues a `TXT` query for `a.miek.example.org.`.

### Why the mapping is exact, not a gimmick

Linux's VFS is a *namespace multiplexer* — the "everything is a file" idea from
Plan 9, where unlike resources are reached through one hierarchical name tree.
DNS independently evolved the same primitives, so the two line up term for term:

- **Hierarchy.** Labels nested under a zone are nested directories; resolving a
  name walks the tree the way `path_lookup` walks dentries.
- **Delegation.** A zone cut (`NS` delegation) is exactly a mount point: a
  subtree owned by a different authority, stitched into one namespace.
- **Lifetime, not bytes.** A record's TTL *is* the cache lifetime of an object;
  `dnsfs` expires a cached entry when its TTL elapses, the same way a dentry can
  go stale. There is no durable block store underneath — the namespace is the
  thing.
- **Negative space.** A cached `NXDOMAIN` (negative caching, RFC 2308) is a
  negative dentry: "known absent, for this long," distinct from "unknown."
- **Indirection.** A `CNAME` is a symlink — a name that resolves to another name.

`dnsfs` doesn't bolt a filesystem onto DNS; it teaches the VFS to read the side
DNS already implements. Storage mode (below) then pushes the idea further:
*content* itself, not just names, is carried in the namespace as TXT records.

DNS is not enumerable: there is no `AXFR`, so a plain directory's `readdir`
lists only `.`/`..` and the reserved record-type files. (A *storage* directory
additionally lists children from a designated index — see below.)

Errors map to the natural errno:

| DNS rcode / event | errno        |
| ----------------- | ------------ |
| `NXDOMAIN`        | `ENOENT`     |
| `SERVFAIL`        | `EIO`        |
| `REFUSED`         | `EACCES`     |
| `FORMERR`         | `EINVAL`     |
| no response       | `ETIMEDOUT`  |

## Storage mode: files *inside* DNS

With `-o storage`, `dnsfs` reassembles real file contents out of TXT records. A
file is split into fixed-size chunks (≈180 raw bytes, so base64 fits one
255-byte TXT). Each chunk lives at a record named `{epoch}-{base36offset}-{name}`,
carrying `<crc32c> <base64-payload>`. Per-file metadata (`size mode mtime
chunk_count epoch crc32c`) gives the inode its stat fields, and EOF comes from
the metadata `chunk_count` — never from `NXDOMAIN`, which loss or poisoning
could forge. The `epoch` prevents serving a mix of stale and fresh chunks.

CRC32c here is integrity only — it detects transport/cache corruption but is
trivially spoofable. Tamper resistance needs end-to-end DNSSEC validation or a
trusted resolver, not a checksum.

### Publishing files

By default the module only reads; publishing to DNS is a userspace concern.
Writes are enabled only when the mount explicitly names a publisher executable
with `publisher=/absolute/path`. `make` creates a local validation publisher at
`/tmp/kdnsfs-build/publisher`; it writes files under
`/tmp/kdnsfs-build/publisher-store`. If you build with `BUILD_DIR=/tmp/foo`, pass
`publisher=/tmp/foo/publisher`.

DNS queries use `nameserver=`, while writes call the publisher as
`publisher put <label> <hex-payload>` or `publisher del <label>`. The publisher
must keep the file metadata and chunk records available so later mounts can
still resolve them.
The kernel never mutates real DNS: a write buffers in the page cache and, on
`fsync`/close, the whole file is handed to the local publisher, which owns the
store and re-validates every name.

For local validation, serve the generated publisher store with the test
resolver:

```sh
make
make dns-server
sudo insmod /tmp/kdnsfs-build/dnsfs.ko
sudo mkdir -p /mnt/dnsfs
sudo /tmp/kdnsfs-build/dns-server 5354 --serve-dir=/tmp/kdnsfs-build/publisher-store &
dns_pid=$!
sudo mount -t dnsfs -o storage,nameserver=127.0.0.1,port=5354,publisher=/tmp/kdnsfs-build/publisher example.org /mnt/dnsfs

printf 'hello world\n' | sudo tee /mnt/dnsfs/hello >/dev/null   # publisher put hello ...
cat /mnt/dnsfs/hello                     # -> hello world
sudo umount /mnt/dnsfs
sudo mount -t dnsfs -o storage,nameserver=127.0.0.1,port=5354,publisher=/tmp/kdnsfs-build/publisher example.org /mnt/dnsfs
cat /mnt/dnsfs/hello                     # -> hello world, read back after remount
sudo rm /mnt/dnsfs/hello                 # unpublishes it
sudo umount /mnt/dnsfs
sudo rmmod dnsfs
kill "$dns_pid"
```

Without `publisher=`, `-o storage` remains read-only.
`nameserver` defaults to `127.0.0.1` in storage mode, and `port` (53),
`timeout`, and `retries` have defaults too.
File names must be valid lowercase DNS labels. Files are capped at a small
teaching size, and metadata (mode/owner) is owned by the publisher, so
`chmod`/`chown` through the mount are not pushed back to DNS.

## System design

Three kernel translation units plus a userspace-shaped parser, split by trust
boundary and concern:

```
                 untrusted DNS bytes
                         │
   parser.c  ◀───────────┘   pure, allocation-free, fuzzed.
   (the gate)                Decodes wire messages + the storage encoding.
                         │   Compiles in userspace too (see tests/test-parser.c).
                         ▼
   dns.c                     The resolver engine: build query, UDP/TCP client,
   (engine)                  response parse, record presentation, the TTL cache,
                         │   a per-mount query kthread, reclaim hooks.
                         ▼
   main.c                    VFS glue: fs_context mount, inode/dir/file/symlink
   (VFS)                     ops, path↔FQDN mapping, the storage layer, /proc.

   dnsfs.h                   shared structs, #defines, cross-TU prototypes.
```

- **Trust boundary.** Everything that touches untrusted network bytes lives in
  `parser.c`, which never allocates and never trusts its input. It is fuzzed
  (ASan/UBSan, millions of iterations) *before* the socket layer is allowed to
  feed it. Touch it and re-fuzz.
- **Concurrency.** A reader checks the per-mount TTL cache; on a miss it joins
  an in-flight `{fqdn,qtype}` request or enqueues a new one and waits on a
  completion. A single per-mount **kthread** owns all *resolver* socket I/O, so
  duplicate misses for the same name collapse into one wire query and no reader
  ever blocks the network from a VFS atomic section. Storage write commits call
  the configured publisher only from process context (`fsync`/`close`/`create`/
  `unlink`), never an atomic one.
- **Page cache.** Record and storage reads go through `read_folio` /
  `readahead`, so repeat reads are served from the page cache; TTL expiry
  invalidates the mapping before refetch. Storage writes buffer via
  `write_begin`/`write_end` and commit the whole file to the local publisher on
  `fsync`/close, then drop the cached pages so the next read reflects the new
  epoch.
- **Reclaim.** The DNS cache is exposed to VFS memory pressure via
  `super_operations->{nr,free}_cached_objects`, evicting LRU-tail entries.

## Building and running

This is a Linux kernel module. Build, load, mount, and test it inside a Linux VM
such as Lima, not on the host.

```sh
cd /path/to/kdnsfs
make # builds /tmp/kdnsfs-build/dnsfs.ko and /tmp/kdnsfs-build/publisher
sudo insmod /tmp/kdnsfs-build/dnsfs.ko
sudo mkdir -p /mnt/dnsfs
```

**Synthetic mode** needs no resolver — records are generated, useful for poking
at the namespace logic:

```sh
sudo mount -t dnsfs example.org /mnt/dnsfs
cat /mnt/dnsfs/TXT                  # -> TXT example.org. synthetic
cat /mnt/dnsfs/miek/a/TXT           # -> TXT a.miek.example.org. synthetic
readlink /mnt/dnsfs/CNAME           # -> target
sudo umount /mnt/dnsfs
```

**Live mode** queries a real resolver. Point it at a proper recursive,
caching resolver:

```sh
sudo mount -t dnsfs -o nameserver=1.1.1.1,port=53,timeout=2000,retries=2 example.org /mnt/dnsfs
cat /mnt/dnsfs/TXT          # -> the real example.org TXT records
sudo umount /mnt/dnsfs
```

Avoid pointing it at a local stub like systemd-resolved (`127.0.0.53`): such
stubs often return `TTL=0` (so nothing is cached) and rate-limit repeats, and a
single `cat` issues two queries (one to size the file on `open`, one to read
it) — the second gets dropped and you see `ETIMEDOUT` (errno 110). A real
resolver returns a usable TTL, so the read is a cache hit and only one wire
query goes out (watch `/proc/fs/dnsfs/wire_queries`). For fully deterministic
local testing, use the bundled `tests/dns-server.c` (see *Debugging*).

Mount options: `nameserver=` (comma/semicolon-separated, up to 4 for failover),
`publisher=` (absolute userhelper path that maintains storage DNS records),
`port=`, `timeout=` (ms), `retries=`, `dnssec` (sets the EDNS DO bit),
`storage`. Finish with `sudo rmmod dnsfs`.

The smoke suite (build, parser checks, mounts, behavior tests, clean `dmesg`)
runs via:

```sh
make check                 # fast: incremental build, skips slow TTL-timing tests
THOROUGH=1 make check      # full gate: clean rebuild, 1M-iteration fuzz, 100x load loop
```

## Debugging

- **Wire-query counter.** Every real DNS query bumps a counter you can watch to
  confirm caching/coalescing:
  ```sh
  cat /proc/fs/dnsfs/wire_queries
  ```
- **Kernel log.** All warnings/oopses surface in `dmesg`; the smoke suite fails
  if it sees any `WARNING:`/`BUG:`/`Oops`/GPF.
  ```sh
  sudo dmesg -w
  ```
- **Offline test resolver.** `tests/dns-server.c` is a self-contained C DNS
  server that synthesizes live records, every malformed-response case, and the
  storage layer — no external DNS or Python needed. The suite drives it; you can
  too:
  ```sh
  cc -o /tmp/dns-server tests/dns-server.c
  /tmp/dns-server 5354 --storage &
  dns_pid=$!
  sudo insmod /tmp/kdnsfs-build/dnsfs.ko
  sudo mkdir -p /mnt/dnsfs
  sudo mount -t dnsfs -o nameserver=127.0.0.1,port=5354,storage example.org /mnt/dnsfs
  sudo umount /mnt/dnsfs
  sudo rmmod dnsfs
  kill "$dns_pid"
  ```
  Flags include `--nxdomain`, `--truncate-udp` (forces TCP fallback),
  `--rcode=N`, `--bad-*-rdata`, `--multi-*`, and `--ttl1`.
- **Parser fuzzing inside Linux.** The parser builds in userspace, so you can
  fuzz it under ASan/UBSan without the kernel. Run this inside Lima/a Linux VM:
  ```sh
  cc -Wall -Wextra -Werror -fsanitize=address,undefined -g \
     -o /tmp/pt tests/test-parser.c src/parser.c
  /tmp/pt 1000000        # deterministic fuzz iterations
  ```
- **Formatting.** `make indent` runs clang-format on the C sources and `shfmt`
  on the shell, per `.clang-format`/`.editorconfig`.

## Non-goals

No RFC 2136 / DNS UPDATE / TSIG zone-update path in the kernel — writes on a
storage mount go through the local publisher executable. That publisher may
update a real DNS zone in userspace and must keep the records available for
later reads; the kernel never mutates real DNS. No DoH/DoT transport, no eBPF
interception. The plain kernel UDP socket *is* the lesson.

## Further reading

The idea of treating DNS as storage or as a filesystem has prior art worth
reading; `dnsfs` borrows the namespace mapping but builds it natively in the
kernel rather than over FUSE or a userspace daemon.

DNS-as-a-filesystem, the direct inspiration:

- Ben Cox, *DNS filesystem: true cloud storage (DNSFS)* — storing files in the
  caches of open recursive resolvers.
  <https://blog.benjojo.co.uk/post/dns-filesystem-true-cloud-storage-dnsfs>
- *DNSFS — a DNS file system* (Invicti), the same trick from a web-security
  angle. <https://www.invicti.com/blog/web-security/dnsfs-dns-file-system>
- Talk / demo of a DNS-backed filesystem (video).
  <https://youtu.be/8hu3SszwgtQ>

The namespace idea this rests on:
- R. Pike et al., *The Use of Name Spaces in Plan 9* — "everything is a file" and
  per-process namespaces, the lineage of the VFS view used here.
- Linux kernel `Documentation/filesystems/vfs.rst` and `path-lookup.rst` — the
  dentry/inode model, negative dentries, and `read_folio`/`readahead`.

The DNS / encoding standards the mapping leans on:
- RFC 1034 / RFC 1035 — DNS concepts and message format (the wire `parser.c`
  decodes).
- RFC 2308 — negative caching of DNS queries (the `NXDOMAIN` → negative-dentry
  mapping and the TTL-as-lifetime model).
- RFC 1464 — storing arbitrary attribute/value pairs in TXT records (storage
  mode's lineage).
- RFC 4648 — base64, the chunk payload encoding.
- RFC 6891 — EDNS(0), used to set the DNSSEC `DO` bit.
- RFC 4033 / 4034 / 4035 — DNSSEC; the only real defense against cache poisoning
  (CRC32c here is integrity against corruption, not authenticity).
- RFC 2136 — DNS UPDATE; deliberately *out* of the kernel (a non-goal), left to
  the userspace publisher.

## License

GPL-2.0-only. The full text is in [`LICENSE`](LICENSE); every source file also
carries an `SPDX-License-Identifier: GPL-2.0-only` header and the module declares
`MODULE_LICENSE("GPL")`, so `dnsfs.ko` loads as a GPL-compatible module (no
tainting).
