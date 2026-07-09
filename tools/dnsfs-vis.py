#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""ANSI monitor for live dnsfs kernel-module internals."""

from __future__ import annotations

import argparse
import os
import platform
import select
import shutil
import sys
import termios
import time
import tty
from dataclasses import dataclass
from pathlib import Path


PROC_DIR = Path("/proc/fs/dnsfs")
DEBUG_DIR = Path("/sys/kernel/debug/dnsfs")
SAMPLES = ("TXT", "miek/a/TXT", "A", "CNAME")
WORKLOAD_PATHS = (
    "TXT",
    "A",
    "MX",
    "NS",
    "SOA",
    "AAAA",
    "DNSKEY",
    "DS",
    "miek/a/TXT",
    "miek/a/A",
    "CNAME",
    "CNAME/TXT",
)


@dataclass
class Mount:
    source: str
    target: str
    options: str


@dataclass
class Snapshot:
    registered: bool
    mounts: list[Mount]
    counters: dict[str, str]
    debug: dict[str, str]
    errors: list[str]


def read_text(path: Path, limit: int = 8192) -> str:
    try:
        with path.open("r", encoding="utf-8", errors="replace") as f:
            return f.read(limit).strip()
    except OSError as err:
        return f"unavailable: {err.strerror}"


def dnsfs_registered() -> bool:
    try:
        return any(line.split()[-1] == "dnsfs" for line in Path("/proc/filesystems").read_text().splitlines())
    except OSError:
        return False


def unescape_mount(text: str) -> str:
    return text.replace("\\040", " ").replace("\\011", "\t").replace("\\012", "\n").replace("\\134", "\\")


def dnsfs_mounts() -> list[Mount]:
    mounts: list[Mount] = []
    try:
        lines = Path("/proc/self/mountinfo").read_text().splitlines()
    except OSError:
        return mounts
    for line in lines:
        pre, sep, post = line.partition(" - ")
        if not sep:
            continue
        left = pre.split()
        right = post.split()
        if len(left) < 5 or len(right) < 3 or right[0] != "dnsfs":
            continue
        mounts.append(Mount(right[1], unescape_mount(left[4]), right[2]))
    return mounts


def snapshot() -> Snapshot:
    errors: list[str] = []
    counters = {
        "wire_queries": read_text(PROC_DIR / "wire_queries"),
        "record_refreshes": read_text(PROC_DIR / "record_refreshes"),
    }
    debug: dict[str, str] = {}
    try:
        debug_dir = DEBUG_DIR.is_dir()
    except OSError as err:
        debug_dir = False
        errors.append(f"{DEBUG_DIR} not readable: {err.strerror}")
    if debug_dir:
        try:
            paths = sorted(DEBUG_DIR.iterdir())
        except OSError as err:
            paths = []
            errors.append(f"{DEBUG_DIR} not readable: {err.strerror}")
        for path in paths:
            try:
                if path.is_file():
                    debug[path.name] = read_text(path, 12000)
            except OSError as err:
                errors.append(f"{path} not readable: {err.strerror}")
    elif platform.system() == "Linux":
        errors.append(f"{DEBUG_DIR} not readable; mount debugfs or run with permission")
    else:
        errors.append("not running on Linux; dnsfs kernel state is unavailable here")
    return Snapshot(dnsfs_registered(), dnsfs_mounts(), counters, debug, errors)


def read_sample(mount: Mount, sample: str) -> str:
    path = Path(mount.target) / sample
    try:
        if sample == "CNAME":
            return f"{path}: symlink -> {os.readlink(path)}"
        with path.open("r", encoding="utf-8", errors="replace") as f:
            return f"{path}: {f.read(512).strip()}"
    except OSError as err:
        return f"{path}: {err.strerror}"


def run_workload(mount: Mount) -> str:
    root = Path(mount.target)
    reads = stats = links = errors = 0
    try:
        list(root.iterdir())
    except OSError:
        errors += 1

    for rel in WORKLOAD_PATHS:
        path = root / rel
        try:
            path.stat()
            stats += 1
        except OSError:
            errors += 1
        try:
            if rel == "CNAME":
                os.readlink(path)
                links += 1
            else:
                with path.open("r", encoding="utf-8", errors="replace") as f:
                    f.read(512)
                reads += 1
        except OSError:
            errors += 1

    stamp = int(time.monotonic()) % 1000
    for idx in range(6):
        for suffix in ("TXT", "A", "MX", "NS"):
            path = root / f"vis-{stamp}-{idx}" / suffix
            try:
                with path.open("r", encoding="utf-8", errors="replace") as f:
                    f.read(128)
                reads += 1
            except OSError:
                errors += 1
    return f"workload: {reads} reads, {stats} stats, {links} readlinks, {errors} errors"


class DnsfsVis:
    def __init__(self, interval: float, read_now: bool = True) -> None:
        self.interval = interval
        self.mount = 0
        self.sample = 0
        self.message = "ready"
        self.snap = snapshot() if read_now else Snapshot(False, [], {}, {}, [])

    def run(self) -> None:
        saved = termios.tcgetattr(sys.stdin)
        try:
            tty.setraw(sys.stdin)
            sys.stdout.write("\x1b[?25l")
            while True:
                self.snap = snapshot()
                self._draw()
                key = self._read_key(self.interval)
                if self._handle_key(key):
                    return
        finally:
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, saved)
            sys.stdout.write("\x1b[0m\x1b[?25h\x1b[2J\x1b[H")
            sys.stdout.flush()

    def _read_key(self, timeout: float) -> str:
        if not select.select([sys.stdin], [], [], timeout)[0]:
            return ""
        key = sys.stdin.read(1)
        if key == "\x1b":
            rest = ""
            while len(rest) < 2 and select.select([sys.stdin], [], [], 0.02)[0]:
                rest += sys.stdin.read(1)
            return {"[A": "UP", "[B": "DOWN", "[C": "RIGHT", "[D": "LEFT"}.get(rest, "\x1b")
        return key

    def _handle_key(self, key: str) -> bool:
        if key in ("q", "\x1b"):
            return True
        if key in ("DOWN", "j") and self.snap.mounts:
            self.mount = min(self.mount + 1, len(self.snap.mounts) - 1)
        elif key in ("UP", "k") and self.snap.mounts:
            self.mount = max(self.mount - 1, 0)
        elif key in ("RIGHT", "l"):
            self.sample = min(self.sample + 1, len(SAMPLES) - 1)
        elif key in ("LEFT", "h"):
            self.sample = max(self.sample - 1, 0)
        elif key == "r":
            self.message = "refreshed"
        elif key == "t":
            if self.snap.mounts:
                self.message = read_sample(self.snap.mounts[self.mount], SAMPLES[self.sample])
            else:
                self.message = "no dnsfs mount to read"
        elif key == "w":
            if self.snap.mounts:
                self.message = run_workload(self.snap.mounts[self.mount])
            else:
                self.message = "no dnsfs mount for workload"
        return False

    def self_test(self) -> None:
        self.snap = Snapshot(True, [Mount("example.org", "/mnt/dnsfs", "rw")], {}, {}, [])
        assert self._handle_key("DOWN") is False
        assert self.mount == 0
        assert self._handle_key("RIGHT") is False
        assert self.sample == 1
        assert self._handle_key("LEFT") is False
        assert self.sample == 0
        assert self._handle_key("w") is False
        assert self._handle_key("q") is True

    def _draw(self) -> None:
        size = shutil.get_terminal_size((100, 30))
        height, width = size.lines, size.columns
        out = ["\x1b[2J\x1b[H"]
        if height < 22 or width < 72:
            out.append("terminal too small; use at least 72x22\n")
            self._write(out)
            return
        self._line(out, 0, 0, "dnsfs live DNS/VFS monitor", "\x1b[1m")
        self._line(out, 1, 0, "q quit  r refresh  j/k mount  h/l sample  t read sample  w workload")

        self._box(out, 3, 0, 7, 34, "status", height, width)
        self._line(out, 5, 2, f"kernel: {'dnsfs registered' if self.snap.registered else 'dnsfs not registered'}")
        self._line(out, 6, 2, f"mounts: {len(self.snap.mounts)}")
        for idx, (name, value) in enumerate(self.snap.counters.items()):
            self._line(out, 7 + idx, 2, f"{name}: {value}", max_width=30)

        self._box(out, 3, 36, 7, width - 36, "sample probe", height, width)
        self._line(out, 5, 38, f"selected: {SAMPLES[self.sample]}")
        self._line(out, 6, 38, "t reads one path; w runs a bounded real-op burst")
        self._line(out, 8, 38, self.message, "\x1b[2m", width - 40)

        self._box(out, 11, 0, 7, width, "mounts", height, width)
        if self.snap.mounts:
            for idx, mount in enumerate(self.snap.mounts[:4]):
                attr = "\x1b[7m" if idx == self.mount else ""
                self._line(out, 13 + idx, 2,
                           f"{mount.target}  source={mount.source}  opts={mount.options}",
                           attr, width - 4)
        else:
            self._line(out, 13, 2, "no dnsfs mounts found in /proc/self/mountinfo")

        self._box(out, 19, 0, height - 19, width, "debugfs internals", height, width)
        y = 21
        if self.snap.debug:
            for name, text in self.snap.debug.items():
                self._line(out, y, 2, f"[{name}]", "\x1b[1m", width - 4)
                y += 1
                for line in text.splitlines()[: max(1, height - y - 1)]:
                    self._line(out, y, 2, line, max_width=width - 4)
                    y += 1
                    if y >= height - 1:
                        break
                if y >= height - 1:
                    break
        else:
            for err in self.snap.errors or ["no debugfs dnsfs files visible"]:
                self._line(out, y, 2, err, max_width=width - 4)
                y += 1
        self._write(out)

    def _box(self, out: list[str], y: int, x: int, h: int, w: int, title: str,
             height: int, width: int) -> None:
        h = min(h, height - y)
        w = min(w, width - x)
        if h < 3 or w < 8:
            return
        self._line(out, y, x, "+" + "-" * (w - 2) + "+")
        for row in range(y + 1, y + h - 1):
            self._line(out, row, x, "|")
            self._line(out, row, x + w - 1, "|")
        self._line(out, y + h - 1, x, "+" + "-" * (w - 2) + "+")
        self._line(out, y, x + 2, f" {title} ", "\x1b[1m", w - 4)

    def _line(self, out: list[str], y: int, x: int, text: str, attr: str = "",
              max_width: int | None = None) -> None:
        size = shutil.get_terminal_size((100, 30))
        height, width = size.lines, size.columns
        if y >= height or x >= width:
            return
        max_width = min(max_width or width - x, width - x)
        if y == height - 1:
            max_width = max(0, max_width - 1)
        if max_width <= 0:
            return
        reset = "\x1b[0m" if attr else ""
        out.append(f"\x1b[{y + 1};{x + 1}H{attr}{text[:max_width].ljust(max_width)}{reset}")

    def _write(self, out: list[str]) -> None:
        sys.stdout.write("".join(out))
        sys.stdout.flush()


def print_once() -> None:
    snap = snapshot()
    print(f"dnsfs registered: {snap.registered}")
    print("mounts:")
    for mount in snap.mounts:
        print(f"  {mount.target} source={mount.source} opts={mount.options}")
    if not snap.mounts:
        print("  (none)")
    print("counters:")
    for name, value in snap.counters.items():
        print(f"  {name}: {value}")
    print("debugfs:")
    if snap.debug:
        for name, text in snap.debug.items():
            print(f"  {name}:")
            for line in text.splitlines()[:20]:
                print(f"    {line}")
    else:
        for err in snap.errors or ["no debugfs dnsfs files visible"]:
            print(f"  {err}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--interval", type=float, default=1.0)
    parser.add_argument("--once", action="store_true", help="print one snapshot")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        DnsfsVis(args.interval, read_now=False).self_test()
    elif args.once or not sys.stdout.isatty():
        print_once()
    else:
        vis = DnsfsVis(args.interval)
        vis.run()
