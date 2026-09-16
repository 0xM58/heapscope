"""Process memory access with no ptrace, no preload, and no debugger.

Everything here rests on one property: ``/proc/<pid>/mem`` and
``/proc/<pid>/maps`` are readable by a process's *parent*, with no attach step
and no observable side effect in the target. When your harness spawns the
target itself - which is what :class:`heapscope.Probe` does - that is exactly
what you are.

This matters because the usual alternative is an ``LD_PRELOAD`` shim or a
ptrace attach, and both perturb the thing you are trying to measure: a preload
shifts the heap layout and an attach is visible to the target. Reading
``/proc`` changes nothing.
"""

from __future__ import annotations

import os
import re
import struct
from dataclasses import dataclass
from typing import Iterator, List, Optional

from .errors import Unmapped

__all__ = ["MapRegion", "MemoryMap", "MemReader"]

_MAPS_RE = re.compile(
    r"^(?P<start>[0-9a-f]+)-(?P<end>[0-9a-f]+)\s+"
    r"(?P<perms>[rwxps-]{4})\s+"
    r"(?P<offset>[0-9a-f]+)\s+"
    r"(?P<dev>[0-9a-f]+:[0-9a-f]+)\s+"
    r"(?P<inode>\d+)\s*"
    r"(?P<path>.*)$"
)

#: Address range a PIE binary and its brk heap land in on x86-64 Linux.
_PIE_RANGE = (0x5000_0000_0000, 0x6000_0000_0000)


@dataclass(frozen=True)
class MapRegion:
    """One line of ``/proc/<pid>/maps``."""

    start: int
    end: int
    perms: str
    offset: int
    dev: str
    inode: int
    path: str

    @property
    def size(self) -> int:
        return self.end - self.start

    @property
    def readable(self) -> bool:
        return "r" in self.perms

    @property
    def writable(self) -> bool:
        return "w" in self.perms

    @property
    def executable(self) -> bool:
        return "x" in self.perms

    @property
    def is_anon(self) -> bool:
        return self.path == ""

    def contains(self, addr: int) -> bool:
        return self.start <= addr < self.end

    def __str__(self) -> str:
        return "%#x-%#x %s %s" % (self.start, self.end, self.perms, self.path or "[anon]")


class MemoryMap:
    """A parsed snapshot of ``/proc/<pid>/maps``.

    Snapshots are cheap and deliberately not cached by the reader: the brk heap
    grows, and mmap regions appear as the target runs. Re-parse whenever you
    need to be sure.
    """

    def __init__(self, regions: List[MapRegion]):
        self.regions = regions

    @classmethod
    def parse(cls, text: str) -> "MemoryMap":
        regions = []
        for line in text.splitlines():
            m = _MAPS_RE.match(line.strip())
            if not m:
                continue
            regions.append(
                MapRegion(
                    start=int(m.group("start"), 16),
                    end=int(m.group("end"), 16),
                    perms=m.group("perms"),
                    offset=int(m.group("offset"), 16),
                    dev=m.group("dev"),
                    inode=int(m.group("inode")),
                    path=m.group("path").strip(),
                )
            )
        return cls(regions)

    @classmethod
    def from_pid(cls, pid: int) -> "MemoryMap":
        with open("/proc/%d/maps" % pid, "r") as fh:
            return cls.parse(fh.read())

    # ---- lookup ----------------------------------------------------------
    def find(self, needle: str) -> List[MapRegion]:
        """Every region whose path contains *needle*."""
        return [r for r in self.regions if needle in r.path]

    def containing(self, addr: int) -> Optional[MapRegion]:
        for r in self.regions:
            if r.contains(addr):
                return r
        return None

    def base(self, needle: str) -> Optional[int]:
        """Lowest load address of the mapping whose path contains *needle*.

        This is ground truth for a libc/binary base - the same number a leak
        is trying to produce, which is what makes it useful as an oracle.
        """
        hits = self.find(needle)
        return min(r.start for r in hits) if hits else None

    def exe_regions(self, exe_path: str) -> List[MapRegion]:
        """Regions backed by the main executable (matched on basename)."""
        name = os.path.basename(exe_path)
        return [r for r in self.regions if os.path.basename(r.path) == name]

    def heap_base(self, exe_path: Optional[str] = None) -> Optional[int]:
        """Address of the brk heap.

        Prefers the ``[heap]`` label. Container kernels frequently omit it for
        the brk mapping, so the fallback is the lowest anonymous ``rw-p`` region
        at or above the main executable's highest mapping, which is where brk
        sits. Getting this wrong tends to fail silently, so the fallback is
        worth reading before you trust it.
        """
        for r in self.regions:
            if r.path == "[heap]":
                return r.start

        anchor = 0
        if exe_path:
            ends = [r.end for r in self.exe_regions(exe_path)]
            if ends:
                anchor = max(ends)

        cands = [
            r.start
            for r in self.regions
            if r.is_anon and r.writable and r.start >= anchor
        ]
        if cands:
            return min(cands)

        # Last resort: the historical heuristic for unlabelled PIE heaps.
        cands = [
            r.start
            for r in self.regions
            if r.is_anon and r.writable and _PIE_RANGE[0] <= r.start < _PIE_RANGE[1]
        ]
        return min(cands) if cands else None

    def __iter__(self) -> Iterator[MapRegion]:
        return iter(self.regions)

    def __len__(self) -> int:
        return len(self.regions)

    def __str__(self) -> str:
        return "\n".join(str(r) for r in self.regions)


class MemReader:
    """Reads another process's memory through ``/proc/<pid>/mem``.

    Requires no privileges beyond being the parent (or root). Reads that touch
    an unmapped page raise :class:`~heapscope.errors.Unmapped` rather than
    returning short data, because a silent short read is how heap walkers end
    up reporting nonsense.
    """

    def __init__(self, pid: int):
        self.pid = pid
        self._fd: Optional[int] = None

    def _fd_or_open(self) -> int:
        if self._fd is None:
            self._fd = os.open("/proc/%d/mem" % self.pid, os.O_RDONLY)
        return self._fd

    def read(self, addr: int, size: int) -> bytes:
        fd = self._fd_or_open()
        out = bytearray()
        while len(out) < size:
            try:
                chunk = os.pread(fd, size - len(out), addr + len(out))
            except OSError as exc:
                raise Unmapped(addr, size, len(out)) from exc
            if not chunk:
                break
            out += chunk
        if len(out) != size:
            raise Unmapped(addr, size, len(out))
        return bytes(out)

    def try_read(self, addr: int, size: int) -> Optional[bytes]:
        """Read, returning ``None`` instead of raising when unmapped."""
        try:
            return self.read(addr, size)
        except Unmapped:
            return None

    # ---- scalars ---------------------------------------------------------
    def u8(self, addr: int) -> int:
        return struct.unpack("<B", self.read(addr, 1))[0]

    def u16(self, addr: int) -> int:
        return struct.unpack("<H", self.read(addr, 2))[0]

    def u32(self, addr: int) -> int:
        return struct.unpack("<I", self.read(addr, 4))[0]

    def u64(self, addr: int) -> int:
        return struct.unpack("<Q", self.read(addr, 8))[0]

    def try_u64(self, addr: int) -> Optional[int]:
        raw = self.try_read(addr, 8)
        return struct.unpack("<Q", raw)[0] if raw else None

    def cstring(self, addr: int, maxlen: int = 256) -> bytes:
        """Read a NUL-terminated string, truncated at *maxlen*."""
        out = bytearray()
        while len(out) < maxlen:
            step = min(64, maxlen - len(out))
            raw = self.try_read(addr + len(out), step)
            if not raw:
                break
            idx = raw.find(b"\x00")
            if idx >= 0:
                out += raw[:idx]
                break
            out += raw
        return bytes(out)

    def close(self) -> None:
        if self._fd is not None:
            try:
                os.close(self._fd)
            except OSError:
                pass
            self._fd = None

    def __enter__(self) -> "MemReader":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
