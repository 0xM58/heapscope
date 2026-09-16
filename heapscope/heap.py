"""Symbolic views over a live glibc heap.

This module turns a byte range into *chunks, tcache bins and bin lists* so you
can reason about and diff them. It reads through
:class:`heapscope.memory.MemReader`, so it works on any process you are the
parent of, with no debugger attached.

Layout facts used here were measured, not assumed - see the constants below,
each of which was confirmed against a live glibc 2.29 process (Ubuntu
glibc 2.29-0ubuntu2). Where a value is derived rather than measured, that is
called out.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple

from .errors import HeapCorrupt
from .glibc import GlibcLayout
from .memory import MemReader

__all__ = ["Chunk", "TcacheBin", "HeapDiff", "HeapView", "TCACHE_MAX_BINS"]

#: Chunk header size: prev_size + size.
CHUNK_HDR = 0x10

#: Smallest possible chunk: header plus two pointers.
MIN_CHUNK = 0x20

#: Flag bits in the size field.
PREV_INUSE = 0x1
IS_MMAPPED = 0x2
NON_MAIN_ARENA = 0x4

#: Number of tcache bins, and the size of the entries array.
TCACHE_MAX_BINS = 64
TCACHE_ENTRIES_BYTES = TCACHE_MAX_BINS * 8

#: ``counts[]`` begins immediately after the tcache chunk's own header.
#: Measured: the tcache chunk has size 0x251 (0x250 | PREV_INUSE) and its
#: counts array is all-zero at heap+0x10 after the first allocation.
TCACHE_COUNTS_OFF = 0x10

#: Default cap on how many bytes of a chunk are hashed when diffing. Bounds
#: the cost of a diff on a heap holding large buffers.
DEFAULT_SAMPLE = 0x1000


def tcache_index_for_size(size: int) -> int:
    """Tcache bin index for a *request* size, or -1 if too large.

    Bin 0 holds 0x20-byte chunks, bin ``i`` holds ``0x20 + 0x10*i``.
    """
    if size < MIN_CHUNK:
        size = MIN_CHUNK
    size = (size + 0xF) & ~0xF
    idx = (size - MIN_CHUNK) // 0x10
    return idx if 0 <= idx < TCACHE_MAX_BINS else -1


def tcache_size_for_index(idx: int) -> int:
    """Chunk size held by tcache bin *idx*."""
    return MIN_CHUNK + 0x10 * idx


def tcache_counts_offset() -> int:
    return TCACHE_COUNTS_OFF


def tcache_entries_offset(counts_size: int = 1) -> int:
    """Where ``entries[]`` starts, given the width of ``counts[]``.

    glibc 2.29 uses one byte per count; 2.30 widened them to ``uint16_t``,
    which shifts ``entries[]`` by 64 bytes. Measured for 2.29: entries at
    heap+0x50, and the first user chunk at heap+0x250.
    """
    return TCACHE_COUNTS_OFF + TCACHE_MAX_BINS * counts_size


def first_chunk_offset(counts_size: int = 1) -> int:
    """Offset of the first *user chunk header* from the heap base.

    The tcache struct occupies the first chunk, so this is the tcache chunk's
    size: header + counts + entries. Measured as 0x250 for glibc 2.29.
    """
    return CHUNK_HDR + TCACHE_MAX_BINS * counts_size + TCACHE_ENTRIES_BYTES


@dataclass
class Chunk:
    """One ``malloc_chunk``, addressed by its *user* pointer."""

    addr: int                 # user pointer (header + 0x10)
    size: int                 # size with flag bits masked off
    raw_size: int             # size field exactly as stored
    prev_size: int = 0
    fd: Optional[int] = None
    bk: Optional[int] = None
    data: bytes = b""
    is_top: bool = False

    @property
    def header(self) -> int:
        return self.addr - CHUNK_HDR

    @property
    def usable(self) -> int:
        return self.size - CHUNK_HDR

    @property
    def next_header(self) -> int:
        return self.header + self.size

    @property
    def prev_inuse(self) -> bool:
        return bool(self.raw_size & PREV_INUSE)

    @property
    def is_mmapped(self) -> bool:
        return bool(self.raw_size & IS_MMAPPED)

    @property
    def non_main_arena(self) -> bool:
        return bool(self.raw_size & NON_MAIN_ARENA)

    @property
    def tcache_index(self) -> int:
        return tcache_index_for_size(self.size)

    def digest(self, limit: int = DEFAULT_SAMPLE) -> str:
        return hashlib.sha1(self.data[:limit]).hexdigest()[:12]

    def __str__(self) -> str:
        flags = "".join([
            "P" if self.prev_inuse else "-",
            "M" if self.is_mmapped else "-",
            "A" if self.non_main_arena else "-",
        ])
        tail = " [top]" if self.is_top else ""
        return "%#x size=%#x user=%#x flags=%s%s" % (
            self.header, self.size, self.addr, flags, tail)


@dataclass
class TcacheBin:
    """One tcache bin: its count field and the chain it points at."""

    index: int
    count: int
    head: Optional[int]
    entries: List[int] = field(default_factory=list)
    truncated: bool = False   # chain longer than count, or a cycle

    @property
    def size(self) -> int:
        return tcache_size_for_index(self.index)

    def __bool__(self) -> bool:
        return self.count > 0

    def __str__(self) -> str:
        return "tcache[%d] size=%#x count=%d head=%s chain=%s%s" % (
            self.index, self.size, self.count,
            "None" if self.head is None else "%#x" % self.head,
            "[" + ", ".join("%#x" % e for e in self.entries) + "]",
            " (truncated)" if self.truncated else "")


@dataclass
class HeapDiff:
    """What changed between two :class:`HeapView` snapshots."""

    added: List[int] = field(default_factory=list)
    removed: List[int] = field(default_factory=list)
    changed: List[Tuple[int, str, str]] = field(default_factory=list)
    tcache_before: Dict[int, Tuple[int, Optional[int]]] = field(default_factory=dict)
    tcache_after: Dict[int, Tuple[int, Optional[int]]] = field(default_factory=dict)

    @property
    def tcache_changed(self) -> List[int]:
        keys = set(self.tcache_before) | set(self.tcache_after)
        return sorted(k for k in keys
                      if self.tcache_before.get(k) != self.tcache_after.get(k))

    def __bool__(self) -> bool:
        return bool(self.added or self.removed or self.changed or self.tcache_changed)

    def __str__(self) -> str:
        if not self:
            return "heap unchanged"
        parts = []
        if self.added:
            parts.append("+%d chunk(s): %s"
                         % (len(self.added), ", ".join("%#x" % a for a in self.added[:6])))
        if self.removed:
            parts.append("-%d chunk(s): %s"
                         % (len(self.removed), ", ".join("%#x" % a for a in self.removed[:6])))
        for addr, before, after in self.changed[:8]:
            parts.append("~%#x %s -> %s" % (addr, before, after))
        if len(self.changed) > 8:
            parts.append("~... %d more" % (len(self.changed) - 8))
        for idx in self.tcache_changed[:8]:
            b = self.tcache_before.get(idx, (0, None))
            a = self.tcache_after.get(idx, (0, None))
            parts.append("tcache[%d] count %d->%d head %s->%s"
                         % (idx, b[0], a[0],
                            "None" if b[1] is None else "%#x" % b[1],
                            "None" if a[1] is None else "%#x" % a[1]))
        return "\n".join(parts)


class HeapView:
    """A point-in-time, symbolic view of a glibc heap.

    Construct with :meth:`capture`. All reads go through a
    :class:`~heapscope.memory.MemReader`, so nothing here perturbs the target.
    """

    def __init__(self, base: int, chunks: List[Chunk], tcache: Dict[int, TcacheBin],
                 layout: Optional[GlibcLayout] = None, region_end: Optional[int] = None,
                 truncated: bool = False):
        self.base = base
        self.chunks = chunks
        self.tcache = tcache
        self.layout = layout
        self.region_end = region_end
        self.truncated = truncated

    # ---- construction ----------------------------------------------------
    @classmethod
    def capture(cls, reader: MemReader, base: int, layout: Optional[GlibcLayout] = None,
                region_end: Optional[int] = None, max_chunks: int = 4096,
                sample: int = DEFAULT_SAMPLE) -> "HeapView":
        """Read and decode the heap of the process behind *reader*."""
        counts_size = layout.tcache_counts_size if layout else 1

        tcache = cls._decode_tcache(reader, base, counts_size)
        chunks, truncated = cls._walk_chunks(
            reader, base + first_chunk_offset(counts_size),
            region_end or (base + 0x1000_0000), max_chunks, sample,
        )
        return cls(base, chunks, tcache, layout, region_end, truncated)

    @staticmethod
    def _decode_tcache(reader: MemReader, base: int, counts_size: int) -> Dict[int, TcacheBin]:
        """Decode ``tcache_perthread_struct``.

        The count field is authoritative: the chain is walked at most
        ``count`` links, so a poisoned ``fd`` pointing somewhere absurd cannot
        spin forever. A cycle is reported via ``truncated`` instead.
        """
        counts_off = tcache_counts_offset()
        entries_off = tcache_entries_offset(counts_size)

        raw_counts = reader.try_read(base + counts_off, TCACHE_MAX_BINS * counts_size)
        raw_entries = reader.try_read(base + entries_off, TCACHE_ENTRIES_BYTES)
        if raw_counts is None or raw_entries is None:
            return {}

        fmt = "<B" if counts_size == 1 else "<H"
        bins: Dict[int, TcacheBin] = {}
        for idx in range(TCACHE_MAX_BINS):
            count = struct.unpack_from(fmt, raw_counts, idx * counts_size)[0]
            head = struct.unpack_from("<Q", raw_entries, idx * 8)[0]
            if count == 0 and head == 0:
                continue

            entries: List[int] = []
            truncated = False
            cur = head
            seen = set()
            while cur and len(entries) < count:
                if cur in seen:
                    truncated = True
                    break
                seen.add(cur)
                entries.append(cur)
                nxt = reader.try_u64(cur)
                if nxt is None:
                    truncated = True
                    break
                cur = nxt

            bins[idx] = TcacheBin(index=idx, count=count, head=head or None,
                                  entries=entries, truncated=truncated)
        return bins

    @staticmethod
    def _walk_chunks(reader: MemReader, start: int, limit: int, max_chunks: int,
                     sample: int) -> Tuple[List[Chunk], bool]:
        """Follow the chunk chain from *start* to the top chunk."""
        chunks: List[Chunk] = []
        addr = start
        while len(chunks) < max_chunks:
            if addr + CHUNK_HDR > limit:
                break
            head = reader.try_read(addr, CHUNK_HDR + min(sample, MIN_CHUNK))
            if head is None:
                break
            prev_size, raw_size = struct.unpack_from("<QQ", head, 0)
            size = raw_size & ~0xF

            # A chunk that cannot be valid means the heap has already been
            # corrupted - report the walk so far, it is the useful part.
            if size < MIN_CHUNK or size % 0x10 or addr + size > limit:
                if not chunks:
                    raise HeapCorrupt(
                        "chunk chain does not start cleanly at %#x (size=%#x)"
                        % (addr, size), at=addr)
                break

            body_len = min(size - CHUNK_HDR, sample)
            body = reader.try_read(addr + CHUNK_HDR, body_len) or b""
            fd = struct.unpack_from("<Q", body, 0)[0] if len(body) >= 8 else None
            bk = struct.unpack_from("<Q", body, 8)[0] if len(body) >= 16 else None

            is_top = addr + size >= limit
            chunks.append(Chunk(addr=addr + CHUNK_HDR, size=size, raw_size=raw_size,
                                prev_size=prev_size, fd=fd, bk=bk, data=body,
                                is_top=is_top))
            if is_top:
                break
            addr += size
        return chunks, len(chunks) >= max_chunks

    # ---- queries ---------------------------------------------------------
    @property
    def top(self) -> Optional[Chunk]:
        """The top (wilderness) chunk, if the walk reached it."""
        for c in reversed(self.chunks):
            if c.is_top:
                return c
        return None

    def allocated(self) -> List[Chunk]:
        """Chunks that are neither the top chunk nor sitting in tcache.

        Note the address space being compared: a tcache chain links *user*
        pointers (the ``tcache_entry`` is overlaid on the user data), so this
        compares against ``Chunk.addr``, not ``Chunk.header``. This does not
        account for chunks in the fastbins, smallbins or unsorted bin - use
        :meth:`unsorted` for the unsorted bin.
        """
        in_tcache = {e for b in self.tcache.values() for e in b.entries}
        return [c for c in self.chunks
                if not c.is_top and c.addr not in in_tcache]

    def bin_for(self, size: int) -> Optional[TcacheBin]:
        """The tcache bin a request of *size* would use."""
        idx = tcache_index_for_size(size)
        return self.tcache.get(idx) if idx >= 0 else None

    def unsorted(self, reader: MemReader, limit: int = 64) -> List[Chunk]:
        """Walk the unsorted bin.

        The head is ``bin_at(av, 1)`` - a pointer *skewed* 0x10 below
        ``bins[0]`` so that it looks like a chunk - which is why the fd field
        lives at ``head + 0x10``.
        """
        if self.layout is None or self.layout.unsorted_bin is None:
            return []
        head = self.layout.unsorted_bin
        out: List[Chunk] = []
        cur = reader.try_u64(head + CHUNK_HDR)
        seen = set()
        while cur and cur != head and len(out) < limit and cur not in seen:
            seen.add(cur)
            raw = reader.try_u64(cur + 8)
            if raw is None:
                break
            size = raw & ~0xF
            if size < MIN_CHUNK or size % 0x10:
                break
            body = reader.try_read(cur + CHUNK_HDR, min(size - CHUNK_HDR, DEFAULT_SAMPLE)) or b""
            fd = struct.unpack_from("<Q", body, 0)[0] if len(body) >= 8 else None
            bk = struct.unpack_from("<Q", body, 8)[0] if len(body) >= 16 else None
            out.append(Chunk(addr=cur + CHUNK_HDR, size=size, raw_size=raw,
                             fd=fd, bk=bk, data=body))
            cur = fd
        return out

    # ---- diffing ---------------------------------------------------------
    def snapshot(self) -> Dict[int, Tuple[int, str]]:
        return {c.header: (c.size, c.digest()) for c in self.chunks}

    def diff(self, other: "HeapView") -> HeapDiff:
        """Compare this (earlier) view against a later one."""
        before, after = self.snapshot(), other.snapshot()
        d = HeapDiff()
        d.added = sorted(set(after) - set(before))
        d.removed = sorted(set(before) - set(after))
        for addr in sorted(set(before) & set(after)):
            b_size, b_dig = before[addr]
            a_size, a_dig = after[addr]
            if (b_size, b_dig) != (a_size, a_dig):
                d.changed.append(
                    (addr, "size=%#x %s" % (b_size, b_dig),
                     "size=%#x %s" % (a_size, a_dig))
                )
        d.tcache_before = {i: (b.count, b.head) for i, b in self.tcache.items()}
        d.tcache_after = {i: (b.count, b.head) for i, b in other.tcache.items()}
        return d

    # ---- rendering -------------------------------------------------------
    def __str__(self) -> str:
        lines = ["heap @ %#x  chunks=%d%s"
                 % (self.base, len(self.chunks),
                    "  (truncated)" if self.truncated else "")]
        for c in self.chunks:
            lines.append("  " + str(c))
        if self.tcache:
            lines.append("tcache:")
            for idx in sorted(self.tcache):
                lines.append("  " + str(self.tcache[idx]))
        return "\n".join(lines)

    def __len__(self) -> int:
        return len(self.chunks)

    def __iter__(self) -> Iterable[Chunk]:
        return iter(self.chunks)
