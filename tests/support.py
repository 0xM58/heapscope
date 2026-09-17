"""Shared fixtures for the snapshot tests.

The describe layer, the terminal UI and the snapshot format all work on the
same :class:`~heapscope.snapshot.HeapSnapshot` shape, so they all want the same
builders. Keeping them here means a change to that shape is fixed in one place.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from heapscope.heap import tcache_size_for_index
from heapscope.snapshot import HeapSnapshot

LIBC_BASE = 0x7FFFF7C00000
LIBC_END = LIBC_BASE + 0x200000
HEAP_BASE = 0x555555559000

#: ``bin_at(av, 1)`` for the glibc 2.36 the demo runs against. The value a freed
#: unsorted chunk receives in ``fd``.
UNSORTED_OFF = 0x1D3CC0

#: A tcache head holding stale chunk data. Above 2**53, so it does not survive a
#: trip through a JavaScript number.
STALE_HEAD = 0x4343434616161619


def chunk(header: int, size: int, is_top: bool = False,
          fd: Optional[int] = None, bk: Optional[int] = None,
          digest: str = "00") -> Dict[str, Any]:
    """One chunk record, shaped the way ``HeapSnapshot.capture`` writes it."""
    return {
        "header": header,
        "addr": header + 0x10,
        "size": size,
        "raw_size": size | 1,
        "digest": digest,
        "is_top": is_top,
        "fd": fd,
        "bk": bk,
    }


def bin_(index: int, count: int, head: Optional[int] = None,
         entries: Optional[List[int]] = None,
         truncated: bool = False) -> Dict[str, Any]:
    """One tcache bin record."""
    return {
        "count": count,
        "size": tcache_size_for_index(index),
        "head": head,
        "entries": list(entries or []),
        "truncated": truncated,
    }


def build(label: str, chunks: List[Dict[str, Any]],
          tcache: Optional[Dict[int, Dict[str, Any]]] = None,
          base: int = HEAP_BASE,
          region_end: Optional[int] = None,
          libc_base: Optional[int] = LIBC_BASE,
          libc_end: Optional[int] = LIBC_END,
          offsets: Optional[Dict[str, int]] = None,
          glibc: Optional[str] = "2.36",
          pid: Optional[int] = None,
          truncated: bool = False) -> HeapSnapshot:
    """A snapshot shaped like the one ``capture`` writes.

    Chunk states are deliberately not stored: they are derived when needed, so a
    snapshot only carries the raw fields.
    """
    snap = HeapSnapshot(label=label, base=base, libc_base=libc_base,
                        libc_end=libc_end, glibc=glibc, pid=pid,
                        truncated=truncated)
    snap.region_end = region_end
    snap.offsets = dict(offsets or {})
    snap.chunks = [dict(c) for c in chunks]
    snap.tcache = tcache or {}
    return snap


def unsorted_chunk(header: int = 0x2000, size: int = 0x490,
                   alone: bool = True) -> Dict[str, Any]:
    """A chunk sitting in the unsorted bin, as a real one looks.

    The unsorted bin is a circular doubly-linked list headed by
    ``bin_at(av, 1)``. A chunk that is alone has both pointers on that head. A
    chunk sharing the bin has one pointer on the head and the other on the next
    chunk, which is a heap address, so only one of the two is a libc pointer.
    """
    arena = LIBC_BASE + UNSORTED_OFF
    if alone:
        return chunk(header, size, fd=arena, bk=arena)
    return chunk(header, size, fd=HEAP_BASE + 0x3000, bk=arena)
