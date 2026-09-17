"""Heap snapshots: a heap frozen at one moment, and written to disk.

``heapscope`` is headless on purpose. The assertions are meant to run in CI,
with no debugger and no display, and that is the whole reason the library
exists. But a heap *diff* is hard to read as text:

    +1 chunk(s): 0x55555555a310
    ~0x55555555a2a0 size=0x1fd60 1ceaf73df40e -> size=0x70 ba94a82a8a5c
    tcache[5] count 0->1 head None->0x55555555a2b0

That tells you something moved. It does not tell you what the heap looks like
now, so you rebuild the layout in your head from four addresses. A snapshot is
how you avoid that: dump one at each stage you care about, and read them back
afterwards, once, without the target running.

    from heapscope import HeapSnapshot

    with Probe(["./chall"]) as p:
        p.recvuntil(b"Choice? ")
        HeapSnapshot.capture(p, label="start").save("stages/01.json")
        ...
        HeapSnapshot.capture(p, label="after free(0)").save("stages/03.json")

    heapscope tui stages/

Unlike :class:`~heapscope.asserts.LayoutSnapshot`, this *does* record absolute
addresses. That is deliberate: a layout snapshot exists to catch drift across
runs, so addresses would make it useless. A heap snapshot exists to be read, so
the addresses are the point.

The headless property is kept intact. Nothing here reads or writes a process,
and loading a snapshot back never touches a target.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence

from .asserts import DEFAULT_OFFSETS
from .heap import HeapDiff

__all__ = ["HeapSnapshot", "load_snapshots"]

#: Bumped when the on-disk shape changes, so a stale snapshot fails loudly.
FORMAT = "heapscope.heapview/1"


def _libc_bounds(probe) -> "tuple[Optional[int], Optional[int]]":
    """Start and end of the target's libc mapping, for pointer classification.

    Recorded so that reading a snapshot back can tell a real freelist pointer
    from whatever happens to sit in the first 16 bytes of an allocated chunk's
    user data, without the target still being alive to ask.
    """
    try:
        regions = [r for r in probe.maps().regions if "libc" in (r.path or "")]
    except Exception:
        return None, None
    if not regions:
        return None, None
    return min(r.start for r in regions), max(r.end for r in regions)


@dataclass
class HeapSnapshot:
    """A point-in-time heap, serialised.

    Unlike :class:`~heapscope.asserts.LayoutSnapshot`, this *does* record
    absolute addresses. That is deliberate: a layout snapshot exists to catch
    drift across runs, so addresses would make it useless. A heap snapshot
    exists to be drawn, so the addresses are the point.
    """

    label: str = "snapshot"
    pid: Optional[int] = None
    glibc: Optional[str] = None
    base: int = 0
    region_end: Optional[int] = None
    truncated: bool = False
    libc_base: Optional[int] = None
    libc_end: Optional[int] = None
    offsets: Dict[str, int] = field(default_factory=dict)
    chunks: List[Dict[str, Any]] = field(default_factory=list)
    tcache: Dict[int, Dict[str, Any]] = field(default_factory=dict)
    format: str = FORMAT

    # ---- capture ---------------------------------------------------------
    @classmethod
    def capture(cls, probe, label: str = "snapshot") -> "HeapSnapshot":
        """Read the current heap of *probe* into a serialisable snapshot."""
        heap = probe.heap()

        snap = cls(label=label, pid=getattr(probe, "pid", None))
        snap.base = heap.base
        snap.region_end = heap.region_end
        snap.truncated = heap.truncated

        layout = probe.glibc
        if layout is not None:
            snap.glibc = layout.version
            for key in DEFAULT_OFFSETS:
                value = getattr(layout, key, None)
                if value is not None:
                    snap.offsets[key] = value

        snap.libc_base, snap.libc_end = _libc_bounds(probe)

        for chunk in heap.chunks:
            snap.chunks.append({
                "header": chunk.header,
                "addr": chunk.addr,
                "size": chunk.size,
                "raw_size": chunk.raw_size,
                "digest": chunk.digest(),
                "is_top": chunk.is_top,
                "fd": chunk.fd,
                "bk": chunk.bk,
            })

        for index, bin_ in heap.tcache.items():
            snap.tcache[index] = {
                "count": bin_.count,
                "size": bin_.size,
                "head": bin_.head,
                "entries": list(bin_.entries),
                "truncated": bin_.truncated,
            }
        return snap

    # ---- queries over a loaded snapshot ----------------------------------
    def tcache_members(self) -> set:
        """Every address that sits in some tcache chain."""
        return {e for b in self.tcache.values() for e in b["entries"]}

    def _by_header(self) -> Dict[int, "tuple[int, str]"]:
        return {c["header"]: (c["size"], c["digest"]) for c in self.chunks}

    def diff(self, other: "HeapSnapshot") -> HeapDiff:
        """Compare this (earlier) snapshot against a later one.

        Reuses :class:`~heapscope.heap.HeapDiff` so the text rendering, the
        ``tcache_changed`` helper and the semantics stay identical to the
        library's own diffing.
        """
        before, after = self._by_header(), other._by_header()

        result = HeapDiff()
        result.added = sorted(set(after) - set(before))
        result.removed = sorted(set(before) - set(after))
        for addr in sorted(set(before) & set(after)):
            b_size, b_digest = before[addr]
            a_size, a_digest = after[addr]
            if (b_size, b_digest) != (a_size, a_digest):
                result.changed.append((
                    addr,
                    "size=%#x %s" % (b_size, b_digest),
                    "size=%#x %s" % (a_size, a_digest),
                ))
        result.tcache_before = {i: (b["count"], b["head"]) for i, b in self.tcache.items()}
        result.tcache_after = {i: (b["count"], b["head"]) for i, b in other.tcache.items()}
        return result

    # ---- persistence -----------------------------------------------------
    def to_dict(self) -> Dict[str, Any]:
        data = dict(self.__dict__)
        data["tcache"] = {str(k): v for k, v in self.tcache.items()}
        return data

    @classmethod
    def from_dict(cls, raw: Dict[str, Any]) -> "HeapSnapshot":
        if raw.get("format") != FORMAT:
            raise ValueError(
                "unsupported snapshot format %r (this build writes %r)"
                % (raw.get("format"), FORMAT))
        data = dict(raw)
        data["tcache"] = {int(k): v for k, v in raw.get("tcache", {}).items()}
        return cls(**data)

    def save(self, path: str) -> None:
        directory = os.path.dirname(path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        with open(path, "w") as fh:
            json.dump(self.to_dict(), fh, indent=1, sort_keys=True)

    @classmethod
    def load(cls, path: str) -> "HeapSnapshot":
        with open(path) as fh:
            return cls.from_dict(json.load(fh))

    def __str__(self) -> str:
        return "heap %r @ %#x chunks=%d tcache_bins=%d%s" % (
            self.label, self.base, len(self.chunks), len(self.tcache),
            " (truncated)" if self.truncated else "")


def load_snapshots(paths: Sequence[str]) -> List[HeapSnapshot]:
    """Load snapshots from files and directories, sorted by name.

    Directories are searched for ``*.json``, so ``stages/01.json``,
    ``stages/02.json`` and so on come back in the order you numbered them.
    """
    found: List[str] = []
    for path in paths:
        if os.path.isdir(path):
            found.extend(
                os.path.join(path, name)
                for name in sorted(os.listdir(path))
                if name.endswith(".json")
            )
        else:
            found.append(path)
    return [HeapSnapshot.load(p) for p in found]
