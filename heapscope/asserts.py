"""Assertions and layout snapshots.

Exploit code breaks *silently*. A libc update moves ``__free_hook`` by 0x8, an
image rebuild changes a struct layout, and the exploit does not crash - it just
stops working, three stages after the thing that actually changed. Nothing in
the normal toolchain catches that, because exploit code has no test suite.

So record the facts you are relying on and assert them on every run. Snapshots
serialise to JSON, so one can live in a repository and be checked in CI.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional

from .errors import LayoutDrift
from .glibc import GlibcLayout

__all__ = ["LayoutSnapshot", "assert_layout"]

#: Offset fields captured by default - the ones exploits actually depend on.
DEFAULT_OFFSETS = (
    "main_arena", "unsorted_bin", "free_hook", "malloc_hook",
    "stdout", "system", "setcontext", "file_jumps",
)


@dataclass
class LayoutSnapshot:
    """A record of the environment facts an exploit depends on.

    Note what is *not* here: absolute addresses. Those change on every run
    under ASLR and asserting them would be meaningless. What is recorded is
    everything that should be stable across runs of the same target - symbol
    offsets, the chunk-size sequence your script produces, and tcache
    occupancy.
    """

    name: str = "default"
    version: Optional[str] = None
    offsets: Dict[str, int] = field(default_factory=dict)
    chunk_sizes: List[int] = field(default_factory=list)
    tcache_counts: Dict[int, int] = field(default_factory=dict)

    @classmethod
    def capture(cls, probe, name: str = "default",
                offsets=DEFAULT_OFFSETS) -> "LayoutSnapshot":
        """Record the current layout of *probe*."""
        snap = cls(name=name)

        layout: Optional[GlibcLayout] = probe.glibc
        if layout is not None:
            snap.version = layout.version
            for key in offsets:
                value = getattr(layout, key, None)
                if value is not None:
                    snap.offsets[key] = value

        heap = probe.heap()
        snap.chunk_sizes = [c.size for c in heap.chunks if not c.is_top]
        snap.tcache_counts = {i: b.count for i, b in heap.tcache.items() if b.count}
        return snap

    # ---- comparison ------------------------------------------------------
    def diff(self, other: "LayoutSnapshot") -> Dict[str, tuple]:
        """Differences between this snapshot and *other*."""
        changes: Dict[str, tuple] = {}
        if self.version != other.version:
            changes["glibc version"] = (self.version, other.version)

        for key in sorted(set(self.offsets) | set(other.offsets)):
            a, b = self.offsets.get(key), other.offsets.get(key)
            if a != b:
                changes["offset." + key] = (
                    "n/a" if a is None else "%#x" % a,
                    "n/a" if b is None else "%#x" % b,
                )

        if self.chunk_sizes != other.chunk_sizes:
            changes["chunk_sizes"] = (
                "%d chunks" % len(self.chunk_sizes),
                "%d chunks" % len(other.chunk_sizes),
            )

        if self.tcache_counts != other.tcache_counts:
            changes["tcache_counts"] = (self.tcache_counts, other.tcache_counts)

        return changes

    def assert_unchanged(self, other: "LayoutSnapshot") -> None:
        """Raise :class:`~heapscope.errors.LayoutDrift` if *other* differs."""
        changes = self.diff(other)
        if changes:
            raise LayoutDrift(changes)

    def verify(self, probe) -> None:
        """Capture *probe* and assert it still matches this snapshot."""
        self.assert_unchanged(self.capture(probe, name=self.name))

    # ---- persistence -----------------------------------------------------
    def save(self, path: str) -> None:
        with open(path, "w") as fh:
            json.dump(asdict(self), fh, indent=2, sort_keys=True)

    @classmethod
    def load(cls, path: str) -> "LayoutSnapshot":
        with open(path) as fh:
            raw = json.load(fh)
        raw["tcache_counts"] = {int(k): v for k, v in raw.get("tcache_counts", {}).items()}
        return cls(**raw)

    def __str__(self) -> str:
        return "layout %r glibc=%s offsets=%d chunks=%d tcache_bins=%d" % (
            self.name, self.version, len(self.offsets),
            len(self.chunk_sizes), len(self.tcache_counts),
        )


def assert_layout(probe, snapshot: LayoutSnapshot) -> None:
    """Assert that *probe*'s layout still matches *snapshot*."""
    snapshot.verify(probe)
