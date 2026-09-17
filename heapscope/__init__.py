"""heapscope - headless glibc heap introspection and assertions.

Exploit development has debuggers and it has exploit frameworks, but it has no
*test* story. This library fills that gap: it observes a heap without a
debugger, without ``ptrace`` and without ``LD_PRELOAD``, and it lets you assert
the facts your exploit depends on so a silent environment change fails loudly
instead of mysteriously.

Quick start::

    from heapscope import Probe

    with Probe(["./chall"], libc="./libc.so.6") as p:
        p.recvuntil(b"Choice? ")

        before = p.heap()                  # chunks, tcache, bins - as data
        run_the_operation_you_are_debugging()

        print(before.diff(p.heap()))       # what did that actually change?
        p.assert_leak(leaked, kind="libc") # raises unless it is exactly right

Nothing here writes to the target. Every observation is a read of
``/proc/<pid>/mem``, which is available to the parent process with no attach
step - so observing the target cannot perturb the heap you are observing.
"""

from .asserts import LayoutSnapshot, assert_layout
from .errors import (
    HeapCorrupt,
    HeapscopeError,
    LayoutDrift,
    LayoutUnknown,
    LeakMismatch,
    ProcessDied,
    Unmapped,
)
from .glibc import GlibcLayout, detect_version, elf_symbols
from .heap import (
    Chunk,
    HeapDiff,
    HeapView,
    TcacheBin,
    first_chunk_offset,
    tcache_entries_offset,
    tcache_index_for_size,
    tcache_size_for_index,
)
from .memory import MapRegion, MemReader, MemoryMap
from .probe import Diagnosis, Probe
from .describe import Finding, classify_chunk, snapshot_findings
from .snapshot import HeapSnapshot

__version__ = "0.1.0"

__all__ = [
    # harness
    "Probe",
    "Diagnosis",
    # memory
    "MemoryMap",
    "MapRegion",
    "MemReader",
    # glibc
    "GlibcLayout",
    "elf_symbols",
    "detect_version",
    # heap
    "HeapView",
    "Chunk",
    "TcacheBin",
    "HeapDiff",
    "tcache_index_for_size",
    "tcache_size_for_index",
    "tcache_entries_offset",
    "first_chunk_offset",
    # assertions
    "LayoutSnapshot",
    "assert_layout",
    # snapshots and the two front ends
    "HeapSnapshot",
    "Finding",
    "classify_chunk",
    "snapshot_findings",
    # errors
    "HeapscopeError",
    "ProcessDied",
    "Unmapped",
    "HeapCorrupt",
    "LayoutUnknown",
    "LayoutDrift",
    "LeakMismatch",
    "__version__",
]
