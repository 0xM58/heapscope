"""Turn a heap snapshot into facts a person can read.

This is the layer between a snapshot and whoever is showing it. It holds the
reasoning: which state a chunk is in, which anomalies are worth pointing out,
and the sentences explaining what the numbers mean. Keeping it out of the
curses code means what counts as anomalous is decided in one place, and it
keeps 64-bit pointer arithmetic out of the presentation layer.

Nothing here reads a process. It works on a
:class:`~heapscope.snapshot.HeapSnapshot`, which is plain data, so all of it is
testable without a target.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple

from .heap import (
    CHUNK_HDR,
    IS_MMAPPED,
    NON_MAIN_ARENA,
    PREV_INUSE,
    tcache_index_for_size,
    tcache_size_for_index,
)

if TYPE_CHECKING:  # pragma: no cover - import for annotations only
    from .snapshot import HeapSnapshot

__all__ = [
    "Finding",
    "INFO",
    "WARN",
    "classify_chunk",
    "snapshot_states",
    "snapshot_findings",
    "chunk_facts",
    "chunk_notes",
    "bin_facts",
    "bin_notes",
    "hexfmt",
]

#: Levels a finding can carry. Ordered by how much attention they want.
INFO = "info"
WARN = "warn"

#: Chunk states, as produced by :func:`classify_chunk`.
TOP = "top"
TCACHE = "tcache"
UNSORTED = "unsorted"
LIVE = "live"


def hexfmt(value: Optional[int]) -> str:
    """A 64-bit value as hex, or a dash when it is absent.

    ``None`` renders as ``-`` rather than ``0x0`` so that "no pointer here" and
    "a pointer to address zero" stay distinguishable.
    """
    return "-" if value is None else "%#x" % value


def _flag_letters(raw_size: int) -> str:
    """The three flag bits, in the same letters ``Chunk.__str__`` uses."""
    return "".join([
        "P" if raw_size & PREV_INUSE else "-",
        "M" if raw_size & IS_MMAPPED else "-",
        "A" if raw_size & NON_MAIN_ARENA else "-",
    ])


def _flag_names(raw_size: int) -> List[str]:
    names = []
    if raw_size & PREV_INUSE:
        names.append("prev_inuse")
    if raw_size & IS_MMAPPED:
        names.append("mmapped")
    if raw_size & NON_MAIN_ARENA:
        names.append("non_main_arena")
    return names


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------

def heap_bounds(snap: "HeapSnapshot") -> Tuple[int, int]:
    """The heap region, with the same fallback the walker uses."""
    return snap.base, (snap.region_end or snap.base + 0x1000_0000)


def in_libc(snap: "HeapSnapshot", value: Optional[int]) -> bool:
    return bool(value) and bool(snap.libc_base) and bool(snap.libc_end) \
        and snap.libc_base <= value < snap.libc_end


def in_heap(snap: "HeapSnapshot", value: Optional[int]) -> bool:
    if not value:
        return False
    low, high = heap_bounds(snap)
    return low <= value < high


def classify_chunk(snap: "HeapSnapshot", chunk: Dict[str, Any],
                   members: Optional[set] = None) -> str:
    """Which state a chunk is in.

    ``members`` is the set of addresses sitting in some tcache chain. Pass it in
    when classifying many chunks so it is built once; see
    :func:`snapshot_states`.
    """
    if chunk["is_top"]:
        return TOP
    if members is None:
        members = snap.tcache_members()
    if chunk["addr"] in members:
        return TCACHE

    fd, bk = chunk["fd"], chunk["bk"]
    if not (fd and bk):
        return LIVE

    # An unsorted-bin chunk is on the arena's doubly-linked list. One of its two
    # pointers is the list head in libc, and the other is either that same head
    # (when the chunk is alone) or another chunk in the heap.
    #
    # Note what this is not: "both pointers are in libc" only holds for a bin
    # holding exactly one chunk. With two chunks the first one has fd in the
    # heap and bk in libc, so that rule would miss it. What actually separates a
    # freed chunk from a live one is that a live chunk's first 16 bytes are user
    # data, and one stray libc pointer there is ordinary, while two pointers
    # that both land somewhere sensible are not.
    if in_libc(snap, fd) and (in_libc(snap, bk) or in_heap(snap, bk)):
        return UNSORTED
    if in_libc(snap, bk) and (in_libc(snap, fd) or in_heap(snap, fd)):
        return UNSORTED
    return LIVE


def snapshot_states(snap: "HeapSnapshot") -> Dict[int, str]:
    """State of every chunk, keyed by header address.

    One pass, so the tcache membership set is built once instead of per chunk.
    """
    members = snap.tcache_members()
    return {c["header"]: classify_chunk(snap, c, members) for c in snap.chunks}


def _state_label(state: str, snap: "HeapSnapshot", chunk: Dict[str, Any]) -> str:
    """A short phrase for the state, for a label/value row."""
    if state == TOP:
        return "top chunk, unallocated"
    if state == TCACHE:
        index = tcache_index_for_size(chunk["size"])
        return "in tcache bin %d" % index
    if state == UNSORTED:
        return "in the unsorted bin"
    # Not top, not tcache, not unsorted. It may still be free, sitting in a
    # fastbin or a smallbin, which this library does not walk.
    return "allocated, or in a bin we do not walk"


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Finding:
    """One thing worth pointing out, and where it applies."""

    level: str
    scope: str
    message: str


def snapshot_findings(snap: "HeapSnapshot") -> List[Finding]:
    """Everything anomalous about a snapshot.

    The single source of truth for the warnings shown about a snapshot, so the
    header count, the per-item list and the detail pane cannot disagree.
    """
    out: List[Finding] = []

    for index in sorted(snap.tcache):
        b = snap.tcache[index]
        scope = "tcache[%d]" % index
        count, entries, head = b["count"], b["entries"], b["head"]

        if b["truncated"]:
            out.append(Finding(WARN, scope,
                               "the chain is broken or cyclic, so the walk "
                               "stopped early"))
        if head and len(entries) != count:
            out.append(Finding(WARN, scope,
                               "count says %d but %d chunk(s) could be walked"
                               % (count, len(entries))))
        if not count and head:
            out.append(Finding(WARN, scope,
                               "the bin is empty but its head still holds a "
                               "pointer, so the next free will link to it"))
        if count and not head:
            out.append(Finding(WARN, scope,
                               "count says %d but the head is NULL" % count))

    if snap.truncated:
        out.append(Finding(WARN, "heap",
                           "the chunk walk stopped before the end of the "
                           "region, so this list is incomplete"))

    unsorted = [c for c in snap.chunks
                if classify_chunk(snap, c, snap.tcache_members()) == UNSORTED]
    for chunk in unsorted:
        if chunk["fd"] != chunk["bk"]:
            out.append(Finding(INFO, hexfmt(chunk["header"]),
                               "fd and bk differ, so this chunk is not alone "
                               "in the unsorted bin"))

    return out


# ---------------------------------------------------------------------------
# Describing one chunk
# ---------------------------------------------------------------------------

def chunk_facts(snap: "HeapSnapshot", chunk: Dict[str, Any],
                state: Optional[str] = None) -> List[Tuple[str, str]]:
    """Label/value rows describing one chunk."""
    if state is None:
        state = classify_chunk(snap, chunk)

    raw = chunk["raw_size"]
    names = _flag_names(raw)
    # The first 16 bytes are freelist pointers only when the chunk is actually
    # in a bin. On a live chunk they are user data, and calling them fd and bk
    # invites you to read meaning into them that is not there.
    linked = state in (TCACHE, UNSORTED)
    return [
        ("header", hexfmt(chunk["header"])),
        ("user", hexfmt(chunk["addr"])),
        ("size", "%#x  (%d bytes, %d usable)"
         % (chunk["size"], chunk["size"], max(0, chunk["size"] - CHUNK_HDR))),
        ("size field", "%#x" % raw),
        ("flags", "%s  (%s)" % (_flag_letters(raw),
                                ", ".join(names) if names else "none")),
        ("state", _state_label(state, snap, chunk)),
        ("fd" if linked else "user+0", hexfmt(chunk["fd"])),
        ("bk" if linked else "user+8", hexfmt(chunk["bk"])),
        ("digest", chunk["digest"]),
    ]


def _entry_of(snap: "HeapSnapshot", chunk: Dict[str, Any]) -> Optional[Tuple[int, int, int]]:
    """``(bin index, position, walked length)`` if the chunk is in a chain."""
    index = tcache_index_for_size(chunk["size"])
    b = snap.tcache.get(index)
    if b is None:
        return None
    for position, entry in enumerate(b["entries"], 1):
        if entry == chunk["addr"]:
            return index, position, len(b["entries"])
    return None


def chunk_notes(snap: "HeapSnapshot", chunk: Dict[str, Any],
                state: Optional[str] = None) -> List[str]:
    """Plain sentences about what the chunk's numbers mean.

    This is the part a hex dump cannot give you, and the reason the inspector
    exists at all.
    """
    if state is None:
        state = classify_chunk(snap, chunk)

    notes: List[str] = []

    if state == TOP:
        total = (snap.region_end or 0) - chunk["header"]
        notes.append("The heap ends here. %s bytes (%.1f%% of the region) are "
                     "not allocated to anything."
                     % ("%#x" % chunk["size"],
                        100.0 * chunk["size"] / total if total > 0 else 0.0))
        return notes

    if state == TCACHE:
        entry = _entry_of(snap, chunk)
        if entry is None:
            notes.append("Listed as a tcache member, but it is not in the "
                         "chain the walker returned. That should not happen.")
        else:
            index, position, walked = entry
            b = snap.tcache[index]
            notes.append("Entry %d of %d walked in tcache[%d]. The bin's count "
                         "field says %d."
                         % (position, walked, index, b["count"]))
            if b["truncated"]:
                notes.append("The chain does not terminate where the count "
                             "says it should. A tcache double free puts the "
                             "same chunk in the bin twice, which makes the "
                             "last link point back into the chain.")
            if b["head"] == chunk["addr"] and b["count"] > 1:
                notes.append("This chunk is the head, so the next allocation "
                             "from this bin returns it.")
        return notes

    if state == UNSORTED:
        fd, bk = chunk["fd"], chunk["bk"]
        if fd == bk:
            notes.append("fd == bk, so it is alone in the unsorted bin and "
                         "both are bin_at(av, 1) = main_arena + 0x60.")
        else:
            notes.append("fd and bk differ, so other chunks share this bin. "
                         "Only the pointer that reaches the arena is any use "
                         "for a libc leak.")

        # Pick whichever pointer actually lands in libc. With neighbours, only
        # one of the two does, and it is not always fd.
        arena_ptr = fd if in_libc(snap, fd) else (bk if in_libc(snap, bk) else None)
        offset = snap.offsets.get("unsorted_bin")
        if offset and arena_ptr:
            base = arena_ptr - offset
            notes.append("%s - %#x = %#x, which is the libc base if that "
                         "offset is right for this build."
                         % (hexfmt(arena_ptr), offset, base))
            if snap.libc_base and base == snap.libc_base:
                notes.append("That matches the libc mapping, so the offset "
                             "arithmetic holds.")
        return notes

    # Live. Say something only when there is something to say. A chunk's first
    # 16 bytes are user data, so arbitrary non-zero values there are the norm,
    # not a finding; a libc pointer among them is worth a second look because it
    # is also what a leak looks like.
    if in_libc(snap, chunk["fd"]):
        notes.append("The first 8 bytes of user data are %s, which is in libc. "
                     "On an allocated chunk that is just data, but it is also "
                     "a libc pointer sitting in a chunk you may control."
                     % hexfmt(chunk["fd"]))
    return notes


# ---------------------------------------------------------------------------
# Describing one bin
# ---------------------------------------------------------------------------

def bin_facts(snap: "HeapSnapshot", index: int) -> List[Tuple[str, str]]:
    """Label/value rows describing one tcache bin."""
    b = snap.tcache.get(index)
    if b is None:
        return [("bin", str(index)), ("state", "not present in this snapshot")]

    return [
        ("bin", str(index)),
        ("chunk size", "%#x  (%d bytes)" % (tcache_size_for_index(index),
                                            tcache_size_for_index(index))),
        ("count", str(b["count"])),
        ("head", hexfmt(b["head"])),
        ("walked", "%d chunk(s)" % len(b["entries"])),
        ("chain", ", ".join(hexfmt(e) for e in b["entries"]) or "-"),
        ("truncated", "yes" if b["truncated"] else "no"),
    ]


def bin_notes(snap: "HeapSnapshot", index: int) -> List[str]:
    """Plain sentences about what a bin's numbers mean."""
    b = snap.tcache.get(index)
    if b is None:
        return []

    notes: List[str] = []
    count, entries, head = b["count"], b["entries"], b["head"]

    if b["truncated"] and count > len(entries):
        notes.append("The count is %d but only %d distinct chunk(s) could be "
                     "walked before the chain led somewhere it should not. "
                     "This is the signature of a tcache double free."
                     % (count, len(entries)))
    elif b["truncated"]:
        notes.append("The walk stopped early even though the count was "
                     "reached, which means the last link was not a valid "
                     "chunk.")

    if not count and head:
        notes.append("The count is zero but the head is not NULL. That is a "
                     "stale pointer in the entries array: the next free into "
                     "this bin will link to it, and the next allocation will "
                     "return it.")

    if head and not b["truncated"] and count == len(entries) and count:
        notes.append("%d chunk(s) in this bin, head at %s. A tcache bin hands "
                     "out from the head, so that is what the next request of "
                     "this size gets." % (count, hexfmt(head)))

    if not count and not head:
        notes.append("Empty, and the head is NULL. Nothing here.")

    return notes
