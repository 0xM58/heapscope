#!/usr/bin/env python3
"""Measure a target's real heap layout, rather than recalling it.

Dumps the first bytes of the heap and decodes ``tcache_perthread_struct``, then
locates the first chunk header by scanning for the first plausible one after the
tcache struct. This is the tool that produced the layout numbers quoted in the
README; run it against your own target to get yours.

    python3 tools/measure_heap_layout.py -- /path/to/target

glibc's struct layouts are version-dependent, and remembering them is not the
same as knowing them. glibc 2.30 widened ``counts[]`` from one byte to two,
which moves ``entries[]`` and the first user chunk by 64 bytes. This measures
that rather than assuming it.
"""

from __future__ import annotations

import argparse
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from heapscope import Probe, tcache_entries_offset  # noqa: E402

DUMP_SIZE = 0x400


def hexdump(blob: bytes, base: int, width: int = 16) -> None:
    for off in range(0, len(blob), width):
        row = blob[off:off + width]
        hexs = " ".join("%02x" % b for b in row)
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
        print("  %#012x  %-47s  %s" % (base + off, hexs, text))


def first_chunk_header(blob: bytes, search_from: int) -> int:
    """Offset of the first plausible chunk header at or after *search_from*.

    Validity is judged on the size field alone - minimum size, 16-byte
    alignment, and PREV_INUSE set (the tcache chunk is in use, so the chunk
    after it has it). It deliberately does *not* require the chunk to fit in
    the dump: the top chunk's size spans the rest of the heap, so a
    fits-in-buffer test would reject exactly the header we are looking for.
    """
    off = search_from
    while off + 0x10 <= len(blob):
        _prev, raw_size = struct.unpack_from("<QQ", blob, off)
        size = raw_size & ~0xF
        if raw_size & 0x1 and 0x20 <= size <= 0x1000_0000 and size % 0x10 == 0:
            return off
        off += 0x10
    return -1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--libc", help="path to the target's libc")
    ap.add_argument("--wait", type=float, default=0.4,
                    help="quiet period before reading (default 0.4s)")
    ap.add_argument("target", nargs=argparse.REMAINDER)
    args = ap.parse_args()

    argv = list(args.target)
    if argv and argv[0] == "--":
        argv = argv[1:]
    if not argv:
        print("error: no target given (use: measure_heap_layout.py -- ./target)",
              file=sys.stderr)
        return 2

    p = Probe(argv, libc=args.libc)
    try:
        p.recv(quiet=args.wait)

        base = p.heap_base()
        if base is None:
            print("error: could not locate the heap", file=sys.stderr)
            return 1

        region = p.heap_region()
        print("pid         %d" % p.pid)
        print("heap base   %#x" % base)
        print("heap region %s" % (region if region else "unknown"))

        layout = p.glibc
        counts_size = layout.tcache_counts_size if layout else 1
        print("glibc       %s (counts[] width = %d byte(s))"
              % (layout.version if layout else "unknown", counts_size))
        print()

        blob = p.mem(base, DUMP_SIZE)
        print("=== first %#x bytes of the heap ===" % DUMP_SIZE)
        hexdump(blob, base)

        prev, size = struct.unpack_from("<QQ", blob, 0x00)
        print("\ntcache chunk header: prev_size=%#x size=%#x" % (prev, size))
        print("  (size & ~0xf = %#x, the tcache chunk's own size)" % (size & ~0xF))

        counts_off = 0x10
        entries_off = tcache_entries_offset(counts_size)
        print("counts[]  at heap+%#x" % counts_off)
        print("entries[] at heap+%#x" % entries_off)

        fmt = "<B" if counts_size == 1 else "<H"
        used = [(i, struct.unpack_from(fmt, blob, counts_off + i * counts_size)[0])
                for i in range(64)]
        used = [(i, c) for i, c in used if c]
        print("non-empty tcache bins: %s" % (used or "none"))

        guess = first_chunk_header(blob, entries_off + 64 * 8)
        print("\nfirst chunk header at heap+%#x" % guess)
        print("  -> derived first_chunk_offset = %#x" % guess)
        print("  -> for comparison, 0x10 + 64*%d + 512 = %#x"
              % (counts_size, 0x10 + 64 * counts_size + 512))
        return 0
    finally:
        p.close()


if __name__ == "__main__":
    sys.exit(main())
