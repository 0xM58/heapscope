"""Tests for the symbolic heap view.

These run against a synthetic heap image served by a fake reader, so they need
no live process and no privileges. The image is built to match the layout
measured from a real glibc 2.29 process (see the module docstring in
``heapscope/heap.py``): tcache chunk of size 0x250, first user chunk at
heap+0x250, top chunk after it.
"""

import struct
import unittest

from heapscope.errors import HeapCorrupt
from heapscope.glibc import GlibcLayout
from heapscope.heap import (
    HeapView,
    first_chunk_offset,
    tcache_entries_offset,
    tcache_index_for_size,
    tcache_size_for_index,
)

BASE = 0x555555757000
REGION_END = BASE + 0x400
IMAGE_SIZE = 0x400

# Offsets for the default (glibc 2.29, 1-byte counts) image.
FIRST = first_chunk_offset(1)        # 0x250 - first user chunk header
USER = FIRST + 0x10                  # 0x260 - its user pointer
TOP = FIRST + 0x80                   # 0x2d0 - top chunk header


class FakeReader:
    """Serves a fixed byte image, mimicking MemReader's read interface."""

    def __init__(self, image, base=BASE):
        self.image = image
        self.base = base

    def try_read(self, addr, size):
        off = addr - self.base
        if off < 0 or off + size > len(self.image):
            return None
        return self.image[off:off + size]

    def try_u64(self, addr):
        raw = self.try_read(addr, 8)
        return struct.unpack("<Q", raw)[0] if raw else None


def build_image(counts_size=1, tcache_index=6, tcache_count=1):
    """One 0x80 chunk linked into tcache, followed by the top chunk.

    Offsets are derived from *counts_size* rather than hardcoded, because
    glibc 2.30 widened ``counts[]`` to 16 bits and shifted everything by 64
    bytes - the same trap this suite is meant to guard against.
    """
    first = first_chunk_offset(counts_size)
    img = bytearray(IMAGE_SIZE)

    # tcache chunk header, sized to hold counts[] + entries[]
    struct.pack_into("<Q", img, 0x08, first | 1)

    counts_off = 0x10
    entries_off = tcache_entries_offset(counts_size)
    if tcache_count:
        fmt = "<B" if counts_size == 1 else "<H"
        struct.pack_into(fmt, img, counts_off + tcache_index * counts_size, tcache_count)
        # tcache entries hold *user* pointers, not chunk headers
        struct.pack_into("<Q", img, entries_off + tcache_index * 8, BASE + first + 0x10)

    # first user chunk
    struct.pack_into("<Q", img, first + 8, 0x80 | 1)
    img[first + 0x10:first + 0x10 + 0x40] = b"A" * 0x40

    # top chunk, sized to reach the end of the region
    top = first + 0x80
    struct.pack_into("<Q", img, top + 8, (IMAGE_SIZE - top) | 1)
    return bytes(img)


class TestTcacheMath(unittest.TestCase):
    def test_index_for_size(self):
        self.assertEqual(tcache_index_for_size(0x20), 0)
        self.assertEqual(tcache_index_for_size(0x10), 0)   # rounds up to min
        self.assertEqual(tcache_index_for_size(0x70), 5)
        self.assertEqual(tcache_index_for_size(0x68), 5)   # rounds to 0x70

    def test_index_out_of_range(self):
        self.assertEqual(tcache_index_for_size(0x500), -1)

    def test_size_for_index_round_trips(self):
        for idx in (0, 1, 5, 63):
            self.assertEqual(tcache_index_for_size(tcache_size_for_index(idx)), idx)

    def test_layout_constants_match_a_real_229_heap(self):
        # Measured: tcache chunk size 0x250, entries at heap+0x50.
        self.assertEqual(tcache_entries_offset(1), 0x50)
        self.assertEqual(first_chunk_offset(1), 0x250)
        # 2.30+ widened counts[] to 16 bits, shifting both by 64 bytes.
        self.assertEqual(tcache_entries_offset(2), 0x90)
        self.assertEqual(first_chunk_offset(2), 0x290)


class TestHeapView(unittest.TestCase):
    def capture(self, image=None, counts_size=1, layout=None):
        reader = FakeReader(image if image is not None else build_image(counts_size))
        lay = layout or GlibcLayout(version="2.29", tcache_counts_size=counts_size)
        return HeapView.capture(reader, BASE, lay, region_end=REGION_END)

    def test_walks_the_chunk_chain(self):
        view = self.capture()
        self.assertEqual(len(view.chunks), 2)   # one real chunk plus top
        self.assertEqual(view.chunks[0].addr, BASE + USER)
        self.assertEqual(view.chunks[0].size, 0x80)
        self.assertTrue(view.chunks[0].prev_inuse)

    def test_finds_the_top_chunk(self):
        view = self.capture()
        top = view.top
        self.assertIsNotNone(top)
        self.assertEqual(top.header, BASE + TOP)
        self.assertTrue(top.is_top)

    def test_decodes_tcache(self):
        view = self.capture()
        bin6 = view.bin_for(0x80)
        self.assertIsNotNone(bin6)
        self.assertEqual(bin6.count, 1)
        self.assertEqual(bin6.head, BASE + USER)
        self.assertEqual(bin6.entries, [BASE + USER])

    def test_allocated_excludes_tcache_chunks(self):
        # Regression: tcache entries are user pointers, so the comparison must
        # be against Chunk.addr rather than Chunk.header.
        view = self.capture()
        self.assertEqual(view.allocated(), [])

    def test_wide_counts_layout_2_30(self):
        view = self.capture(image=build_image(counts_size=2), counts_size=2)
        self.assertEqual(view.chunks[0].addr, BASE + first_chunk_offset(2) + 0x10)
        bin6 = view.bin_for(0x80)
        self.assertIsNotNone(bin6)
        self.assertEqual(bin6.count, 1)

    def test_chunk_flags(self):
        img = bytearray(build_image())
        struct.pack_into("<Q", img, FIRST + 8, 0x80 | 0x1 | 0x2 | 0x4)
        view = self.capture(image=bytes(img))
        chunk = view.chunks[0]
        self.assertTrue(chunk.prev_inuse)
        self.assertTrue(chunk.is_mmapped)
        self.assertTrue(chunk.non_main_arena)
        self.assertEqual(chunk.size, 0x80)

    def test_corrupt_heap_raises_with_position(self):
        img = bytearray(build_image())
        struct.pack_into("<Q", img, FIRST + 8, 0x10)  # below the minimum size
        with self.assertRaises(HeapCorrupt) as ctx:
            self.capture(image=bytes(img))
        self.assertEqual(ctx.exception.at, BASE + FIRST)

    def test_truncated_region_stops_the_walk(self):
        # Cutting the image before the top chunk header means the walk simply
        # ends, rather than inventing a chunk or raising.
        view = self.capture(image=build_image()[:TOP])
        self.assertEqual(len(view.chunks), 1)
        self.assertIsNone(view.top)


class TestDiff(unittest.TestCase):
    def capture(self, image):
        reader = FakeReader(image)
        return HeapView.capture(reader, BASE, GlibcLayout(version="2.29"),
                                region_end=REGION_END)

    def test_identical_views_show_no_change(self):
        img = build_image()
        self.assertFalse(self.capture(img).diff(self.capture(img)))
        self.assertEqual(str(self.capture(img).diff(self.capture(img))), "heap unchanged")

    def test_detects_modified_chunk_data(self):
        a = self.capture(build_image())
        img = bytearray(build_image())
        img[USER:USER + 8] = b"B" * 8
        diff = a.diff(self.capture(bytes(img)))
        self.assertTrue(diff)
        self.assertEqual(len(diff.changed), 1)
        self.assertEqual(diff.changed[0][0], BASE + FIRST)

    def test_detects_tcache_change(self):
        diff = self.capture(build_image(tcache_count=1)).diff(
            self.capture(build_image(tcache_count=0)))
        self.assertTrue(diff)
        self.assertEqual(diff.tcache_changed, [6])

    def test_detects_a_new_chunk(self):
        a = self.capture(build_image())
        img = bytearray(build_image())
        # split the top chunk: shrink it and plant another chunk before it
        struct.pack_into("<Q", img, TOP + 8, 0x80 | 1)
        struct.pack_into("<Q", img, TOP + 0x80 + 8, (IMAGE_SIZE - TOP - 0x80) | 1)
        diff = a.diff(self.capture(bytes(img)))
        self.assertTrue(diff)
        self.assertEqual(diff.added, [BASE + TOP + 0x80])


if __name__ == "__main__":
    unittest.main()
