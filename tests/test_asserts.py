"""Tests for layout snapshots.

Snapshots are the CI-facing part of the library: record the facts an exploit
relies on, then assert them on every run so a silent environment change fails
loudly. These tests use a stub probe so they need no live target.
"""

import json
import os
import tempfile
import unittest

from heapscope.asserts import LayoutSnapshot, assert_layout
from heapscope.errors import LayoutDrift
from heapscope.glibc import GlibcLayout
from heapscope.heap import Chunk, TcacheBin


class FakeHeap:
    def __init__(self, sizes, tcache=None):
        self.chunks = [
            Chunk(addr=0x555555757260 + i * 0x80, size=size, raw_size=size | 1)
            for i, size in enumerate(sizes)
        ] + [Chunk(addr=0x555555759000, size=0x1000, raw_size=0x1001, is_top=True)]
        self.tcache = {i: TcacheBin(index=i, count=c, head=None)
                       for i, c in (tcache or {}).items()}


class FakeProbe:
    def __init__(self, layout, heap):
        self._layout = layout
        self._heap = heap

    @property
    def glibc(self):
        return self._layout

    def heap(self):
        return self._heap


def make_probe(version="2.29", sizes=(0x80, 0x90), tcache=None, system=0x52FD0):
    layout = GlibcLayout(version=version, main_arena=0x1E4C40, stdout=0x1E5760,
                         free_hook=0x1E75A8, system=system, setcontext=0x55E00)
    return FakeProbe(layout, FakeHeap(list(sizes), tcache))


class TestCapture(unittest.TestCase):
    def test_records_offsets_and_shape(self):
        snap = LayoutSnapshot.capture(make_probe(), name="dummy")
        self.assertEqual(snap.name, "dummy")
        self.assertEqual(snap.version, "2.29")
        self.assertEqual(snap.offsets["free_hook"], 0x1E75A8)
        self.assertEqual(snap.chunk_sizes, [0x80, 0x90])   # top excluded

    def test_excludes_the_top_chunk(self):
        snap = LayoutSnapshot.capture(make_probe())
        self.assertNotIn(0x1000, snap.chunk_sizes)

    def test_records_only_nonzero_tcache_bins(self):
        snap = LayoutSnapshot.capture(make_probe(tcache={5: 2, 6: 0}))
        self.assertEqual(snap.tcache_counts, {5: 2})

    def test_survives_a_probe_with_no_layout(self):
        probe = FakeProbe(None, FakeHeap([0x80]))
        snap = LayoutSnapshot.capture(probe)
        self.assertEqual(snap.offsets, {})
        self.assertEqual(snap.chunk_sizes, [0x80])


class TestComparison(unittest.TestCase):
    def test_identical_layouts_do_not_drift(self):
        a = LayoutSnapshot.capture(make_probe())
        b = LayoutSnapshot.capture(make_probe())
        self.assertEqual(a.diff(b), {})
        a.assert_unchanged(b)

    def test_detects_a_moved_offset(self):
        # The realistic failure: a libc update shifts __free_hook by 8 bytes.
        a = LayoutSnapshot.capture(make_probe())
        b = LayoutSnapshot.capture(make_probe())
        b.offsets["free_hook"] += 8
        changes = a.diff(b)
        self.assertIn("offset.free_hook", changes)
        self.assertEqual(changes["offset.free_hook"], ("0x1e75a8", "0x1e75b0"))

    def test_detects_a_version_change(self):
        a = LayoutSnapshot.capture(make_probe(version="2.29"))
        b = LayoutSnapshot.capture(make_probe(version="2.31"))
        self.assertIn("glibc version", a.diff(b))

    def test_detects_a_shape_change(self):
        a = LayoutSnapshot.capture(make_probe(sizes=(0x80, 0x90)))
        b = LayoutSnapshot.capture(make_probe(sizes=(0x80, 0x90, 0xA0)))
        self.assertIn("chunk_sizes", a.diff(b))

    def test_detects_a_tcache_change(self):
        a = LayoutSnapshot.capture(make_probe(tcache={5: 1}))
        b = LayoutSnapshot.capture(make_probe(tcache={5: 2}))
        self.assertIn("tcache_counts", a.diff(b))

    def test_assert_unchanged_raises_with_details(self):
        a = LayoutSnapshot.capture(make_probe())
        b = LayoutSnapshot.capture(make_probe())
        b.offsets["system"] += 0x10
        with self.assertRaises(LayoutDrift) as ctx:
            a.assert_unchanged(b)
        self.assertIn("offset.system", ctx.exception.changes)

    def test_module_level_assert_layout(self):
        probe = make_probe()
        snap = LayoutSnapshot.capture(probe)
        assert_layout(probe, snap)   # must not raise

    def test_verify_against_a_live_probe(self):
        snap = LayoutSnapshot.capture(make_probe())
        snap.verify(make_probe())    # must not raise


class TestPersistence(unittest.TestCase):
    def test_round_trips_through_json(self):
        original = LayoutSnapshot.capture(make_probe(tcache={5: 2}), name="dummy")
        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        self.addCleanup(os.unlink, path)

        original.save(path)
        loaded = LayoutSnapshot.load(path)

        self.assertEqual(loaded.name, original.name)
        self.assertEqual(loaded.offsets, original.offsets)
        self.assertEqual(loaded.chunk_sizes, original.chunk_sizes)
        self.assertEqual(loaded.tcache_counts, original.tcache_counts)

    def test_saved_form_is_readable_json(self):
        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        self.addCleanup(os.unlink, path)
        LayoutSnapshot.capture(make_probe()).save(path)
        with open(path) as fh:
            raw = json.load(fh)
        self.assertIn("offsets", raw)
        self.assertIn("chunk_sizes", raw)

    def test_tcache_keys_become_ints_again(self):
        # JSON object keys are strings; load() must convert them back or
        # comparisons silently never match.
        fd, path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        self.addCleanup(os.unlink, path)
        LayoutSnapshot.capture(make_probe(tcache={5: 2})).save(path)
        loaded = LayoutSnapshot.load(path)
        self.assertIn(5, loaded.tcache_counts)
        self.assertNotIn("5", loaded.tcache_counts)


if __name__ == "__main__":
    unittest.main()
