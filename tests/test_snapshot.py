"""Tests for heap snapshots: writing one, reading it back, loading a set.

A snapshot is the one part of heapscope that is not about reading a process, so
it can be tested without one. Building them by hand also makes it easy to
assert states a live process would rarely produce on demand, such as a tcache
head holding a value above 2**53 that a JavaScript number could not carry.

What a snapshot *means* is tested in `test_describe.py`; how it is drawn is
tested in `test_tui.py`. This file is only about the file format and the round
trip, which is the part that has to stay compatible.
"""

import json
import os
import tempfile
import unittest

from heapscope.snapshot import FORMAT, HeapSnapshot, load_snapshots

from tests.support import bin_, build, chunk


class TestRoundTrip(unittest.TestCase):
    def test_save_and_load_preserve_the_snapshot(self):
        snap = build("after free(0)", [chunk(0x1000, 0x70)],
                     {5: bin_(5, 1, head=0x1010, entries=[0x1010])})
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "nested", "01.json")
            snap.save(path)          # the parent directory is created
            back = HeapSnapshot.load(path)

        self.assertEqual(back.label, "after free(0)")
        self.assertEqual(back.base, snap.base)
        self.assertEqual(back.chunks, snap.chunks)
        self.assertEqual(back.tcache[5]["count"], 1)
        self.assertEqual(back.tcache[5]["head"], 0x1010)

    def test_tcache_keys_come_back_as_integers(self):
        # JSON object keys are strings. If they stayed strings, tcache[5] would
        # miss and a bin would render as absent.
        snap = build("x", [], {5: bin_(5, 1, head=0x1010, entries=[0x1010])})
        back = HeapSnapshot.from_dict(json.loads(json.dumps(snap.to_dict())))
        self.assertIn(5, back.tcache)
        self.assertNotIn("5", back.tcache)

    def test_the_format_stamp_is_written(self):
        self.assertEqual(build("x", []).to_dict()["format"], FORMAT)

    def test_a_snapshot_from_another_format_is_rejected(self):
        raw = build("x", []).to_dict()
        raw["format"] = "heapscope.heapview/99"
        with self.assertRaises(ValueError):
            HeapSnapshot.from_dict(raw)

    def test_annotations_and_context_round_trip(self):
        snap = build("x", [])
        snap.captured_at = "2026-10-04T12:00:00+00:00"
        snap.target = ["./chall", "--quiet"]
        snap.environment = {"platform": "Linux"}
        snap.annotate("before allocator call")
        back = HeapSnapshot.from_dict(snap.to_dict())
        self.assertEqual(back.annotations, ["before allocator call"])
        self.assertEqual(back.target, ["./chall", "--quiet"])
        self.assertEqual(back.environment, {"platform": "Linux"})

    def test_a_format_one_capture_remains_loadable(self):
        raw = build("x", []).to_dict()
        raw["format"] = "heapscope.heapview/1"
        for key in ("captured_at", "target", "environment", "annotations"):
            raw.pop(key, None)
        back = HeapSnapshot.from_dict(raw)
        self.assertEqual(back.annotations, [])
        self.assertEqual(back.target, [])


class TestLoadSnapshots(unittest.TestCase):
    def test_a_directory_expands_sorted_by_name(self):
        with tempfile.TemporaryDirectory() as d:
            for name in ("03.json", "01.json", "02.json"):
                build(name, []).save(os.path.join(d, name))
            build("not a snapshot", []).save(os.path.join(d, "notes.txt"))
            snaps = load_snapshots([d])
        self.assertEqual([s.label for s in snaps], ["01.json", "02.json", "03.json"])

    def test_an_explicit_file_is_loaded(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "only.json")
            build("only", []).save(path)
            snaps = load_snapshots([path])
        self.assertEqual([s.label for s in snaps], ["only"])

    def test_an_empty_directory_yields_nothing(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(load_snapshots([d]), [])

    def test_a_stale_snapshot_fails_loudly(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "old.json")
            with open(path, "w") as fh:
                json.dump({"format": "heapscope.heapview/0"}, fh)
            with self.assertRaises(ValueError):
                load_snapshots([d])


if __name__ == "__main__":
    unittest.main()
