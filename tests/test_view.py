"""Tests for the snapshot viewer.

The viewer is the one part of heapscope that is not about reading a process, so
it can be tested without one. Building snapshots by hand also makes it easy to
assert states a live process would rarely produce on demand: an empty bin whose
head still holds a stale pointer, or a head large enough to lose precision on
the way into JavaScript.
"""

import json
import os
import tempfile
import threading
import unittest
import urllib.error
import urllib.request

from heapscope.heap import tcache_size_for_index
from heapscope.view import (
    FORMAT,
    HeapSnapshot,
    _h,
    load_snapshots,
    make_server,
    payload,
)

from tests.support import (
    LIBC_BASE,
    STALE_HEAD,
    bin_,
    build,
    chunk,
    unsorted_chunk,
)


class TestHexFormatting(unittest.TestCase):
    def test_none_stays_none(self):
        self.assertIsNone(_h(None))

    def test_zero_is_formatted_rather_than_dropped(self):
        # Zero is a real value for a freed field, so it must not be rendered
        # the same way as "absent".
        self.assertEqual(_h(0), "0x0")

    def test_a_large_value_survives_exactly(self):
        # The whole reason addresses travel as strings. Through a JS number
        # this value would come back as 0x4343434616161800.
        text = _h(STALE_HEAD)
        self.assertEqual(text, "0x4343434616161619")
        self.assertEqual(int(text, 16), STALE_HEAD)
        self.assertNotEqual(int(float(STALE_HEAD)), STALE_HEAD)


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
        # miss and the page would draw an empty bin.
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


class TestDisplayPayload(unittest.TestCase):
    def test_addresses_cross_into_the_page_as_strings(self):
        snap = build("x", [chunk(0x1000, 0x70)],
                     {5: bin_(5, 1, head=0x1010, entries=[0x1010])})
        shown = payload([snap])["snapshots"][0]
        self.assertIsInstance(shown["base"], str)
        self.assertIsInstance(shown["chunks"][0]["header"], str)
        self.assertIsInstance(shown["tcache"]["5"]["head"], str)
        self.assertIsInstance(shown["tcache"]["5"]["entries"][0], str)

    def test_a_stale_head_arrives_without_rounding(self):
        snap = build("x", [], {5: bin_(5, 0, head=STALE_HEAD)})
        shown = payload([snap])["snapshots"][0]
        self.assertEqual(shown["tcache"]["5"]["head"], "0x4343434616161619")
        self.assertEqual(int(shown["tcache"]["5"]["head"], 16), STALE_HEAD)

    def test_bin_size_is_derived_from_the_index(self):
        # A bin knows its slot even when the count is zero, and even when the
        # file was written before the size was recorded. It must never render
        # as "n/a".
        snap = build("x", [], {5: {"count": 0, "head": 0x1010,
                                   "entries": [], "truncated": False}})
        shown = payload([snap])["snapshots"][0]
        self.assertEqual(shown["tcache"]["5"]["size"], "0x70")
        self.assertEqual(shown["tcache"]["5"]["size"],
                         _h(tcache_size_for_index(5)))

    def test_chunk_states_are_derived_when_the_payload_is_built(self):
        # Not read out of the file, so a snapshot written before a change to
        # the rule still draws correctly.
        freed = chunk(0x1000, 0x70)
        snap = build("x", [freed, chunk(0x2000, 0x100, is_top=True)],
                     {5: bin_(5, 1, head=freed["addr"],
                              entries=[freed["addr"]])})
        states = [c["state"] for c in payload([snap])["snapshots"][0]["chunks"]]
        self.assertEqual(states, ["tcache", "top"])

    def test_an_unsorted_chunk_is_recognised(self):
        snap = build("x", [unsorted_chunk(0x1000, 0x490)])
        states = [c["state"] for c in payload([snap])["snapshots"][0]["chunks"]]
        self.assertEqual(states, ["unsorted"])

    def test_a_live_chunk_with_one_libc_pointer_is_not_unsorted(self):
        snap = build("x", [chunk(0x1000, 0x70, fd=LIBC_BASE + 0x100,
                                 bk=0x4141414141414141)])
        states = [c["state"] for c in payload([snap])["snapshots"][0]["chunks"]]
        self.assertEqual(states, ["live"])

    def test_findings_are_carried_in_the_payload(self):
        # The page renders these rather than deciding for itself what counts as
        # anomalous, so they have to survive the trip.
        stale = bin_(5, 0, head=STALE_HEAD)
        shown = payload([build("x", [], {5: stale})])["snapshots"][0]
        self.assertTrue(shown["findings"])
        self.assertEqual(shown["findings"][0]["scope"], "tcache[5]")
        self.assertIn("empty", shown["findings"][0]["message"])

    def test_the_format_stamp_is_in_the_payload(self):
        self.assertEqual(payload([build("a", [])])["format"], FORMAT)

    def test_the_first_diff_is_absent(self):
        p = payload([build("a", []), build("b", [])])
        self.assertIsNone(p["diffs"][0])
        self.assertEqual(len(p["diffs"]), len(p["snapshots"]))

    def test_a_tcache_change_is_reported(self):
        before = build("a", [], {5: bin_(5, 1, head=0x1010, entries=[0x1010])})
        after = build("b", [], {5: bin_(5, 2, head=0x1010,
                                        entries=[0x1010], truncated=True)})
        d = payload([before, after])["diffs"][1]
        self.assertEqual(d["tcache_changed"], [5])
        self.assertEqual(d["tcache_before"]["5"], [1, "0x1010"])
        self.assertEqual(d["tcache_after"]["5"], [2, "0x1010"])

    def test_an_added_chunk_is_reported(self):
        before = build("a", [chunk(0x1000, 0x70)])
        after = build("b", [chunk(0x1000, 0x70), chunk(0x2000, 0x70)])
        d = payload([before, after])["diffs"][1]
        self.assertEqual(d["added"], ["0x2000"])
        self.assertEqual(d["removed"], [])

    def test_a_removed_chunk_is_reported(self):
        before = build("a", [chunk(0x1000, 0x70), chunk(0x2000, 0x70)])
        after = build("b", [chunk(0x1000, 0x70)])
        d = payload([before, after])["diffs"][1]
        self.assertEqual(d["removed"], ["0x2000"])
        self.assertEqual(d["added"], [])

    def test_an_empty_snapshot_list_still_produces_a_payload(self):
        # The page has a branch for this, so the payload has to support it.
        p = payload([])
        self.assertEqual(p["snapshots"], [])
        self.assertEqual(p["diffs"], [])


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


class TestServer(unittest.TestCase):
    def setUp(self):
        self.snaps = [
            build("start", [chunk(0x1000, 0x70)]),
            build("after free(0)", [chunk(0x1000, 0x70)],
                  {5: bin_(5, 1, head=0x1010, entries=[0x1010])}),
        ]
        self.httpd, self.url = make_server(self.snaps, port=0)
        self.thread = threading.Thread(target=self.httpd.serve_forever,
                                       daemon=True)
        self.thread.start()

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=5)

    def get(self, path):
        with urllib.request.urlopen(self.url.rstrip("/") + path) as resp:
            return resp.status, resp.read()

    def test_it_binds_to_loopback_only(self):
        self.assertEqual(self.httpd.server_address[0], "127.0.0.1")

    def test_the_page_is_served(self):
        status, body = self.get("/")
        self.assertEqual(status, 200)
        self.assertIn(b"heapscope view", body)

    def test_the_page_fetches_the_route_the_server_serves(self):
        # Catches a rename on one side only, which is otherwise a blank page.
        _, body = self.get("/")
        self.assertIn(b'"/api/snapshots"', body)

    def test_the_api_serves_the_payload(self):
        status, body = self.get("/api/snapshots")
        self.assertEqual(status, 200)
        data = json.loads(body)
        self.assertEqual(data["format"], FORMAT)
        self.assertEqual(len(data["snapshots"]), 2)
        self.assertIsNone(data["diffs"][0])

    def test_an_unknown_route_is_404(self):
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            self.get("/nope")
        self.assertEqual(ctx.exception.code, 404)

    def test_there_is_no_write_path(self):
        request = urllib.request.Request(self.url, data=b"x", method="POST")
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(request)
        self.assertEqual(ctx.exception.code, 501)


if __name__ == "__main__":
    unittest.main()
