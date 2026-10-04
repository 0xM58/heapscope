"""Tests for the portable investigation report."""

import unittest

from heapscope.report import html_report

from tests.support import STALE_HEAD, bin_, build, chunk


class TestHtmlReport(unittest.TestCase):
    def test_it_contains_a_timeline_map_links_and_findings(self):
        free = chunk(0x1000, 0x70)
        first = build("start", [chunk(0x1000, 0x70)])
        second = build("after free <0>", [free],
                       {5: bin_(5, 2, head=free["addr"],
                                  entries=[free["addr"]], truncated=True)})
        second.annotate("controlled reproduction")
        report = html_report([first, second], title="case <42>")
        self.assertIn("Timeline", report)
        self.assertIn("Heap map", report)
        self.assertIn("Free-list links", report)
        self.assertIn("Investigation", report)
        self.assertIn("controlled reproduction", report)
        self.assertIn("case &lt;42&gt;", report)
        self.assertIn("after free &lt;0&gt;", report)
        self.assertIn("broken or cyclic", report)

    def test_an_empty_report_is_still_valid_html(self):
        report = html_report([])
        self.assertIn("<!doctype html>", report)
        self.assertIn("0 snapshot(s)", report)

    def test_a_stale_head_is_never_coerced_or_lost(self):
        report = html_report([build("x", [], {5: bin_(5, 0, head=STALE_HEAD)})])
        self.assertIn("empty but its head", report)


if __name__ == "__main__":
    unittest.main()
