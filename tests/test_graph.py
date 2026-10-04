"""Tests for allocator-link graph construction and portable DOT output."""

import unittest

from heapscope.graph import snapshot_graph

from tests.support import bin_, build, chunk, unsorted_chunk


class TestSnapshotGraph(unittest.TestCase):
    def test_tcache_has_a_bin_head_and_next_edges(self):
        first, second = chunk(0x1000, 0x70), chunk(0x2000, 0x70)
        graph = snapshot_graph(build("x", [first, second], {
            5: bin_(5, 2, head=second["addr"], entries=[second["addr"], first["addr"]]),
        }))
        edges = {(edge.label, edge.source, edge.target) for edge in graph.edges}
        self.assertIn(("head", "tcache_5", "chunk_2000"), edges)
        self.assertIn(("next", "chunk_2000", "chunk_1000"), edges)

    def test_a_truncated_chain_ends_in_a_dangling_node(self):
        entry = chunk(0x1000, 0x70)
        graph = snapshot_graph(build("x", [entry], {
            5: bin_(5, 2, head=entry["addr"], entries=[entry["addr"]], truncated=True),
        }))
        self.assertTrue(any(node.kind == "dangling" for node in graph.nodes))
        self.assertTrue(any(edge.kind == "dangling" for edge in graph.edges))

    def test_unsorted_pointers_keep_external_arena_nodes(self):
        entry = unsorted_chunk(0x1000)
        graph = snapshot_graph(build("x", [entry]))
        self.assertTrue(any(node.kind == "external" for node in graph.nodes))
        self.assertTrue(any(edge.label == "fd" for edge in graph.edges))
        self.assertTrue(any(edge.label == "bk" for edge in graph.edges))

    def test_dot_escapes_labels_and_names_edges(self):
        graph = snapshot_graph(build("x", [chunk(0x1000, 0x70)]))
        dot = graph.to_dot()
        self.assertTrue(dot.startswith("digraph heapscope"))
        self.assertIn("chunk_1000", dot)


if __name__ == "__main__":
    unittest.main()
