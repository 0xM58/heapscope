"""Heap ownership and pointer graphs built from an offline snapshot.

The graph deliberately models *observed* links only.  A dangling or truncated
edge is kept as such instead of guessed into a chunk, which makes poisoned
freelists visible without making the visualisation lie.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

from .describe import snapshot_states
from .snapshot import HeapSnapshot

__all__ = ["GraphNode", "GraphEdge", "HeapGraph", "snapshot_graph"]


@dataclass(frozen=True)
class GraphNode:
    id: str
    label: str
    kind: str


@dataclass(frozen=True)
class GraphEdge:
    source: str
    target: str
    label: str
    kind: str = "pointer"


@dataclass
class HeapGraph:
    nodes: List[GraphNode] = field(default_factory=list)
    edges: List[GraphEdge] = field(default_factory=list)

    def to_dot(self) -> str:
        """Graphviz DOT, requiring only the optional ``dot`` executable to draw."""
        colours = {"tcache": "#fbbf24", "unsorted": "#fb7185", "top": "#34d399",
                   "live": "#60a5fa", "bin": "#a78bfa", "external": "#9ca3af",
                   "dangling": "#ef4444"}
        quote = lambda text: '"' + str(text).replace("\\", "\\\\").replace('"', '\\"') + '"'
        lines = ["digraph heapscope {", "  rankdir=LR;",
                 "  node [shape=box style=rounded fontname=Helvetica];"]
        for node in self.nodes:
            lines.append("  %s [label=%s color=%s];" %
                         (quote(node.id), quote(node.label), quote(colours.get(node.kind, "#d1d5db"))))
        for edge in self.edges:
            style = "dashed" if edge.kind == "dangling" else "solid"
            lines.append("  %s -> %s [label=%s style=%s];" %
                         (quote(edge.source), quote(edge.target), quote(edge.label), style))
        return "\n".join(lines + ["}", ""])

    def to_dict(self) -> Dict[str, List[Dict[str, str]]]:
        return {"nodes": [node.__dict__ for node in self.nodes],
                "edges": [edge.__dict__ for edge in self.edges]}


def snapshot_graph(snap: HeapSnapshot) -> HeapGraph:
    """Model tcache and unsorted-bin relationships in *snap*."""
    graph = HeapGraph()
    states = snapshot_states(snap)
    by_pointer = {}
    for chunk in snap.chunks:
        node_id = "chunk_%x" % chunk["header"]
        by_pointer[chunk["header"]] = node_id
        by_pointer[chunk["addr"]] = node_id
        graph.nodes.append(GraphNode(node_id, "%#x\n%#x %s" % (
            chunk["header"], chunk["size"], states.get(chunk["header"], "live")),
            states.get(chunk["header"], "live")))

    def endpoint(pointer: int) -> str:
        if pointer in by_pointer:
            return by_pointer[pointer]
        node_id = "external_%x" % pointer
        if not any(node.id == node_id for node in graph.nodes):
            graph.nodes.append(GraphNode(node_id, "%#x\nexternal" % pointer, "external"))
        return node_id

    for index, bin_ in sorted(snap.tcache.items()):
        bin_id = "tcache_%d" % index
        graph.nodes.append(GraphNode(bin_id, "tcache[%d]\ncount=%d" %
                                     (index, bin_["count"]), "bin"))
        entries = bin_["entries"]
        if entries:
            graph.edges.append(GraphEdge(bin_id, endpoint(entries[0]), "head"))
        for current, next_ in zip(entries, entries[1:]):
            graph.edges.append(GraphEdge(endpoint(current), endpoint(next_), "next"))
        if bin_["truncated"]:
            dangling = "dangling_tcache_%d" % index
            graph.nodes.append(GraphNode(dangling, "walk stopped", "dangling"))
            graph.edges.append(GraphEdge(endpoint(entries[-1]) if entries else bin_id,
                                         dangling, "unknown next", "dangling"))

    for chunk in snap.chunks:
        if states.get(chunk["header"]) != "unsorted":
            continue
        source = by_pointer[chunk["header"]]
        for name in ("fd", "bk"):
            pointer = chunk.get(name)
            if pointer:
                graph.edges.append(GraphEdge(source, endpoint(pointer), name))
    return graph
