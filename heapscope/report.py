"""Portable, self-contained HTML reports for saved heap snapshots.

The terminal inspector is best while investigating interactively.  This module
serves the other half of the workflow: one file that can be attached to a CI
job or sent to a teammate, with no server, JavaScript framework or target
process required to read it.
"""

from __future__ import annotations

from html import escape
from typing import List, Sequence

from .describe import TOP, TCACHE, UNSORTED, snapshot_findings, snapshot_states
from .snapshot import HeapSnapshot

__all__ = ["html_report"]


def _h(value) -> str:
    return escape(str(value))


def _diff_count(before: HeapSnapshot, after: HeapSnapshot) -> int:
    diff = before.diff(after)
    return len(diff.added) + len(diff.removed) + len(diff.changed) + len(diff.tcache_changed)


def _map(snap: HeapSnapshot) -> str:
    """A proportional heap strip; each chunk is a linkable visual segment."""
    span = max(1, (snap.region_end or (snap.chunks[-1]["header"] + snap.chunks[-1]["size"]
                                        if snap.chunks else snap.base)) - snap.base)
    states = snapshot_states(snap)
    parts = []
    for chunk in snap.chunks:
        state = states.get(chunk["header"], "live")
        css = {TCACHE: "tcache", UNSORTED: "unsorted", TOP: "top"}.get(state, "live")
        width = max(1.0, 100.0 * chunk["size"] / span)
        title = "%#x · %#x · %s" % (chunk["header"], chunk["size"], state)
        parts.append('<span class="chunk %s" style="width: %.3f%%" title="%s"></span>'
                     % (css, width, _h(title)))
    return '<div class="map">%s</div>' % "".join(parts)


def _links(snap: HeapSnapshot) -> str:
    rows = []
    for index, bin_ in sorted(snap.tcache.items()):
        nodes = ["%#x" % address for address in bin_["entries"]]
        chain = " → ".join(nodes) if nodes else "∅"
        suffix = " ⚠ truncated" if bin_["truncated"] else ""
        rows.append("<li><b>tcache[%d]</b> %s%s</li>" % (index, _h(chain), suffix))
    unsorted = [c for c in snap.chunks
                if snapshot_states(snap).get(c["header"]) == UNSORTED]
    if unsorted:
        rows.append("<li><b>unsorted</b> %s</li>" % _h(" ↔ ".join(
            "%#x" % c["header"] for c in unsorted)))
    return "<ul>%s</ul>" % "".join(rows or ["<li>No free-list links captured.</li>"])


def html_report(snapshots: Sequence[HeapSnapshot], title: str = "heapscope report") -> str:
    """Render snapshots as one standalone, responsive HTML document."""
    timeline = []
    sections = []
    for i, snap in enumerate(snapshots):
        changes = _diff_count(snapshots[i - 1], snap) if i else 0
        warnings = [f for f in snapshot_findings(snap) if f.level == "warn"]
        timeline.append('<li class="%s"><a href="#snapshot-%d">%d. %s</a><small>%d changes · %d warnings</small></li>'
                        % ("warn" if warnings else "", i, i + 1, _h(snap.label), changes, len(warnings)))
        facts = [
            ("captured", snap.captured_at or "not recorded"),
            ("glibc", snap.glibc or "unknown"),
            ("target", " ".join(snap.target) or "not recorded"),
            ("chunks", len(snap.chunks)),
            ("tcache bins", len(snap.tcache)),
        ]
        finding_html = "".join("<li>%s</li>" % _h(f.message) for f in warnings)
        annotations = "".join("<li>%s</li>" % _h(note) for note in snap.annotations)
        sections.append('''<section id="snapshot-%d"><h2>%d. %s</h2>
<dl>%s</dl><h3>Heap map</h3>%s<h3>Free-list links</h3>%s
<h3>Investigation</h3><ul class="findings">%s</ul>
%s</section>''' % (
            i, i + 1, _h(snap.label),
            "".join("<dt>%s</dt><dd>%s</dd>" % (_h(k), _h(v)) for k, v in facts),
            _map(snap), _links(snap), finding_html or "<li>No anomalies detected.</li>",
            "<h3>Notes</h3><ul>%s</ul>" % annotations if annotations else "",
        ))
    return '''<!doctype html><html><head><meta charset="utf-8"><title>%s</title><style>
body{font:15px system-ui,sans-serif;margin:0;color:#e5e7eb;background:#111827}main{max-width:1100px;margin:auto;padding:2rem}a{color:#67e8f9}.layout{display:grid;grid-template-columns:260px 1fr;gap:2rem}.timeline{position:sticky;top:1rem;height:max-content;background:#1f2937;padding:1rem;border-radius:10px}.timeline li{margin:.7rem 0}.timeline small{display:block;color:#9ca3af}.warn{border-left:3px solid #fb7185;padding-left:.5rem}section{background:#1f2937;padding:1.2rem;margin-bottom:1rem;border-radius:10px}dl{display:grid;grid-template-columns:max-content 1fr;gap:.3rem 1rem}dt{color:#9ca3af}.map{height:32px;display:flex;overflow:hidden;border-radius:5px;background:#374151}.chunk{min-width:2px}.live{background:#60a5fa}.tcache{background:#fbbf24}.unsorted{background:#fb7185}.top{background:#34d399}.findings{color:#fecdd3}@media(max-width:720px){.layout{display:block}.timeline{position:static;margin-bottom:1rem}}</style></head><body><main><h1>%s</h1><p>Offline heap investigation report · %d snapshot(s)</p><div class="layout"><nav class="timeline"><h2>Timeline</h2><ol>%s</ol></nav><div>%s</div></div></main></body></html>''' % (_h(title), _h(title), len(snapshots), "".join(timeline), "".join(sections))
