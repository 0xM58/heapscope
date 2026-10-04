"""Command line interface.

Things you can do from a shell without writing a script: read the offset table
out of a libc, see what a target actually mapped, look at its heap at startup,
and browse a set of saved heap snapshots in a terminal.

    heapscope offsets ./libc.so.6
    heapscope bases  -- ./chall
    heapscope heap   -- ./chall
    heapscope tui    ./stages
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from .glibc import GlibcLayout
from .probe import Probe


def _add_target_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--libc", help="path to the target's libc")
    parser.add_argument("--wait", type=float, default=0.4,
                        help="quiet period to allow before reading (default: 0.4s)")
    parser.add_argument("--no-aslr", action="store_true",
                        help="attempt to disable ASLR for the child (often a no-op)")
    parser.add_argument("target", nargs=argparse.REMAINDER,
                        help="-- command to run")


def _target_argv(ns) -> List[str]:
    argv = list(ns.target)
    if argv and argv[0] == "--":
        argv = argv[1:]
    return argv


def _cmd_offsets(args) -> int:
    try:
        layout = GlibcLayout.from_libc(args.libc)
    except (OSError, ValueError) as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 1
    print(layout)
    return 0


def _cmd_bases(args) -> int:
    argv = _target_argv(args)
    if not argv:
        print("error: no target given (use: heapscope bases -- ./chall)", file=sys.stderr)
        return 2

    p = Probe(argv, libc=args.libc, no_aslr=args.no_aslr)
    try:
        p.recv(quiet=args.wait)
        print("pid          %d" % p.pid)
        print("pie base     %s" % _hex(p.pie_base()))
        print("libc base    %s" % _hex(p.libc_base()))
        print("heap base    %s" % _hex(p.heap_base()))
        layout = p.glibc
        if layout is not None:
            print()
            print(layout)
        else:
            print("\n(no libc layout resolved - pass --libc to get offsets)")
    finally:
        p.close()
    return 0


def _cmd_maps(args) -> int:
    argv = _target_argv(args)
    if not argv:
        print("error: no target given", file=sys.stderr)
        return 2
    p = Probe(argv, libc=args.libc, no_aslr=args.no_aslr)
    try:
        p.recv(quiet=args.wait)
        print(p.maps())
    finally:
        p.close()
    return 0


def _cmd_heap(args) -> int:
    argv = _target_argv(args)
    if not argv:
        print("error: no target given", file=sys.stderr)
        return 2
    p = Probe(argv, libc=args.libc, no_aslr=args.no_aslr)
    try:
        p.recv(quiet=args.wait)
        base = p.heap_base()
        if base is None:
            print("error: could not locate the heap", file=sys.stderr)
            return 1
        print(p.heap())
    finally:
        p.close()
    return 0


def _load_snapshots_or_report(args):
    """Load the snapshots named on the command line, or explain why not.

    Returns ``None`` after printing the reason.
    """
    from .snapshot import load_snapshots

    try:
        snapshots = load_snapshots(args.paths)
    except (OSError, ValueError) as exc:
        print("error: %s" % exc, file=sys.stderr)
        return None
    if not snapshots:
        print("error: no snapshots found in %s" % ", ".join(args.paths),
              file=sys.stderr)
        return None
    return snapshots


def _cmd_tui(args) -> int:
    from .tui import run

    snapshots = _load_snapshots_or_report(args)
    if snapshots is None:
        return 1

    return run(snapshots)


def _cmd_report(args) -> int:
    from .report import html_report

    snapshots = _load_snapshots_or_report(args)
    if snapshots is None:
        return 1
    try:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(html_report(snapshots, title=args.title))
    except OSError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 1
    print("wrote %s (%d snapshots)" % (args.output, len(snapshots)))
    return 0


def _cmd_graph(args) -> int:
    from .graph import snapshot_graph

    snapshots = _load_snapshots_or_report(args)
    if snapshots is None:
        return 1
    try:
        snapshot = snapshots[args.snapshot]
    except IndexError:
        print("error: snapshot index %d is out of range" % args.snapshot, file=sys.stderr)
        return 2
    graph = snapshot_graph(snapshot)
    output = graph.to_dot() if args.format == "dot" else json.dumps(graph.to_dict(), indent=2)
    try:
        if args.output:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(output)
        else:
            print(output)
    except OSError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 1
    return 0


def _hex(value: Optional[int]) -> str:
    return "n/a" if value is None else "%#x" % value


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="heapscope",
        description="Headless glibc heap introspection.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_off = sub.add_parser("offsets", help="print symbol offsets read from a libc")
    p_off.add_argument("libc")
    p_off.set_defaults(func=_cmd_offsets)

    for name, help_text, func in (
        ("bases", "resolve pie/libc/heap bases for a target", _cmd_bases),
        ("maps", "dump /proc/<pid>/maps for a target", _cmd_maps),
        ("heap", "dump the heap of a freshly started target", _cmd_heap),
    ):
        sp = sub.add_parser(name, help=help_text)
        _add_target_args(sp)
        sp.set_defaults(func=func)

    p_tui = sub.add_parser("tui", help="browse saved heap snapshots in a terminal")
    p_tui.add_argument("paths", nargs="+", help="snapshot files or directories")
    p_tui.set_defaults(func=_cmd_tui)

    p_report = sub.add_parser("report", help="write a self-contained HTML heap report")
    p_report.add_argument("paths", nargs="+", help="snapshot files or directories")
    p_report.add_argument("-o", "--output", default="heapscope-report.html",
                          help="report path (default: heapscope-report.html)")
    p_report.add_argument("--title", default="heapscope report", help="report title")
    p_report.set_defaults(func=_cmd_report)

    p_graph = sub.add_parser("graph", help="export an allocator pointer graph")
    p_graph.add_argument("paths", nargs="+", help="snapshot files or directories")
    p_graph.add_argument("--snapshot", type=int, default=-1,
                         help="snapshot index to export (default: last)")
    p_graph.add_argument("--format", choices=("dot", "json"), default="dot")
    p_graph.add_argument("-o", "--output", help="write to a file instead of stdout")
    p_graph.set_defaults(func=_cmd_graph)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
