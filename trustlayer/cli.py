"""Command-line interface for TrustLayer."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .models import ScanResult
from .repo_scanner import scan_repo
from .reporting import write_json, write_markdown


_URL_SCAN_WARNING = """\
⚠️  URL scan notice: TrustLayer will make HTTP GET requests to the provided URL
   and links it discovers on the same origin. This traffic will appear in your
   server logs. Scans are bounded and read-only, but do not run against systems
   you do not own or have permission to test.
"""

_LAUNCH_DISCLAIMER = """\
─────────────────────────────────────────────────────────────────────────────
TrustLayer is a build-literacy tool, not a professional security audit.
Findings are heuristic pattern matches and may include false positives.
No automated scan can verify runtime behaviour, auth logic, or business rules.
Human review is required before launch.
─────────────────────────────────────────────────────────────────────────────
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="trustlayer",
        description=(
            "TrustLayer — build-readiness and launch-literacy assistant. "
            "Scans a local repo for common data-exposure and privacy risks."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Scan a local directory (and optionally a URL)")
    scan.add_argument("path", help="Local repo path to scan")
    scan.add_argument(
        "--url",
        metavar="URL",
        default=None,
        help="Optional preview URL to crawl (GET-only, same-origin)",
    )
    scan.add_argument(
        "--report",
        metavar="FILE",
        default=None,
        help="Write Markdown report to FILE",
    )
    scan.add_argument(
        "--json",
        metavar="FILE",
        default=None,
        dest="json_out",
        help="Write JSON report to FILE",
    )
    scan.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress progress output; only show errors",
    )
    return parser


def run_scan(args: argparse.Namespace) -> int:
    path = args.path
    if not Path(path).is_dir():
        print(f"error: {path!r} is not a directory", file=sys.stderr)
        return 2

    if not args.quiet:
        print(_LAUNCH_DISCLAIMER)
        print(f"Scanning repo: {path}")

    result = ScanResult(target=path)
    result = scan_repo(path, result)

    if args.url:
        if not args.quiet:
            print(_URL_SCAN_WARNING)
            print(f"Crawling URL:   {args.url}")
        from .url_scanner import scan_url
        result = scan_url(args.url, result)

    counts = result.counts_by_severity()
    if not args.quiet:
        print(
            f"\nFinished. Files scanned: {result.scanned_files}, "
            f"skipped: {result.skipped_files}"
        )
        if result.url_scan_enabled:
            print(f"URLs crawled: {result.scanned_urls}")
        total = len(result.findings)
        print(
            f"Findings: {total} total — "
            f"{counts['high']} high, {counts['medium']} medium, "
            f"{counts['low']} low, {counts['info']} info"
        )
        if total == 0:
            print(
                "\nNo urgent automated patterns detected. "
                "Human review is still required before launch."
            )

    if args.report:
        try:
            write_markdown(result, args.report)
            if not args.quiet:
                print(f"Markdown report: {args.report}")
        except OSError as exc:
            print(f"error: could not write report: {exc}", file=sys.stderr)
            return 1

    if args.json_out:
        try:
            write_json(result, args.json_out)
            if not args.quiet:
                print(f"JSON report:     {args.json_out}")
        except OSError as exc:
            print(f"error: could not write JSON report: {exc}", file=sys.stderr)
            return 1

    if not args.quiet and (args.report or args.json_out):
        print(
            "\n⚠️  Review your report before sharing — it may contain sanitised "
            "evidence from your project files."
        )

    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return run_scan(args)
    parser.print_help()
    return 1
