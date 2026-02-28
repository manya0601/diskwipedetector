#!/usr/bin/env python3
"""
detector.py - WipeDetector: Forensic Wipe-Pattern Scanner

Scans disk images, raw block devices, or file-system paths to identify
anti-forensic wiping patterns. Generates console reports + JSON/CSV exports.

Usage:
    python detector.py <target> [options]

Examples:
    python detector.py test_data/dod_3pass.bin
    python detector.py /dev/sdb --json report.json
    python detector.py /mnt/volume --slack --csv
    python detector.py test_data/ --all
"""

import argparse
import os
import sys
import time
import json

# ── local imports ─────────────────────────────────────────────────────────────
sys.path.insert(0, os.path.dirname(__file__))
from analyzer import analyze_region
from scanner import scan_file, scan_slack_space
from reporter import print_banner, print_summary, save_json_report, save_csv_report
from utils import progress_bar, elapsed, format_size

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    COLOR = True
except ImportError:
    COLOR = False
    class _Stub:
        def __getattr__(self, _): return ""
    Fore = Style = _Stub()


# ── Detection thresholds ──────────────────────────────────────────────────────

MIN_CONFIDENCE = 40.0          # skip results below this confidence
DEFAULT_CHUNK  = 4096          # bytes per chunk


# ── Core scan logic ───────────────────────────────────────────────────────────

def scan_image(target: str, chunk_size: int = DEFAULT_CHUNK, verbose: bool = False):
    """Scan a raw file or block device and return list of detection results."""
    results = []
    total_size = 0
    try:
        total_size = os.path.getsize(target)
    except OSError:
        total_size = 0

    chunk_count = max(1, total_size // chunk_size) if total_size else 1
    processed = 0

    for offset, chunk in scan_file(target, chunk_size):
        result = analyze_region(chunk, offset)
        processed += 1

        if total_size:
            progress_bar(processed, chunk_count)

        if result["pattern_type"] != "unknown" and result["confidence"] >= MIN_CONFIDENCE:
            results.append(result)
            if verbose:
                _print_detection(result)

    if total_size:
        progress_bar(chunk_count, chunk_count)  # ensure 100%

    return results


def scan_slack(target: str, verbose: bool = False):
    """Scan slack space of every file under target directory."""
    results = []
    for fpath, offset, slack_data in scan_slack_space(target):
        if not slack_data:
            continue
        result = analyze_region(slack_data, offset)
        result["source_file"] = fpath
        if result["pattern_type"] != "unknown" and result["confidence"] >= MIN_CONFIDENCE:
            results.append(result)
            if verbose:
                _print_detection(result)
    return results


def scan_directory_images(target: str, chunk_size: int = DEFAULT_CHUNK, verbose: bool = False):
    """Scan all .bin files inside a directory."""
    results = []
    for fname in sorted(os.listdir(target)):
        if not fname.endswith(".bin"):
            continue
        fpath = os.path.join(target, fname)
        print(f"\n  {Fore.CYAN}Scanning: {fname}{Style.RESET_ALL}" if COLOR else f"\n  Scanning: {fname}")
        res = scan_image(fpath, chunk_size, verbose)
        for r in res:
            r["source_file"] = fpath
        results.extend(res)
    return results


# ── Helper ────────────────────────────────────────────────────────────────────

def _print_detection(r: dict):
    """Print a single detection line while scanning (verbose mode)."""
    color = Fore.RED if r["confidence"] > 80 else Fore.YELLOW
    reset = Style.RESET_ALL
    print(f"\n    {color}[DETECT]{reset} offset=0x{r['offset']:08X}  "
          f"type={r['pattern_type'].upper():<12}  "
          f"conf={r['confidence']:.1f}%  "
          f"algo={r.get('algorithm_label', r['algorithm'])[:35]}")


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    global MIN_CONFIDENCE  # noqa: PLW0603
    print_banner()

    parser = argparse.ArgumentParser(
        description="WipeDetector – Forensic wipe-pattern scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python detector.py test_data/dod_3pass.bin
  python detector.py /dev/sdb --json --verbose
  python detector.py test_data/ --all
  python detector.py /mnt/vol --slack --csv
        """,
    )
    parser.add_argument("target", help="File, disk device, or directory to scan")
    parser.add_argument("--chunk", type=int, default=DEFAULT_CHUNK,
                        help=f"Chunk size in bytes (default: {DEFAULT_CHUNK})")
    parser.add_argument("--slack", action="store_true",
                        help="Scan file slack space (target must be a directory)")
    parser.add_argument("--all", action="store_true",
                        help="Scan all .bin files in a directory")
    parser.add_argument("--json", nargs="?", const=True, metavar="FILE",
                        help="Save JSON report (optionally specify filename)")
    parser.add_argument("--csv", nargs="?", const=True, metavar="FILE",
                        help="Save CSV report (optionally specify filename)")
    parser.add_argument("--min-confidence", type=float, default=MIN_CONFIDENCE,
                        help=f"Minimum confidence to report (default: {MIN_CONFIDENCE})")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Print each detection as it is found")
    args = parser.parse_args()

    MIN_CONFIDENCE = args.min_confidence

    target = os.path.abspath(args.target)
    if not os.path.exists(target):
        print(f"[!] Target not found: {target}")
        sys.exit(1)

    start = time.time()
    results = []

    # Choose scan mode
    if args.slack and os.path.isdir(target):
        print(f"\n  Mode   : Slack-space scan")
        print(f"  Target : {target}\n")
        results = scan_slack(target, verbose=args.verbose)

    elif args.all and os.path.isdir(target):
        print(f"\n  Mode   : Batch scan (.bin files in directory)")
        print(f"  Target : {target}\n")
        results = scan_directory_images(target, args.chunk, verbose=args.verbose)

    else:
        size_str = format_size(os.path.getsize(target)) if os.path.isfile(target) else "?"
        print(f"\n  Mode   : Raw image / file scan")
        print(f"  Target : {target}  ({size_str})\n")
        results = scan_image(target, args.chunk, verbose=args.verbose)

    elapsed_sec = elapsed(start)
    print_summary(results, target, elapsed_sec)

    # Save reports
    if args.json:
        path = args.json if isinstance(args.json, str) else None
        out = save_json_report(results, target, path)
        print(f"  JSON report saved: {out}")

    if args.csv:
        path = args.csv if isinstance(args.csv, str) else None
        out = save_csv_report(results, path)
        print(f"  CSV report saved : {out}")

    print()


if __name__ == "__main__":
    main()
