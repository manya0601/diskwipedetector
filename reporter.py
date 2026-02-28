"""
reporter.py - Forensic report generation for Wipe-Pattern Detector.

Outputs:
  - Colorized console table (via tabulate + colorama)
  - JSON report file
  - (Optional) CSV export
"""

import json
import csv
import os
from datetime import datetime
from typing import List, Dict, Any

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    COLOR = True
except ImportError:
    COLOR = False
    class _Stub:
        def __getattr__(self, _): return ""
    Fore = Style = _Stub()

try:
    from tabulate import tabulate
    HAS_TABULATE = True
except ImportError:
    HAS_TABULATE = False


# ── Color helpers ────────────────────────────────────────────────────────────

PATTERN_COLORS = {
    "zero_fill":    Fore.CYAN,
    "one_fill":     Fore.YELLOW,
    "random":       Fore.RED,
    "repeating":    Fore.MAGENTA,
    "multi_pass":   Fore.RED + Style.BRIGHT if COLOR else "",
    "unknown":      Fore.WHITE,
}

def _colorize(text: str, pattern_type: str) -> str:
    if not COLOR:
        return text
    color = PATTERN_COLORS.get(pattern_type, "")
    return f"{color}{text}{Style.RESET_ALL}"


# ── Console output ───────────────────────────────────────────────────────────

BANNER = r"""
 __        ___            ____       _            _
 \ \      / (_)_ __   ___|  _ \  ___| |_ ___  ___| |_ ___  _ __
  \ \ /\ / /| | '_ \ / _ \ | | |/ _ \ __/ _ \/ __| __/ _ \| '__|
   \ V  V / | | |_) |  __/ |_| |  __/ ||  __/ (__| || (_) | |
    \_/\_/  |_| .__/ \___|____/ \___|\__\___|\___|\__\___/|_|
              |_|
        Forensic Wipe-Pattern Detector  |  Hackathon MVP
"""


def print_banner():
    if COLOR:
        print(Fore.GREEN + Style.BRIGHT + BANNER + Style.RESET_ALL)
    else:
        print(BANNER)


def print_summary(results: List[Dict], target: str, elapsed: float):
    """Print a summary table to stdout."""
    total = len(results)
    wiped = [r for r in results if r["pattern_type"] != "unknown"]

    print(f"\n{'─'*70}")
    if COLOR:
        print(Fore.GREEN + Style.BRIGHT + "  SCAN COMPLETE" + Style.RESET_ALL)
    else:
        print("  SCAN COMPLETE")
    print(f"{'─'*70}")
    print(f"  Target      : {target}")
    print(f"  Regions     : {total}")
    print(f"  Wiped found : {len(wiped)}")
    print(f"  Elapsed     : {elapsed:.2f}s")
    print(f"{'─'*70}\n")

    if not results:
        print("  No detections to display.")
        return

    rows = []
    for r in results:
        offset_str = f"0x{r['offset']:08X}"
        size_str = f"{r['size']:,}"
        ptype = r["pattern_type"]
        conf = f"{r['confidence']:.1f}%"
        algo = r.get("algorithm_label", r.get("algorithm", "?"))[:40]
        ent = f"{r['entropy']:.3f}"

        if COLOR:
            ptype_disp = _colorize(ptype.upper(), ptype)
            conf_disp = (Fore.RED if r["confidence"] > 80 else Fore.YELLOW) + conf + Style.RESET_ALL
        else:
            ptype_disp = ptype.upper()
            conf_disp = conf

        rows.append([offset_str, size_str, ptype_disp, conf_disp, ent, algo])

    headers = ["Offset", "Size (B)", "Pattern", "Confidence", "Entropy", "Algorithm"]

    if HAS_TABULATE:
        print(tabulate(rows, headers=headers, tablefmt="rounded_outline"))
    else:
        # Fallback plain text
        col_w = [12, 10, 16, 12, 9, 42]
        header_line = "  ".join(h.ljust(col_w[i]) for i, h in enumerate(headers))
        print(header_line)
        print("-" * len(header_line))
        for row in rows:
            print("  ".join(str(v).ljust(col_w[i]) for i, v in enumerate(row)))

    print()


# ── JSON report ──────────────────────────────────────────────────────────────

def save_json_report(results: List[Dict], target: str, output_path: str = None) -> str:
    """Serialize detections to a JSON report file. Returns the output path."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    if output_path is None:
        output_path = f"wipe_report_{ts}.json"

    report = {
        "scan_timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "tool": "WipeDetector v1.0",
        "target": target,
        "regions_analyzed": len(results),
        "detections_found": len([r for r in results if r["pattern_type"] != "unknown"]),
        "detections": results,
    }

    with open(output_path, "w") as fh:
        json.dump(report, fh, indent=2, default=str)

    return output_path


# ── CSV export ───────────────────────────────────────────────────────────────

def save_csv_report(results: List[Dict], output_path: str = None) -> str:
    """Export detections to CSV for further analysis. Returns the output path."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    if output_path is None:
        output_path = f"wipe_report_{ts}.csv"

    if not results:
        return output_path

    fields = [
        "offset", "size", "pattern_type", "confidence",
        "algorithm", "algorithm_label", "entropy",
        "chi_square", "chi_is_random", "zero_confidence", "one_confidence",
    ]

    with open(output_path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(results)

    return output_path
