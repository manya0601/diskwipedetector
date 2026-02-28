"""
utils.py - Utility helpers for WipeDetector.
"""

import os
import time
import sys


def format_size(n: int) -> str:
    """Human-readable byte size."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def progress_bar(current: int, total: int, width: int = 40, prefix: str = "Scanning") -> None:
    """Print an in-place progress bar."""
    if total == 0:
        return
    pct = current / total
    filled = int(width * pct)
    bar = "█" * filled + "░" * (width - filled)
    sys.stdout.write(f"\r  {prefix}: [{bar}] {pct*100:.1f}%  ({current}/{total} chunks)")
    sys.stdout.flush()
    if current >= total:
        print()


def confirm(prompt: str) -> bool:
    """Ask the user for a yes/no confirmation."""
    answer = input(f"{prompt} [y/N]: ").strip().lower()
    return answer in ("y", "yes")


def elapsed(start: float) -> float:
    """Return seconds since start."""
    return time.time() - start
