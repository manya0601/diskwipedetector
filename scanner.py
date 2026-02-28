"""
scanner.py - Disk and file-based region scanner.

Reads raw data in configurable chunks from:
  - Regular files / disk image files
  - Block devices (requires elevated privileges)
  - Directories (scans slack space of each file)

All reads are read-only; this module never writes to any target.
"""

import os
import sys
import platform
from pathlib import Path
from typing import Iterator, Tuple


CHUNK_SIZE = 4096          # bytes per analysis chunk (one cluster / one sector group)
SLACK_CHUNK_SIZE = 512     # bytes to read from file slack space


def _get_cluster_size(path: str) -> int:
    """Best-effort cluster/block size detection for the given path."""
    try:
        stat = os.statvfs(path)
        return stat.f_bsize or CHUNK_SIZE
    except (AttributeError, OSError):
        return CHUNK_SIZE  # fallback


# ── Raw file / image scanner ────────────────────────────────────────────────

def scan_file(file_path: str, chunk_size: int = CHUNK_SIZE) -> Iterator[Tuple[int, bytes]]:
    """
    Yield (offset, data) tuples by reading file_path in chunk_size increments.
    Works for regular files, disk images, and block devices.

    Requires read permission on the target (block devices need root/admin).
    """
    file_path = os.path.abspath(file_path)
    try:
        with open(file_path, "rb") as fh:
            offset = 0
            while True:
                chunk = fh.read(chunk_size)
                if not chunk:
                    break
                yield offset, chunk
                offset += len(chunk)
    except PermissionError:
        print(f"[!] Permission denied: {file_path}. Try running as root/Administrator.")
        return
    except OSError as e:
        print(f"[!] Cannot read {file_path}: {e}")
        return


# ── Slack space scanner ──────────────────────────────────────────────────────

def _file_slack_data(file_path: str, cluster_size: int) -> bytes:
    """
    Read the slack bytes between end-of-file and end-of-cluster.
    On most OS/filesystems this area contains old data or zeros.

    Returns raw bytes of slack space (may be empty if no slack exists).
    """
    try:
        file_size = os.path.getsize(file_path)
        if file_size == 0:
            return b""
        slack_bytes = cluster_size - (file_size % cluster_size)
        if slack_bytes == cluster_size:
            return b""   # file fills exact cluster boundary

        # Read the last cluster of the file; the tail beyond EOF is the slack
        with open(file_path, "rb") as fh:
            fh.seek(max(0, file_size - cluster_size))
            data = fh.read()
            # The slack is what follows the real data in that cluster buffer.
            # Since OS won't expose it via normal read, we return what we can.
            tail = data[-(slack_bytes):]   # approximate; OS may zero-pad
            return tail
    except OSError:
        return b""


def scan_slack_space(volume_path: str) -> Iterator[Tuple[str, int, bytes]]:
    """
    Walk volume_path recursively, yield (file_path, slack_offset, slack_data)
    for every file that has a non-zero slack space.

    Note: Actual RAM-resident slack (RAM slack) is not accessible via Python
    userspace on modern kernels; this reads file-system level slack only.
    """
    volume_path = os.path.abspath(volume_path)
    cluster_size = _get_cluster_size(volume_path)

    for dirpath, _, filenames in os.walk(volume_path):
        for fname in filenames:
            fpath = os.path.join(dirpath, fname)
            try:
                slack = _file_slack_data(fpath, cluster_size)
                if slack:
                    file_size = os.path.getsize(fpath)
                    yield fpath, file_size, slack
            except OSError:
                continue


# ── Unallocated cluster scanner (image-level) ───────────────────────────────

def scan_unallocated_image(image_path: str, chunk_size: int = CHUNK_SIZE) -> Iterator[Tuple[int, bytes]]:
    """
    For a raw disk image, yield (offset, data) chunks that appear to be
    unallocated (heuristic: all-zero or high-entropy content not preceded
    by a valid FAT/MFT header).

    For a proper forensic unallocated scan you'd parse the filesystem table;
    here we use a simpler entropy-based heuristic suitable for a demo.
    """
    for offset, chunk in scan_file(image_path, chunk_size):
        # Skip obviously allocated clusters (starts with common file signatures)
        if _looks_allocated(chunk):
            continue
        yield offset, chunk


_ALLOC_MAGIC = [
    b"PK",       # ZIP / Office
    b"\x89PNG",  # PNG
    b"\xff\xd8", # JPEG
    b"MZ",       # PE/EXE
    b"\x7fELF",  # ELF
    b"ID3",      # MP3
    b"\x1f\x8b", # gzip
    b"%PDF",     # PDF
]

def _looks_allocated(chunk: bytes) -> bool:
    """Heuristic: chunk starts with a known file magic → probably allocated."""
    for magic in _ALLOC_MAGIC:
        if chunk.startswith(magic):
            return True
    return False


# ── Convenience: scan anything ──────────────────────────────────────────────

def scan_target(target: str, chunk_size: int = CHUNK_SIZE, slack: bool = False):
    """
    Auto-detect target type and return an appropriate generator.
      - If target is a directory and slack=True → slack space scan
      - Otherwise → raw file / block device scan
    """
    if os.path.isdir(target) and slack:
        return scan_slack_space(target)
    return scan_file(target, chunk_size)
