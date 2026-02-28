"""
test_data/generate_samples.py

Generates synthetic disk images with known wiping patterns so you can
verify the detector against ground-truth data without needing a real drive.

Produces files in the test_data/ directory:
  clean.bin          - Normal random-ish "file" data, no wipe patterns
  zero_fill.bin      - Entirely 0x00
  one_fill.bin       - Entirely 0xFF
  random_fill.bin    - Cryptographically random bytes
  dod_3pass.bin      - Simulated DoD 5220.22-M 3-pass (zeros → ones → random)
  dod_7pass.bin      - Simulated DoD 7-pass (zones of zeros/ones/random)
  alternating.bin    - Repeating "AAAAABBBBBAAAAABBBBB" pattern
  novelty_haha.bin   - Repeating "haha-" (from dwipe novelty mode)
  mixed.bin          - Sections of different patterns concatenated
  gutmann_sim.bin    - Rough Gutmann simulation (many entropy zones)
"""

import os
import sys
import struct
import random

# Ensure we can run from any directory
OUTDIR = os.path.join(os.path.dirname(__file__))
SIZE = 1 * 1024 * 1024   # 1 MB per sample (small for fast demos)
CHUNK = 64 * 1024         # 64 KB sections for multi-pass images


def write_file(name: str, data: bytes):
    path = os.path.join(OUTDIR, name)
    with open(path, "wb") as fh:
        fh.write(data)
    kb = len(data) // 1024
    print(f"  [+] {name:<30} {kb:>6} KB")


def gen_clean(size=SIZE) -> bytes:
    """Simulate realistic file data: pseudo-random with structure."""
    rng = random.Random(42)
    return bytes(rng.getrandbits(8) for _ in range(size))


def gen_zero(size=SIZE) -> bytes:
    return b"\x00" * size


def gen_one(size=SIZE) -> bytes:
    return b"\xFF" * size


def gen_random(size=SIZE) -> bytes:
    return os.urandom(size)


def gen_dod_3pass(size=SIZE) -> bytes:
    """
    Simulate the *result* of a 3-pass DoD wipe where the last writer wins
    but we interleave sections to make multi-pass detection possible.
    In reality only the final pass remains; we simulate layered sections.
    """
    section = size // 3
    return gen_zero(section) + gen_one(section) + gen_random(size - 2 * section)


def gen_dod_7pass(size=SIZE) -> bytes:
    """7 sections alternating zeros, ones, random."""
    sec = size // 7
    pattern = [gen_zero, gen_one, gen_random, gen_zero, gen_one, gen_random, gen_zero]
    parts = [p(sec) for p in pattern]
    remainder = size - sec * 7
    return b"".join(parts) + gen_random(remainder)


def gen_alternating(size=SIZE) -> bytes:
    """Repeating 0xAA 0x55 alternating byte pattern."""
    unit = b"\xAA\x55"
    return (unit * (size // len(unit) + 1))[:size]


def gen_novelty_haha(size=SIZE) -> bytes:
    unit = b"haha-"
    return (unit * (size // len(unit) + 1))[:size]


def gen_mixed(size=SIZE) -> bytes:
    """Mixed: normal data + zero section + random section + repeating."""
    q = size // 4
    return gen_clean(q) + gen_zero(q) + gen_random(q) + gen_alternating(size - 3 * q)


def gen_gutmann_sim(size=SIZE) -> bytes:
    """
    Rough Gutmann simulation: many small sections of varying entropy.
    The 35-pass Gutmann method uses specific magnetic patterns; here we
    simulate the resulting entropy profile with 10 distinct zones.
    """
    zones = 10
    sec = size // zones
    parts = []
    for i in range(zones):
        if i % 3 == 0:
            parts.append(gen_zero(sec))
        elif i % 3 == 1:
            parts.append(gen_one(sec))
        else:
            parts.append(gen_random(sec))
    remainder = size - sec * zones
    parts.append(gen_random(remainder))
    return b"".join(parts)


def main():
    os.makedirs(OUTDIR, exist_ok=True)
    print(f"\n  Generating test samples in: {os.path.abspath(OUTDIR)}\n")

    samples = [
        ("clean.bin",          gen_clean()),
        ("zero_fill.bin",      gen_zero()),
        ("one_fill.bin",       gen_one()),
        ("random_fill.bin",    gen_random()),
        ("dod_3pass.bin",      gen_dod_3pass()),
        ("dod_7pass.bin",      gen_dod_7pass()),
        ("alternating.bin",    gen_alternating()),
        ("novelty_haha.bin",   gen_novelty_haha()),
        ("mixed.bin",          gen_mixed()),
        ("gutmann_sim.bin",    gen_gutmann_sim()),
    ]

    for name, data in samples:
        write_file(name, data)

    print(f"\n  Done! {len(samples)} sample files created.\n")
    print("  Run the detector against any of these, e.g.:")
    print("    python detector.py test_data/dod_3pass.bin\n")


if __name__ == "__main__":
    main()
