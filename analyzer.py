"""
analyzer.py - Core detection algorithms for wipe pattern identification.

Uses statistical methods (Shannon entropy, chi-square test, pattern matching)
to identify wiping signatures and estimate which algorithm was used.
"""

import math
import os
from collections import Counter


# ── Entropy & Randomness ────────────────────────────────────────────────────

def calculate_entropy(data: bytes) -> float:
    """
    Calculate Shannon entropy of a byte sequence.
    Returns value in range [0.0, 8.0].
      0.0 → all identical bytes (e.g. all-zeros)
      8.0 → perfectly uniform random distribution
    """
    if not data:
        return 0.0
    freq = Counter(data)
    length = len(data)
    entropy = -sum((c / length) * math.log2(c / length) for c in freq.values())
    return round(entropy, 4)


def chi_square_test(data: bytes) -> dict:
    """
    Chi-square goodness-of-fit test against a uniform byte distribution.
    For a truly random sequence of n bytes, each of the 256 values should
    appear n/256 times.  Large chi² → non-random.

    Returns:
        {
            "chi_square": float,
            "is_random": bool,      # True if chi² suggests uniform dist.
            "p_estimate": str       # rough p-value bucket
        }
    """
    if len(data) < 256:
        return {"chi_square": 0.0, "is_random": False, "p_estimate": "n/a (too short)"}

    freq = Counter(data)
    expected = len(data) / 256.0
    chi2 = sum((freq.get(b, 0) - expected) ** 2 / expected for b in range(256))

    # Rough p-value buckets (df=255)
    # chi² < 293 → p > 0.10  (very likely random)
    # chi² < 310 → p > 0.05  (likely random)
    # chi² > 350 → p < 0.01  (unlikely random)
    is_random = chi2 < 310
    if chi2 < 270:
        p_est = ">0.20 (strongly uniform)"
    elif chi2 < 293:
        p_est = ">0.10 (likely uniform)"
    elif chi2 < 310:
        p_est = ">0.05 (possibly uniform)"
    elif chi2 < 350:
        p_est = "<0.05 (non-uniform)"
    else:
        p_est = "<0.01 (strongly non-uniform)"

    return {
        "chi_square": round(chi2, 2),
        "is_random": is_random,
        "p_estimate": p_est,
    }


# ── Simple Pattern Detectors ────────────────────────────────────────────────

def detect_zero_pattern(data: bytes) -> float:
    """Return confidence (0-100) that data is all 0x00 bytes."""
    if not data:
        return 0.0
    zeros = data.count(0x00)
    return round((zeros / len(data)) * 100, 2)


def detect_one_pattern(data: bytes) -> float:
    """Return confidence (0-100) that data is all 0xFF bytes."""
    if not data:
        return 0.0
    ones = data.count(0xFF)
    return round((ones / len(data)) * 100, 2)


def detect_repeating_pattern(data: bytes) -> dict:
    """
    Scan for short repeating byte sequences (period 1-64).
    Returns the dominant period and its confidence, or None if not found.
    """
    if len(data) < 128:
        return {"found": False, "pattern": None, "period": None, "confidence": 0.0}

    best_period = None
    best_score = 0.0

    for period in range(1, min(65, len(data) // 4)):
        matches = sum(
            1 for i in range(period, len(data)) if data[i] == data[i % period]
        )
        score = matches / len(data)
        if score > best_score:
            best_score = score
            best_period = period

    if best_score >= 0.95 and best_period is not None:
        sample = data[:best_period]
        return {
            "found": True,
            "pattern": sample.hex(),
            "period": best_period,
            "confidence": round(best_score * 100, 2),
        }
    return {"found": False, "pattern": None, "period": None, "confidence": round(best_score * 100, 2)}


# ── Multi-Pass Heuristics ───────────────────────────────────────────────────

def detect_multi_pass(data: bytes, chunk_size: int = 512) -> dict:
    """
    Estimate whether the data shows signs of multiple overwrite passes.
    Strategy: split data into chunks and check entropy variance.
    A large variance suggests sequential overwrites with different patterns
    (e.g. zeros → ones → random = DoD 3-pass).

    Returns confidence and a list of detected phase labels.
    """
    if len(data) < chunk_size * 4:
        return {"confidence": 0.0, "phases": [], "entropy_variance": 0.0}

    chunks = [data[i:i + chunk_size] for i in range(0, len(data) - chunk_size, chunk_size)]
    entropies = [calculate_entropy(c) for c in chunks]

    mean_e = sum(entropies) / len(entropies)
    variance = sum((e - mean_e) ** 2 for e in entropies) / len(entropies)

    phases = []
    for e in entropies:
        if e < 0.1:
            label = "zeros"
        elif e > 7.8:
            label = "random"
        elif 7.9 > e > 0.08:
            label = "ones_or_pattern"
        else:
            label = "mixed"
        if not phases or phases[-1] != label:
            phases.append(label)

    # Confidence based on variance magnitude
    if variance > 4.0:
        confidence = 90.0
    elif variance > 2.0:
        confidence = 75.0
    elif variance > 0.5:
        confidence = 50.0
    else:
        confidence = 10.0

    return {
        "confidence": round(confidence, 1),
        "phases": phases,
        "entropy_variance": round(variance, 4),
    }


# ── Algorithm Classifier ────────────────────────────────────────────────────

ALGORITHM_SIGNATURES = {
    "simple_zero":      {"entropy_max": 0.1,  "zero_min": 99.0},
    "simple_one":       {"entropy_max": 0.1,  "one_min": 99.0},
    "random_only":      {"entropy_min": 7.5,  "chi_random": True},
    "dod_5220_3pass":   {"phases": {"zeros", "random"}, "min_phases": 2},
    "dod_5220_7pass":   {"phases": {"zeros", "ones", "random"}, "min_phases": 3},
    "gutmann_35pass":   {"entropy_range": (5.0, 8.0), "phase_count_min": 4},
    "rcmp_tssit_7pass": {"phases": {"zeros", "ones", "random"}, "min_phases": 3},
    "alternating":      {"repeating": True},
}


def classify_wiping_algorithm(
    entropy: float,
    zero_conf: float,
    one_conf: float,
    chi: dict,
    multi: dict,
    repeating: dict,
) -> dict:
    """
    Match collected statistics against known wiping algorithm signatures.
    Returns the best match, a confidence score, and a human-readable label.
    """
    phase_set = set(multi.get("phases", []))
    phase_count = len(phase_set)

    # --- exact single-pass patterns ---
    if zero_conf >= 99.0:
        return {"algorithm": "simple_zero", "label": "Zero-fill (0x00)", "confidence": zero_conf}

    if one_conf >= 99.0:
        return {"algorithm": "simple_one", "label": "One-fill (0xFF)", "confidence": one_conf}

    if entropy >= 7.5 and chi.get("is_random", False):
        return {"algorithm": "random_only", "label": "Random-fill (single pass)", "confidence": round(entropy / 8.0 * 100, 1)}

    # --- repeating pattern (novelty wipes like "haha-", "3===D", alternating) ---
    if repeating.get("found"):
        return {
            "algorithm": "alternating_pattern",
            "label": f"Repeating pattern (period={repeating['period']}, hex={repeating['pattern'][:16]})",
            "confidence": repeating["confidence"],
        }

    # --- multi-pass algorithms ---
    if multi["confidence"] >= 70.0:
        if "zeros" in phase_set and "random" in phase_set and phase_count >= 2:
            if "ones" in phase_set or multi["entropy_variance"] > 3.5:
                return {
                    "algorithm": "dod_5220_7pass",
                    "label": "DoD 5220.22-M 7-pass / RCMP TSSIT",
                    "confidence": multi["confidence"],
                }
            return {
                "algorithm": "dod_5220_3pass",
                "label": "DoD 5220.22-M 3-pass",
                "confidence": multi["confidence"],
            }
        if phase_count >= 4:
            return {
                "algorithm": "gutmann_35pass",
                "label": "Gutmann 35-pass (estimated)",
                "confidence": min(multi["confidence"], 70.0),
            }

    # --- mixed / unknown ---
    return {
        "algorithm": "unknown",
        "label": "Unknown / unrecognized pattern",
        "confidence": 0.0,
    }


# ── Full Region Analysis ────────────────────────────────────────────────────

def analyze_region(data: bytes, offset: int = 0) -> dict:
    """
    Run all detectors on a data region and return a consolidated result dict.
    """
    entropy = calculate_entropy(data)
    chi = chi_square_test(data)
    zero_conf = detect_zero_pattern(data)
    one_conf = detect_one_pattern(data)
    repeating = detect_repeating_pattern(data)
    multi = detect_multi_pass(data)

    algo = classify_wiping_algorithm(entropy, zero_conf, one_conf, chi, multi, repeating)

    # Determine top-level pattern type
    if zero_conf >= 99.0:
        pattern_type = "zero_fill"
    elif one_conf >= 99.0:
        pattern_type = "one_fill"
    elif entropy >= 7.5 and chi.get("is_random"):
        pattern_type = "random"
    elif repeating.get("found"):
        pattern_type = "repeating"
    elif multi["confidence"] >= 50.0:
        pattern_type = "multi_pass"
    else:
        pattern_type = "unknown"

    return {
        "offset": offset,
        "size": len(data),
        "pattern_type": pattern_type,
        "confidence": algo["confidence"],
        "algorithm": algo["algorithm"],
        "algorithm_label": algo["label"],
        "entropy": entropy,
        "chi_square": chi["chi_square"],
        "chi_is_random": chi["is_random"],
        "zero_confidence": zero_conf,
        "one_confidence": one_conf,
        "repeating": repeating,
        "multi_pass": multi,
    }
