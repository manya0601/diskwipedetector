# WipeDetector – Forensic Wipe-Pattern Scanner

A Python-based digital forensics tool that scans disk images, raw block devices,
and file-system volumes to **detect and classify data-wiping patterns**.  
Built as a hackathon MVP add-on to the [Disk-Wipe](https://github.com/manya0601/Disk-Wipe) project.

---

## Features

- **Statistical detection** – Shannon entropy + Chi-square test for randomness
- **Pattern matching** – zero-fill (0x00), one-fill (0xFF), repeating sequences
- **Multi-pass detection** – identifies entropy variance suggesting sequential overwrites
- **Algorithm classification** – DoD 5220.22-M (3- and 7-pass), Gutmann (35-pass), RCMP TSSIT, random-only, zero-fill, one-fill, alternating/novelty patterns
- **Confidence scoring** – 0–100% confidence for each detection
- **Real-time progress bar** – chunk-by-chunk scanning with ETA
- **JSON + CSV reports** – machine-readable output for further analysis
- **Test data generator** – 10 sample disk images with known patterns for demos
- **Read-only** – never modifies the scanned target

---

## Project Structure

```
wipe_detector/
├── detector.py              # Main CLI entry point
├── analyzer.py              # Detection algorithms (entropy, chi-sq, patterns)
├── scanner.py               # Disk/file/slack-space reader
├── reporter.py              # Console table + JSON/CSV output
├── utils.py                 # Progress bar, size formatting, helpers
├── requirements.txt
├── README.md
└── test_data/
    ├── generate_samples.py  # Generates 10 synthetic test images
    ├── clean.bin
    ├── zero_fill.bin
    ├── one_fill.bin
    ├── random_fill.bin
    ├── dod_3pass.bin
    ├── dod_7pass.bin
    ├── alternating.bin
    ├── novelty_haha.bin
    ├── mixed.bin
    └── gutmann_sim.bin
```

---

## Installation

### Prerequisites
- Python 3.6+
- pip

### Install dependencies

```bash
pip install -r requirements.txt
```

> **Note:** On Linux/macOS, scanning block devices (`/dev/sdb`) requires `sudo`.  
> On Windows, run your terminal as Administrator.

---

## Quick Start

### Step 1 – Generate test data

```bash
python test_data/generate_samples.py
```

### Step 2 – Scan a test image

```bash
python detector.py test_data/dod_3pass.bin
```

### Step 3 – Save reports

```bash
python detector.py test_data/mixed.bin --json report.json --csv report.csv
```

### Step 4 – Scan all test images at once

```bash
python detector.py test_data/ --all --json
```

---

## Usage

```
python detector.py <target> [options]
```

| Argument | Description |
|---|---|
| `target` | File, disk image, block device (`/dev/sdb`), or directory |
| `--chunk N` | Analysis chunk size in bytes (default: 4096) |
| `--slack` | Scan file slack space (target must be a directory) |
| `--all` | Scan all `.bin` files in a directory |
| `--json [FILE]` | Save JSON report |
| `--csv [FILE]` | Save CSV report |
| `--min-confidence N` | Skip results below N% confidence (default: 40) |
| `--verbose` / `-v` | Print each detection as it is found |

### Examples

```bash
# Scan a disk image
python detector.py disk_image.bin

# Scan a real block device (Linux, requires root)
sudo python detector.py /dev/sdb --json report.json

# Scan a mounted volume's slack space
python detector.py /mnt/usb --slack --csv

# Batch scan all .bin files in test_data/
python detector.py test_data/ --all --verbose

# High-confidence detections only
python detector.py disk.bin --min-confidence 80
```

---

## Understanding Results

### Output columns

| Column | Description |
|---|---|
| **Offset** | Hexadecimal byte offset in the file/device |
| **Size** | Chunk size analyzed (bytes) |
| **Pattern** | Detected pattern type |
| **Confidence** | Detection confidence (0–100%) |
| **Entropy** | Shannon entropy (0=identical bytes, 8=perfectly random) |
| **Algorithm** | Best-match wiping algorithm |

### Pattern types

| Pattern | Description |
|---|---|
| `ZERO_FILL` | All 0x00 bytes – simple zero wipe |
| `ONE_FILL` | All 0xFF bytes – simple one wipe |
| `RANDOM` | Cryptographically random data |
| `REPEATING` | Short repeating byte sequence (e.g. "haha-", 0xAA55) |
| `MULTI_PASS` | Multiple overwrite passes detected (high entropy variance) |

### Detection thresholds

| Metric | Threshold | Meaning |
|---|---|---|
| Entropy | > 7.8 | Likely random / encrypted |
| Entropy | < 0.1 | Uniform fill (zeros or ones) |
| Chi-square p | > 0.05 | Statistically random distribution |
| Pattern repeat confidence | > 95% | Repeating byte sequence |
| Multi-pass variance | > 2.0 | Multiple different passes detected |

---

## JSON Report Format

```json
{
  "scan_timestamp": "2026-02-28 10:30:00",
  "tool": "WipeDetector v1.0",
  "target": "/dev/sdb1",
  "regions_analyzed": 256,
  "detections_found": 253,
  "detections": [
    {
      "offset": 0,
      "size": 4096,
      "pattern_type": "zero_fill",
      "confidence": 100.0,
      "algorithm": "simple_zero",
      "algorithm_label": "Zero-fill (0x00)",
      "entropy": 0.0,
      "chi_square": 0.0,
      "chi_is_random": false,
      "zero_confidence": 100.0,
      "one_confidence": 0.0
    }
  ]
}
```

---

## Hackathon Demo Workflow

1. **Generate samples:** `python test_data/generate_samples.py`
2. **Show clean disk (no false positives):** `python detector.py test_data/clean.bin`  
   → Should return 0 detections
3. **Show zero-fill detection:** `python detector.py test_data/zero_fill.bin`  
   → 100% confidence zero-fill detected
4. **Show DoD 3-pass detection:** `python detector.py test_data/dod_3pass.bin`  
   → Shows zones of zeros, ones, and random data
5. **Show mixed real-world scenario:** `python detector.py test_data/mixed.bin --json --csv`  
   → Multiple pattern types in one file

---

## Detected Algorithms

| Algorithm | Passes | Detection method |
|---|---|---|
| **Zero-fill** | 1 | 100% 0x00 bytes, entropy ≈ 0 |
| **One-fill** | 1 | 100% 0xFF bytes, entropy ≈ 0 |
| **Random-fill** | 1 | Entropy > 7.5, chi-square uniform |
| **DoD 5220.22-M 3-pass** | 3 | Zeros + ones + random zones |
| **DoD 5220.22-M 7-pass** | 7 | All three zone types, high variance |
| **RCMP TSSIT OPS-II** | 7 | Similar signature to DoD 7-pass |
| **Gutmann 35-pass** | 35 | Many distinct entropy zones (≥4) |
| **Alternating/Novelty** | 1 | Short repeating byte pattern |

---

## Limitations

- Multi-pass algorithms (DoD, Gutmann) are simulated at the section level.
  In a real wipe, only the **last pass** remains on disk — detection relies on
  the scanner seeing sections written at different times (slack space, partial
  overwrites, etc.).
- Slack space access via Python is limited to file-system-level slack.
  RAM slack requires kernel-level access.
- SSD wear-leveling may hide some patterns from userspace tools.
- Block device access requires elevated privileges on all platforms.

---

## License

MIT – See LICENSE in the parent repository.
