import streamlit as st
import os
import sys
import json
import time
import tempfile
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime

# ── Make sure local modules are importable ────────────────────────────────────
sys.path.insert(0, os.path.dirname(__file__))
from analyzer import analyze_region
from scanner import scan_file

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="WipeDetector",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Custom CSS ────────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;600;700&display=swap');

/* Base */
html, body, [class*="css"] {
    font-family: 'Rajdhani', sans-serif;
}

/* Dark forensic theme */
.stApp {
    background-color: #0a0e14;
    color: #c9d1d9;
}

/* Sidebar */
[data-testid="stSidebar"] {
    background-color: #0d1117;
    border-right: 1px solid #1a2332;
}

/* Header banner */
.hero-banner {
    background: linear-gradient(135deg, #0d1117 0%, #0a1628 50%, #0d1117 100%);
    border: 1px solid #1e3a5f;
    border-radius: 8px;
    padding: 2rem 2.5rem;
    margin-bottom: 1.5rem;
    position: relative;
    overflow: hidden;
}
.hero-banner::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0; bottom: 0;
    background: repeating-linear-gradient(
        0deg,
        transparent,
        transparent 2px,
        rgba(0,255,136,0.02) 2px,
        rgba(0,255,136,0.02) 4px
    );
    pointer-events: none;
}
.hero-title {
    font-family: 'Share Tech Mono', monospace;
    font-size: 2.4rem;
    color: #00ff88;
    letter-spacing: 4px;
    margin: 0;
    text-shadow: 0 0 20px rgba(0,255,136,0.4);
}
.hero-sub {
    font-family: 'Share Tech Mono', monospace;
    color: #4a9eff;
    font-size: 0.85rem;
    letter-spacing: 2px;
    margin-top: 0.3rem;
}

/* Metric cards */
.metric-card {
    background: #0d1117;
    border: 1px solid #1e3a5f;
    border-radius: 6px;
    padding: 1.2rem 1.5rem;
    text-align: center;
}
.metric-value {
    font-family: 'Share Tech Mono', monospace;
    font-size: 2rem;
    font-weight: bold;
    color: #00ff88;
}
.metric-label {
    font-size: 0.8rem;
    color: #8b949e;
    letter-spacing: 1px;
    text-transform: uppercase;
    margin-top: 0.2rem;
}

/* Detection table rows */
.pattern-zero    { color: #58a6ff; font-weight: 600; }
.pattern-one     { color: #f0e68c; font-weight: 600; }
.pattern-random  { color: #ff6b6b; font-weight: 600; }
.pattern-repeat  { color: #da70d6; font-weight: 600; }
.pattern-multi   { color: #ff4444; font-weight: 700; }
.pattern-unknown { color: #8b949e; }

/* Section headers */
.section-header {
    font-family: 'Share Tech Mono', monospace;
    color: #4a9eff;
    font-size: 0.8rem;
    letter-spacing: 3px;
    text-transform: uppercase;
    border-bottom: 1px solid #1e3a5f;
    padding-bottom: 0.5rem;
    margin-bottom: 1rem;
}

/* Buttons */
.stButton > button {
    background: linear-gradient(135deg, #00ff88, #00cc6a) !important;
    color: #0a0e14 !important;
    font-family: 'Share Tech Mono', monospace !important;
    font-weight: bold !important;
    letter-spacing: 2px !important;
    border: none !important;
    border-radius: 4px !important;
    padding: 0.6rem 2rem !important;
}
.stButton > button:hover {
    background: linear-gradient(135deg, #00cc6a, #009950) !important;
    box-shadow: 0 0 15px rgba(0,255,136,0.3) !important;
}

/* Progress bar */
.stProgress > div > div {
    background-color: #00ff88 !important;
}

/* Alert / info boxes */
.stAlert {
    background-color: #0d1117 !important;
    border-color: #1e3a5f !important;
}

/* Tabs */
.stTabs [data-baseweb="tab-list"] {
    background-color: #0d1117;
    border-bottom: 1px solid #1e3a5f;
}
.stTabs [data-baseweb="tab"] {
    font-family: 'Share Tech Mono', monospace;
    letter-spacing: 1px;
    color: #8b949e;
}
.stTabs [aria-selected="true"] {
    color: #00ff88 !important;
    border-bottom-color: #00ff88 !important;
}

/* Scan log box */
.scan-log {
    background: #0d1117;
    border: 1px solid #1e3a5f;
    border-radius: 6px;
    padding: 1rem;
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.78rem;
    color: #8b949e;
    max-height: 200px;
    overflow-y: auto;
}

/* File uploader */
[data-testid="stFileUploader"] {
    border: 1px dashed #1e3a5f !important;
    border-radius: 6px !important;
    background: #0d1117 !important;
}

/* Selectbox / number input */
.stSelectbox > div, .stNumberInput > div {
    background-color: #0d1117 !important;
    border-color: #1e3a5f !important;
}

/* Expander */
.streamlit-expanderHeader {
    background-color: #0d1117 !important;
    font-family: 'Share Tech Mono', monospace !important;
    color: #4a9eff !important;
}
</style>
""", unsafe_allow_html=True)

# ── Constants ─────────────────────────────────────────────────────────────────
PATTERN_COLORS = {
    "zero_fill":  "#58a6ff",
    "one_fill":   "#f0e68c",
    "random":     "#ff6b6b",
    "repeating":  "#da70d6",
    "multi_pass": "#ff4444",
    "unknown":    "#8b949e",
}

PATTERN_LABELS = {
    "zero_fill":  "ZERO FILL",
    "one_fill":   "ONE FILL",
    "random":     "RANDOM",
    "repeating":  "REPEATING",
    "multi_pass": "MULTI-PASS",
    "unknown":    "UNKNOWN",
}

ALGO_DESCRIPTIONS = {
    "simple_zero":      "All bytes are 0x00. Basic zero-wipe, fastest method.",
    "simple_one":       "All bytes are 0xFF. One-fill wipe.",
    "random_only":      "Cryptographically random data. Single-pass secure wipe.",
    "dod_5220_3pass":   "DoD 5220.22-M 3-pass: zeros → ones → random.",
    "dod_5220_7pass":   "DoD 5220.22-M 7-pass or RCMP TSSIT OPS-II.",
    "gutmann_35pass":   "Gutmann 35-pass: complex magnetic pattern sequence.",
    "alternating_pattern": "Short repeating byte sequence (novelty/alternating wipe).",
    "unknown":          "Pattern does not match known wiping algorithms.",
}

# ── Session state ─────────────────────────────────────────────────────────────
if "results" not in st.session_state:
    st.session_state.results = []
if "scan_done" not in st.session_state:
    st.session_state.scan_done = False
if "scan_target" not in st.session_state:
    st.session_state.scan_target = ""
if "scan_time" not in st.session_state:
    st.session_state.scan_time = 0.0

# ── Helpers ───────────────────────────────────────────────────────────────────

def run_scan(filepath: str, chunk_size: int = 4096, min_conf: float = 40.0, limit_mb: int = 0):
    """Run scan and yield results + progress."""
    results = []
    total_size = os.path.getsize(filepath)
    max_bytes = limit_mb * 1024 * 1024 if limit_mb else total_size
    scan_size = min(max_bytes, total_size) if max_bytes else total_size
    total_chunks = max(1, scan_size // chunk_size)
    processed = 0
    bytes_read = 0

    for offset, chunk in scan_file(filepath, chunk_size):
        if limit_mb and bytes_read >= limit_mb * 1024 * 1024:
            break
        bytes_read += len(chunk)
        result = analyze_region(chunk, offset)
        processed += 1

        if result["pattern_type"] != "unknown" and result["confidence"] >= min_conf:
            results.append(result)

        progress = min(processed / total_chunks, 1.0)
        yield progress, results, processed, total_chunks

def format_offset(n: int) -> str:
    return f"0x{n:08X}"

def format_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"

def make_df(results):
    rows = []
    for r in results:
        rows.append({
            "Offset": format_offset(r["offset"]),
            "Size": format_size(r["size"]),
            "Pattern": PATTERN_LABELS.get(r["pattern_type"], r["pattern_type"]),
            "Confidence": f"{r['confidence']:.1f}%",
            "Entropy": f"{r['entropy']:.3f}",
            "Algorithm": r.get("algorithm_label", r.get("algorithm", "?")),
            "_pattern_type": r["pattern_type"],
            "_confidence_raw": r["confidence"],
        })
    return pd.DataFrame(rows)

# ── SIDEBAR ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown('<p class="section-header">⚙ SCAN CONFIGURATION</p>', unsafe_allow_html=True)

    scan_mode = st.selectbox(
        "Scan Mode",
        ["Upload File / Image", "Local Path (disk/device)"],
        help="Upload a .bin disk image, or enter a local path like /dev/sda"
    )

    st.divider()

    chunk_size = st.select_slider(
        "Chunk Size",
        options=[512, 1024, 2048, 4096, 8192, 16384],
        value=4096,
        help="Bytes analyzed per region. Smaller = more detail, slower."
    )

    min_confidence = st.slider(
        "Min Confidence %",
        min_value=10, max_value=99, value=40,
        help="Filter out low-confidence detections."
    )

    limit_mb = st.number_input(
        "Limit Scan (MB, 0 = unlimited)",
        min_value=0, max_value=100000, value=0,
        help="Limit how many MB to scan. Useful for large disks."
    )

    st.divider()
    st.markdown('<p class="section-header">ℹ ABOUT</p>', unsafe_allow_html=True)
    st.markdown("""
    <div style="font-size:0.78rem; color:#8b949e; line-height:1.6;">
    <b style="color:#4a9eff">WipeDetector v1.0</b><br>
    Forensic wipe-pattern scanner.<br><br>
    Detects: Zero-fill, One-fill,<br>
    Random, DoD 3/7-pass,<br>
    Gutmann 35-pass, RCMP TSSIT,<br>
    Repeating/novelty patterns.<br><br>
    <span style="color:#00ff88">Read-only — never modifies disk.</span>
    </div>
    """, unsafe_allow_html=True)

# ── MAIN AREA ─────────────────────────────────────────────────────────────────

# Hero banner
st.markdown("""
<div class="hero-banner">
    <div class="hero-title">🔍 WIPEDETECTOR</div>
    <div class="hero-sub">FORENSIC WIPE-PATTERN SCANNER &nbsp;|&nbsp; HACKATHON MVP &nbsp;|&nbsp; v1.0</div>
</div>
""", unsafe_allow_html=True)

# ── INPUT SECTION ─────────────────────────────────────────────────────────────
st.markdown('<p class="section-header">📂 TARGET</p>', unsafe_allow_html=True)

uploaded_file = None
local_path = ""

if scan_mode == "Upload File / Image":
    uploaded_file = st.file_uploader(
        "Upload a disk image (.bin, .img, .raw, or any file)",
        type=None,
        help="Upload any binary file or disk image to scan"
    )
else:
    local_path = st.text_input(
        "Enter local file or device path",
        placeholder="/dev/sda  or  /home/kali/test_data/dod_3pass.bin",
        help="Requires read permissions. Use sudo for block devices."
    )

col1, col2 = st.columns([1, 4])
with col1:
    scan_btn = st.button("▶  RUN SCAN", use_container_width=True)

# ── SCAN LOGIC ────────────────────────────────────────────────────────────────
if scan_btn:
    target_path = None

    if scan_mode == "Upload File / Image":
        if uploaded_file is None:
            st.error("Please upload a file first.")
            st.stop()
        # Save to temp file
        suffix = os.path.splitext(uploaded_file.name)[1] or ".bin"
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=suffix)
        tmp.write(uploaded_file.read())
        tmp.flush()
        tmp.close()
        target_path = tmp.name
        display_name = uploaded_file.name
    else:
        if not local_path.strip():
            st.error("Please enter a file or device path.")
            st.stop()
        if not os.path.exists(local_path.strip()):
            st.error(f"Path not found: `{local_path.strip()}`")
            st.stop()
        target_path = local_path.strip()
        display_name = target_path

    # Run scan with live progress
    st.markdown('<p class="section-header">⚡ SCANNING...</p>', unsafe_allow_html=True)
    progress_bar = st.progress(0)
    status_text = st.empty()
    log_placeholder = st.empty()

    all_results = []
    start_time = time.time()
    log_lines = []

    try:
        for progress, results, processed, total in run_scan(
            target_path, chunk_size, min_confidence, int(limit_mb)
        ):
            progress_bar.progress(progress)
            status_text.markdown(
                f'<span style="font-family:Share Tech Mono,monospace;color:#4a9eff;font-size:0.85rem;">'
                f'Chunk {processed}/{total} &nbsp;|&nbsp; Detections: {len(results)}'
                f'</span>',
                unsafe_allow_html=True
            )
            all_results = results

            # Live log of new detections
            if results and (len(results) > len(log_lines)):
                for r in results[len(log_lines):]:
                    log_lines.append(
                        f"[{format_offset(r['offset'])}]  "
                        f"{PATTERN_LABELS.get(r['pattern_type'],'?'):<12}  "
                        f"{r['confidence']:.1f}%  →  {r.get('algorithm_label','?')[:40]}"
                    )
                log_placeholder.markdown(
                    '<div class="scan-log">' +
                    "<br>".join(f'<span style="color:#00ff88">▸</span> {l}' for l in log_lines[-20:]) +
                    '</div>',
                    unsafe_allow_html=True
                )

        elapsed = time.time() - start_time
        progress_bar.progress(1.0)
        status_text.empty()
        log_placeholder.empty()

        st.session_state.results = all_results
        st.session_state.scan_done = True
        st.session_state.scan_target = display_name
        st.session_state.scan_time = elapsed

        if uploaded_file:
            os.unlink(target_path)

    except Exception as e:
        st.error(f"Scan error: {e}")
        st.stop()

# ── RESULTS ───────────────────────────────────────────────────────────────────
if st.session_state.scan_done and st.session_state.results is not None:
    results = st.session_state.results
    elapsed = st.session_state.scan_time
    target_name = st.session_state.scan_target

    st.markdown('<p class="section-header">✅ SCAN COMPLETE</p>', unsafe_allow_html=True)

    # ── Metric cards ──
    wiped_count = len([r for r in results if r["pattern_type"] != "unknown"])
    avg_conf = sum(r["confidence"] for r in results) / len(results) if results else 0
    pattern_counts = {}
    for r in results:
        p = r["pattern_type"]
        pattern_counts[p] = pattern_counts.get(p, 0) + 1

    m1, m2, m3, m4 = st.columns(4)
    with m1:
        st.markdown(f'<div class="metric-card"><div class="metric-value">{len(results)}</div><div class="metric-label">Regions Detected</div></div>', unsafe_allow_html=True)
    with m2:
        st.markdown(f'<div class="metric-card"><div class="metric-value" style="color:#ff6b6b">{wiped_count}</div><div class="metric-label">Wiped Regions</div></div>', unsafe_allow_html=True)
    with m3:
        st.markdown(f'<div class="metric-card"><div class="metric-value">{avg_conf:.1f}%</div><div class="metric-label">Avg Confidence</div></div>', unsafe_allow_html=True)
    with m4:
        st.markdown(f'<div class="metric-card"><div class="metric-value" style="color:#4a9eff">{elapsed:.2f}s</div><div class="metric-label">Elapsed</div></div>', unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    if not results:
        st.info("✅ No wipe patterns detected. Disk appears clean.")
    else:
        tab1, tab2, tab3 = st.tabs(["📋  DETECTIONS TABLE", "📊  CHARTS", "📄  JSON REPORT"])

        # ── Tab 1: Table ──────────────────────────────────────────────────────
        with tab1:
            df = make_df(results)
            display_df = df.drop(columns=["_pattern_type", "_confidence_raw"])

            def color_pattern(val):
                for key, label in PATTERN_LABELS.items():
                    if val == label:
                        color = PATTERN_COLORS.get(key, "#c9d1d9")
                        return f"color: {color}; font-weight: 600; font-family: 'Share Tech Mono', monospace;"
                return ""

            def color_confidence(val):
                try:
                    pct = float(val.replace("%", ""))
                    if pct >= 90:
                        return "color: #ff4444; font-weight: bold;"
                    elif pct >= 70:
                        return "color: #ffa500;"
                    else:
                        return "color: #c9d1d9;"
                except:
                    return ""

            styled = display_df.style.applymap(color_pattern, subset=["Pattern"]) \
                                     .applymap(color_confidence, subset=["Confidence"])
            st.dataframe(styled, use_container_width=True, height=400)

            # Download buttons
            c1, c2 = st.columns(2)
            with c1:
                csv_data = display_df.to_csv(index=False)
                st.download_button(
                    "⬇  DOWNLOAD CSV",
                    data=csv_data,
                    file_name=f"wipe_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv",
                    use_container_width=True
                )

        # ── Tab 2: Charts ─────────────────────────────────────────────────────
        with tab2:
            col_a, col_b = st.columns(2)

            with col_a:
                st.markdown("**Pattern Distribution**")
                if pattern_counts:
                    labels = [PATTERN_LABELS.get(k, k) for k in pattern_counts.keys()]
                    values = list(pattern_counts.values())
                    colors = [PATTERN_COLORS.get(k, "#8b949e") for k in pattern_counts.keys()]
                    fig_pie = go.Figure(data=[go.Pie(
                        labels=labels,
                        values=values,
                        marker=dict(colors=colors, line=dict(color="#0a0e14", width=2)),
                        textfont=dict(family="Share Tech Mono", color="white"),
                        hole=0.4,
                    )])
                    fig_pie.update_layout(
                        paper_bgcolor="#0d1117",
                        plot_bgcolor="#0d1117",
                        font=dict(color="#c9d1d9", family="Rajdhani"),
                        margin=dict(t=10, b=10, l=10, r=10),
                        legend=dict(font=dict(color="#c9d1d9")),
                        showlegend=True,
                    )
                    st.plotly_chart(fig_pie, use_container_width=True)

            with col_b:
                st.markdown("**Entropy by Region (first 100)**")
                sample = results[:100]
                offsets = [format_offset(r["offset"]) for r in sample]
                entropies = [r["entropy"] for r in sample]
                ptypes = [r["pattern_type"] for r in sample]
                fig_bar = go.Figure(data=[go.Bar(
                    x=list(range(len(sample))),
                    y=entropies,
                    marker_color=[PATTERN_COLORS.get(p, "#8b949e") for p in ptypes],
                    hovertext=[f"{offsets[i]}<br>Entropy: {entropies[i]:.3f}<br>{PATTERN_LABELS.get(ptypes[i])}" for i in range(len(sample))],
                    hoverinfo="text",
                )])
                fig_bar.add_hline(y=7.8, line_dash="dash", line_color="#ff6b6b",
                                  annotation_text="random threshold", annotation_font_color="#ff6b6b")
                fig_bar.update_layout(
                    paper_bgcolor="#0d1117",
                    plot_bgcolor="#0d1117",
                    font=dict(color="#c9d1d9", family="Rajdhani"),
                    xaxis=dict(showgrid=False, color="#4a9eff", title="Region Index"),
                    yaxis=dict(gridcolor="#1e3a5f", color="#4a9eff", title="Entropy (bits)", range=[0, 8.5]),
                    margin=dict(t=20, b=40, l=50, r=20),
                    showlegend=False,
                )
                st.plotly_chart(fig_bar, use_container_width=True)

            # Confidence scatter
            st.markdown("**Confidence Score per Detection**")
            conf_vals = [r["confidence"] for r in results]
            ptype_vals = [PATTERN_LABELS.get(r["pattern_type"], "?") for r in results]
            fig_scatter = go.Figure(data=[go.Scatter(
                x=list(range(len(results))),
                y=conf_vals,
                mode="markers",
                marker=dict(
                    color=[PATTERN_COLORS.get(r["pattern_type"], "#8b949e") for r in results],
                    size=6,
                    opacity=0.8,
                ),
                hovertext=[f"{format_offset(results[i]['offset'])}<br>{ptype_vals[i]}<br>Conf: {conf_vals[i]:.1f}%" for i in range(len(results))],
                hoverinfo="text",
            )])
            fig_scatter.update_layout(
                paper_bgcolor="#0d1117",
                plot_bgcolor="#0d1117",
                font=dict(color="#c9d1d9", family="Rajdhani"),
                xaxis=dict(showgrid=False, color="#4a9eff", title="Region Index"),
                yaxis=dict(gridcolor="#1e3a5f", color="#4a9eff", title="Confidence (%)", range=[0, 105]),
                height=250,
                margin=dict(t=10, b=40, l=50, r=20),
            )
            st.plotly_chart(fig_scatter, use_container_width=True)

        # ── Tab 3: JSON ───────────────────────────────────────────────────────
        with tab3:
            report = {
                "scan_timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "tool": "WipeDetector v1.0",
                "target": target_name,
                "elapsed_seconds": round(elapsed, 3),
                "regions_analyzed": len(results),
                "detections_found": wiped_count,
                "detections": results,
            }
            json_str = json.dumps(report, indent=2, default=str)
            st.code(json_str[:3000] + ("\n... (truncated)" if len(json_str) > 3000 else ""), language="json")
            st.download_button(
                "⬇  DOWNLOAD JSON REPORT",
                data=json_str,
                file_name=f"wipe_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json",
                use_container_width=False
            )

elif not st.session_state.scan_done:
    # Welcome state
    st.markdown("""
    <div style="
        background: #0d1117;
        border: 1px solid #1e3a5f;
        border-radius: 8px;
        padding: 3rem;
        text-align: center;
        margin-top: 2rem;
    ">
        <div style="font-size: 4rem; margin-bottom: 1rem;">🔬</div>
        <div style="font-family: 'Share Tech Mono', monospace; color: #4a9eff; font-size: 1.1rem; letter-spacing: 2px;">
            READY TO SCAN
        </div>
        <div style="color: #8b949e; margin-top: 0.8rem; font-size: 0.95rem; line-height: 1.8;">
            Upload a disk image or specify a local path,<br>
            then click <b style="color:#00ff88">RUN SCAN</b> to detect wipe patterns.
        </div>
        <div style="margin-top: 2rem; display: flex; justify-content: center; gap: 1rem; flex-wrap: wrap;">
            <span style="background:#0a1628; border:1px solid #1e3a5f; border-radius:4px; padding:0.4rem 0.8rem; font-size:0.8rem; color:#58a6ff; font-family:Share Tech Mono,monospace;">ZERO-FILL</span>
            <span style="background:#0a1628; border:1px solid #1e3a5f; border-radius:4px; padding:0.4rem 0.8rem; font-size:0.8rem; color:#f0e68c; font-family:Share Tech Mono,monospace;">ONE-FILL</span>
            <span style="background:#0a1628; border:1px solid #1e3a5f; border-radius:4px; padding:0.4rem 0.8rem; font-size:0.8rem; color:#ff6b6b; font-family:Share Tech Mono,monospace;">RANDOM</span>
            <span style="background:#0a1628; border:1px solid #1e3a5f; border-radius:4px; padding:0.4rem 0.8rem; font-size:0.8rem; color:#da70d6; font-family:Share Tech Mono,monospace;">REPEATING</span>
            <span style="background:#0a1628; border:1px solid #1e3a5f; border-radius:4px; padding:0.4rem 0.8rem; font-size:0.8rem; color:#ff4444; font-family:Share Tech Mono,monospace; font-weight:bold;">DOD 3/7-PASS</span>
            <span style="background:#0a1628; border:1px solid #1e3a5f; border-radius:4px; padding:0.4rem 0.8rem; font-size:0.8rem; color:#ff4444; font-family:Share Tech Mono,monospace; font-weight:bold;">GUTMANN 35-PASS</span>
        </div>
    </div>
    """, unsafe_allow_html=True)
