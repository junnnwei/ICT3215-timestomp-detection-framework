import json
import yaml
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import matplotlib as mpl
import pandas as pd
import os
import sys
from textwrap import wrap
from matplotlib import patheffects as pe

VIOLATIONS_JSON = "violations_output_TS008.json" 
RULES_YAML = "timestomp_rules.yaml"
OUTPUT_DIR = "graphs"
os.makedirs(OUTPUT_DIR, exist_ok=True)

mpl.rcParams.update({
    "font.size": 12,
    "axes.facecolor": "white",
    "figure.facecolor": "white",
    "savefig.facecolor": "white",
})

SEVERITY_STYLES = {
    "CRITICAL": {"border": "#7F1D1D", "bg": "#FCF2F2", "text": "#7F1D1D"},
    "HIGH":     {"border": "#B91C1C", "bg": "#FCEDED", "text": "#B91C1C"},
    "MEDIUM":   {"border": "#9A3412", "bg": "#FFF4E8", "text": "#9A3412"},
    "LOW":      {"border": "#7A5E00", "bg": "#FFFBE8", "text": "#7A5E00"},
}

ARTIFACT_COLORS = {
    "$MFT": "#4CAF50",
    "PREFETCH": "#2196F3",
    "$USN_JOURNAL": "#EF4444",
    "APPCOMPATCACHE": "#9C27B0",
    "PCA_LOG": "#FFEB3B",
    "USERASSIST_REGKEY": "#795548",
    "AMCACHE": "#00BCD4",
}

MACB_SEMANTICS = {
    "....": "None", "...b": "Creation", "..c.": "MetaChange", "..cb": "MetaChange+Creation",
    ".a..": "Accessed", ".a.b": "Accessed+Creation", ".ac.": "Accessed+MetaChange",
    ".acb": "Accessed+MetaChange+Creation", "m...": "Modified", "m..b": "Modified+Creation",
    "m.c.": "Modified+MetaChange", "m.cb": "Modified+MetaChange+Creation", "ma..": "Modified+Accessed",
    "ma.b": "Modified+Accessed+Creation", "mac.": "Modified+Accessed+MetaChange", "macb": "All (MACB)",
}

def _info(msg): print(f"✓ {msg}")
def _warn(msg): print(f"⚠ {msg}")
def _err(msg):  print(f"✗ {msg}")

def get_severity_style(sev):
    return SEVERITY_STYLES.get((sev or "MEDIUM").upper(), SEVERITY_STYLES["MEDIUM"])

def wrap_text(text, width=88):
    return "\n".join(wrap(text or "", width=width, break_long_words=False))

def fmt_ts(ts_str):
    try:
        return pd.to_datetime(ts_str).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return ts_str or ""

def human_delta(a, b):
    try:
        t1, t2 = pd.to_datetime(a), pd.to_datetime(b)
        d = abs(t2 - t1)
        days = d.days
        s = d.seconds
        hh, mm, ss = s // 3600, (s % 3600) // 60, s % 60
        return f"{days} days {hh:02d}:{mm:02d}:{ss:02d}" if days else f"{hh:02d}:{mm:02d}:{ss:02d}"
    except Exception:
        return ""

def parse_artifact_semantic(src):
    if not src or "." not in src: return src or "", ""
    art, attr = src.split(".", 1)
    art, attr = art.strip(), attr.strip()

    if art == "$MFT":
        macb_map = {
            "creation": "...b", "metachange": "..c.", "accessed": ".a..", "modified": "m...",
            "modified_creation": "m..b", "modified_metachange": "m.c.",
            "modified_accessed_metachange_creation": "macb",
        }
        flag = macb_map.get(attr, attr)
        return art, MACB_SEMANTICS.get(flag, attr)

    if art == "PREFETCH":
        if attr == "firstrun": return art, "First Run"
        if attr == "lastrun":  return art, "Last Run"
        if attr == "creation_time": return art, "Created"
        return art, attr.replace("_", " ").title()

    if art == "$USN_JOURNAL":
        label = "\n".join([r.replace("USN_REASON_", "") for r in attr.split("|")])
        return art, label

    return art, attr.replace("_", " ").title()

def load_rule_metadata(yaml_path):
    if not os.path.exists(yaml_path):
        _warn(f"YAML file not found: {yaml_path}")
        return {}
    try:
        with open(yaml_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        meta = {}
        for r in data.get("rules", []):
            rid = r.get("id")
            if not rid: continue
            meta[rid] = {
                "name": r.get("name", ""),
                "description": r.get("description", ""),
                "explanation": r.get("explanation", ""),
                "severity": (r.get("severity") or "MEDIUM").upper(),
            }
        return meta
    except Exception as e:
        _warn(f"Failed to parse YAML: {e}")
        return {}

# ---------- contrast helpers for FILE text -----------------------------------
def _hex_to_rgb(hex_color):
    hex_color = hex_color.lstrip('#')
    return tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))

def _relative_luminance(hex_color):
    r, g, b = [_c/255.0 for _c in _hex_to_rgb(hex_color)]
    def _lin(c): return c/12.92 if c <= 0.03928 else ((c+0.055)/1.055)**2.4
    R, G, B = _lin(r), _lin(g), _lin(b)
    return 0.2126*R + 0.7152*G + 0.0722*B

def best_text_color(bg_hex, light="#F3F4F6", dark="#111111"):
    return light if _relative_luminance(bg_hex) < 0.5 else dark

# ---------- small helper: auto font size for explanation ---------------------
def auto_font_for_lines(base, text, max_width=110, high=12, low=9):
    # Estimate line count with wrapping; reduce font size if too many lines.
    lines = wrap(text or "", width=max_width, break_long_words=False)
    n = len(lines)
    if n <= 6: return high, "\n".join(lines)
    # scale down gradually with a floor
    stepdowns = min(n - 6, high - low)
    return high - stepdowns, "\n".join(lines)

# -----------------------------------------------------------------------------
def draw_violation(violation, rules_meta, out_path):
    rule_id  = violation.get("rule_id", "UNKNOWN")
    entity   = violation.get("entity", "Unknown")
    severity = (violation.get("severity") or "MEDIUM").upper()
    style    = get_severity_style(severity)

    rules_row   = rules_meta.get(rule_id, {})
    rule_title  = rules_row.get("name", "")
    description = rules_row.get("description", "")
    explanation = (rules_row.get("explanation") or "").strip()

    file_name = os.path.basename(entity) or entity
    viols = violation.get("violations") or []
    if not viols: return

    v = viols[0].get("violating_event", {})
    left_src, right_src = v.get("left_src", ""), v.get("right_src", "")
    left_ts, right_ts   = fmt_ts(v.get("left_timestamp")), fmt_ts(v.get("right_timestamp"))
    left_art, left_sem  = parse_artifact_semantic(left_src)
    right_art, right_sem = parse_artifact_semantic(right_src)

    try:
        if pd.to_datetime(right_ts) < pd.to_datetime(left_ts):
            (left_art, right_art) = (right_art, left_art)
            (left_sem, right_sem) = (right_sem, left_sem)
            (left_ts, right_ts)   = (right_ts, left_ts)
    except Exception:
        pass

    left_color  = ARTIFACT_COLORS.get(left_art, "#94A3B8")
    right_color = ARTIFACT_COLORS.get(right_art, "#4CAF50")
    file_color  = "#1F2937"  # slate-800

    fig, ax = plt.subplots(figsize=(20, 12))
    fig.subplots_adjust(left=0.06, right=0.96, top=0.95, bottom=0.18)
    ax.set_xlim(0, 1); ax.set_ylim(0, 1); ax.axis("off")
    ax.set_facecolor(style["bg"]); fig.patch.set_facecolor(style["bg"])
    ax.set_aspect('equal', adjustable='box')

    # Header lines
    ax.text(0.5, 0.965, f"SEVERITY: {severity}",
            ha="center", va="center", fontsize=14, fontweight="bold", color=style["text"],
            bbox=dict(boxstyle="round,pad=0.28", facecolor="white", edgecolor=style["border"], lw=1.5),
            transform=ax.transAxes)

    title_text = rule_id if not rule_title else f"{rule_id}: {rule_title}"
    ax.text(0.5, 0.91, title_text, ha="center", va="center",
            fontsize=26, fontweight="bold", color=style["text"],
            bbox=dict(boxstyle="round,pad=0.22", facecolor="white", edgecolor=style["border"], lw=1.2),
            transform=ax.transAxes)

    ax.text(0.5, 0.86, f"File: {file_name}   •   Violations: {len(viols)}",
            ha="center", va="center", fontsize=14, color=style["text"], fontweight="bold",
            bbox=dict(boxstyle="round,pad=0.20", facecolor="white", edgecolor=style["border"], lw=1.0),
            transform=ax.transAxes)

    if description:
        ax.text(0.5, 0.815, wrap_text(description, width=100),
                ha="center", va="center", fontsize=12, color=style["text"],
                bbox=dict(boxstyle="round,pad=0.18", facecolor="white", edgecolor=style["border"], lw=0.9, alpha=0.98),
                transform=ax.transAxes)

    # Legend (bottom center)
    legend_handles = [
        plt.Line2D([0], [0], marker="o", linestyle="None",
                   markerfacecolor=col, markeredgecolor=style["border"],
                   markeredgewidth=1.4, markersize=11, label=art)
        for art, col in ARTIFACT_COLORS.items()
    ]
    legend_handles.append(plt.Line2D([0], [0], color="#C62828", lw=4, label="Red arrow: violation direction"))
    leg = fig.legend(handles=legend_handles, loc="lower center", bbox_to_anchor=(0.5, 0.03),
                     ncol=3, frameon=True, framealpha=1.0, borderpad=0.6, labelspacing=0.6, fontsize=11)
    leg.get_frame().set_edgecolor(style["border"])
    leg.get_frame().set_facecolor(style["bg"])

    # Node band
    y_center = 0.55
    circle_r = 0.06
    file_w, file_h = 0.24, 0.15
    xs = [0.18, 0.50, 0.82]

    left_node = mpatches.Circle((xs[0], y_center), circle_r,
                                fc=left_color, ec=style["border"], lw=2.8, transform=ax.transAxes, zorder=2)
    right_node = mpatches.Circle((xs[2], y_center), circle_r,
                                 fc=right_color, ec=style["border"], lw=2.8, transform=ax.transAxes, zorder=2)
    ax.add_patch(left_node); ax.add_patch(right_node)

    file_node = mpatches.FancyBboxPatch(
        (xs[1] - file_w/2, y_center - file_h/2), file_w, file_h,
        boxstyle="round,pad=0.02,rounding_size=0.03",
        fc=file_color, ec=style["border"], lw=3.0, transform=ax.transAxes, zorder=2.5
    )
    ax.add_patch(file_node)

    # Callouts for circle nodes
    def callout(x, lines):
        ax.text(x, y_center - circle_r - 0.03, "\n".join([l for l in lines if l]),
                ha="center", va="top", fontsize=12, color="#111",
                bbox=dict(boxstyle="round,pad=0.14", facecolor="white", edgecolor=style["border"], lw=0.9, alpha=0.98),
                transform=ax.transAxes, zorder=3)
    left_lbl  = [left_art, left_sem, left_ts]
    right_lbl = [right_art, right_sem, right_ts]
    callout(xs[0], left_lbl); callout(xs[2], right_lbl)

    # Arrows (under text)
    y = y_center
    pad = 0.008
    arrow_kw = dict(arrowstyle="->", lw=4.2, color="#C62828", shrinkA=0, shrinkB=0, zorder=2.6)
    ax.annotate("", xy=(xs[1] - file_w/2 - pad, y), xytext=(xs[0] + circle_r + pad, y),
                arrowprops=arrow_kw, transform=ax.transAxes)
    ax.annotate("", xy=(xs[2] - circle_r - pad, y), xytext=(xs[1] + file_w/2 + pad, y),
                arrowprops=arrow_kw, transform=ax.transAxes)

    # Δt badge
    dt = human_delta(left_ts, right_ts)
    if dt:
        ax.text(xs[1], y_center + file_h/2 + 0.05, f"Δt: {dt}",
                ha="center", va="bottom", fontsize=16, fontweight="bold", color=style["text"],
                bbox=dict(boxstyle="round,pad=0.20", facecolor="white", edgecolor=style["border"], lw=1.2),
                transform=ax.transAxes, zorder=3)

    # FILE label (dynamic contrast + outline)
    file_text_color = best_text_color(file_color)
    outline = '#000000' if file_text_color != '#111111' else '#FFFFFF'
    outline_effect = [pe.withStroke(linewidth=3.0, foreground=outline, alpha=0.85)]

    ax.text(xs[1], y_center + 0.01, file_name,
            ha="center", va="bottom", fontsize=14.5, color=file_text_color,
            fontweight="bold", transform=ax.transAxes, zorder=4, path_effects=outline_effect)
    ax.text(xs[1], y_center - 0.01, "FILE",
            ha="center", va="top", fontsize=12, color=file_text_color,
            fontweight="bold", transform=ax.transAxes, zorder=4, path_effects=outline_effect)

    # ------------------------ EXPLANATION block ------------------------------
    if explanation:
        # Title + body, centered. Dynamically reduce font size if long.
        label = "Explanation"
        expl_font, expl_text = auto_font_for_lines(12, explanation, max_width=110, high=12, low=9)
        ax.text(
            0.5, 0.28, label,
            ha="center", va="bottom", fontsize=12.5, color=style["border"],
            fontweight="bold",
            transform=ax.transAxes
        )
        ax.text(
            0.5, 0.27, expl_text,
            ha="center", va="top", fontsize=expl_font, color=style["border"],
            fontstyle="italic",
            bbox=dict(boxstyle="round,pad=0.16", facecolor="white", edgecolor=style["border"], lw=0.8, alpha=0.96),
            transform=ax.transAxes, zorder=3
        )
    # ------------------------------------------------------------------------

    # Full path
    ax.text(0.5, 0.12, f"Full Path: {entity}",
            ha="center", va="top", fontsize=11, color="#555",
            bbox=dict(boxstyle="round,pad=0.12", facecolor="white", edgecolor="0.75", lw=0.0, alpha=0.85),
            transform=ax.transAxes, zorder=3)

    plt.savefig(out_path, dpi=260, bbox_inches="tight")
    plt.close()
    _info(f"Generated: {out_path}")

def main():
    meta = load_rule_metadata(RULES_YAML)

    if not os.path.exists(VIOLATIONS_JSON):
        _err(f"Violations file not found: {VIOLATIONS_JSON}")
        sys.exit(1)

    try:
        with open(VIOLATIONS_JSON, "r", encoding="utf-8") as f:
            violations = json.load(f)
    except Exception as e:
        _err(f"Invalid JSON: {e}")
        sys.exit(1)

    if not isinstance(violations, list):
        _err("Expected a list of violation objects.")
        sys.exit(1)

    actual = [v for v in violations if v.get("violations")]
    if not actual:
        _warn("No confirmed violations to visualize.")
        return

    for i, v in enumerate(actual, 1):
        entity = v.get("entity", f"entity_{i}")
        rid = v.get("rule_id", "UNKNOWN")
        safe = entity.replace("\\", "_").replace("/", "_").replace(":", "_")
        out = os.path.join(OUTPUT_DIR, f"{rid}_{safe}.png")
        draw_violation(v, meta, out)

    print(f"Graphs saved to: {OUTPUT_DIR}/ (total: {len(actual)})")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(0)
