#!/usr/bin/env python3
"""
Regenerates Fig. 14 of the paper: average throughput and ingest latency
across all evaluated scenarios, showing (a) average throughput and
(b) average ingest latency.

Every value below is taken directly from Table 5 of the paper. Replace
them with your own measurements to reproduce the figure on your data.

Output: Fig14.pdf, a true vector PDF with the fonts embedded. Hatching is
applied as well as colour so the bars remain distinguishable in the
print edition, which is greyscale.
"""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.ticker import FuncFormatter

# embed real fonts rather than outlines, so the text stays selectable
matplotlib.rcParams["pdf.fonttype"] = 42
matplotlib.rcParams["font.family"] = "DejaVu Sans"
matplotlib.rcParams["hatch.linewidth"] = 0.6

# ---- Table 5 -----------------------------------------------------------
LABELS = ["Without\nPseud.", "Unopt.\n100% uniq", "Unopt.\n50% uniq",
          "Optimized\n0% hit", "Optimized\n50% hit"]
COLORS = ["#4c72b0", "#dd8452", "#e8a87c", "#55a868", "#2e8b57"]
# Hatches group the bars the way the data does: baseline solid, the two
# unoptimized runs mirrored diagonals, the two optimized runs dots and crosses.
HATCH  = ["", "///", "\\\\\\", "...", "xxx"]

MEMORY   = [393596, 19028144, 19027016, 17016920, 10515354]   # KiB
CPU      = [0.1, 97.7, 97.6, 30.4, 16.2]                      # %
CPU_SD   = [0.03, 2.8, 2.8, 1.0, 0.7]
THRU     = [1800, 750, 750, 1450, 1650]                       # events/sec
THRU_SD  = [32, 21, 21, 28, 25]
LATENCY  = [1.8, 5.4, 5.4, 2.6, 2.3]                          # seconds

BAR_KW = dict(width=0.62, edgecolor="#1a1a1a", linewidth=0.8, zorder=3)
ERR_KW = dict(fmt="none", ecolor="#222222", elinewidth=1.4, capsize=4,
              capthick=1.4, zorder=4)


def style(ax, ylabel, title):
    ax.set_title(title, fontsize=13, pad=12)
    ax.set_ylabel(ylabel, fontsize=11)
    ax.tick_params(axis="x", labelsize=9.5, length=0)
    ax.tick_params(axis="y", labelsize=10)
    ax.grid(axis="y", linestyle="--", linewidth=0.7, color="#cccccc",
            alpha=0.8, zorder=0)
    ax.set_axisbelow(True)
    for side in ("top", "right", "left", "bottom"):   # full box, as in the originals
        ax.spines[side].set_visible(True)
        ax.spines[side].set_linewidth(0.9)
        ax.spines[side].set_color("#444444")


def labels_on(ax, xs, ys, texts, dy_frac=0.02, log=False):
    for x, y, t in zip(xs, ys, texts):
        if log:
            ax.annotate(t, (x, y), xytext=(0, 6), textcoords="offset points",
                        ha="center", va="bottom", fontsize=9.5, color="#111111")
        else:
            top = ax.get_ylim()[1]
            ax.annotate(t, (x, y + top * dy_frac), ha="center", va="bottom",
                        fontsize=9.5, color="#111111")


fig, (axa, axb) = plt.subplots(1, 2, figsize=(12.90, 4.91))
x = range(len(LABELS))

# (a) throughput with SD
axa.bar(x, THRU, color=COLORS, hatch=HATCH, **BAR_KW)
axa.errorbar(x, THRU, yerr=THRU_SD, **ERR_KW)
axa.set_ylim(0, 2100)
style(axa, "Throughput (Events/Sec)", "(a) Average Throughput (mean $\\pm$ SD)")
axa.set_xticks(list(x)); axa.set_xticklabels(LABELS)
labels_on(axa, x, [t + s for t, s in zip(THRU, THRU_SD)],
          [f"{v:,}" for v in THRU], dy_frac=0.015)

# (b) latency
axb.bar(x, LATENCY, color=COLORS, hatch=HATCH, **BAR_KW)
axb.set_ylim(0, 6.4)
style(axb, "Average Ingest Latency (Seconds)", "(b) Average Ingest Latency")
axb.set_xticks(list(x)); axb.set_xticklabels(LABELS)
labels_on(axb, x, LATENCY, [f"{v}s" for v in LATENCY], dy_frac=0.015)

fig.tight_layout(pad=1.6)
fig.savefig("Fig14.pdf", format="pdf", bbox_inches="tight",
            facecolor="white")
plt.close(fig)
print("wrote Fig14.pdf")

