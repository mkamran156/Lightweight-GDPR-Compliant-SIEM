import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch

plt.rcParams['font.family'] = 'DejaVu Sans'

fig, ax = plt.subplots(figsize=(11, 5.8))
ax.set_xlim(0, 11)
ax.set_ylim(0, 6.4)
ax.axis('off')

NAVY = '#2C3E50'
SLATE_FILL = '#EEF1F4'
SLATE_EDGE = '#5D6D7E'
GREEN_FILL = '#E8F5EC'
GREEN_EDGE = '#2E7D46'
ORANGE_FILL = '#FDF1E6'
ORANGE_EDGE = '#C87F16'
RED = '#B03A2E'

def box(x, y, w, h, text, fc, ec, fontsize=10.5, weight='normal', textcolor='#1C2833', lw=1.6):
    b = FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.09,rounding_size=0.12",
                        linewidth=lw, edgecolor=ec, facecolor=fc)
    ax.add_patch(b)
    ax.text(x + w/2, y + h/2, text, ha='center', va='center', fontsize=fontsize,
             weight=weight, color=textcolor, linespacing=1.4)
    return b

ax.text(5.5, 6.15, 'Threat Model: Trust Boundary and Adversary Access',
        ha='center', fontsize=13.5, weight='bold', color=NAVY)

# Trust boundary
boundary = FancyBboxPatch((5.9, 0.45), 4.6, 5.15, boxstyle="round,pad=0.1,rounding_size=0.16",
                           linewidth=2.0, edgecolor=GREEN_EDGE, facecolor='#FAFDFB', linestyle=(0, (6, 3)))
ax.add_patch(boundary)
ax.text(8.2, 5.32, 'TRUST BOUNDARY', ha='center', fontsize=10.5, weight='bold', color=GREEN_EDGE)
ax.text(8.2, 5.02, '(Administrator-only access)', ha='center', fontsize=9, style='italic', color='#4A6B57')

# Protected assets
box(6.15, 3.55, 4.3, 1.05, 'Per-field Pseudonymization\nSalts', GREEN_FILL, GREEN_EDGE)
box(6.15, 2.2, 4.3, 1.05, 'Re-identification Key Store\n(AES-256, encrypted at rest)', GREEN_FILL, GREEN_EDGE)
box(6.15, 0.85, 4.3, 1.05, 'Persistent Pseudonym Store\n(value \u2192 pseudonym mapping)', GREEN_FILL, GREEN_EDGE)

# Central pseudonymized-output box (y: 2.35 to 3.70)
CENTER_TOP = 3.70
CENTER_BOTTOM = 2.35
box(0.35, CENTER_BOTTOM, 4.4, CENTER_TOP - CENTER_BOTTOM,
    'Pseudonymized Logs,\nDashboards & Reports\n(accessible to authorized roles)',
    SLATE_FILL, SLATE_EDGE, fontsize=10.5, weight='bold')

# Adversary boxes
box(0.55, 4.55, 3.9, 1.0, 'Adversary A\nExternal attacker with\nread access to outputs only',
    ORANGE_FILL, ORANGE_EDGE, fontsize=9.5)
box(0.55, 0.35, 3.9, 1.0, 'Adversary B\nUnauthorized internal user\n(non-Administrator role)',
    ORANGE_FILL, ORANGE_EDGE, fontsize=9.5)

# Arrows placed OUTSIDE the central box's text column (offset to the left edge area)
# so they terminate exactly at the box border, never crossing through the label.
ARROW_X = 1.3
ax.annotate('', xy=(ARROW_X, CENTER_TOP), xytext=(ARROW_X, 4.55),
            arrowprops=dict(arrowstyle='-|>', color=ORANGE_EDGE, lw=1.7))
ax.annotate('', xy=(ARROW_X, CENTER_BOTTOM), xytext=(ARROW_X, 1.35),
            arrowprops=dict(arrowstyle='-|>', color=ORANGE_EDGE, lw=1.7))

# Blocked arrow: outputs -> trust boundary (kept clear of the box, in the gap between panels)
ax.annotate('', xy=(5.85, 3.0), xytext=(4.85, 3.0),
            arrowprops=dict(arrowstyle='-|>', color=RED, lw=2.0))
ax.text(5.35, 3.42, '\u2717', fontsize=19, color=RED, ha='center', weight='bold')
ax.text(5.35, 2.62, 'no direct\naccess', fontsize=8.2, color=RED, ha='center', style='italic', linespacing=1.3)

plt.tight_layout()
plt.savefig('fig_threat_model_v3.png', dpi=300, bbox_inches='tight', facecolor='white')
print("saved")
