import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch
import matplotlib.lines as mlines

plt.rcParams['font.family'] = 'DejaVu Sans'

fig, ax = plt.subplots(figsize=(11, 6))
ax.set_xlim(0, 11)
ax.set_ylim(0, 6.2)
ax.axis('off')

def box(x, y, w, h, text, fc='#EAF2FB', ec='#4C72B0', fontsize=10, weight='normal'):
    b = FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.08,rounding_size=0.08",
                        linewidth=1.5, edgecolor=ec, facecolor=fc)
    ax.add_patch(b)
    ax.text(x + w/2, y + h/2, text, ha='center', va='center', fontsize=fontsize, weight=weight, wrap=True)
    return b

# Title labels for batches
ax.text(2.1, 5.85, 'Batch 1', ha='center', fontsize=12, weight='bold')
ax.text(8.1, 5.85, 'Batch 2 (later)', ha='center', fontsize=12, weight='bold')

# Batch 1 log entries
box(0.3, 4.7, 3.6, 0.8, 'Log entry: src_ip = 10.13.21.5', fc='#FDF3E7', ec='#DD8452')
box(0.3, 3.6, 3.6, 0.8, 'Log entry: src_ip = 10.10.39.2', fc='#FDF3E7', ec='#DD8452')

# Batch 2 log entries (later, same IP repeats)
box(6.3, 4.7, 3.6, 0.8, 'Log entry: src_ip = 10.13.21.5', fc='#FDF3E7', ec='#DD8452')
box(6.3, 3.6, 3.6, 0.8, 'Log entry: src_ip = 172.16.4.9', fc='#FDF3E7', ec='#DD8452')

# Persistent pseudonym store in the middle
store = box(3.9, 1.9, 3.2, 1.5, 'Persistent\nPseudonym Store\n(value \u2192 pseudonym)\nlives for full\ndeployment lifetime',
            fc='#E7F4EA', ec='#55A868', fontsize=10, weight='bold')

# Arrows from batch 1 entries down to store
for y in (5.1, 4.0):
    ax.annotate('', xy=(3.85, 2.7), xytext=(2.1, y),
                arrowprops=dict(arrowstyle='-|>', color='#4C72B0', lw=1.4,
                                 connectionstyle="arc3,rad=-0.15"))
# Arrows from batch 2 entries down to store
for y in (5.1, 4.0):
    ax.annotate('', xy=(7.15, 2.7), xytext=(8.1, y),
                arrowprops=dict(arrowstyle='-|>', color='#4C72B0', lw=1.4,
                                 connectionstyle="arc3,rad=0.15"))

# Output pseudonymized entries
box(0.3, 0.3, 3.6, 0.9, 'Output:\npseudonym = H(10.13.21.5)', fc='#EAF2FB', ec='#4C72B0')
box(6.3, 0.3, 3.6, 0.9, 'Output:\npseudonym = H(10.13.21.5)\n(same as Batch 1)', fc='#EAF2FB', ec='#4C72B0')

ax.annotate('', xy=(2.1, 1.2), xytext=(4.5, 1.9),
            arrowprops=dict(arrowstyle='-|>', color='#55A868', lw=1.6))
ax.annotate('', xy=(8.1, 1.2), xytext=(6.5, 1.9),
            arrowprops=dict(arrowstyle='-|>', color='#55A868', lw=1.6))

# Highlight consistency with a bracket/check
ax.annotate('', xy=(8.0, 0.75), xytext=(2.4, 0.75),
            arrowprops=dict(arrowstyle='<->', color='#C44E52', lw=1.6, linestyle='dashed',
                             connectionstyle="arc3,rad=-0.35"))
ax.text(5.2, -0.15, 'Same pseudonym for the same value, across batches and over time\n(cross-batch correlation preserved for attack tracking)',
        ha='center', fontsize=10, color='#C44E52', style='italic')

plt.tight_layout()
plt.savefig('fig_persistent_store.png', dpi=300, bbox_inches='tight')
print("saved")
