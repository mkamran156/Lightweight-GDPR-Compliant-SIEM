import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

plt.rcParams['font.family'] = 'DejaVu Sans'
plt.rcParams['font.size'] = 11

scenarios = ['Without\nPseudonymization', 'Unoptimized\nPseudonymization', 'Optimized\nPseudonymization']
throughput = [1800, 750, 1450]
throughput_err = [40, 25, 35]
latency = [1.8, 5.4, 2.7]

fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 4.5))
colors = ['#4C72B0', '#DD8452', '#55A868']

bars1 = ax1.bar(scenarios, throughput, yerr=throughput_err, capsize=6, color=colors, width=0.6,
                 error_kw={'elinewidth': 1.5, 'ecolor': 'black'})
ax1.set_ylabel('Throughput (Events/Sec)')
ax1.set_title('(a) Average Throughput (mean \u00b1 SD)')
for bar, val, err in zip(bars1, throughput, throughput_err):
    ax1.text(bar.get_x() + bar.get_width()/2, val+err+40, f'{val}', ha='center', va='bottom', fontsize=9)
ax1.set_ylim(0, 2100)
ax1.grid(axis='y', linestyle='--', alpha=0.4)
ax1.axhline(1800, color='gray', linestyle=':', linewidth=1, alpha=0.7)

bars2 = ax2.bar(scenarios, latency, color=colors, width=0.6)
ax2.set_ylabel('Average Ingest Latency (Seconds)')
ax2.set_title('(b) Average Ingest Latency')
for bar, val in zip(bars2, latency):
    ax2.text(bar.get_x() + bar.get_width()/2, val+0.15, f'{val}s', ha='center', va='bottom', fontsize=9)
ax2.set_ylim(0, 6.5)
ax2.grid(axis='y', linestyle='--', alpha=0.4)

for ax in (ax1, ax2):
    ax.tick_params(axis='x', labelsize=9)
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)

plt.tight_layout()
plt.savefig('fig_throughput_latency.png', dpi=300, bbox_inches='tight')
print("saved")
