import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

plt.rcParams['font.family'] = 'DejaVu Sans'
plt.rcParams['font.size'] = 11

scenarios = ['Without\nPseudonymization', 'Unoptimized\nPseudonymization', 'Optimized\nPseudonymization']
memory = [393596, 19028144, 17320204]
cpu = [0.1, 97.7, 28.3]
cpu_err = [0.05, 3.2, 1.1]

fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 4.5))

colors = ['#4C72B0', '#DD8452', '#55A868']

# Panel A: Memory (log scale)
bars1 = ax1.bar(scenarios, memory, color=colors, width=0.6)
ax1.set_yscale('log')
ax1.set_ylabel('Memory Utilization (KiB, log scale)')
ax1.set_title('(a) Memory Utilization')
for bar, val in zip(bars1, memory):
    ax1.text(bar.get_x() + bar.get_width()/2, val*1.3, f'{val:,}', ha='center', va='bottom', fontsize=9)
ax1.set_ylim(1e4, 5e7)
ax1.grid(axis='y', linestyle='--', alpha=0.4)

# Panel B: CPU with error bars
bars2 = ax2.bar(scenarios, cpu, yerr=cpu_err, capsize=6, color=colors, width=0.6,
                 error_kw={'elinewidth': 1.5, 'ecolor': 'black'})
ax2.set_ylabel('CPU Utilization (%)')
ax2.set_title('(b) CPU Utilization (mean \u00b1 SD)')
for bar, val, err in zip(bars2, cpu, cpu_err):
    ax2.text(bar.get_x() + bar.get_width()/2, val+err+3, f'{val}%', ha='center', va='bottom', fontsize=9)
ax2.set_ylim(0, 110)
ax2.grid(axis='y', linestyle='--', alpha=0.4)

for ax in (ax1, ax2):
    ax.tick_params(axis='x', labelsize=9)
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)

plt.tight_layout()
plt.savefig('fig9_revised.png', dpi=300, bbox_inches='tight')
print("saved")
