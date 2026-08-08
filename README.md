# Lightweight GDPR-Compliant Open-Source SIEM

Reproducibility repository for the paper:

> **A Lightweight GDPR-Compliant Open-Source SIEM Framework with Optimized Log Pseudonymization for Real-Time Threat Detection**

This repository accompanies the paper and provides the implementation, configuration, and evaluation scripts needed to reproduce its results.

## Overview

Security Information and Event Management (SIEM) tools help organizations detect security incidents in real time, but GDPR compliance requires that personal data in logs (IP addresses, usernames, emails) be pseudonymized without undermining detection performance. This project presents a lightweight, open-source SIEM solution built on **Wazuh** and the **Elastic Stack**, with an optimized log pseudonymization algorithm that combines:

- **Batch processing** for efficient log ingestion
- **Per-field salted hashing** (MD5 with distinct salts per sensitive-field type)
- **A persistent, cross-batch pseudonym store**, guaranteeing that a given sensitive value always maps to the same pseudonym across the full deployment lifetime — not just within a single batch

The system was evaluated in a real organizational data centre against internal and external attack scenarios, comparing three configurations: no pseudonymization, an unoptimized Logstash-based baseline, and the proposed optimized approach.

## Repository Structure

```
├── evaluation/
│   └── figures/          # Scripts to regenerate the paper's figures
│       ├── fig4_threat_model.py
│       ├── fig5_persistent_store.py
│       ├── fig11_resource_utilization.py
│       ├── fig12_throughput_latency.py
│       └── requirements.txt
├── src/                   # Core pseudonymization implementation (in progress)
├── config/                 # Wazuh / Elastic Stack configuration (in progress)
├── LICENSE
└── README.md
```

This repository is under active development alongside the paper's submission process. Additional components (source code, Wazuh rules, RBAC configuration, and benchmarking scripts) are being added incrementally — see the Roadmap section below.

## Getting Started

### Regenerating the paper's figures

```bash
cd evaluation/figures
pip install -r requirements.txt --break-system-packages
python fig11_resource_utilization.py
```

Each script writes a 300 DPI PNG matching the corresponding figure in the paper. See `evaluation/figures/README.md` for details on updating the scripts with your own measured data.

## Roadmap

- [x] Figure reproduction scripts (Figs. 4, 5, 11, 12)
- [ ] Core pseudonymization algorithm implementation
- [ ] Wazuh custom detection rules (SSH brute-force, auth failure, unauthorized access)
- [ ] RBAC role configuration
- [ ] Benchmarking and attack simulation scripts
- [ ] Raw evaluation data (Table 4, confusion matrix)

## Citation

If you use this work, please cite:

```bibtex
@article{mkamran156_lightweight_siem,
  title   = {A Lightweight GDPR-Compliant Open-Source SIEM Framework with Optimized Log Pseudonymization for Real-Time Threat Detection},
  author  = {[Muhammad Kamran Khan]},
  year    = {2026},
  journal = {[]}
}
```

## License

This project is licensed under the MIT License — see [LICENSE](LICENSE) for details.
