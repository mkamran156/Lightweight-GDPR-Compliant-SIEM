# Lightweight GDPR-Compliant Open-Source SIEM

Reproducibility repository for the paper:

> **A Lightweight GDPR-Compliant Open-Source SIEM Framework with Optimized Log Pseudonymization for Real-Time Threat Detection**

This repository accompanies the paper and provides the implementation, configuration, and evaluation scripts needed to reproduce its results.

## Overview

Security Information and Event Management (SIEM) tools help organizations detect security incidents in real time, but GDPR compliance requires that personal data in logs (IP addresses, usernames, emails) be pseudonymized without undermining detection performance. This project presents a lightweight, open-source SIEM solution built on **Wazuh** and the **Elastic Stack**, with an optimized log pseudonymization algorithm that combines:

- **Batch processing** for efficient log ingestion
- **Per-field salted hashing** (MD5 with distinct salts per sensitive-field type)
- **A persistent, cross-batch pseudonym store**, guaranteeing that a given sensitive value always maps to the same pseudonym across the full deployment lifetime — not just within a single batch
- **Role-based access control**, separating pseudonymized log access (Security Analyst, Viewer) from re-identification capability (Administrator only)

The system was evaluated in a real organizational data centre against internal and external attack scenarios, comparing three configurations: no pseudonymization, an unoptimized Logstash-based baseline, and the proposed optimized approach.

## Repository Structure

```
├── src/
│   ├── pseudonymization/     # Algorithm 1: batch processing, salted hashing,
│   │                         # persistent pseudonym store, re-identification key store
│   └── rbac/                 # Role-based access control (Administrator/Analyst/Viewer)
├── config/
│   └── wazuh/
│       └── custom_rules/     # Detection rules: SSH brute-force, auth failures,
│                             # unauthorized access
├── evaluation/
│   └── figures/              # Scripts to regenerate the paper's figures
│       ├── fig4_threat_model.py
│       ├── fig5_persistent_store.py
│       ├── fig11_resource_utilization.py
│       └── fig12_throughput_latency.py
├── LICENSE
└── README.md
```

## Getting Started

### Running the pseudonymization algorithm

```bash
cd src
pip install -r pseudonymization/requirements.txt --break-system-packages
python -m pseudonymization.example_usage
```

This demonstrates the full pipeline, including the cross-batch consistency
property shown in Fig. 5: the same source IP appearing in two separate
batches receives the identical pseudonym both times.

### Checking RBAC permissions

```bash
python src/rbac/access_control.py
```

### Deploying the Wazuh detection rules

See `config/wazuh/custom_rules/README.md` for installation instructions.

### Regenerating the paper's figures

```bash
cd evaluation/figures
pip install -r requirements.txt --break-system-packages
python fig11_resource_utilization.py
```

Each script writes a 300 DPI PNG matching the corresponding figure in the paper.

## Citation

If you use this work, please cite:

```bibtex
@article{mkamran156_lightweight_siem,
  title   = {A Lightweight GDPR-Compliant Open-Source SIEM Framework with Optimized Log Pseudonymization for Real-Time Threat Detection},
  author  = {[Muhammad Kamran Khan]},
  year    = {2026},
  journal = {[Journal name once accepted]}
}
```

## License

This project is licensed under the MIT License — see [LICENSE](LICENSE) for details.
