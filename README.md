# Lightweight GDPR-Compliant Open-Source SIEM

Reproducibility repository for the paper:

> **A Lightweight, Field-Piloted GDPR-Compliant Open-Source SIEM Framework with Optimized Log Pseudonymization for Real-Time Threat Detection**
> Muhammad Kamran Khan
> Department of Computer Science, COMSATS University Islamabad, Wah Campus, Pakistan
>
> Under review.

This repository contains the implementation, the Wazuh detection rules, the
figure-generation scripts and the tests that accompany the paper.

## Overview

Security Information and Event Management (SIEM) tools help organizations
detect security incidents in real time, but the GDPR requires that personal
data in logs (IP addresses, usernames, email addresses) be protected without
undermining detection. This project is a lightweight, open-source SIEM
solution built on **Wazuh** and the **Elastic Stack**, with an optimized log
pseudonymization algorithm that combines:

- **Batch processing**, so memory is bounded by the batch rather than the log volume
- **Per-field keyed hashing** using **HMAC-SHA-256**, with a distinct secret key
  per sensitive-field type
- **A persistent, cross-batch pseudonym store**, which avoids recomputing the
  HMAC for values that repeat across batches
- **Role-based access control**, separating pseudonymized log access (Security
  Analyst, Viewer) from re-identification (Administrator only)

The system was evaluated in a real organizational data centre against internal
and external attack scenarios, comparing three configurations: no
pseudonymization, an unoptimized Logstash-based baseline, and the proposed
optimized approach.

### What makes pseudonyms stable

HMAC-SHA-256 under a **static** per-field key is deterministic, so the same
input value always produces the same pseudonym. The persistent store does not
create that property, it exploits it: the store is a cache that avoids
recomputing the HMAC for a value already seen. `tests/test_pseudonymization.py`
contains a test for exactly this, using two algorithm instances that share a
key but have separate empty stores.

### Why HMAC rather than a salted hash

Security against re-identification rests on the secrecy of the per-field key,
not on the collision resistance of the hash, so a keyed MAC is the natural
construction and is in line with the EDPB Guidelines on Pseudonymisation.
HMAC is used rather than `hash(key || value)` because the naive prefix
construction is vulnerable to length extension against SHA-256.

## Repository structure

```
├── src/
│   ├── pseudonymization/     # Algorithm 1: batching, HMAC-SHA-256 keyed hashing,
│   │                         # persistent pseudonym store, re-identification store
│   └── rbac/                 # Role-based access control (Administrator/Analyst/Viewer)
├── config/
│   └── wazuh/
│       └── custom_rules/     # Detection rules: SSH brute-force, authentication
│                             # failures, unauthorized access
├── evaluation/
│   └── figures/              # Scripts that regenerate the paper's figures
│       ├── fig4_threat_model.py
│       ├── fig5_persistent_store.py
│       ├── fig13_resource_utilization.py
│       └── fig14_throughput_latency.py
├── tests/                    # Tests for the properties claimed in the paper
├── CITATION.cff
├── LICENSE
└── README.md
```

## Getting started

### Running the pseudonymization algorithm

```bash
pip install -r src/pseudonymization/requirements.txt --break-system-packages
python -m src.pseudonymization.example_usage
```

This runs the full pipeline and demonstrates the cross-batch consistency
property shown in Fig. 5 of the paper: the same source IP appearing in two
separate batches receives the identical pseudonym both times.

### Running the tests

```bash
pip install pytest --break-system-packages
python -m pytest tests/ -v
```

Each test names the section or claim of the paper it checks.

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
python fig13_resource_utilization.py   # -> Fig13.pdf
python fig14_throughput_latency.py     # -> Fig14.pdf
```

Each script writes a vector PDF with the fonts embedded. The values are taken
directly from Table 5 of the paper and are listed at the top of each script.

## Field names

The algorithm's default sensitive fields are `user.name`, `user.email` and
`ip.address`, which are the names used in Algorithm 1 of the paper. Map them
to the field names your own pipeline emits before deployment. Under Elastic
Common Schema the usual equivalents are `source.ip` or `host.ip`, `user.name`
and `user.email`.

## What is not in this repository

The log data used in the evaluation cannot be published. It comes from a
production environment and contains personal data subject to the GDPR. The
code and configuration here can therefore be inspected and re-run on other log
corpora, but the specific results in the paper cannot be reproduced
byte-for-byte without the original logs.

The development backends in this repository (`LocalFileKeyBackend`,
`InMemoryBackend`, `InMemoryReidBackend`) are for testing only. Production
deployments must store keys in a separate, access-controlled index encrypted
at rest, as described in Section 4.2 of the paper.

## Citation

See `CITATION.cff`, or:

```bibtex
@article{khan2026lightweight,
  title   = {A Lightweight, Field-Piloted GDPR-Compliant Open-Source SIEM
             Framework with Optimized Log Pseudonymization for Real-Time
             Threat Detection},
  author  = {Khan, Muhammad Kamran},
  year    = {2026},
  note    = {Under review}
}
```

## License

MIT. See [LICENSE](LICENSE).
