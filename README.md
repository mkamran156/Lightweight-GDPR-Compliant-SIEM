# Figure Reproduction Scripts

Each script regenerates one figure from the paper at 300 DPI. Update the
hardcoded values at the top of each script with your own measured results
before running.

| Script | Paper Figure | Produces |
|---|---|---|
| `fig4_threat_model.py` | Fig. 4 | Threat model diagram (trust boundary, adversary classes) |
| `fig5_persistent_store.py` | Fig. 5 | Persistent pseudonym store / cross-batch consistency diagram |
| `fig11_resource_utilization.py` | Fig. 11 | Memory (log-scale) + CPU utilization with error bars |
| `fig12_throughput_latency.py` | Fig. 12 | Throughput + ingest latency across the three scenarios |

## Setup

```bash
pip install -r requirements.txt --break-system-packages
```

## Usage

```bash
python fig11_resource_utilization.py
# -> fig9_revised.png (300 DPI, ready to embed in the manuscript)
```

## Updating with real data

`fig11_resource_utilization.py` and `fig12_throughput_latency.py` currently
contain the values from Table 4. Once you re-run the evaluation under the
persistent-store implementation (see `../benchmarking/`), replace the
`memory`, `cpu`, `cpu_err`, `throughput`, `throughput_err`, and `latency`
lists near the top of each script with your new measured values, then
re-run to regenerate the figures.

`fig4_threat_model.py` and `fig5_persistent_store.py` are structural/
conceptual diagrams and do not depend on measured data — they only need
updating if the architecture itself changes.
