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

## Data source

`fig11_resource_utilization.py` and `fig12_throughput_latency.py` plot the
memory, CPU, throughput, and latency measurements from Table 4. The
`memory`, `cpu`, `cpu_err`, `throughput`, `throughput_err`, and `latency`
lists near the top of each script hold these values directly.

`fig4_threat_model.py` and `fig5_persistent_store.py` are structural/
conceptual diagrams illustrating the system architecture.
