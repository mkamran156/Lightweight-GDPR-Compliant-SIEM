# Figure reproduction scripts

Each script regenerates one figure from the paper. The two chart scripts
produce vector PDFs with the fonts embedded, at the size used in the
manuscript.

| Script | Paper figure | Produces |
|---|---|---|
| `fig4_threat_model.py` | Fig. 4 | Threat model diagram: trust boundary and the two adversary classes |
| `fig5_persistent_store.py` | Fig. 5 | Persistent pseudonym store, cross-batch consistency |
| `fig13_resource_utilization.py` | Fig. 13 | (a) memory utilization, log scale, and (b) CPU utilization with error bars |
| `fig14_throughput_latency.py` | Fig. 14 | (a) average throughput with error bars, and (b) average ingest latency |

## Setup

```bash
pip install -r requirements.txt --break-system-packages
```

## Usage

```bash
python fig13_resource_utilization.py   # -> Fig13.pdf
python fig14_throughput_latency.py     # -> Fig14.pdf
```

## Data source

`fig13_resource_utilization.py` and `fig14_throughput_latency.py` plot the
memory, CPU, throughput and latency measurements from **Table 5** of the
paper. The `MEMORY`, `CPU`, `CPU_SD`, `THRU`, `THRU_SD` and `LATENCY` lists
near the top of each script hold those values directly. Replace them with
your own measurements to redraw the charts on your data.

All five scenarios from Table 5 are plotted: no pseudonymization, unoptimized
pseudonymization at 100% and 50% unique values, and optimized pseudonymization
at 0% and 50% cache hit rate.

Bars carry hatch patterns as well as colour, because the print edition of the
journal is greyscale.

`fig4_threat_model.py` and `fig5_persistent_store.py` are structural diagrams
of the architecture and contain no measurements.
