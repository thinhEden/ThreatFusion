<p align="center">
  <h1 align="center">ThreatFusion AI</h1>
  <p align="center">
    <strong>AI-Assisted Threat Detection &amp; Intelligence Platform for OT/ICS Networks</strong>
  </p>
  <p align="center">
    <em>C++ Detection Engine · LSTM Autoencoder · Isolation Forest · YARA · Suricata · Real-time SOC Dashboard</em>
  </p>
</p>

---

## Overview

ThreatFusion AI is a high-performance C++ security engine designed for **Operational Technology (OT)** and **Industrial Control System (ICS)** environments. It combines rule-based behavioral analysis, deep-learning anomaly detection, and threat intelligence correlation to identify cyberattacks targeting SCADA/ICS infrastructure in real time.

### Key Capabilities

| Category | Details |
| :--- | :--- |
| **Data Ingestion** | CSV, JSONL (Zeek/tshark), PCAP (via `tshark`), real-time TCP socket streaming (port 8080) |
| **Threat Intelligence** | IOC matching (IP, hash, protocol), STIX 2.x / TAXII v2 feed ingestion |
| **Detection Engine** | Rule-based behavioral detection for Modbus, S7Comm, DNP3, BACnet, IEC-104, IEC 61850/MMS, OPC UA, CODESYS |
| **Signature Scanning** | YARA indicator rules (Stuxnet, Triton, Industroyer, PipeDream) and local Suricata rules; coverage requires separate validation |
| **AI Anomaly Detection** | C++ Isolation Forest, LSTM Autoencoder (PyTorch training + LibTorch JIT inference) |
| **Classification** | Reconnaissance, Command Injection, DoS, Unauthorized Firmware Update, Malware Signature, Network Signature |
| **Risk Scoring** | `Asset Criticality × Threat Severity × Confidence Score` (0–100), with multi-detection correlation boost |
| **SOC Workspace** | Alert queue, investigation evidence, persistent analyst triage/cases, OT context audit, evaluation and SIEM pivots |
| **Evaluation** | Confusion matrix (TP/TN/FP/FN), Precision, Recall, F1, Accuracy, FPR, detection latency (avg/p95/max) |

---

## Repository Layout

```
├── include/threatfusion/   C++ headers (Event, Detectors, Scorers, Ingestion)
├── src/                    C++ engine implementation and CLI entry point
├── data/                   Sample IOC, rule, CSV, JSONL event data
├── rules/                  YARA, Suricata, and Snort signature rules
├── tools/                  Python utilities (normalization, training, PCAP generation, dashboard server)
├── lab/                    Docker Compose OT/ICS simulation lab and attack scripts
├── dashboard/              Local React SOC workspace, compiled bundle and vendored runtime assets
├── datasets/               Dataset integration guide and manifest (MSU ICS)
├── models/                 Trained model artifacts (LSTM Autoencoder weights)
├── tests/                  C++ unit tests
├── out/                    Generated alerts, incidents, and evaluation metrics
├── captures/               PCAP capture files
└── samples/                Harmless lab payload markers for YARA validation
```

---

## Getting Started

### Prerequisites

- **C++17** compiler (MSVC recommended on Windows, GCC/Clang on Linux)
- **CMake** ≥ 3.16
- **Python** ≥ 3.8 (for tools and dashboard server)
- **Optional**: [LibTorch](https://pytorch.org/cppdocs/installing.html), [tshark](https://www.wireshark.org/), [Suricata](https://suricata.io/), [YARA](https://virustotal.github.io/yara/)

### Build with CMake

```bash
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
```

### Build with LibTorch (Optional)

```bash
cmake -S . -B build -DUSE_LIBTORCH=ON -DCMAKE_PREFIX_PATH="/path/to/libtorch"
cmake --build build --config Release
```

Verified local Windows build (MSVC + CPU LibTorch):

```powershell
cmake -S . -B build-libtorch -G "Visual Studio 17 2022" -A x64 -DUSE_LIBTORCH=ON -DCMAKE_PREFIX_PATH="D:/libtorch"
cmake --build build-libtorch --config Release
ctest --test-dir build-libtorch -C Release --output-on-failure
```

LibTorch DLLs are copied next to the executable. Requesting a real `.pt` model on a non-LibTorch build is an error; the lab proxy must be requested explicitly with `--lstm simulated`.

### Alternative: MinGW Build (Windows)

```powershell
g++ -std=c++17 -I include src/*.cpp -o build/threatfusion.exe -lws2_32
```

> **Note:** MinGW builds support the core engine and simulated LSTM fallback. Real LibTorch JIT inference requires an MSVC build.

---

## Usage

### SOC Portfolio: Four Reproducible Outputs

```powershell
.venv/Scripts/python.exe -m pip install -r tools/requirements-demo.txt
.venv/Scripts/python.exe tools/portfolio_demo.py --engine build-libtorch/Release/threatfusion.exe --siem
```

This command generates offline Modbus PCAP evidence, runs C++ baseline / peer-only / bounded-context ablations, produces an analyst case study, and ingests ECS alerts into an authenticated local Elastic Security stack. The main exercise removes 60 maintenance false positives while retaining 80 explicit violations. A separate compromised-endpoint challenge exposes five contextual misses: combined Recall is 94.12%. These are controlled rule-policy results, independent of the MSU ML benchmark.

See [the full runbook](docs/PORTFOLIO_RUNBOOK.md) for build instructions, saved KQL queries, native SIEM alerts, tests, video recording, evidence paths and limitations. Generated deliverables are under `out/portfolio_demo/`; archived findings are under `docs/portfolio/`.

### Core CSV Pipeline

```bash
./build/threatfusion.exe \
  --events data/sample_ot_events.csv \
  --format csv \
  --baseline data/sample_ot_events.csv \
  --baseline-format csv \
  --iocs data/iocs.csv \
  --rules data/behavior_rules.csv \
  --alerts out/alerts.csv \
  --incidents out/incidents.csv \
  --metrics out/metrics.txt \
  --threshold 60
```

### JSONL Events (Zeek/tshark)

```bash
./build/threatfusion.exe \
  --events data/sample_zeek_ot_events.jsonl \
  --format jsonl \
  --iocs data/iocs.csv \
  --rules data/behavior_rules.csv \
  --threshold 60
```

### YARA Signature Scanning

```bash
./build/threatfusion.exe \
  --events data/sample_yara_family_events.csv \
  --format csv \
  --yara /path/to/yara.exe \
  --yara-rules rules/yara/ics_malware_indicators.yar \
  --threshold 60
```

### PCAP Ingestion with Suricata

```bash
# Generate a valid BACnet/IP test PCAP
python tools/generate_bacnet_pcap.py

# Run the full pipeline
./build/threatfusion.exe \
  --events captures/valid_bacnet.pcap \
  --format pcap \
  --tshark /path/to/tshark.exe \
  --suricata /path/to/suricata.exe \
  --suricata-rules rules/suricata/local_ics.rules \
  --threshold 60
```

### Real-time TCP Streaming

```bash
# Start the C++ engine in stream mode (listens on port 8080)
./build/threatfusion.exe --mode stream --port 8080

# Stream MSU ICS dataset events to the engine
python tools/collector_daemon.py --input data/msu_events.jsonl --port 8080 --rate 5
```

---

## SOC Dashboard

ThreatFusion provides a local SOC workspace centered on the alert queue, with a focused investigation panel and separate views for cases, endpoints, OT context, research and rules.

```powershell
python tools/dashboard_server.py --port 8031 --default-source main
# Open http://127.0.0.1:8031
```

The main lab is explicitly marked as recorded synthetic evidence. Select Live stream for the current engine output, or import an engine alerts CSV. The default server source is live when no source option is supplied.

- Filter, sort, paginate and export alert evidence.
- Inspect packet fields, context decisions, maintenance tickets and raw events.
- Assign owners, save analyst dispositions/notes and create linked cases with persistent history.
- Inspect observed endpoint connections and actual on-disk rule definitions.
- Compare before/after FP/FN/Recall, including the documented challenge failures.
- Pivot into Elastic by packet/capture/time and download the case study, PCAP or recorded video.

Analyst state is stored locally in SQLite and is separate from both lab ground truth and Elastic case state. The compiled frontend and runtime assets are served locally. See [dashboard workflow and build instructions](docs/DASHBOARD.md).

---

## Dataset Integration

ThreatFusion supports the **Mississippi State University (MSU) ICS Modbus RTU** dataset for training and evaluation.

```bash
# Normalize the MSU dataset
python tools/normalize_msu_ics.py --input path/to/MSU_dataset.csv --output data/msu_events.jsonl

# Stream to C++ engine
python tools/collector_daemon.py --input data/msu_events.jsonl --port 8080 --rate 5
```

See [`datasets/dataset_manifest.csv`](datasets/dataset_manifest.csv) for the full dataset registry.

SWaT process telemetry support is restored in `tools/normalize_swat.py`. It preserves all 51 measurements in `extra_features`; it does not infer Modbus packets from sensor rows. See [the dataset guide](datasets/README.md) for raw-file paths, training-only scaler fitting, duplicate handling, and conversion commands.

---

## Benchmark Results

The verified benchmark uses the command injection, response injection, and DoS capture files in `datasets/MSU_ICS/ModbusRTUfeatureSetsV2`. It trains a fresh deterministic LSTM for each capture and obtains both LSTM reconstruction loss and Isolation Forest scores from the **C++ LibTorch engine**.

```powershell
python -m venv .venv
.venv/Scripts/python.exe -m pip install -r tools/requirements-research.txt --extra-index-url https://download.pytorch.org/whl/cpu
.venv/Scripts/python.exe tools/benchmark_msu.py --engine build-libtorch/Release/threatfusion.exe --epochs 5 --output out/benchmark_msu
```

Protocol: per-capture row-order split 60% training / 20% validation / 20% test. Training uses benign windows grouped by source endpoint, with attack gaps resetting a flow window. Thresholds use only benign validation scores at a target FPR of 1%; the test set is never used for tuning. Hybrid weights are fixed at 0.5 / 0.5, with LSTM loss scaled using validation data. Every test row contributes to the confusion matrix; missing warmup scores are treated as negative predictions.

| Capture | Isolation Forest F1 | LSTM F1 | Hybrid F1 | LSTM Test FPR |
| :--- | ---: | ---: | ---: | ---: |
| Command Injection | 94.33% | 92.57% | 93.26% | 0.57% |
| Response Injection | 89.27% | 96.75% | 96.67% | 0.71% |
| DoS | 91.03% | 95.57% | 95.51% | 1.65% |

[Archived report](docs/benchmarks/msu_report.md) includes TP/TN/FP/FN. Generated models, their metadata, dataset SHA-256 hashes, split counts, validation thresholds, raw scores, and engine logs are saved under `out/benchmark_msu`. Use `--max-rows` only for smoke runs; those are labeled as subsampled in the report.

**Data caveat:** [the MSU data audit](docs/benchmarks/msu_data_audit.md) shows that each capture is a benign block with an appended attack block. A single `TimeInterval` threshold calibrated with the same protocol scores F1 0.998 on command, 0.983 on response and 0.977 on DoS, which beats every model above. `SetPoint` alone separates command injection. Treat this table as capture-specific novelty detection, not evidence that the models learned attack behaviour.

These are binary detector-score results for these captures. They do not measure malware-family identification or the engine's separate operational risk cutoff. Hybrid results are offline weighted score analysis. MSU feature CSVs have no capture timestamps; synthetic endpoint addresses are display mappings, and these results do not validate network-cycle timing. The old tuned benchmark table was removed because its evaluation procedure was not available in this repository.

### OT Context on Public Data (MSU New Gas Pipeline 2015)

This experiment repeats the lab false-positive study on a public, timestamped capture with interleaved attacks. The C++ engine applies an operating envelope to BR-001 write alerts. The envelope is derived only from benign writes in the first 60% of the capture:

```powershell
python tools/benchmark_gas2015.py --engine build-libtorch/Release/threatfusion.exe
```

| Test window, FC16 writes | FP | Recall | MSCI recall | MPCI recall |
| :--- | ---: | ---: | ---: | ---: |
| Baseline (every write alerts) | 9,723 | 1.000 | 1.000 | 1.000 |
| + operating envelope | **0** | 0.516 | **0.000** | 0.789 |
| + envelope, state changes kept for review | 594 | 0.665 | 0.209 | 0.929 |

The envelope removes every false positive but misses all state-command injections (MSCI) and DoS writes. Those attacks use values that operators also use, and serial Modbus has no authenticated source. The validation window shows the same pattern. The full protocol, per-category results and limits are in the [report](docs/benchmarks/gas2015_context_report.md).

---

## Simulation Lab

A Docker Compose-based OT/ICS simulation environment for generating benign and attack traffic.

See [`lab/README.md`](lab/README.md) for setup instructions.

**Included tools:**
- Modbus PLC simulator
- HMI client
- Modbus scan / write / flood traffic generator
- OPC UA probe

---

## Metrics Semantics

The confusion matrix evaluates only events labeled `benign` or `malicious`:

- **Unlabeled events**: Events with no label or intermediate labels (e.g., `suspicious`) are excluded from the confusion matrix.
- **External alerts**: Alerts generated by external tools (e.g., Suricata PCAP alerts) are counted separately as `external_alerts`.

This prevents unlabeled operational traffic from being incorrectly counted as true negatives.

---

## Known Limitations

- **YARA samples**: The bundled lab marker files are harmless placeholders, not real malware. Validate rules against approved malware datasets before making production claims.
- **PCAP parsing**: The `tshark` field parser may require tuning for specific Wireshark versions or proprietary protocol plugins.
- **LibTorch on Windows**: Real TorchScript inference requires an MSVC-compatible build. MinGW builds use a simulated LSTM fallback.

## Verification

```powershell
ctest --test-dir build-libtorch -C Release --output-on-failure
# Run the benchmark first to create the real model used by batch/stream parity tests.
.venv/Scripts/python.exe -m unittest discover -s tests -p test_workflows.py -v
```

The workflow suite checks SWaT scaler fitting/duplicate handling, benign flow-window boundaries, confusion matrix warmup semantics, dashboard API clearing, and real LibTorch batch/stream parity with fragmented TCP frames and an idle connected client. `tests/test_dashboard_workspace.py` covers evidence-source isolation, analyst persistence, case lifecycle, CSV imports and mutation validation. `tests/soc_workspace.cjs` (also available through `tests/dashboard_smoke.cjs`) checks desktop/mobile layout, queue filters, context evidence, endpoint canvas, research and rules. `tests/soc_triage.cjs` verifies the analyst workflow, imports, export and API-error recovery on an isolated workspace. See [dashboard verification instructions](docs/DASHBOARD.md) for server setup and Playwright configuration.

---

## License

This project is developed as part of an academic research initiative. Please contact the repository owner for licensing information.
