# ThreatFusion

**OT/ICS detection engineering, evaluated on public data and reported with its failures.** This project has five parts:

- a C++ detection engine for industrial protocols;
- OT context that suppresses false positives on write commands;
- Windows host detections in Elastic Security;
- host-to-OT correlation;
- MITRE ATT&CK coverage measured on public datasets.

## Research Question

Legitimate engineering writes flood OT analysts with alerts. **Can operational context remove those false positives without hiding attacks, and where does it fail?** The context tested here is maintenance tickets, a commissioned operating envelope and host evidence.

## Key Results

| Question | Data | Result | Report |
|---|---|---|---|
| Does an operating envelope remove write false positives on public data? | MSU New Gas Pipeline 2015: 274,628 Modbus packets, split by time | FP fell from 9,723 to **0**, but write recall fell from 1.000 to 0.516. **Every** state-command injection (MSCI) was missed because it reuses operator values. | [Gas Pipeline 2015](docs/benchmarks/gas2015_context_report.md) |
| Does bounded maintenance authorisation work? | Lab Modbus/TCP PCAP (synthetic) | FP fell from 60 to **0** and all 80 explicit violations were kept. All 5 approved-looking commands from a compromised workstation were missed. | [Lab report](docs/portfolio/report.md) |
| Does host evidence close that gap? | Lab PCAP plus one real OTRF detection on a constructed timeline | All 5 commands were recovered. The cost was 54 maintenance writes returned to review. | [Runbook](docs/PORTFOLIO_RUNBOOK.md) |
| Do the Windows detections fire on real attack logs? | 13 public captures (OTRF, EVTX-to-MITRE-Attack, splunk/attack_data, EVTX-ATTACK-SAMPLES), 14,340 events, 2 of them negative controls | 11 rules (7 EQL, 4 ES\|QL), including Kerberoasting (4769) and NTLM brute force (4625/4776). 81 hits, all dispositioned: 67 TP, 14 FP, all FPs from the per-ticket Kerberoasting rule on an altered capture. The negative controls raise nothing. Elastic Security runs the same rules. | [Windows evaluation](docs/benchmarks/windows_detection_report.md) |
| Do the playbook hunting queries return what they claim? | The same captures and the lab OT alert index | 11 of 11 hunts match counts taken from raw fields, parsed by Kibana itself. Running them found 3 hunts that could only return zero because the normalizer lacked the ECS fields they use; that is fixed. | [Hunting validation](docs/benchmarks/hunting_query_validation.md) |
| Does the C++ engine hold up under sustained load? | The Gas Pipeline 2015 test window replayed over TCP with every detector on | One hour at 1,000 events/s: 3.6 million events, none lost, memory flat (172.5 MB at the start, 172.4 MB at the end), 47% of one core. Measuring found four faults, now fixed: stream inference spun on every core, each alert reopened the log file, LSTM memory grew with every new source address, and an uncalibrated AI threshold undid the OT context. | [Engine performance](docs/benchmarks/engine_performance.md) |
| Did the ML models learn attack behaviour? | MSU ModbusRTUfeatureSetsV2, byte-identical to the official archive | **No evidence.** A one-feature `TimeInterval` rule (F1 0.977-0.998) beats the evaluated models using all features. | [Data audit](docs/benchmarks/msu_data_audit.md) |
| Does AI add useful coverage beyond simple rules? | MSU New Gas Pipeline 2015, same time split, 3 seeds | Limited extra detections, weaker overall results. The models reach ROC-AUC 0.61-0.68 and find 2.6-4.2% of attack packets with thresholds targeting 1% benign-validation FPR. Two simple rules find 55% with 360 false positives. Isolation Forest adds 24-92 attack packets beyond their union across seeds. | [AI on Gas Pipeline 2015](docs/benchmarks/gas2015_ai_report.md) |

The mapping inventory records ATT&CK IDs, confidence and rationale where the rule evidence supports them; BR-004 intentionally has no technique mapping. Public-data evidence distinguishes detections carrying the technique ID from indirect detections:

- **Confirmed:** T1692.001 and T0888.
- **Detected under another technique:** T0814, T0836 and T0846.
- **Documented gap:** T1692.002, spoofed reporting messages.

See the [ATT&CK coverage report](docs/attack/coverage.md). Four [incident response playbooks](docs/playbooks/README.md) follow NIST SP 800-61r3 and SP 800-82r3.

## What This Does Not Show

- **No real plant.** The lab PCAPs are synthetic, and the public datasets come from laboratory testbeds and attack ranges recorded in 2013-2024.
- **Lab precision is not production precision.** Precision on lab captures with little benign background is not a production false-positive rate.
- **The host-evidence result is designed, not measured.** It shows how the correlation works on a constructed timeline, not a detection rate.
- **Performance is one laptop and one hour.** The numbers come from an i7-10750H with Elasticsearch and Kibana running beside the engine. The soak lasted one hour at a fixed rate, not days, and the engine uses one core per connection.
- **Windows credential-access samples are small.** Each Kerberoasting or brute-force capture holds one short attack with almost no benign authentication around it, and the splunk Kerberoasting capture was altered after collection. They prove rule logic and field names, not thresholds on domain-controller volume.
- **Untested:** detection of spoofed reporting messages (T1692.002), and hunts for Office child processes, file drops, lockouts and a success after failures, which no public capture contains (their control queries pass).

## Quick Start

The build and benchmark took about one minute on the development machine with prerequisites installed; setup time varies. This path needs a C++17 compiler, CMake, Python and NumPy, without LibTorch, Docker or tshark:

```powershell
cmake -S . -B build
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
python -m pip install numpy
python tools/benchmark_gas2015.py --engine build/Release/threatfusion.exe --output out/benchmark_gas2015 --report out/gas2015_context_report
```

`out/gas2015_context_report.md` is the public-data context experiment, scored by the C++ engine. On Linux the engine is `build/threatfusion`.

| To reproduce | Additional requirements and command |
|---|---|
| Lab PCAP study, case study and dashboard data | tshark and `pip install -r tools/requirements-demo.txt`, then `python tools/portfolio_demo.py --engine <engine>` |
| Elastic SIEM ingestion and native alerts | Docker, then `python tools/portfolio_demo.py --engine <engine> --siem` |
| Windows detections | The Elastic stack above, then `python tools/benchmark_windows.py --deploy`. The GPL-3.0 EVTX sample is downloaded separately ([datasets](datasets/README.md)); `.evtx` parsing needs Windows. |
| Playbook hunting queries | The Elastic stack after the Windows step, then `python tools/validate_hunting_queries.py` |
| MSU ML benchmark | A LibTorch build and `pip install -r tools/requirements-research.txt`, then `python tools/benchmark_msu.py --engine <engine>` |
| AI on Gas Pipeline 2015 | The same LibTorch build and requirements, then `python tools/benchmark_gas2015_ai.py --engine <engine>` |
| Engine performance | After the AI benchmark, `python tools/benchmark_engine_performance.py --engine <engine>` (includes a one-hour soak; `--soak-seconds` changes it) |
| Dashboard UI tests | Playwright, as described under [Verification](#verification) |

## Architecture

```
PCAP (tshark) / JSONL / CSV / TCP stream
        |
        v
C++ engine: behaviour rules, IOCs, Suricata/YARA, Isolation Forest, LSTM (LibTorch)
        |
        v
OT context: maintenance tickets, operating envelope, host alerts  <---------------+
        |                                                                          |
        v                                                                          |
Alerts + MITRE ATT&CK IDs  -->  SOC dashboard (triage, cases, evidence)            |
        |                                                                          |
        v                                                                          |
Elastic Security (ECS)  <--  Windows/Sysmon logs  -->  EQL / ES|QL rules  --> host alerts
```

### Components

| Category | Details |
| :--- | :--- |
| **Data ingestion** | CSV, JSONL (Zeek/tshark), PCAP (via `tshark`), TCP stream mode (port 8080) |
| **Threat intelligence** | IOC matching (IP, hash, protocol), STIX 2.x / TAXII v2 feed ingestion |
| **Detection engine** | Behaviour rules for Modbus, S7Comm, DNP3, BACnet, IEC-104, IEC 61850/MMS, OPC UA and CODESYS |
| **Signature scanning** | YARA lab indicator rules (Stuxnet, Triton, Industroyer, PipeDream) and local Suricata rules. Coverage needs separate validation. |
| **Anomaly detection** | C++ Isolation Forest and an LSTM autoencoder (PyTorch training, LibTorch TorchScript inference) |
| **OT context** | Ticket-bounded register writes, a commissioned operating envelope for serial Modbus, and host-alert correlation (`--host-alerts`) |
| **Risk scoring** | `Asset Criticality x Threat Severity x Confidence Score` (0-100), with a multi-detection boost |
| **Host detections** | EQL and ES\|QL rules for Windows/Sysmon logs, deployed as native Elastic Security rules |
| **SOC workspace** | Alert queue, investigation evidence, analyst triage and cases, OT context audit, evaluation and SIEM pivots |
| **Evaluation** | Confusion matrix, precision, recall, F1, FPR, single-feature baselines, analyst triage records and per-event processing time |
| **MITRE ATT&CK** | ATT&CK for ICS v19 and Enterprise IDs on every alert, in ECS `threat.*` fields and in the dashboard |

---

## Repository Layout

```
├── include/threatfusion/   C++ headers (Event, Detectors, Scorers, Ingestion)
├── src/                    C++ engine implementation and CLI entry point
├── data/                   Sample IOC, rule, CSV, JSONL event data
├── rules/                  YARA, Suricata, and Snort signature rules
├── tools/                  Python utilities (normalization, benchmarks, PCAP generation, SIEM, dashboard server)
├── siem/elastic/           Elastic compose file, saved queries and Windows detection rules
├── lab/                    Docker Compose OT/ICS simulation lab and attack scripts
├── dashboard/              Local React SOC workspace, compiled bundle and vendored runtime assets
├── datasets/               Public datasets with provenance (MSU, Gas Pipeline 2015, OTRF) and manifest
├── docs/                   Benchmark reports, ATT&CK coverage, playbooks and portfolio evidence
├── models/                 Trained model artifacts (LSTM Autoencoder weights)
├── tests/                  C++ unit tests, Python tests and Playwright UI tests
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

This command generates offline Modbus PCAP evidence, runs C++ baseline / peer-only / bounded-context ablations, produces an analyst case study, and ingests ECS alerts into an authenticated local Elastic Security stack. The main exercise removes 60 maintenance false positives while retaining 80 explicit violations. A separate compromised-endpoint challenge exposes five contextual misses: combined Recall is 94.12%. A constructed host-evidence variant replays a real Windows detection (WIN-001) on the engineering workstation. The engine then correlates it with that host's later OT commands (`--host-alerts`, HOST-OT-001). This retains all five challenge commands and returns 54 maintenance writes to review. These are controlled rule-policy results, independent of the MSU ML benchmark.

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

### TCP Stream Mode

```bash
# Start the C++ engine in stream mode (listens on port 8080)
./build/threatfusion.exe --mode stream --port 8080

# Stream MSU ICS dataset events to the engine
python tools/collector_daemon.py --input data/msu_events.jsonl --port 8080 --rate 5
```

Stream alerts go to `out/alerts_stream.csv`, which stays open and is flushed per alert. `--stats out/stats.csv --stats-interval 1` exports processed events, alerts and detection time every second. `--if-threshold` sets a calibrated Isolation Forest threshold; the 0.55 default is uncalibrated and, on Gas Pipeline 2015, fires on 29% of packets. `--lstm-max-flows` (default 4096) bounds the per-source LSTM windows.

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

[`datasets/README.md`](datasets/README.md) documents the source, licence, hashes and known issues of every dataset:

- MSU ModbusRTUfeatureSetsV2;
- MSU New Gas Pipeline 2015;
- OTRF Security-Datasets;
- EVTX-to-MITRE-Attack (CC0) and splunk/attack_data (Apache-2.0) Kerberoasting and NTLM brute-force samples;
- the local-only EVTX-ATTACK-SAMPLES capture;
- the SWaT Kaggle mirror, which is not yet benchmarked.

The MSU Modbus RTU captures can also be streamed to the engine:

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

| Capture | Isolation Forest F1 | LSTM F1 | Hybrid F1 | LSTM Test FPR | TimeInterval rule F1 | LSTM F1 without TimeInterval |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: |
| Command Injection | 94.33% | 92.57% | 93.26% | 0.57% | **99.81%** | 98.22% |
| Response Injection | 89.27% | 96.75% | 96.67% | 0.71% | **98.33%** | 91.58% |
| DoS | 91.03% | 95.57% | 95.51% | 1.65% | **97.71%** | 94.37% |

[Archived report](docs/benchmarks/msu_report.md) includes TP/TN/FP/FN. Generated models, their metadata, dataset SHA-256 hashes, split counts, validation thresholds, raw scores, and engine logs are saved under `out/benchmark_msu`. Use `--max-rows` only for smoke runs; those are labeled as subsampled in the report.

**Data caveat:** [the MSU data audit](docs/benchmarks/msu_data_audit.md) shows that each capture is a benign block with an appended attack block. A single `TimeInterval` threshold, calibrated with the same protocol, beats every model on every capture. `SetPoint` alone separates command injection. Without `TimeInterval`, the engine models still reach 0.92-0.98 F1, using other values that the attacks change. Treat this table as capture-specific novelty detection, not evidence that the models learned attack behaviour.

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

### Anomaly Detection on the Same Capture

Does AI find what the envelope misses? The C++ Isolation Forest and the LSTM autoencoder (TorchScript in C++) are trained on benign packets from the same training window, with 23 packet, process and timing features. Every threshold targets 1% FPR on benign validation packets, and three seeds retrain both models. Two parameter-free baselines use the same benign training data:

- a range rule: an unseen function code, length or address, or any process value outside its training range;
- a state rule: a mode/scheme/pump/solenoid combination never seen in benign training writes.

```powershell
python tools/benchmark_gas2015_ai.py --engine build-libtorch/Release/threatfusion.exe
```

| Test window, all packets | Recall | FP | ROC-AUC |
| :--- | ---: | ---: | ---: |
| Isolation Forest | 0.026 ± 0.008 | 391 ± 165 | 0.621 |
| LSTM autoencoder | 0.026 ± 0.007 | 322 ± 33 | 0.612 |
| Hybrid | 0.042 ± 0.006 | 327 ± 19 | 0.683 |
| Range rule + state rule | **0.547** | 360 | n/a |

**The models perform worse overall, but their detections are not identical to the rules.** Isolation Forest adds 92, 24 and 64 attack packets beyond the range/state rule union for seeds 1337, 2024 and 7, including 61, 17 and 55 MSCI packets. Its mean MSCI request recall is 19% at 390 request false positives; the state rule reaches 39% at 358. Envelope gating removes all IF request false positives, while LSTM and hybrid retain 311 and 309 on average; all three lose their MSCI detections. Many parameter injections change a value constant in benign traffic, which Isolation Forest cannot split on but an exact range check detects. These results do not justify enabling the models by default. See the [report](docs/benchmarks/gas2015_ai_report.md).

### C++ Engine Performance

The same 54,323 test packets drive batch, stream, source-cardinality and soak measurements. CPU and memory come from the OS for the engine process only; stream counters come from the engine's own `--stats` export. Run the AI benchmark first: the performance runner automatically copies its first evaluated LSTM seed and applies that seed's benign-validation threshold to `lstm_perf.pt.json`. A custom `--model` must include its own calibrated metadata. Linux additionally needs `psutil` for live memory sampling; final CPU and peak RSS come from `wait4`.

```powershell
python tools/benchmark_engine_performance.py --engine build-libtorch/Release/threatfusion.exe
```

| Measure (i7-10750H, one engine thread) | Rules + OT envelope | Every detector (IF + LSTM) |
| :--- | ---: | ---: |
| Batch, end to end, including startup | 26,176 events/s | 1,914 events/s |
| Batch, p50 / p99 detection per event | 0.003 / 0.013 ms | 0.34 / 0.80 ms |
| Stream over TCP, median of 3 runs | 29,674 events/s | 2,338 events/s |
| Soak, 1 h at 1,000 events/s | not run | 0 of 3.6 million events lost, 47% of one core, memory 172.5 → 172.4 MB |

Adding the models, mostly the LSTM, cuts throughput by a factor of about 13. Measuring found four faults, all fixed with regression tests:

- **Stream inference spun on every core.** LibTorch thread limits apply per OS thread, and stream inference runs on the socket thread: 236 events/s at 635% CPU. Now 1,990 events/s on one core with the same detectors.
- **Every stream alert reopened the log file** and re-read its header. Keeping it open raised the rule path from 4,205 to 29,674 events/s.
- **LSTM memory grew with every new source address,** about 5 KB each with no limit. `--lstm-max-flows` (default 4,096) evicts the least recently seen source; memory now plateaus from 4,096 sources on.
- **The Isolation Forest default threshold (0.55) was never calibrated.** On this capture it fires on 29% of packets, and those detections stop the OT context from downgrading approved writes: 12,794 alerts at risk 60 instead of 2,917. `--if-threshold` takes a calibrated value.

See the [performance report](docs/benchmarks/engine_performance.md) for the full tables and limits.

---

## MITRE ATT&CK Coverage and Incident Response

[`data/attack_mapping.csv`](data/attack_mapping.csv) maps every behaviour rule, Suricata SID and YARA rule to ATT&CK for ICS v19 technique or software IDs. Each mapping has a confidence level and a rationale. ATT&CK v19 revoked T0855/T0856/T0857; this repository uses their replacements, T1692.001, T1692.002 and T1693.001. The engine attaches the IDs to each alert (`--attack-map`, loaded by default).

```powershell
python tools/attack_coverage.py
```

The command regenerates the [coverage report](docs/attack/coverage.md) and an [ATT&CK Navigator layer](docs/attack/threatfusion_ics_layer.json). A technique counts as detected only when public-data alerts carry that technique's ID. For example, DoS writes in the MSU 2015 capture are caught by the generic write rule, so T0814 is reported as detected indirectly, not as covered. T1692.002 (spoofed reporting messages) is a documented gap.

[Incident response playbooks](docs/playbooks/README.md) follow NIST SP 800-61r3 (CSF 2.0) and SP 800-82r3 OT safety constraints:

- unauthorized OT command;
- phishing reaching an engineering workstation;
- malware on an engineering workstation;
- brute force and account misuse.

### Windows Host Detections

Seven EQL rules and four ES|QL rules in [`siem/elastic/windows_rules.json`](siem/elastic/windows_rules.json) cover:

- encoded PowerShell;
- LSASS memory access;
- comsvcs MiniDump;
- services and scheduled tasks that run an interpreter;
- script hosts spawning PowerShell;
- Kerberos password spraying (ES|QL, distinct failed accounts per source);
- Kerberoasting: an RC4 service ticket for a user service account (EQL), and RC4 tickets for five or more services from one source (ES|QL);
- password guessing and spraying from failed logons (4625) and from NTLM validation failures on a domain controller (4776).

The rules run on 13 public captures, 14,340 events, after they are normalised to ECS (`tools/normalize_windows_events.py`):

| Source | Licence | Captures |
|---|---|---|
| [OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets) | MIT | 5 Empire and PowerShell captures |
| [EVTX-to-MITRE-Attack](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack) | CC0 | Kerberoasting, local brute force, and two negative controls |
| [splunk/attack_data](https://github.com/splunk/attack_data) | Apache-2.0 | Two PurpleSharp NTLM spraying runs and one RC4 ticket burst |
| [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) | GPL-3.0, kept local | Kerberos password spraying |

An analyst dispositioned all 81 hits: 67 TP and 14 FP. The 14 FPs are isolated RC4 tickets that WIN-008 flags in the splunk Kerberoasting capture. That capture was altered after collection, and the report shows the evidence. The burst rule WIN-009 does not fire on them. The negative controls, BloodHound's AES ticket enumeration and two isolated logon failures, raise nothing. Each rule lists its expected production false positives. The same rules run as native Elastic Security EQL and ES|QL detections, with ATT&CK Enterprise threat mapping.

```powershell
python tools/benchmark_windows.py --deploy
```

These are lab captures with little benign background, so their precision is not a production false-positive rate. See the [evaluation](docs/benchmarks/windows_detection_report.md) for the full hit list and limits.

The KQL and EQL hunting queries in the playbooks are in [`siem/elastic/hunting_queries.json`](siem/elastic/hunting_queries.json). `tools/validate_hunting_queries.py` runs each one through Kibana's own KQL parser, saves it as a Discover search, and compares the result with counts taken from the raw fields:

```powershell
python tools/validate_hunting_queries.py
```

All 11 hunts match. Running them first found three hunts that used ECS fields the normalizer never produced, and a PB-04 sequence that joined on an address local logons do not carry. It also found two platform behaviours worth knowing: ES|QL `KQL()` needs twice as many backslashes as Kibana for a Windows path, and a query-rule preview skipped documents that share a timestamp at a page boundary. See the [hunting validation](docs/benchmarks/hunting_query_validation.md).

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
# Run the MSU benchmark first: it creates the real model used by the batch/stream parity test.
.venv/Scripts/python.exe -m unittest discover -s tests -p "test_*.py"
# Playwright UI tests against dashboard servers on 8031 (workspace) and 8032 (isolated triage state).
$env:PLAYWRIGHT_MODULE = "<python site-packages>/playwright/driver/package"   # only if the Node package is not installed
node tests/soc_workspace.cjs
node tests/soc_triage.cjs
```

The workflow suite checks SWaT scaler fitting/duplicate handling, benign flow-window boundaries, confusion matrix warmup semantics, dashboard API clearing, real LibTorch batch/stream parity with fragmented TCP frames and an idle connected client, the stream alert log surviving a dashboard Clear while the engine holds it open, and the `--stats` counters. CTest covers Isolation Forest seeds and thresholds and the LSTM flow cap. `tests/test_windows.py` covers the ECS fields the hunts use, the splunk XML reader and the hunt definitions; `tests/test_gas2015.py` covers the AUC, average-precision and novelty-rule helpers. `tests/test_dashboard_workspace.py` covers evidence-source isolation, analyst persistence, case lifecycle, CSV imports and mutation validation. `tests/soc_workspace.cjs` (also available through `tests/dashboard_smoke.cjs`) checks desktop/mobile layout, queue filters, context evidence, endpoint canvas, research and rules. `tests/soc_triage.cjs` verifies the analyst workflow, imports, export and API-error recovery on an isolated workspace. See [dashboard verification instructions](docs/DASHBOARD.md) for server setup and Playwright configuration.

---

## License

This project is developed as part of an academic research initiative. Please contact the repository owner for licensing information.
