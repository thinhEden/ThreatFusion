# ThreatFusion Portfolio Workflow

## What Is Demonstrated

1. An investigation follows a deterministic offline Modbus PCAP through tshark, the C++ engine, authorization audit, ECS documents, Elastic investigation queries, analyst disposition and proposed response.
2. A paired ablation compares the unchanged broad BR-001 write rule, an intentionally unsafe peer-only exclusion, and bounded OT authorization. Labels remain in a separate evaluation sidecar.
3. An authenticated Elasticsearch/Kibana 9.3.1 stack receives ECS documents, imports six saved KQL investigations and promotes retained OT alerts into native Elastic Security Alerts using a custom query rule.
4. A reproducible runner creates evidence, reports, hashes and models of known limitations; a separate browser recorder creates an approximately 45-second WebM of real results and SIEM UI.

This supplements the independent MSU ML benchmark. The OT ablation is an engineered policy-validation exercise, not a new real-world dataset or proof of improved LSTM accuracy.

## Run the Evidence Pipeline

Prerequisites: CMake and a C++17 compiler, Python, tshark on PATH, and Docker Desktop for SIEM. LibTorch is not required by this rule-context exercise; the existing LibTorch-enabled engine can be reused.

```powershell
python -m venv .venv
.venv/Scripts/python.exe -m pip install -r tools/requirements-demo.txt
cmake -S . -B build-demo -DUSE_LIBTORCH=OFF
cmake --build build-demo --config Release
.venv/Scripts/python.exe tools/portfolio_demo.py --engine build-demo/Release/threatfusion.exe --siem
```

With the existing build, the end-to-end command is:

```powershell
.venv/Scripts/python.exe tools/portfolio_demo.py --engine build-libtorch/Release/threatfusion.exe --siem
```

For Linux/single-config generators, use `build-demo/threatfusion`. If `--engine` is omitted, the runner looks for an existing executable and otherwise tries a CMake build. Omit `--siem` for an entirely offline evidence run.

Raw PCAP, normalized requests, ground truth, policy, alert/incident CSVs, audit trails, per-event processing timings, ECS JSONL, case study, metric report and checksums are written to `out/portfolio_demo/`. The same scenario and policy are fixed before any evaluation. The raw PCAP never contains the ground-truth labels, and the C++ detector receives no ground truth.

## Inspect the Case

Read `out/portfolio_demo/case_study.md`, then check its frame IDs in `main.pcap` using Wireshark/tshark. These are protocol-valid generated packets with TCP handshakes and Modbus requests/responses; they are written to disk, not transmitted to a plant. The filter `tcp.dstport == 502 && modbus` selects requests so response echoes are not falsely counted as controller-bound write attempts.

The ticket authorizes source 10.50.1.20 to write PLC 10.50.2.10, unit 1, registers 100-101, values 50-60, during [10:00,10:10) UTC on 2026-09-30, up to 60 commands. Any missing payload field, incomplete register count, wrong unit/range/value/time or exhausted quota leaves the broad write alert intact. Additional IOC, signature, baseline or ML evidence also leaves all detections intact.

Every decision is auditable. A downgrade does not erase the packet or the raw candidate. The peer-only mode is exposed strictly for the ablation and must not be treated as a deployment policy. Policy input needs trustworthy operator approval; source IP is not user authentication. Quota state is in memory and resets on engine restart; durable authorization accounting and retransmission handling remain future work.

## Expected Results and Honest Interpretation

| Capture | Variant | TP | FP | FN | Recall |
|---|---|---:|---:|---:|---:|
| Main | Broad rule | 80 | 60 | 0 | 100% |
| Main | Peer-only exclusion | 30 | 0 | 50 | 37.5% |
| Main | Bounded authorization | 80 | 0 | 0 | 100% |
| Compromised-endpoint challenge | Broad rule | 5 | 0 | 0 | 100% |
| Compromised-endpoint challenge | Bounded authorization | 0 | 0 | 5 | 0% |
| Main | Bounded + host alert (constructed) | 80 | 54 | 0 | 100% |
| Compromised-endpoint challenge | Bounded + host alert (constructed) | 5 | 0 | 0 | 100% |

The main result is 60/60 maintenance FPs removed without losing its 80 explicit violations. The challenge consists of malicious-intent commands whose packet fields fit unused authorization. Context cannot distinguish them from permitted commands. Combined Recall is therefore **94.12%, not 100%**. Report both captures and the negative result.

`bounded-host` adds the missing host evidence as a constructed scenario. `host_alerts.csv` holds a real OTRF WIN-001 detection (encoded PowerShell stager), re-timed to 10:01:30Z and mapped to the engineering workstation. The engine then refuses to suppress any write from that host for one hour (`--host-alerts`, `--host-alert-window 3600`) and adds correlation detection HOST-OT-001. The five challenge commands are retained. The price is that 54 approved maintenance writes after the alert return to review, because a compromised workstation cannot vouch for its own session. This shows how the correlation works on a designed timeline; it is not a measured detection rate.

Ground truth comes from the scenario plan. A production analyst would also need operator/identity, EDR, change-control and PLC history evidence; those are not available here. No actual PLC effects, malware-family detection or production zero-FP claim is established.

C++ timings cover every decoded request and include context evaluation plus audit buffering. They exclude parser startup, final disk output, transport and SIEM ingestion. Per-run wall time is recorded separately. A single small capture does not establish sustained throughput, memory limits or a live-capture latency SLA.

## Elastic SIEM

The isolated Compose project is named `threatfusion-siem`. It does not reuse other Docker applications. Services bind to loopback at Elasticsearch `http://127.0.0.1:19200` and Kibana `http://127.0.0.1:15601`.

Setup creates random local credentials in Git-ignored `siem/elastic/.env`. Log into Kibana as `elastic`, using `ELASTIC_PASSWORD` from that local file. HTTP and a superuser are used for this authenticated loopback demo; use TLS and least-privilege ingestion for deployment.

```powershell
python tools/siem_elastic.py setup
python tools/siem_elastic.py verify --report out/portfolio_demo/siem_verification.json
python tools/siem_elastic.py stop
```

Open Discover and select one of the six saved `TF - ...` investigations. Set absolute UTC time to 2026-09-30 09:58-10:15; Kibana may display local time (16:58-17:15 in Asia/Saigon). For native Security Alerts, select the whole day or the rule execution time. The recorder configures these ranges explicitly.

The runner bulk-indexes 394 deterministic ECS documents: baseline 145, bounded-host 139, bounded 80 and peer-only 30. IDs include capture, variant and packet ID, so replaying the demo updates documents instead of duplicating them. The saved queries are in `siem/elastic/queries.json`. Verification runs six equivalent Elasticsearch predicates and records their counts:

| Predicate | Count |
|---|---:|
| Engineering baseline | 115 |
| Retained contextual | 80 |
| Unauthorized source | 80 |
| Dangerous values | 30 |
| Challenge | 10 |
| Host correlation (HOST-OT-001) | 109 |

These counts span all variants, so they are larger than the per-variant alert counts.

The rule `ThreatFusion - Retained OT command alerts` promotes bounded alerts with risk >=60 to native Elastic Security alerts. Ingestion also requests an on-demand run over the fixed packet time range, so replay does not depend on a current seven-day lookback. Execution is asynchronous; allow it to complete before recording. Expected native alert count is 80. The SIEM rule severity/risk is separate from the original C++ `event.risk_score`.

Suppression audit remains separate evidence and is not indexed as an actionable alert. Default risk threshold is unchanged at 60 in every variant.

## Record the Short Demo

Start the evidence viewer:

```powershell
python -m http.server 8020 --bind 127.0.0.1 --directory out/portfolio_demo
```

In another terminal:

```powershell
cd demo
npm install
$env:BROWSER_CHANNEL='msedge'
npm run record
```

Use an installed Edge browser, or install Chromium with `npx playwright install chromium` and omit `BROWSER_CHANNEL`. `PLAYWRIGHT_MODULE` may point to an existing Playwright package. The recording logs in before the recording context is created, avoiding credentials in the video. The WebM, chapter timestamps and UI screenshots go to `out/portfolio_demo/`. The recorder fails if the saved investigation or native detection rows cannot be displayed.

The video presents actual generated results, packet evidence, a saved investigation, a false-positive pivot and native SIEM Alerts. This is a recorded workflow, not a simulation of SIEM search results. Regenerate it after changing the policy/data so that it stays consistent with the report.

## Verify

```powershell
ctest --test-dir build-demo -C Release --output-on-failure
$env:THREATFUSION_ENGINE=(Resolve-Path build-demo/Release/threatfusion.exe)
.venv/Scripts/python.exe -m unittest discover -s tests -p test_portfolio.py -v
```

The tests cover policy bounds, UTC window expiry, quota, partial register data, independent IOC evidence, label independence, PCAP determinism, ECS timestamps/zero latency and actual C++ PCAP ablation including the known evasion. Existing real-LibTorch batch/stream tests are run separately with the LibTorch build.

## References

- [Wireshark Modbus fields](https://www.wireshark.org/docs/dfref/m/modbus.html)
- [Elastic ECS alert categorization](https://www.elastic.co/docs/reference/ecs/ecs-allowed-values-event-kind)
- [Elastic native custom-query rules](https://www.elastic.co/docs/api/doc/kibana/operation/operation-createrule)
- [Elastic on-demand rule execution](https://www.elastic.co/docs/explore-analyze/workflows/use-cases/security/manage-detection-rules/run-rules-on-demand)

## Review hardening (2026-10-01)

PCAP frames containing multiple Modbus ADUs retain one event per function with an `-ADU-N` ID suffix. Aggregated register fields are left untrusted, so maintenance policies cannot suppress these events; inspect the original frame for full command evidence. This conservative fallback can add review work until per-ADU field decoding is implemented.

Matching writes consume the maintenance quota even when independent security evidence already retains the alert. Host-alert timestamps accept UTC `Z` with fractional seconds, and read requests do not update the previous-write state used by envelope review.

When appending alerts to an older CSV schema, the engine preserves that file as `.schema-N.bak` and starts a file with the current header. Dashboard Clear uses the current header. Live/imported rows keep their own severity and reason when event IDs repeat across captures.
