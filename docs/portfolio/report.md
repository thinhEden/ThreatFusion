# OT Context False-Positive Ablation

Paired evaluation on the same offline PCAP, fixed rule/IOC inputs and risk threshold 60. Policy is fixed before evaluation; labels stay outside the engine. No training or test-label tuning is performed.

| Capture | Variant | TP | TN | FP | FN | Precision | Recall | F1 | FPR |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| main | baseline | 80 | 200 | 60 | 0 | 0.5714 | 1.0000 | 0.7273 | 0.2308 |
| main | peer-only | 30 | 260 | 0 | 50 | 1.0000 | 0.3750 | 0.5455 | 0.0000 |
| main | bounded | 80 | 260 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 | 0.0000 |
| challenge | baseline | 5 | 0 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 | 0.0000 |
| challenge | peer-only | 0 | 0 | 0 | 5 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| challenge | bounded | 0 | 0 | 0 | 5 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |

## C++ Processing Measurements

All decoded request events are timed, including events without alerts. These batch timers include context evaluation and audit-row buffering, and exclude PCAP parsing, final CSV writes, process startup, networking and SIEM ingestion. Wall time includes final writes and is recorded separately. This is a single-host lab measurement, not a real-time capture SLA.

| Main variant | Processing p50 ms | p95 ms | p99 ms |
|---|---:|---:|---:|
| baseline | 0.00250 | 0.00580 | 0.02230 |
| peer-only | 0.00470 | 0.01250 | 0.03310 |
| bounded | 0.00290 | 0.00620 | 0.01990 |

## Limits

Combined main + adversarial challenge Recall: baseline=1.0000, peer-only=0.3529, bounded=0.9412.
The main capture tests explicit policy violations; the challenge tests malicious intent without a distinguishable policy violation. State both results. Zero main-capture FP is a controlled exercise outcome, not evidence of zero production false alarms.
The peer-only variant is intentionally unsafe and used only as an ablation. UTC timestamps, complete register values and trusted authorization provenance are prerequisites. No PLC execution, identity verification or real malware corpus is represented.
