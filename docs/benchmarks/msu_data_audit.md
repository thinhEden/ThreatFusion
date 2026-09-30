# MSU Data Audit

Audit date: 2026-09-30. Reproduce with `python tools/audit_msu_data.py --archive path/to/ModbusRTUfeatureSetsV2.zip`. It writes `msu_data_audit.json`. The Isolation Forest ablation needs scikit-learn and is skipped without it.

## Provenance

The local folder `datasets/MSU_ICS/ModbusRTUfeatureSetsV2` corresponds to **Dataset 2: Gas Pipeline Datasets** on Tommy Morris's ICS dataset page, not to the 2014 gas pipeline / water storage ARFF files (Dataset 3) or the 2015 "New Gas Pipeline" (Dataset 4).

| Item | Value |
|---|---|
| Source page | <https://sites.google.com/a/uah.edu/tommy-morris-uah/ics-data-sets> |
| Official archive | <http://www.ece.uah.edu/~thm0009/icsdatasets/ModbusRTUfeatureSetsV2.zip> (2,162,663 bytes, Last-Modified 2014-04-25, checked 2026-09-30) |
| Formatting | ORNL formatted MSU raw logs |
| Citation | Beaver, Borges-Hink, Buckner, "An Evaluation of Machine Learning Methods to Detect Malicious SCADA Communications," ICMLA 2013, vol. 2, pp. 54-59, doi:10.1109/ICMLA.2013.105 |

The author's "unintended patterns" warning is attached to Dataset 3, not to this archive. The checks below show that this archive has comparable shortcut features, so the warning is still relevant in practice.

**The local copy matches the official archive.** The archive was downloaded on 2026-09-30: 2,162,663 bytes, SHA-256 `11534aa54e8d70c9279307413ccbfc4afdfba163eade9af918c4e2a04dddab4a`. All 14 CSVs are byte-identical to the archive, and there are no extra local files. `.gitattributes` marks `datasets/MSU_ICS/**` as `-text`, so a checkout with `core.autocrlf=true` no longer converts them to CRLF. `msu_report.json` was generated from CRLF working copies before that change. Its DoS hash (`f547a7a8…`) therefore differs from the archive hash (`71c94f80…`), but the content is the same. Official per-file hashes are in `msu_data_audit.json`.

## Findings

1. **Every file is a benign block followed by one appended attack block.** All command files share the same 28,086 benign rows, and all response/DoS files share the same 28,070 benign rows. The comparison ignores the PIDGain columns, whose values the Multiclass copies truncate (see finding 5). No timestamps exist, so the row-order 60/20/20 split is not a chronological split: training and validation contain no attacks, and the test split contains every attack.
2. **Each file contains one traffic direction only.** Benign command files contain only command frames, and benign response/DoS files contain only response frames.
3. **Benign command traffic is almost entirely repeated.** 98.8% of rows in the command files are exact duplicates. The command benchmark trains on 153 unique feature vectors (17,006 rows). 99.87% of benign test vectors already occur in training, so the low command FPR mostly measures memorisation.
4. **Attack rows carry values never seen in benign rows.**
   - Command injection: `SetPoint` is 90 (IllegalSetpoint) or 60 (PIDmodification). Benign rows use only 0, 10, 15, 20 and 25. Setting 90 is the IllegalSetpoint attack itself. Every PIDmodification row also carries 60, which looks like an artefact of the attack script.
   - DoS: all 873 attack rows have `CommandResponse = X` and malformed function codes/lengths. The benign block never contains either.
   - Almost every attack type: `TimeInterval` values fall outside the benign range. The benign median is about 650 and the attack median is 92-433. The attack block was captured separately, so this may be attack timing or a capture-session artefact; the data cannot tell them apart.
5. **The Multiclass files were re-saved before publication.** The official archive already has them with classic-Mac CR line endings and truncated numerics (`1.0141205E31` becomes `1.01E+31`). The benchmark uses the two Multiclass files plus the DoS file.
6. **No label conflicts affect the benchmark.** Only four rows in the response Multiclass file share a feature vector with a different attack subtype. These rows are all malicious, so the conflict does not affect the binary results.

## Impact on the Benchmark

A two-sided `TimeInterval` band calibrated on benign validation rows at 1% FPR uses the same protocol as `benchmark_msu.py`. It beats every model in [msu_report.md](msu_report.md):

| Capture | Best reported model F1 | TimeInterval rule F1 | Rule FP / FN |
|---|---:|---:|---:|
| Command | 0.9433 (Isolation Forest) | **0.9981** | 1 / 0 |
| Response | 0.9675 (LSTM) | **0.9833** | 40 / 2 |
| DoS | 0.9557 (LSTM) | **0.9771** | 41 / 0 |

The scikit-learn Isolation Forest proxy uses the engine's 12 features, 5 seeds and the same calibration. It reproduces the C++ Isolation Forest F1: 0.943, 0.892 and 0.915 against the reported 0.943, 0.893 and 0.910.

| Capture | All features | Without TimeInterval | TimeInterval only |
|---|---:|---:|---:|
| Command | 0.943 | 1.000 (`SetPoint` alone separates) | 0.906 |
| Response | 0.892 | 0.652 ± 0.162 | 0.981 |
| DoS | 0.915 | 0.928 | 0.978 |

## Conclusion

The data are authentic research data from a credible source and suit a portfolio or pipeline demonstration. The current MSU F1 scores do **not** show that the LSTM, Isolation Forest or hybrid learned attack behaviour: one timing threshold or one setpoint value matches or beats them. Report results on these files as capture-specific novelty detection, next to the single-feature baselines.

Before making research claims:

- Report the `TimeInterval` and `SetPoint` rule baselines in the benchmark table, plus an ablation without `TimeInterval`.
- Deduplicate before splitting, or report metrics over unique vectors.
- Prefer Dataset 4 (New Gas Pipeline, 2015), which the author describes as having more randomness, for claims about learned behaviour.
