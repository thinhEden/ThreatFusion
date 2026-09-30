# Dataset Integration

## MSU ICS

Raw CSV captures are in `MSU_ICS/ModbusRTUfeatureSetsV2`. They are **Dataset 2 (Gas Pipeline Datasets, ORNL formatted)** from the [Tommy Morris ICS dataset page](https://sites.google.com/a/uah.edu/tommy-morris-uah/ics-data-sets). The official archive is <http://www.ece.uah.edu/~thm0009/icsdatasets/ModbusRTUfeatureSetsV2.zip>. Cite Beaver, Borges-Hink and Buckner, ICMLA 2013, doi:10.1109/ICMLA.2013.105. On 2026-09-30 the local files were compared with that archive, whose SHA-256 is `11534aa5…dab4a`. All 14 are byte-identical. `.gitattributes` keeps `datasets/MSU_ICS/**` free of line-ending conversion.

`tools/normalize_msu_ics.py` keeps process features and labels while mapping serial master/slave directions to display endpoints. It cannot recover absent capture timestamps.

Run `tools/benchmark_msu.py` with a LibTorch-enabled C++ executable. It creates row-order train/validation/test files, trains on benign flow windows, calibrates on validation only, and saves hashes, model metadata, raw scores, confusion matrices, and logs. The README describes the exact protocol and command. Test thresholds must not be selected from test labels.

[The data audit](../docs/benchmarks/msu_data_audit.md) (`tools/audit_msu_data.py`) found the following:

- Every file is one benign block followed by one appended attack block, so row order is not time order.
- Benign command traffic is 98.8% exact duplicates.
- Attack rows are separable by single values. In the command files, `SetPoint` alone separates them. In the response and DoS files, a single `TimeInterval` threshold does, and it outperforms every reported model.

Report MSU scores as capture-specific novelty detection, next to those single-feature baselines.

## MSU New Gas Pipeline 2015

`MSU_ICS/GasPipeline2015/IanArffDataset.arff` is **Dataset 4 (New Gas Pipeline)** from the same page, downloaded on 2026-09-30 from <http://www.ece.uah.edu/~thm0009/icsdatasets/IanArffDataset.arff>. The file is 18,340,346 bytes with SHA-256 `970a7bcd…af459`. It is the main public dataset for the OT-context experiment, for three reasons:

- It has 274,628 Modbus RTU packets over 3.2 days, with timestamps.
- Attacks are interleaved throughout the capture: every tenth of the rows is 19.7-24.0% attacks.
- No single feature separates attacks from normal traffic. The best single-feature F1 is 0.355.

`tools/normalize_gas2015.py` writes label-free JSONL events plus a separate ground-truth CSV. Decoded control parameters go into `process_values`. Serial Modbus has no IP addresses, so 10.0.0.1 (master) and 10.0.0.2 (RTU) are display mappings.

`tools/benchmark_gas2015.py` splits the capture by time. It derives an operating envelope from benign training writes only, then scores the validation and test requests with the C++ engine. See [the results](../docs/benchmarks/gas2015_context_report.md).

## Windows Host Logs (OTRF Security-Datasets)

`Windows_OTRF/` holds five host captures from [OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets) (MIT licence). They were downloaded on 2026-09-30 from `datasets/atomic/windows/<tactic>/host/`:

| File | OTRF ID | OTRF technique |
|---|---|---|
| `psh_lsass_memory_dump_comsvcs.zip` | SDWIN-201018195009 | T1003.001 |
| `empire_mimikatz_logonpasswords.zip` | SDWIN-190518202151 | T1003.001 |
| `empire_schtasks_creation_standard_user.zip` | SDWIN-190319024742 | T1053.005 |
| `empire_psexec_dcerpc_tcp_svcctl.zip` | SDWIN-190518210652 | T1021 |
| `empire_launcher_vbs.zip` | SDWIN-190518182022 | T1059.005 |

SHA-256 hashes are recorded in `docs/benchmarks/windows_detection_report.json`.

`EVTX_ATTACK_SAMPLES/` is git-ignored. It holds `kerberos_pwd_spray_4771.evtx` (69,632 bytes, SHA-256 `4a0a1c71…9ae11d`) from [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) `Credential Access/`, downloaded on 2026-09-30. The repository is GPL-3.0, so the file is not redistributed here; download it to reproduce WIN-007. `tools/normalize_windows_events.py` reads `.evtx` with the built-in `Get-WinEvent`, so this step needs Windows. `tools/normalize_windows_events.py` converts the NXLog JSON to ECS and keeps the raw fields under `winlog.event_data`. The comsvcs capture has no time zone on `TimeCreated`, so it is treated as UTC for ordering only.

## SWaT Kaggle Mirror

Local raw paths are configured in `swat_local.json`. The files come from Kaggle [`vishala28/swat-dataset-secure-water-treatment-system`](https://www.kaggle.com/datasets/vishala28/swat-dataset-secure-water-treatment-system) by Vishal Agrawal, created 2025-10-28, with a declared licence of CC0. Kaggle's public API reports these sizes:

| File | Bytes |
|---|---:|
| `attack.csv` | 15,162,438 |
| `normal.csv` | 402,374,633 |
| `merged.csv` | 426,855,390 |

`attack.csv` and `normal.csv` match the local copies byte-for-byte by size. `merged.csv` was never size-checked locally. Kaggle publishes no checksum. The original data is **SWaT.A1 (December 2015)** from [iTrust, SUTD](https://www.sutd.edu.sg/itrust/itrust-labs/datasets/). Cite iTrust as the source and the Kaggle mirror as the download location.

The mirror is **not** the original Normal/Attack split. The row and timestamp counts recorded on 2026-06-10 give the following layout:

- `attack.csv` (54,621 rows) holds only the Attack-labelled rows of the attack period, 28/12/2015 10:29:14 to 02/01/2016 13:41:11. The gaps between attacks are removed, so it is not a continuous time series.
- `normal.csv` (1,387,098 rows) holds three blocks:
  - Normal v0: 496,800 rows.
  - Normal v1: 495,000 rows, re-listing the same seconds. The days from 23 to 27 Dec have 172,800 rows each.
  - The 395,298 Normal-labelled rows from the attack period.
- The file **starts at 28/12/2015 10:00:00**, which is inside the attack period.
- `merged.csv` (1,441,719 rows) is `normal.csv` plus `attack.csv`.

Do not take the first N rows of `normal.csv` as clean training data. Deduplicate by timestamp, then split by time:

- **Train:** 22/12/2015 16:00:00 to 28/12/2015 09:59:59 (496,800 s). The first 30 minutes are often dropped as start-up.
- **Test:** 28/12/2015 10:00:00 to 02/01/2016 14:59:59 (449,919 rows, 54,621 attacks).

At the latest local check, only `D:/attack.csv` is available. A SWaT benchmark needs only `merged.csv`, because it already contains every row of `normal.csv` and `attack.csv`. Download it again from the Kaggle page above and check that it is 426,855,390 bytes. `normal.csv` is redundant.

Inspect a raw file without training a scaler:

```powershell
python tools/normalize_swat.py --input D:/attack.csv --inspect --summary out/swat_attack_inspection.json
```

The commands below show how the converter is used. `normalize_swat.py` has no timestamp filter yet. On the Kaggle `normal.csv`, `--start-row` and `--max-rows` therefore select attack-period rows, so these commands are **not** a valid benchmark protocol until a time-range filter exists. Fit the scaler on the training slice only, then reuse it for the held-out slice and the attack data:

```powershell
python tools/normalize_swat.py --input D:/normal.csv --max-rows 20000 --output data/swat_train.jsonl --scaler models/swat_scaler.json --fit-scaler
python tools/normalize_swat.py --input D:/normal.csv --start-row 20001 --max-rows 5000 --output data/swat_normal_test.jsonl --scaler models/swat_scaler.json
python tools/normalize_swat.py --input D:/attack.csv --output data/swat_attack.jsonl --scaler models/swat_scaler.json
.venv/Scripts/python.exe tools/train_lstm_autoencoder.py --input data/swat_train.jsonl --output models/swat_lstm.pt
build-libtorch/Release/threatfusion.exe --events data/swat_attack.jsonl --format jsonl --baseline data/swat_train.jsonl --baseline-format jsonl --lstm models/swat_lstm.pt
```

The converter strips header whitespace, validates numeric readings and labels, preserves all 51 features, and removes exact timestamp/measurement duplicates. Conflicting labels for the same measurement are errors. It streams rows instead of buffering the whole CSV. IDs are content-derived and independent of the input filename. Splits must be checked for repeated IDs: source-row offsets alone cannot eliminate duplicated measurements already present in a Kaggle mirror. For strict temporal evaluation, split by original timestamp and deduplicate before dividing train/test.

Each SWaT row becomes one process event with `protocol=process`, not fabricated network traffic. Scaler extrema are fit only on benign training rows. Test values outside the training range are retained, including values outside [0,1], so anomalies are not clipped away. Source timestamps have no declared timezone and are not labeled UTC. These process payloads are not malware file hashes.

SWaT benchmark results require the missing benign data. Fixture tests exercise conversion/scaling and are not research accuracy measurements. WADI and CIC adapters/benchmarks remain future work.
