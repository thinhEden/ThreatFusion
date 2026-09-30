# Reproducible MSU Benchmark

Row-order 60/20/20 per capture, benign-only training, validation-only FPR calibration

| Capture | Model | TP | TN | FP | FN | Precision | Recall | F1 | FPR |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| command | isolation_forest | 258 | 5380 | 31 | 0 | 0.8927 | 1.0000 | 0.9433 | 0.0057 |
| command | lstm | 249 | 5380 | 31 | 9 | 0.8893 | 0.9651 | 0.9257 | 0.0057 |
| command | hybrid | 249 | 5384 | 27 | 9 | 0.9022 | 0.9651 | 0.9326 | 0.0050 |
| response | isolation_forest | 1127 | 4464 | 159 | 112 | 0.8764 | 0.9096 | 0.8927 | 0.0344 |
| response | lstm | 1192 | 4590 | 33 | 47 | 0.9731 | 0.9621 | 0.9675 | 0.0071 |
| response | hybrid | 1192 | 4588 | 35 | 47 | 0.9715 | 0.9621 | 0.9667 | 0.0076 |
| dos | isolation_forest | 873 | 4744 | 172 | 0 | 0.8354 | 1.0000 | 0.9103 | 0.0350 |
| dos | lstm | 873 | 4835 | 81 | 0 | 0.9151 | 1.0000 | 0.9557 | 0.0165 |
| dos | hybrid | 873 | 4834 | 82 | 0 | 0.9141 | 1.0000 | 0.9551 | 0.0167 |
