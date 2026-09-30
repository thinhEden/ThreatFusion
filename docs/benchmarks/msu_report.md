# Reproducible MSU Benchmark

Row-order 60/20/20 per capture, benign-only training, validation-only FPR calibration. Rules: TimeInterval outside the benign-validation band at the same FPR; SetPoint value never seen in benign training rows.

Read this table with [the data audit](msu_data_audit.md): a single-feature rule matching or beating the models means the capture is separable without learning attack behaviour.

| Capture | Detector | Features | TP | TN | FP | FN | Precision | Recall | F1 | FPR |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| command | isolation_forest | all | 258 | 5380 | 31 | 0 | 0.8927 | 1.0000 | 0.9433 | 0.0057 |
| command | lstm | all | 249 | 5380 | 31 | 9 | 0.8893 | 0.9651 | 0.9257 | 0.0057 |
| command | hybrid | all | 249 | 5384 | 27 | 9 | 0.9022 | 0.9651 | 0.9326 | 0.0050 |
| command | timeinterval_rule | rule | 258 | 5410 | 1 | 0 | 0.9961 | 1.0000 | 0.9981 | 0.0002 |
| command | setpoint_rule | rule | 247 | 5411 | 0 | 11 | 1.0000 | 0.9574 | 0.9782 | 0.0000 |
| command | isolation_forest | without TimeInterval | 258 | 5411 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 | 0.0000 |
| command | lstm | without TimeInterval | 249 | 5411 | 0 | 9 | 1.0000 | 0.9651 | 0.9822 | 0.0000 |
| command | hybrid | without TimeInterval | 249 | 5411 | 0 | 9 | 1.0000 | 0.9651 | 0.9822 | 0.0000 |
| response | isolation_forest | all | 1127 | 4464 | 159 | 112 | 0.8764 | 0.9096 | 0.8927 | 0.0344 |
| response | lstm | all | 1192 | 4590 | 33 | 47 | 0.9731 | 0.9621 | 0.9675 | 0.0071 |
| response | hybrid | all | 1192 | 4588 | 35 | 47 | 0.9715 | 0.9621 | 0.9667 | 0.0076 |
| response | timeinterval_rule | rule | 1237 | 4583 | 40 | 2 | 0.9687 | 0.9984 | 0.9833 | 0.0087 |
| response | setpoint_rule | rule | 0 | 4623 | 0 | 1239 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| response | isolation_forest | without TimeInterval | 1124 | 4492 | 131 | 115 | 0.8956 | 0.9072 | 0.9014 | 0.0283 |
| response | lstm | without TimeInterval | 1126 | 4529 | 94 | 113 | 0.9230 | 0.9088 | 0.9158 | 0.0203 |
| response | hybrid | without TimeInterval | 1126 | 4518 | 105 | 113 | 0.9147 | 0.9088 | 0.9117 | 0.0227 |
| dos | isolation_forest | all | 873 | 4744 | 172 | 0 | 0.8354 | 1.0000 | 0.9103 | 0.0350 |
| dos | lstm | all | 873 | 4835 | 81 | 0 | 0.9151 | 1.0000 | 0.9557 | 0.0165 |
| dos | hybrid | all | 873 | 4834 | 82 | 0 | 0.9141 | 1.0000 | 0.9551 | 0.0167 |
| dos | timeinterval_rule | rule | 873 | 4875 | 41 | 0 | 0.9551 | 1.0000 | 0.9771 | 0.0083 |
| dos | setpoint_rule | rule | 0 | 4916 | 0 | 873 | 0.0000 | 0.0000 | 0.0000 | 0.0000 |
| dos | isolation_forest | without TimeInterval | 873 | 4767 | 149 | 0 | 0.8542 | 1.0000 | 0.9214 | 0.0303 |
| dos | lstm | without TimeInterval | 872 | 4813 | 103 | 1 | 0.8944 | 0.9989 | 0.9437 | 0.0210 |
| dos | hybrid | without TimeInterval | 872 | 4802 | 114 | 1 | 0.8844 | 0.9989 | 0.9381 | 0.0232 |
