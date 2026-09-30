"""Reproducible MSU benchmark: row-order splits, benign training, validation FPR calibration.

Every capture is also scored by two single-feature rules and re-run without the TimeInterval feature,
because docs/benchmarks/msu_data_audit.md shows TimeInterval and SetPoint separate attacks on their own.
"""
import argparse
import csv
import hashlib
import json
import subprocess
import sys
from pathlib import Path
import numpy as np
from normalize_msu_ics import normalize_msu_row, safe_float
from train_lstm_autoencoder import train_model

CASES = {
    'command': 'Multiclass FeatureSets/MulticlasCommandInjectionV2.csv',
    'response': 'Multiclass FeatureSets/MulticlassResponseInjectionV2.csv',
    'dos': 'DoS Data FeatureSet/modbusRTU_DoSResponseInjectionV2.csv',
}
TIME_INTERVAL = 2  # Index of TimeInterval in normalize_msu_row extra_features.


def metrics(labels, predictions):
    positive = np.asarray(labels) == 'malicious'
    predicted = np.asarray(predictions, dtype=bool)
    tp = int(np.sum(positive & predicted))
    tn = int(np.sum(~positive & ~predicted))
    fp = int(np.sum(~positive & predicted))
    fn = int(np.sum(positive & ~predicted))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    return {'TP': tp, 'TN': tn, 'FP': fp, 'FN': fn,
            'precision': precision, 'recall': recall,
            'f1': 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else 0.0,
            'accuracy': (tp + tn) / len(positive) if len(positive) else 0.0,
            'false_positive_rate': fp / (fp + tn) if fp + tn else 0.0}


def write_events(path, events):
    with path.open('w', encoding='utf-8') as handle:
        for event in events:
            handle.write(json.dumps(event, separators=(',', ':')) + '\n')


def read_scores(path):
    with path.open(newline='', encoding='utf-8') as handle:
        rows = list(csv.DictReader(handle))
    # Warmup is scored negative, not silently excluded from the confusion matrix.
    losses = np.array([float(r['lstm_error']) if r['lstm_error'] else np.nan for r in rows])
    return rows, np.array([float(r['if_score']) for r in rows]), losses


def rule_baselines(raw, labels, cut_train, cut_validation, fpr):
    """Single-feature rules calibrated like the models: benign training/validation rows only."""
    interval = np.array([safe_float(r.get('TimeInterval')) for r in raw])
    setpoint = np.array([safe_float(r.get('SetPoint')) for r in raw])
    benign = np.asarray(labels) == 'benign'
    validation = interval[cut_train:cut_validation][benign[cut_train:cut_validation]]
    low, high = np.quantile(validation, [fpr / 2, 1 - fpr / 2])
    seen = set(setpoint[:cut_train][benign[:cut_train]])
    test_labels = labels[cut_validation:]
    return {'timeinterval_rule': metrics(test_labels, (interval[cut_validation:] < low) | (interval[cut_validation:] > high)),
            'setpoint_rule': metrics(test_labels, [v not in seen for v in setpoint[cut_validation:]])}


def run_case(name, source, engine, output, args, drop_time_interval=False):
    folder = output / (name + ('_without_TimeInterval' if drop_time_interval else ''))
    folder.mkdir(parents=True, exist_ok=True)
    with source.open(encoding='utf-8-sig', newline='') as handle:
        raw = [{k.strip(): (v or '').strip() for k, v in row.items() if k} for row in csv.DictReader(handle)]
    if args.max_rows:
        # Uniform downsampling over the entire capture retains its late attack segment.
        indices = np.linspace(0, len(raw) - 1, min(args.max_rows, len(raw)), dtype=int)
        raw = [raw[i] for i in indices]
    events = [normalize_msu_row(row, i, name) for i, row in enumerate(raw, 1)]
    if drop_time_interval:
        for event in events:
            del event['extra_features'][TIME_INTERVAL]
    cut_train, cut_validation = int(len(events) * .6), int(len(events) * .8)
    partitions = {'train': events[:cut_train], 'validation': events[cut_train:cut_validation],
                  'test': events[cut_validation:]}
    for partition, rows in partitions.items():
        write_events(folder / f'{partition}.jsonl', rows)
    metadata = train_model(partitions['train'], folder / 'model.pt', args.epochs, args.window, seed=args.seed)
    for partition in ('validation', 'test'):
        command = [str(engine), '--events', str(folder / f'{partition}.jsonl'), '--format', 'jsonl',
                   '--baseline', str(folder / 'train.jsonl'), '--baseline-format', 'jsonl',
                   '--lstm', str(folder / 'model.pt'), '--scores', str(folder / f'{partition}_scores.csv'),
                   '--alerts', str(folder / f'{partition}_alerts.csv'),
                   '--incidents', str(folder / f'{partition}_incidents.csv'),
                   '--metrics', str(folder / f'{partition}_operational_metrics.txt')]
        result = subprocess.run(command, capture_output=True, text=True, check=True, timeout=300)
        (folder / f'{partition}_engine.log').write_text(result.stdout + result.stderr, encoding='utf-8')
        if 'Loaded TorchScript model' not in result.stdout:
            raise RuntimeError('Benchmark requires real C++ LibTorch inference; simulated mode is prohibited')
    val_rows, val_if, val_loss = read_scores(folder / 'validation_scores.csv')
    test_rows, test_if, test_loss = read_scores(folder / 'test_scores.csv')
    normal = np.array([r['label'] == 'benign' for r in val_rows])
    valid = normal & np.isfinite(val_loss)
    if not np.any(valid):
        raise ValueError('Validation split must contain benign, full-window events')
    # Scale loss using benign validation only, then calibrate all thresholds independently.
    scale = max(float(np.quantile(val_loss[valid], 1 - args.fpr)), 1e-12)
    threshold_if = float(np.quantile(val_if[normal], 1 - args.fpr))
    hybrid_val = args.if_weight * val_if + (1 - args.if_weight) * np.nan_to_num(val_loss / scale)
    threshold_hybrid = float(np.quantile(hybrid_val[valid], 1 - args.fpr))
    hybrid_test = args.if_weight * test_if + (1 - args.if_weight) * np.nan_to_num(test_loss / scale)
    labels = [r['label'] for r in test_rows]
    report = {
        'source': str(source), 'sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
        'split': {p: {'rows': len(rows), 'benign': sum(r['label'] == 'benign' for r in rows),
                      'malicious': sum(r['label'] == 'malicious' for r in rows)} for p, rows in partitions.items()},
        'training': metadata, 'warmup_events_test': int(np.isnan(test_loss).sum()),
        'calibration': {'target_validation_fpr': args.fpr, 'if_threshold': threshold_if,
                        'lstm_threshold': scale, 'hybrid_threshold': threshold_hybrid,
                        'if_weight': args.if_weight},
        'metrics': {
            'isolation_forest': metrics(labels, test_if > threshold_if),
            'lstm': metrics(labels, np.isfinite(test_loss) & (test_loss > scale)),
            'hybrid': metrics(labels, np.isfinite(test_loss) & (hybrid_test > threshold_hybrid)),
        },
    }
    if not drop_time_interval:
        report['metrics'].update(rule_baselines(raw, [e['label'] for e in events], cut_train, cut_validation, args.fpr))
    (folder / 'report.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--engine', required=True)
    parser.add_argument('--dataset', default='datasets/MSU_ICS/ModbusRTUfeatureSetsV2')
    parser.add_argument('--output', default='out/benchmark_msu')
    parser.add_argument('--epochs', type=int, default=5)
    parser.add_argument('--window', type=int, default=10)
    parser.add_argument('--seed', type=int, default=1337)
    parser.add_argument('--fpr', type=float, default=.01)
    parser.add_argument('--if-weight', type=float, default=.5)
    parser.add_argument('--max-rows', type=int, default=0, help='Uniform subsample for smoke runs; 0 = full capture')
    args = parser.parse_args()
    if not 0 < args.fpr < 1 or not 0 <= args.if_weight <= 1 or args.epochs < 1 or args.window < 1 or args.max_rows < 0:
        parser.error('Invalid benchmark parameters')
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    reports = {}
    for name, filename in CASES.items():
        print(f'Benchmarking {name}...', flush=True)
        source, engine = Path(args.dataset).resolve() / filename, Path(args.engine).resolve()
        reports[name] = run_case(name, source, engine, output, args)
        ablation = run_case(name, source, engine, output, args, drop_time_interval=True)
        reports[name]['metrics_without_TimeInterval'] = ablation['metrics']
    report = {'protocol': 'Row-order 60/20/20 per capture, benign-only training, validation-only FPR calibration. '
                          'Rules: TimeInterval outside the benign-validation band at the same FPR; '
                          'SetPoint value never seen in benign training rows.',
              'engine_sha256': hashlib.sha256(Path(args.engine).read_bytes()).hexdigest(),
              'python': sys.version, 'numpy': np.__version__,
              'command': sys.argv, 'smoke_run': bool(args.max_rows), 'cases': reports,
              'note': 'Labels tune no model features. MSU timestamps are absent. These are capture-specific binary results, not malware-family identification.'}
    (output / 'report.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    lines = ['# Reproducible MSU Benchmark', '', report['protocol'], '',
             'Read this table with [the data audit](msu_data_audit.md): a single-feature rule matching or beating '
             'the models means the capture is separable without learning attack behaviour.', '',
             '| Capture | Detector | Features | TP | TN | FP | FN | Precision | Recall | F1 | FPR |',
             '|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|']
    for name, case in reports.items():
        rows = [(model, 'rule' if model.endswith('_rule') else 'all', m) for model, m in case['metrics'].items()]
        rows += [(model, 'without TimeInterval', m) for model, m in case['metrics_without_TimeInterval'].items()]
        for model, features, m in rows:
            lines.append(f"| {name} | {model} | {features} | {m['TP']} | {m['TN']} | {m['FP']} | {m['FN']} | {m['precision']:.4f} | {m['recall']:.4f} | {m['f1']:.4f} | {m['false_positive_rate']:.4f} |")
    (output / 'report.md').write_text('\n'.join(lines) + '\n', encoding='utf-8')
    print('\n'.join(lines), flush=True)


if __name__ == '__main__':
    main()
