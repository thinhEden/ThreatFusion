"""Audit the MSU/ORNL ModbusRTUfeatureSetsV2 captures used by benchmark_msu.py.

Checks file integrity, label layout, duplicates, attack-only feature values, benign
train/test overlap under the benchmark's row-order split, and a one-feature
TimeInterval rule calibrated exactly like the benchmark (benign validation, 1% FPR).
An optional Isolation Forest ablation runs when scikit-learn is installed.
"""
import argparse
import csv
import hashlib
import json
from collections import Counter
from pathlib import Path
import numpy as np
from benchmark_msu import CASES, metrics
from normalize_msu_ics import normalize_msu_row
from train_lstm_autoencoder import extract_features

SOURCE = {
    'page': 'https://sites.google.com/a/uah.edu/tommy-morris-uah/ics-data-sets',
    'entry': 'Dataset 2: Gas Pipeline Datasets (ORNL formatted, Modbus RTU feature sets V2)',
    'archive': 'http://www.ece.uah.edu/~thm0009/icsdatasets/ModbusRTUfeatureSetsV2.zip',
    'citation': 'Beaver, Borges-Hink, Buckner, "An Evaluation of Machine Learning Methods to Detect '
                'Malicious SCADA Communications," ICMLA 2013, vol. 2, pp. 54-59, doi:10.1109/ICMLA.2013.105',
}
FEATURES = ['src', 'dst', 'protocol', 'function_code', 'asset', 'bytes', 'hour',
            'PipelinePSI', 'SetPoint', 'TimeInterval', 'deltaPipelinePSI', 'deltaSetPoint']
TIME = FEATURES.index('TimeInterval')


def unify_newlines(raw):
    # The Multiclass files use classic-Mac CR line endings; git autocrlf may add CRLF.
    return raw.replace(b'\r\n', b'\n').replace(b'\r', b'\n')


def read_rows(path):
    raw = path.read_bytes()
    text = unify_newlines(raw).decode('utf-8-sig')
    rows = [{k.strip(): (v or '').strip() for k, v in r.items() if k is not None}
            for r in csv.DictReader(text.splitlines())]
    ending = 'CR' if b'\r' in raw and b'\n' not in raw else 'CRLF' if b'\r\n' in raw else 'LF'
    return raw, ending, rows


def file_audit(path, root):
    raw, ending, rows = read_rows(path)
    columns = [c for c in rows[0] if c != 'Label']
    attack = np.array([r['Label'].lower() != 'good' for r in rows])
    positions = np.flatnonzero(attack)
    benign_values = {c: {r[c] for r, a in zip(rows, attack) if not a} for c in columns}
    attack_only = {c: round(float(np.mean([r[c] not in benign_values[c] for r, a in zip(rows, attack) if a])), 4)
                   for c in columns} if len(positions) else {}
    return {
        'file': path.relative_to(root).as_posix(), 'bytes': len(raw),
        'sha256': hashlib.sha256(raw).hexdigest(), 'line_ending': ending, 'rows': len(rows),
        'labels': dict(Counter(r['Label'] for r in rows)),
        'attack_rows_contiguous_at_end': bool(len(positions) and positions[0] == len(rows) - len(positions)),
        'benign_rows_before_attacks': int(positions[0]) if len(positions) else len(rows),
        'exact_duplicate_rows_pct': round(100 * (1 - len({tuple(r.values()) for r in rows}) / len(rows)), 2),
        'direction_benign': dict(Counter(r['CommandResponse'] for r, a in zip(rows, attack) if not a)),
        'direction_attack': dict(Counter(r['CommandResponse'] for r, a in zip(rows, attack) if a)),
        'attack_rows_with_value_unseen_in_benign': {c: v for c, v in attack_only.items() if v >= .5},
    }


def archive_audit(archive, root):
    """Compare local CSVs with the official ModbusRTUfeatureSetsV2.zip."""
    import zipfile
    raw_archive = Path(archive).read_bytes()
    files = {}
    with zipfile.ZipFile(archive) as bundle:
        for info in bundle.infolist():
            if info.is_dir():
                continue
            name = info.filename.split('/', 1)[1]
            official, local = bundle.read(info), root / name
            if not local.exists():
                status = 'missing_locally'
            elif local.read_bytes() == official:
                status = 'identical'
            else:
                status = 'line_endings_only' if unify_newlines(local.read_bytes()) == unify_newlines(official) else 'different'
            files[name] = {'status': status, 'official_sha256': hashlib.sha256(official).hexdigest()}
    return {'archive_bytes': len(raw_archive), 'archive_sha256': hashlib.sha256(raw_archive).hexdigest(),
            'files': files,
            'extra_local_files': sorted({p.relative_to(root).as_posix() for p in root.rglob('*.csv')} - set(files))}


def outside_band(validation, test, fpr):
    lo, hi = np.quantile(validation, [fpr / 2, 1 - fpr / 2])
    return (test < lo) | (test > hi)


def benchmark_audit(name, path, fpr):
    _, _, rows = read_rows(path)
    events = [normalize_msu_row(r, i, name) for i, r in enumerate(rows, 1)]
    X = np.array([extract_features(e) for e in events])
    labels = np.array([e['label'] for e in events])
    a, b = int(len(X) * .6), int(len(X) * .8)
    benign_val = labels[a:b] == 'benign'
    train_vectors = {tuple(v) for v in X[:a][labels[:a] == 'benign'].round(6)}
    test_seen = np.array([tuple(v) in train_vectors for v in X[b:].round(6)])
    test_benign = labels[b:] == 'benign'
    result = {
        'malicious_per_split': {'train': int((labels[:a] == 'malicious').sum()),
                                'validation': int((labels[a:b] == 'malicious').sum()),
                                'test': int((labels[b:] == 'malicious').sum())},
        'unique_train_vectors': len(train_vectors), 'train_rows': a,
        'test_benign_vectors_seen_in_train_pct': round(100 * float(test_seen[test_benign].mean()), 2),
        'test_malicious_vectors_seen_in_train_pct': round(100 * float(test_seen[~test_benign].mean()), 2),
        'timeinterval_rule': metrics(labels[b:], outside_band(X[a:b, TIME][benign_val], X[b:, TIME], fpr)),
    }
    try:
        from sklearn.ensemble import IsolationForest
    except ImportError:
        result['isolation_forest_ablation'] = 'skipped: scikit-learn not installed'
        return result
    ablation = {}
    for variant, keep in [('all_features', list(range(len(FEATURES)))),
                          ('without_TimeInterval', [i for i in range(len(FEATURES)) if i != TIME]),
                          ('TimeInterval_only', [TIME])]:
        f1 = []
        for seed in range(5):
            model = IsolationForest(n_estimators=200, random_state=seed).fit(X[:a][:, keep])
            threshold = np.quantile(-model.score_samples(X[a:b][:, keep])[benign_val], 1 - fpr)
            f1.append(metrics(labels[b:], -model.score_samples(X[b:][:, keep]) > threshold)['f1'])
        ablation[variant] = {'f1_mean': round(float(np.mean(f1)), 4), 'f1_std': round(float(np.std(f1)), 4)}
    result['isolation_forest_ablation'] = ablation
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dataset', default='datasets/MSU_ICS/ModbusRTUfeatureSetsV2')
    parser.add_argument('--output', default='docs/benchmarks/msu_data_audit.json')
    parser.add_argument('--fpr', type=float, default=.01)
    parser.add_argument('--archive', help='Downloaded ModbusRTUfeatureSetsV2.zip to compare against')
    args = parser.parse_args()
    root = Path(args.dataset).resolve()
    report = {'source': SOURCE, 'files': [file_audit(p, root) for p in sorted(root.rglob('*.csv'))],
              'benchmark_cases': {n: benchmark_audit(n, root / f, args.fpr) for n, f in CASES.items()}}
    if args.archive:
        report['official_archive'] = archive_audit(args.archive, root)
        print('Official archive:', dict(Counter(f['status'] for f in report['official_archive']['files'].values())))
    Path(args.output).write_text(json.dumps(report, indent=2), encoding='utf-8')
    for f in report['files']:
        print(f"{f['file']}: rows={f['rows']} dup={f['exact_duplicate_rows_pct']}% attacks_at_end={f['attack_rows_contiguous_at_end']}")
    for n, c in report['benchmark_cases'].items():
        print(f"{n}: TimeInterval rule F1={c['timeinterval_rule']['f1']:.4f} ablation={c['isolation_forest_ablation']}")


if __name__ == '__main__':
    main()
