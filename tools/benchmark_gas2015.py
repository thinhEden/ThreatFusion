"""OT operating-envelope context on the MSU New Gas Pipeline 2015 dataset, scored by the C++ engine.

Protocol: split by capture time 60/20/20. The operating envelope is derived only from benign FC16 writes in
the training window (a stand-in for commissioning documentation), then fixed. Validation and test requests
are scored without labels by three engine variants: baseline, envelope, and envelope + state-change review.
"""
import argparse
import csv
import hashlib
import json
import math
import subprocess
from collections import Counter
from pathlib import Path
import numpy as np
from normalize_gas2015 import CATEGORIES, CONTROL, is_command, read_arff, write_split

ROOT = Path(__file__).resolve().parents[1]
SOURCE = 'http://www.ece.uah.edu/~thm0009/icsdatasets/IanArffDataset.arff'
ENUMERATED = ['system mode', 'control scheme', 'pump', 'solenoid']
VARIANTS = {'baseline': None, 'envelope': False, 'envelope_state_review': True}


def derive_envelope(train_writes, retain_state_changes):
    units = {int(r['address']) for r in train_writes}
    if len(units) != 1:
        raise ValueError(f'Expected one RTU address in benign training writes, got {sorted(units)}')
    if any(r[p] is None for r in train_writes for p in CONTROL):
        raise ValueError('Benign training writes must carry every control parameter')
    parameters = {p: {'values': sorted({r[p] for r in train_writes})} for p in ENUMERATED}
    parameters.update({p: {'min': min(r[p] for r in train_writes), 'max': max(r[p] for r in train_writes)}
                       for p in CONTROL if p not in ENUMERATED})
    return {'schema_version': 2,
            'provenance': 'Derived from benign-labelled FC16 writes in the training window only; '
                          'a stand-in for commissioning documentation, fixed before validation/test',
            'operating_envelope': {'id': 'ENV-GP15-TRAIN', 'unit_id': units.pop(), 'function_codes': [16],
                                   'retain_state_changes': retain_state_changes, 'parameters': parameters}}


def confusion(truth, flagged):
    tp = sum(t['label'] == 'malicious' and t['event_id'] in flagged for t in truth)
    fp = sum(t['label'] == 'benign' and t['event_id'] in flagged for t in truth)
    fn = sum(t['label'] == 'malicious' for t in truth) - tp
    tn = len(truth) - tp - fp - fn
    return {'TP': tp, 'TN': tn, 'FP': fp, 'FN': fn,
            'precision': tp / (tp + fp) if tp + fp else 0.0, 'recall': tp / (tp + fn) if tp + fn else 0.0,
            'f1': 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else 0.0,
            'false_positive_rate': fp / (fp + tn) if fp + tn else 0.0}


def attack_ids_by_category(truth, flagged):
    """Share of each attack category's packets whose alert carries a given ATT&CK ID."""
    result = {}
    for category in sorted({t['category'] for t in truth} - {'Normal'}):
        packets = [t['event_id'] for t in truth if t['category'] == category]
        ids = Counter(i for p in packets for i in flagged.get(p, ()))
        result[category] = {i: round(n / len(packets), 4) for i, n in sorted(ids.items())}
    return result


def percentile(values, q):
    return values[max(0, math.ceil(q * len(values)) - 1)]


def run_variant(engine, folder, split, variant, threshold):
    prefix = folder / f'{split}_{variant}'
    command = [str(engine), '--events', str(folder / f'{split}.events.jsonl'), '--format', 'jsonl',
               '--rules', str(ROOT / 'data/behavior_rules.csv'), '--iocs', str(ROOT / 'data/iocs.csv'),
               '--alerts', f'{prefix}.alerts.csv', '--incidents', f'{prefix}.incidents.csv',
               '--metrics', f'{prefix}.unlabeled_metrics.txt', '--timings', f'{prefix}.timings.csv',
               '--threshold', str(threshold)]
    if VARIANTS[variant] is not None:
        command += ['--context', str(folder / f'policy_{variant}.json'), '--context-audit', f'{prefix}.audit.csv']
    result = subprocess.run(command, capture_output=True, text=True, check=True, timeout=600, cwd=ROOT)
    Path(f'{prefix}.engine.log').write_text(result.stdout + result.stderr, encoding='utf-8')
    with open(f'{prefix}.alerts.csv', newline='', encoding='utf-8') as handle:
        # Alerted event -> MITRE ATT&CK IDs the engine attached to it.
        flagged = {r['event_id']: set(filter(None, r.get('attack_techniques', '').split('|')))
                   for r in csv.DictReader(handle) if int(r['risk_score']) >= threshold}
    with open(f'{prefix}.timings.csv', newline='', encoding='utf-8') as handle:
        timings = sorted(float(r['processing_ms']) for r in csv.DictReader(handle))
    reasons = Counter()
    if VARIANTS[variant] is not None:
        with open(f'{prefix}.audit.csv', newline='', encoding='utf-8') as handle:
            reasons = Counter(r['reason'] for r in csv.DictReader(handle) if r['policy_id'])
    return flagged, {'p50': percentile(timings, .5), 'p95': percentile(timings, .95),
                     'p99': percentile(timings, .99)}, dict(reasons)


def shortcut_probe(rows):
    """Best single-feature depth-3 tree F1 (5-fold CV); skipped without scikit-learn."""
    try:
        from sklearn.model_selection import StratifiedKFold, cross_val_predict
        from sklearn.metrics import f1_score
        from sklearn.tree import DecisionTreeClassifier
    except ImportError:
        return 'skipped: scikit-learn not installed'
    features = [k for k in rows[0] if k not in ('binary result', 'categorized result', 'specific result', 'time')]
    y = np.array([r['binary result'] == 1 for r in rows])
    time = np.array([r['time'] for r in rows])
    columns = {f: np.array([-1e9 if r[f] is None else r[f] for r in rows]) for f in features}
    columns['inter_arrival'] = np.diff(time, prepend=time[0])
    cv = StratifiedKFold(5, shuffle=True, random_state=0)
    scores = {f: float(f1_score(y, cross_val_predict(DecisionTreeClassifier(max_depth=3, random_state=0),
                                                        x.reshape(-1, 1), y, cv=cv))) for f, x in columns.items()}
    return dict(sorted(((f, round(s, 4)) for f, s in scores.items()), key=lambda t: -t[1])[:5])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--engine', required=True)
    parser.add_argument('--dataset', default='datasets/MSU_ICS/GasPipeline2015/IanArffDataset.arff')
    parser.add_argument('--output', default='out/benchmark_gas2015')
    parser.add_argument('--report', default='docs/benchmarks/gas2015_context_report')
    parser.add_argument('--threshold', type=int, default=60)
    args = parser.parse_args()
    folder = Path(args.output).resolve()
    folder.mkdir(parents=True, exist_ok=True)
    dataset, engine = Path(args.dataset).resolve(), Path(args.engine).resolve()

    rows = list(read_arff(dataset))
    indexed = list(enumerate(rows, 1))
    times = np.array([r['time'] for r in rows])
    if np.any(np.diff(times) < 0):
        raise ValueError('Capture timestamps must be non-decreasing')
    start, end = float(times[0]), float(times[-1])
    cut_train, cut_test = start + .6 * (end - start), start + .8 * (end - start)
    train_writes = [r for r in rows if r['time'] < cut_train and r['binary result'] == 0
                    and is_command(r) and r['function'] == 16]
    for variant, retain in VARIANTS.items():
        if retain is not None:
            (folder / f'policy_{variant}.json').write_text(json.dumps(derive_envelope(train_writes, retain), indent=2))
    splits = {'validation': [(i, r) for i, r in indexed if cut_train <= r['time'] < cut_test and is_command(r)],
              'test': [(i, r) for i, r in indexed if r['time'] >= cut_test and is_command(r)]}

    report = {'source': SOURCE, 'sha256': hashlib.sha256(dataset.read_bytes()).hexdigest(),
              'engine_sha256': hashlib.sha256(engine.read_bytes()).hexdigest(),
              'rows': len(rows), 'attack_fraction': float(np.mean([r['binary result'] == 1 for r in rows])),
              'attack_fraction_by_row_decile': [round(float(np.mean([r['binary result'] == 1 for r in part])), 4)
                                                 for part in np.array_split(np.array(rows, dtype=object), 10)],
              'duplicate_rows_excluding_time_pct': round(100 * (1 - len({tuple(v for k, v in r.items() if k != 'time')
                                                                          for r in rows}) / len(rows)), 2),
              'single_feature_shortcut_probe_f1': shortcut_probe(rows),
              'split_epoch': {'start': start, 'train_end': cut_train, 'validation_end': cut_test, 'end': end},
              'training_benign_writes': len(train_writes), 'threshold': args.threshold, 'splits': {}}
    for split, pairs in splits.items():
        write_split(pairs, folder / f'{split}.events.jsonl', folder / f'{split}.truth.csv')
        with open(folder / f'{split}.truth.csv', newline='', encoding='utf-8') as handle:
            truth = list(csv.DictReader(handle))
        writes = {f'GP15-{i}' for i, r in pairs if r['function'] == 16}
        report['splits'][split] = {'requests': len(truth), 'labels': dict(Counter(t['category'] for t in truth)),
                                   'variants': {}}
        for variant in VARIANTS:
            flagged, timing, reasons = run_variant(engine, folder, split, variant, args.threshold)
            report['splits'][split]['variants'][variant] = {
                'all_requests': confusion(truth, flagged),
                'fc16_writes': confusion([t for t in truth if t['event_id'] in writes], flagged),
                'recall_by_category': {c: round(float(np.mean([t['event_id'] in flagged for t in truth if t['category'] == c])), 4)
                                       for c in CATEGORIES.values() if c != 'Normal' and any(t['category'] == c for t in truth)},
                'attack_ids_by_category': attack_ids_by_category(truth, flagged),
                'processing_ms': timing, 'context_decisions': reasons}
    report['envelope'] = derive_envelope(train_writes, False)['operating_envelope']['parameters']
    Path(f'{args.report}.json').write_text(json.dumps(report, indent=2), encoding='utf-8')

    lines = ['# OT Operating-Envelope Context: MSU New Gas Pipeline 2015', '',
             f"Generated by `tools/benchmark_gas2015.py`. Source: {SOURCE}. The SHA-256 is `{report['sha256']}` "
             f"and the file has {report['rows']:,} rows.", '',
             '## Protocol', '',
             f"- The capture is split by time into 60% training, 20% validation and 20% test. "
             f"Attacks are interleaved throughout: each tenth of the rows, in time order, is "
             f"{min(report['attack_fraction_by_row_decile']):.1%}-{max(report['attack_fraction_by_row_decile']):.1%} attacks.",
             f"- The envelope is derived only from the {report['training_benign_writes']:,} benign FC16 writes in the training window. "
             "Mode, scheme, pump and solenoid become value sets; every other control parameter becomes a [min, max] range. "
             "Selecting the benign rows uses training labels. The envelope stands in for commissioning documentation.",
             '- Validation and test requests reach the C++ engine without labels. Ground truth is joined only after scoring. '
             f"An alert counts when its risk score is at least {args.threshold}. Only BR-001 (Modbus write) detections can be "
             'downgraded; any other evidence is retained.',
             '- Variants: `baseline` applies no context. `envelope` suppresses writes inside the envelope. '
             '`envelope_state_review` also keeps writes that change any parameter compared with the previous observed write.', '',
             '## Dataset Checks', '',
             f"- {report['attack_fraction']:.1%} of rows are attacks. {report['duplicate_rows_excluding_time_pct']}% of rows repeat "
             'another row apart from the timestamp, which is expected from cyclic polling.',
             f"- Best single-feature F1 (depth-3 tree, 5-fold CV): {report['single_feature_shortcut_probe_f1']}. "
             'Unlike ModbusRTUfeatureSetsV2, no single feature separates attacks from normal traffic.', '',
             '## Results', '',
             '| Split | Variant | Scope | TP | FP | FN | Precision | Recall | FPR |', '|---|---|---|---:|---:|---:|---:|---:|---:|']
    for split, data in report['splits'].items():
        for variant, result in data['variants'].items():
            for scope in ('all_requests', 'fc16_writes'):
                m = result[scope]
                lines.append(f"| {split} | {variant} | {scope} | {m['TP']} | {m['FP']} | {m['FN']} | "
                             f"{m['precision']:.4f} | {m['recall']:.4f} | {m['false_positive_rate']:.4f} |")
    lines += ['', '| Split | Variant | ' + ' | '.join(c for c in CATEGORIES.values() if c != 'Normal') + ' |',
              '|---|---|' + '---:|' * (len(CATEGORIES) - 1)]
    for split, data in report['splits'].items():
        for variant, result in data['variants'].items():
            lines.append(f'| {split} | {variant} | ' + ' | '.join(
                f"{result['recall_by_category'][c]:.3f}" if c in result['recall_by_category'] else 'n/a'
                for c in CATEGORIES.values() if c != 'Normal') + ' |')
    test = report['splits']['test']['variants']
    lines += ['', 'NMRI and CMRI are response injections, so they fall outside this request-only experiment. '
              'No behaviour rule covers the MFCI invalid function codes, and the context never changes the Recon rules.', '',
              '## C++ Processing', '',
              '| Test variant | p50 ms | p95 ms | p99 ms |', '|---|---:|---:|---:|']
    lines += [f"| {v} | {t['processing_ms']['p50']:.4f} | {t['processing_ms']['p95']:.4f} | {t['processing_ms']['p99']:.4f} |"
              for v, t in test.items()]
    lines += ['', 'These timers cover per-event detection and context evaluation in batch mode. They exclude JSON loading, '
              'output writes and process startup, and they are a single-host measurement.', '',
              '## Limits', '',
              '- MSCI (state command injection) and DoS writes use parameter values that operators also use. '
              'A value envelope therefore cannot separate them. Serial Modbus RTU carries no authenticated source, '
              'so separating them needs host, operator or physical-process evidence.',
              '- State-change review recovers part of MSCI at the cost of FPs on legitimate operator changes. '
              'Report both variants rather than one number.',
              '- This is one laboratory testbed with one time split. The envelope is learned, not a real commissioning '
              'record, and the results are not a production false-alarm rate.']
    Path(f'{args.report}.md').write_text('\n'.join(lines) + '\n', encoding='utf-8')
    print('\n'.join(lines))


if __name__ == '__main__':
    main()
