"""Isolation Forest and LSTM autoencoder on MSU New Gas Pipeline 2015, scored by the C++ engine.

Question: on a capture without single-feature shortcuts, what does anomaly detection find that simple
baselines and the OT operating envelope miss, and does the envelope help or hurt it?

Protocol: the same 60/20/20 time split as benchmark_gas2015.py. The feature scaler, the Isolation Forest
and the LSTM autoencoder see benign-labelled training packets only. Every detector threshold is fixed at a
target FPR on benign validation packets; the test window is scored once. Each seed retrains both models.
Rule variants and the envelope come from the engine; the AI + context combinations are decision-level unions
or gates computed here from those engine outputs, not from the engine's risk scorer.
"""
import argparse
import csv
import hashlib
import json
import math
import subprocess
import sys
from collections import Counter
from pathlib import Path
import numpy as np
from benchmark_gas2015 import ENUMERATED, VARIANTS, confusion, derive_envelope, run_variant
from normalize_gas2015 import CATEGORIES, CONTROL, is_command, read_arff, to_event, to_truth
from train_lstm_autoencoder import train_model

ROOT = Path(__file__).resolve().parents[1]
SCALED = CONTROL + ['pressure measurement', 'crc rate', 'address']
CLIP = (-2.0, 3.0)
DETECTORS = ('isolation_forest', 'lstm', 'hybrid')


def fit_scaler(rows):
    """Min-max ranges from benign training packets; inter-arrival is log-scaled first."""
    scaler = {}
    for field in SCALED:
        values = [r[field] for r in rows if r[field] is not None]
        scaler[field] = (min(values), max(values))
    gaps = [r['_gap'] for r in rows]
    scaler['_gap'] = (min(gaps), max(gaps))
    return scaler


def scale(value, bounds):
    low, high = bounds
    span = high - low if high > low else max(abs(low), 1.0)
    return float(np.clip((value - low) / span, *CLIP))


def features(row, scaler):
    """16 process and timing features appended to the engine's 7 packet features. Missing fields are 0,
    with presence flags so a missing value is not confused with the benign minimum."""
    values = [scale(row[f], scaler[f]) if row[f] is not None else 0.0 for f in CONTROL + ['pressure measurement']]
    values += [float(row['setpoint'] is not None), float(row['pressure measurement'] is not None),
               scale(row['crc rate'], scaler['crc rate']), scale(row['address'], scaler['address']),
               scale(row['_gap'], scaler['_gap'])]
    return values


def range_rule(train, rows):
    """Parameter-free novelty baseline: unseen function code, (function, length) or address, or any
    process value outside its benign training range (value set for enumerated parameters).
    Returns the flags and, per packet, the fields that triggered."""
    seen_function = {(r['command response'], r['function']) for r in train}
    seen_length = {(r['command response'], r['function'], r['length']) for r in train}
    seen_address = {r['address'] for r in train}
    sets = {f: {r[f] for r in train if r[f] is not None} for f in ENUMERATED}
    ranges = {f: (min(v), max(v)) for f in SCALED if f != 'address' and f not in ENUMERATED
              for v in [[r[f] for r in train if r[f] is not None]]}
    reasons = []
    for r in rows:
        fired = [name for name, novel in (
            ('function', (r['command response'], r['function']) not in seen_function),
            ('length', (r['command response'], r['function'], r['length']) not in seen_length),
            ('address', r['address'] not in seen_address)) if novel]
        fired += [f for f, s in sets.items() if r[f] is not None and r[f] not in s]
        fired += [f for f, (lo, hi) in ranges.items() if r[f] is not None and not lo <= r[f] <= hi]
        reasons.append(fired)
    return np.array([bool(f) for f in reasons]), reasons


def state_rule(train, rows):
    """FC16 write whose (mode, scheme, pump, solenoid) combination never occurs in benign training writes."""
    seen = {tuple(r[f] for f in ENUMERATED) for r in train if is_command(r) and r['function'] == 16}
    return np.array([is_command(r) and r['function'] == 16 and tuple(r[f] for f in ENUMERATED) not in seen for r in rows])


def rankdata(a):
    sorter = np.argsort(a, kind='mergesort')
    inverse = np.empty_like(sorter)
    inverse[sorter] = np.arange(len(a))
    ordered = a[sorter]
    distinct = np.r_[True, ordered[1:] != ordered[:-1]]
    dense = distinct.cumsum()[inverse]
    count = np.r_[np.nonzero(distinct)[0], len(distinct)]
    return .5 * (count[dense] + count[dense - 1] + 1)


def roc_auc(y, score):
    positives, negatives = int(y.sum()), int((~y).sum())
    if not positives or not negatives:
        return None
    return float((rankdata(score)[y].sum() - positives * (positives + 1) / 2) / (positives * negatives))


def average_precision(y, score):
    order = np.argsort(-score, kind='mergesort')
    ordered, hits = score[order], y[order]
    last = np.r_[np.nonzero(np.diff(ordered))[0], len(ordered) - 1]
    tps = np.cumsum(hits)[last]
    if not tps[-1]:
        return None
    precision, recall = tps / (last + 1), tps / tps[-1]
    return float(np.sum(np.diff(np.r_[0, recall]) * precision))


def metrics(truth, flags):
    return confusion(truth, {t['event_id'] for t, f in zip(truth, flags) if f})


def recall_by_category(truth, flags):
    result = {}
    for category in CATEGORIES.values():
        hits = [f for t, f in zip(truth, flags) if t['category'] == category]
        if category != 'Normal' and hits:
            result[category] = round(float(np.mean(hits)), 4)
    return result


def run_models(engine, folder, seed, split):
    prefix = folder / f'{split}_seed{seed}'
    command = [str(engine), '--events', str(folder / f'{split}.events.jsonl'), '--format', 'jsonl',
               '--baseline', str(folder / 'train.jsonl'), '--baseline-format', 'jsonl', '--if-seed', str(seed),
               '--lstm', str(folder / f'lstm_seed{seed}.pt'), '--scores', f'{prefix}.scores.csv',
               '--rules', str(ROOT / 'data/behavior_rules.csv'), '--iocs', str(ROOT / 'data/iocs.csv'),
               '--alerts', f'{prefix}.alerts.csv', '--incidents', f'{prefix}.incidents.csv',
               '--metrics', f'{prefix}.unlabeled_metrics.txt', '--timings', f'{prefix}.timings.csv']
    result = subprocess.run(command, capture_output=True, text=True, check=True, timeout=3600, cwd=ROOT)
    Path(f'{prefix}.engine.log').write_text(result.stdout + result.stderr, encoding='utf-8')
    if 'Loaded TorchScript model' not in result.stdout:
        raise RuntimeError('This benchmark requires real LibTorch inference in the C++ engine')
    with open(f'{prefix}.scores.csv', newline='', encoding='utf-8') as handle:
        rows = list(csv.DictReader(handle))
    with open(f'{prefix}.timings.csv', newline='', encoding='utf-8') as handle:
        timings = sorted(float(r['processing_ms']) for r in csv.DictReader(handle))
    loss = np.array([float(r['lstm_error']) if r['lstm_error'] else np.nan for r in rows])
    return ([r['event_id'] for r in rows], np.array([float(r['if_score']) for r in rows]), loss,
            {q: timings[max(0, math.ceil(p * len(timings)) - 1)] for q, p in (('p50', .5), ('p95', .95), ('p99', .99))})


def calibrate(truth, if_score, loss, fpr, if_weight):
    """Thresholds from benign validation packets only. LSTM warm-up packets (no full window) score lowest."""
    benign = np.array([t['label'] == 'benign' for t in truth])
    valid = benign & np.isfinite(loss)
    loss_scale = max(float(np.quantile(loss[valid], 1 - fpr)), 1e-12)
    hybrid = if_weight * if_score + (1 - if_weight) * np.nan_to_num(loss / loss_scale)
    return {'isolation_forest': float(np.quantile(if_score[benign], 1 - fpr)), 'lstm': loss_scale,
            'hybrid': float(np.quantile(hybrid[valid], 1 - fpr)), 'loss_scale': loss_scale, 'if_weight': if_weight}


def scores(if_score, loss, calibration):
    finite = np.isfinite(loss)
    hybrid = calibration['if_weight'] * if_score + (1 - calibration['if_weight']) * np.nan_to_num(loss / calibration['loss_scale'])
    return {'isolation_forest': if_score, 'lstm': np.where(finite, loss, -np.inf), 'hybrid': np.where(finite, hybrid, -np.inf)}


def summarize(values):
    values = [v for v in values if v is not None]
    return {'mean': float(np.mean(values)), 'std': float(np.std(values)), 'min': float(np.min(values)),
            'max': float(np.max(values))} if values else None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--engine', required=True)
    parser.add_argument('--dataset', default='datasets/MSU_ICS/GasPipeline2015/IanArffDataset.arff')
    parser.add_argument('--output', default='out/benchmark_gas2015_ai')
    parser.add_argument('--report', default='docs/benchmarks/gas2015_ai_report')
    parser.add_argument('--seeds', default='1337,2024,7')
    parser.add_argument('--epochs', type=int, default=5)
    parser.add_argument('--window', type=int, default=10)
    parser.add_argument('--fpr', type=float, default=.01)
    parser.add_argument('--if-weight', type=float, default=.5)
    parser.add_argument('--threshold', type=int, default=60)
    args = parser.parse_args()
    seeds = [int(s) for s in args.seeds.split(',')]
    if not 0 < args.fpr < 1 or not 0 <= args.if_weight <= 1 or args.epochs < 1 or args.window < 1 or not seeds:
        parser.error('Invalid benchmark parameters')
    folder = Path(args.output).resolve()
    folder.mkdir(parents=True, exist_ok=True)
    dataset, engine = Path(args.dataset).resolve(), Path(args.engine).resolve()

    rows = list(read_arff(dataset))
    times = np.array([r['time'] for r in rows])
    if np.any(np.diff(times) < 0):
        raise ValueError('Capture timestamps must be non-decreasing')
    for r, gap in zip(rows, np.log1p(np.diff(times, prepend=times[0]))):
        r['_gap'] = float(gap)
    start, end = float(times[0]), float(times[-1])
    cut_train, cut_test = start + .6 * (end - start), start + .8 * (end - start)
    train = [r for r in rows if r['time'] < cut_train]
    benign_train = [r for r in train if r['binary result'] == 0]
    scaler = fit_scaler(benign_train)
    indexed = list(enumerate(rows, 1))
    splits = {'validation': [(i, r) for i, r in indexed if cut_train <= r['time'] < cut_test],
              'test': [(i, r) for i, r in indexed if r['time'] >= cut_test]}

    def event(index, row, labelled):
        e = to_event(row, index)
        e['extra_features'] = features(row, scaler)
        if labelled:
            e['label'] = 'malicious' if row['binary result'] == 1 else 'benign'
        return e

    with (folder / 'train.jsonl').open('w', encoding='utf-8') as handle:
        for i, r in indexed:
            if r['time'] < cut_train:
                handle.write(json.dumps(event(i, r, True), separators=(',', ':')) + '\n')
    truth = {}
    for split, pairs in splits.items():
        with (folder / f'{split}.events.jsonl').open('w', encoding='utf-8') as handle:
            for i, r in pairs:
                handle.write(json.dumps(event(i, r, False), separators=(',', ':')) + '\n')
        truth[split] = [to_truth(r, i) for i, r in pairs]
    train_events = [json.loads(line) for line in (folder / 'train.jsonl').open(encoding='utf-8')]
    train_writes = [r for r in benign_train if is_command(r) and r['function'] == 16]
    for variant, retain in VARIANTS.items():
        if retain is not None:
            (folder / f'policy_{variant}.json').write_text(json.dumps(derive_envelope(train_writes, retain), indent=2))

    # Engine rule variants (seed-independent). Envelope suppressions become the gate for "AI inside context".
    rules = {}
    for variant in VARIANTS:
        flagged, _, _ = run_variant(engine, folder, 'test', variant, args.threshold)
        rules[variant] = np.array([t['event_id'] in flagged for t in truth['test']])
    with open(folder / 'test_envelope.audit.csv', newline='', encoding='utf-8') as handle:
        in_envelope = {r['event_id'] for r in csv.DictReader(handle) if int(r['suppressed_detections'])}
    gate = np.array([t['event_id'] in in_envelope for t in truth['test']])
    rows_by_split = {s: [r for _, r in pairs] for s, pairs in splits.items()}
    novelty = {s: range_rule(benign_train, rows_by_split[s]) for s in splits}
    states = {s: state_rule(benign_train, rows_by_split[s]) for s in splits}

    test_truth = truth['test']
    y = np.array([t['label'] == 'malicious' for t in test_truth])
    requests = np.array([is_command(r) for r in rows_by_split['test']])
    scopes = {'all_packets': np.ones(len(test_truth), dtype=bool), 'requests': requests}
    per_seed = []
    for seed in seeds:
        print(f'seed {seed}: training LSTM autoencoder', flush=True)
        training = train_model(train_events, folder / f'lstm_seed{seed}.pt', args.epochs, args.window, seed=seed)
        _, val_if, val_loss, _ = run_models(engine, folder, seed, 'validation')
        ids, test_if, test_loss, timing = run_models(engine, folder, seed, 'test')
        if ids != [t['event_id'] for t in test_truth]:
            raise ValueError('Engine score order does not match the test split')
        calibration = calibrate(truth['validation'], val_if, val_loss, args.fpr, args.if_weight)
        raw = scores(test_if, test_loss, calibration)
        flags = {name: raw[name] > calibration[name] for name in DETECTORS}
        flags.update({'envelope+' + name: rules['envelope'] | flags[name] for name in DETECTORS})
        flags.update({'envelope_state_review+' + name: rules['envelope_state_review'] | flags[name] for name in DETECTORS})
        flags.update({name + '_gated_by_envelope': flags[name] & ~gate for name in DETECTORS})
        result = {'seed': seed, 'training': training, 'calibration': calibration, 'processing_ms': timing,
                  'threshold_free': {name: {'roc_auc': roc_auc(y, raw[name]), 'average_precision': average_precision(y, raw[name])}
                                     for name in DETECTORS},
                  'scopes': {}}
        for scope, mask in scopes.items():
            scoped = [t for t, m in zip(test_truth, mask) if m]
            result['scopes'][scope] = {name: {**metrics(scoped, f[mask]), 'recall_by_category': recall_by_category(scoped, f[mask])}
                                       for name, f in flags.items()}
        per_seed.append(result)

    simple = {'range_rule': novelty['test'][0], 'state_rule': states['test'],
              'range_rule+state_rule': novelty['test'][0] | states['test']}
    fixed = {**simple, **rules, 'envelope+state_rule': rules['envelope'] | states['test'],
             'envelope+range_rule+state_rule': rules['envelope'] | simple['range_rule+state_rule']}
    reference = {}
    for scope, mask in scopes.items():
        scoped = [t for t, m in zip(test_truth, mask) if m]
        reference[scope] = {name: {**metrics(scoped, f[mask]), 'recall_by_category': recall_by_category(scoped, f[mask])}
                            for name, f in fixed.items() if scope == 'requests' or name in simple}
    reasons = {}
    for t, fired in zip(test_truth, novelty['test'][1]):
        for field in fired:
            reasons.setdefault(t['category'], Counter())[field] += 1
    validation_benign = np.array([t['label'] == 'benign' for t in truth['validation']])
    report = {
        'question': 'What does anomaly detection add over simple baselines and the OT operating envelope?',
        'source': 'http://www.ece.uah.edu/~thm0009/icsdatasets/IanArffDataset.arff',
        'sha256': hashlib.sha256(dataset.read_bytes()).hexdigest(),
        'engine_sha256': hashlib.sha256(engine.read_bytes()).hexdigest(),
        'command': sys.argv, 'seeds': seeds, 'target_validation_fpr': args.fpr, 'epochs': args.epochs, 'window': args.window,
        'feature_count': 7 + len(train_events[0]['extra_features']),
        'split_packets': {'train': len(train), 'train_benign': len(benign_train),
                          **{s: len(p) for s, p in splits.items()}},
        'test_labels': dict(Counter(t['category'] for t in test_truth)),
        'validation_fpr': {'range_rule': float(np.mean(novelty['validation'][0][validation_benign])),
                           'state_rule': float(np.mean(states['validation'][validation_benign]))},
        'range_rule_fields_by_category': {c: dict(v.most_common()) for c, v in sorted(reasons.items())},
        'zero_variance_training_parameters': [f for f in SCALED if scaler[f][0] == scaler[f][1]],
        'reference': reference,
        'summary': {scope: {name: {k: summarize([r['scopes'][scope][name][k] for r in per_seed])
                                   for k in ('precision', 'recall', 'f1', 'false_positive_rate', 'FP', 'TP')}
                            for name in per_seed[0]['scopes'][scope]} for scope in scopes},
        'recall_by_category_mean': {scope: {name: {c: round(float(np.mean([r['scopes'][scope][name]['recall_by_category'][c] for r in per_seed])), 4)
                                                   for c in per_seed[0]['scopes'][scope][name]['recall_by_category']}
                                            for name in per_seed[0]['scopes'][scope]} for scope in scopes},
        'threshold_free_mean': {name: {k: summarize([r['threshold_free'][name][k] for r in per_seed]) for k in ('roc_auc', 'average_precision')}
                                for name in DETECTORS},
        'per_seed': per_seed,
    }
    Path(f'{args.report}.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    Path(f'{args.report}.md').write_text(render(report, args), encoding='utf-8')
    print(Path(f'{args.report}.md').read_text(encoding='utf-8'))


def render(report, args):
    attacks = [c for c in CATEGORIES.values() if c != 'Normal']

    def cell(stats, key, digits=3):
        s = stats[key]
        return f"{s['mean']:.{digits}f} ± {s['std']:.{digits}f}" if s['std'] else f"{s['mean']:.{digits}f}"

    def table(scope, names):
        lines = ['| Detector | TP | FP | Precision | Recall | FPR | ' + ' | '.join(attacks) + ' |',
                 '|---|---:|---:|---:|---:|---:|' + '---:|' * len(attacks)]
        for name in names:
            if name in report['reference'][scope]:
                m, per_category = report['reference'][scope][name], report['reference'][scope][name]['recall_by_category']
                values = [str(m['TP']), str(m['FP']), f"{m['precision']:.3f}", f"{m['recall']:.3f}", f"{m['false_positive_rate']:.4f}"]
            else:
                s, per_category = report['summary'][scope][name], report['recall_by_category_mean'][scope][name]
                values = [cell(s, 'TP', 0), cell(s, 'FP', 0), cell(s, 'precision'), cell(s, 'recall'), cell(s, 'false_positive_rate', 4)]
            lines.append(f'| {name} | ' + ' | '.join(values) + ' | ' +
                         ' | '.join(f"{per_category[c]:.3f}" if c in per_category else 'n/a' for c in attacks) + ' |')
        return lines

    seeds = ', '.join(map(str, report['seeds']))
    free = report['threshold_free_mean']
    fpr = report['validation_fpr']
    lines = ['# Anomaly Detection on MSU New Gas Pipeline 2015', '',
             f"Generated by `tools/benchmark_gas2015_ai.py`. Source: {report['source']} (SHA-256 `{report['sha256']}`).", '',
             '## Question', '',
             'The OT operating envelope removes every write false positive on this capture but misses state-command '
             'injection (MSCI) and DoS writes, because those use values operators also use ([context report](gas2015_context_report.md)). '
             'This experiment asks what anomaly detection adds on the same data, and whether the envelope helps or hurts it.', '',
             '## Findings', '']
    lines += [f'- {finding}' for finding in findings(report)]
    lines += ['', '## Protocol', '',
              f"- Same time split as the context experiment: 60% training ({report['split_packets']['train']:,} packets, "
              f"{report['split_packets']['train_benign']:,} benign), 20% validation ({report['split_packets']['validation']:,}) and "
              f"20% test ({report['split_packets']['test']:,}). Requests and responses are both scored.",
              "- Features: the engine's 7 packet features plus 16 process and timing features: 10 control parameters, "
              'pressure measurement, two presence flags, CRC rate, RTU address and log inter-arrival time. Min-max ranges come '
              'from benign training packets only. The feature set was fixed before the first run and not tuned on the test window.',
              '- Isolation Forest (C++, 100 trees, 256 samples) and the LSTM autoencoder (PyTorch training, TorchScript inference in C++, '
              f"window {report['window']}, {report['epochs']} epochs, flow key = source) train on benign training packets. The hybrid averages "
              'the IF score with the validation-scaled LSTM loss.',
              f"- Every AI threshold is set to a {report['target_validation_fpr']:.0%} FPR on benign validation packets. The test window is "
              f"scored once. Seeds {seeds} retrain both models; AI rows show mean ± standard deviation over seeds.",
              '- Simple baselines use the same benign training packets and have no tuned threshold. `range_rule` flags an unseen function '
              'code, function/length pair or address, or any process value outside its benign training range (value set for mode, scheme, '
              f"pump and solenoid); validation FPR {fpr['range_rule']:.4f}. `state_rule` flags an FC16 write whose (mode, scheme, pump, "
              f"solenoid) combination never occurs in benign training writes; validation FPR {fpr['state_rule']:.4f}.",
              '- `baseline`, `envelope` and `envelope_state_review` are the engine rule variants from the context experiment (requests only). '
              '`A+B` alerts when either A or B fires. `X_gated_by_envelope` drops X alerts on writes the envelope approves. '
              'These combinations are computed from the engine outputs, not by its risk scorer.', '',
              '## Threshold-Free Separation (test, all packets)', '',
              '| Detector | ROC-AUC | Average precision |', '|---|---:|---:|']
    lines += [f"| {name} | {cell(free[name], 'roc_auc')} | {cell(free[name], 'average_precision')} |" for name in DETECTORS]
    lines += ['', f'Attacks are {prevalence(report):.3f} of test packets, which is the average precision of a detector with no skill.', '',
              '## All Packets (test)', '']
    lines += table('all_packets', ['range_rule', 'state_rule', 'range_rule+state_rule', *DETECTORS])
    lines += ['', 'NMRI and CMRI are response injections, so they only appear in this table.', '',
              '## Requests Only: AI Next to the OT Context (test)', '']
    lines += table('requests', ['baseline', 'envelope', 'envelope_state_review', 'range_rule', 'state_rule', *DETECTORS,
                                'envelope+state_rule', 'envelope+range_rule+state_rule',
                                *[f'envelope+{d}' for d in DETECTORS], *[f'envelope_state_review+{d}' for d in DETECTORS],
                                *[f'{d}_gated_by_envelope' for d in DETECTORS]])
    lines += ['', '## Why the Range Rule Fires (test packets)', '',
              '| Category | Fields outside the benign training range (packet counts) |', '|---|---|']
    lines += [f"| {c} | {', '.join(f'{k} {v}' for k, v in fields.items())} |"
              for c, fields in report['range_rule_fields_by_category'].items()]
    zero = report['zero_variance_training_parameters']
    lines += ['', f"Parameters with a single value in benign training: {', '.join(zero) or 'none'}. Isolation Forest never splits "
              'on a feature that is constant in its sample, so an attack that changes only such a parameter does not shorten its '
              'path length. An exact range check sees it at once.', '',
              '## C++ Processing With Both Models (test window)', '',
              '| Seed | p50 ms | p95 ms | p99 ms |', '|---|---:|---:|---:|']
    lines += [f"| {r['seed']} | {r['processing_ms']['p50']:.4f} | {r['processing_ms']['p95']:.4f} | {r['processing_ms']['p99']:.4f} |"
              for r in report['per_seed']]
    lines += ['', 'Per-event detection time with rules, baseline, Isolation Forest and TorchScript LSTM inference in batch mode. '
              'See [the performance report](engine_performance.md) for throughput, CPU and memory.', '',
              '## Limits', '',
              '- One testbed and one time split. Seeds change model initialisation and sampling, not the data split.',
              '- Features and hyperparameters were fixed before the first run. Dropping constant or noisy features might help Isolation '
              'Forest, but choosing them on this test window would overfit; that needs a fresh split.',
              '- The range and state rules assume training covered every legitimate operating point. In a plant, a new setpoint or '
              'state combination after commissioning is a false positive until the baseline is updated through change control.',
              '- Labels are per packet from the dataset; the response to an attack command is labelled as an attack.',
              '- Combinations are decision-level unions or gates computed here. The engine risk scorer does not yet take calibrated '
              'AI thresholds, so these rows are not what the deployed engine alerts on.']
    return '\n'.join(lines) + '\n'


def prevalence(report):
    return sum(v for k, v in report['test_labels'].items() if k != 'Normal') / sum(report['test_labels'].values())


def findings(report):
    """Plain statements computed from the results, so a rerun cannot leave stale prose behind."""
    ref, summary, per_category = report['reference'], report['summary'], report['recall_by_category_mean']
    auc = {d: report['threshold_free_mean'][d]['roc_auc']['mean'] for d in DETECTORS}
    best = max(DETECTORS, key=lambda d: summary['all_packets'][d]['f1']['mean'])
    b, rules = summary['all_packets'][best], ref['all_packets']['range_rule+state_rule']
    result = [f"Separation is weak: mean test ROC-AUC is {min(auc.values()):.3f}-{max(auc.values()):.3f} across the three "
              f"detectors (0.5 is chance), and average precision stays close to the {prevalence(report):.3f} no-skill level.",
              f"At a {report['target_validation_fpr']:.0%} validation FPR the best AI detector ({best}) finds {b['recall']['mean']:.1%} "
              f"of attack packets with {b['FP']['mean']:.0f} false positives. The two simple rules together find "
              f"{rules['recall']:.1%} with {rules['FP']} false positives."]
    simple = ('range_rule', 'state_rule', 'range_rule+state_rule')
    gains = []
    for scope in ('all_packets', 'requests'):
        for category in ref[scope]['range_rule']['recall_by_category']:
            ai = max(per_category[scope][d].get(category, 0) for d in DETECTORS)
            floor = max(ref[scope][s]['recall_by_category'].get(category, 0) for s in simple)
            if ai > floor + .02 and category not in [c for _, c, _, _ in gains]:
                gains.append((scope, category, ai, floor))
    result.append('Attack categories where an AI detector beats every simple rule by more than 2 points: ' +
                  ('; '.join(f"{c} ({s.replace('_', ' ')}: {a:.1%} vs {f:.1%})" for s, c, a, f in gains) if gains else 'none') + '.')
    msci = {d: per_category['requests'][d].get('MSCI', 0) for d in DETECTORS}
    top = max(msci, key=msci.get)
    state = ref['requests']['state_rule']
    result.append(f"MSCI, the gap the envelope leaves: {top} recovers {msci[top]:.1%} of MSCI requests with "
                  f"{summary['requests'][top]['FP']['mean']:.0f} request false positives; the state-combination rule recovers "
                  f"{state['recall_by_category'].get('MSCI', 0):.1%} with {state['FP']}.")
    for d in DETECTORS:
        plain, gated = summary['requests'][d], summary['requests'][f'{d}_gated_by_envelope']
        result.append(f"Envelope as a gate on {d}: request false positives {plain['FP']['mean']:.0f} -> "
                      f"{gated['FP']['mean']:.0f}, recall {plain['recall']['mean']:.1%} -> {gated['recall']['mean']:.1%}.")
    combo = ref['requests']['envelope+range_rule+state_rule']
    ai_combo = max((f'envelope+{d}' for d in DETECTORS), key=lambda n: summary['requests'][n]['recall']['mean'])
    result.append(f"Best request-side combination without AI (envelope + range + state rules): recall {combo['recall']:.1%}, "
                  f"{combo['FP']} false positives. Best envelope + AI union ({ai_combo}): recall "
                  f"{summary['requests'][ai_combo]['recall']['mean']:.1%}, {summary['requests'][ai_combo]['FP']['mean']:.0f} false positives.")
    return result


if __name__ == '__main__':
    main()
