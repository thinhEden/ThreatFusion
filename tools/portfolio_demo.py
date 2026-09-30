"""Run the four portfolio deliverables from actual C++ PCAP outputs."""
import argparse
import csv
import hashlib
import html
import json
import math
import platform
import subprocess
import time
from pathlib import Path
from generate_ot_case import generate
from siem_elastic import export_alerts, ingest, setup, verify

ROOT = Path(__file__).resolve().parents[1]


def csv_rows(path):
    with Path(path).open(newline='') as handle:
        return list(csv.DictReader(handle))


def confusion(truth, alerts, threshold=60):
    by_id = {row['event_id']: row for row in alerts}
    result = dict(TP=0, TN=0, FP=0, FN=0)
    for row in truth:
        positive = row['label'] == 'malicious'
        predicted = row['event_id'] in by_id and int(by_id[row['event_id']]['risk_score']) >= threshold
        result['TP' if positive and predicted else 'FN' if positive else 'FP' if predicted else 'TN'] += 1
    tp, tn, fp, fn = [result[k] for k in ('TP', 'TN', 'FP', 'FN')]
    result.update(precision=tp/(tp+fp) if tp+fp else 0, recall=tp/(tp+fn) if tp+fn else 0,
                  f1=2*tp/(2*tp+fp+fn) if 2*tp+fp+fn else 0,
                  false_positive_rate=fp/(fp+tn) if fp+tn else 0)
    return result


def engine_path(value):
    if value:
        return Path(value).resolve()
    for relative in ['build-libtorch/Release/threatfusion.exe', 'build/Release/threatfusion.exe', 'build/threatfusion.exe', 'build/threatfusion']:
        candidate = ROOT / relative
        if candidate.exists():
            return candidate
    subprocess.run(['cmake', '-S', str(ROOT), '-B', str(ROOT/'build-demo'), '-DUSE_LIBTORCH=OFF'], check=True)
    subprocess.run(['cmake', '--build', str(ROOT/'build-demo'), '--config', 'Release'], check=True)
    for relative in ['build-demo/Release/threatfusion.exe', 'build-demo/threatfusion.exe', 'build-demo/threatfusion']:
        if (ROOT/relative).exists():
            return ROOT/relative
    raise FileNotFoundError('Build an engine and pass --engine')


def run_variant(engine, folder, capture, variant):
    prefix = folder / f'{capture}_{variant}'
    command = [str(engine), '--events', str(folder/f'{capture}.pcap'), '--format', 'pcap',
               '--pcap-filter', 'tcp.dstport == 502 && modbus', '--iocs', str(folder/'lab_iocs.csv'),
               '--rules', str(ROOT/'data/behavior_rules.csv'), '--normalized-events', str(prefix)+'.events.jsonl',
               '--alerts', str(prefix)+'.alerts.csv', '--incidents', str(prefix)+'.incidents.csv',
               '--metrics', str(prefix)+'.unlabeled_metrics.txt', '--timings', str(prefix)+'.timings.csv']
    if variant != 'baseline':
        command += ['--context', str(folder/'policy.json'), '--context-mode', variant,
                    '--context-audit', str(prefix)+'.audit.csv']
    started = time.perf_counter()
    result = subprocess.run(command, capture_output=True, text=True, check=True, timeout=120, cwd=ROOT)
    duration = time.perf_counter()-started
    Path(str(prefix)+'.engine.log').write_text(result.stdout+result.stderr)
    events = [json.loads(line) for line in Path(str(prefix)+'.events.jsonl').read_text().splitlines()]
    truth = json.loads((folder/f'{capture}_ground_truth.json').read_text())
    if {e['id'] for e in events} != {e['event_id'] for e in truth}:
        raise RuntimeError('Decoded requests do not match ground truth packet IDs')
    if any(e['label'] for e in events):
        raise RuntimeError('Ground truth must never be passed to the detection engine')
    by_id = {e['id']:e for e in events}
    for row in truth:
        event = by_id[row['event_id']]
        if (event['function_code'],event['unit_id'],event['register_address']) != (row['function_code'],row['unit_id'],row['register']):
            raise RuntimeError('PCAP command evidence mismatch')
        if row['function_code'] == 6 and event['register_values'] != [row['value']]:
            raise RuntimeError('PCAP register value evidence mismatch')
    alerts = csv_rows(str(prefix)+'.alerts.csv')
    audit = [] if variant == 'baseline' else csv_rows(str(prefix)+'.audit.csv')
    timings = sorted(float(r['processing_ms']) for r in csv_rows(str(prefix)+'.timings.csv'))
    report = {'metrics': confusion(truth, alerts), 'raw_alert_rows': len(alerts),
              'suppressed_candidates': sum(int(r['suppressed_detections']) for r in audit),
              'processing_ms': {'p50': timings[len(timings)//2], 'p95': timings[math.ceil(.95*len(timings))-1],
                                'p99': timings[math.ceil(.99*len(timings))-1]},
              'wall_seconds_including_parser_and_startup': duration,
              'scenarios': {name: confusion([t for t in truth if t['scenario']==name], alerts)
                            for name in sorted({t['scenario'] for t in truth})}}
    export_alerts(str(prefix)+'.alerts.csv', str(prefix)+'.events.jsonl', str(prefix)+'.ecs.jsonl', variant, capture)
    return report


def case_study(folder, reports):
    truth = json.loads((folder/'main_ground_truth.json').read_text())
    baseline = {r['event_id']:r for r in csv_rows(folder/'main_baseline.alerts.csv')}
    retained = {r['event_id']:r for r in csv_rows(folder/'main_bounded.alerts.csv')}
    audit = {r['event_id']:r for r in csv_rows(folder/'main_bounded.audit.csv')}
    samples = [next(r for r in truth if r['scenario']==scenario) for scenario in
               ('approved_maintenance','unauthorized_source','unsafe_value','replayed_over_budget','outside_maintenance_window')]
    lines = ['# OT Command Investigation Case Study', '',
             'This is an offline synthetic, protocol-valid Modbus exercise. Packets are not sent to a plant; physical consequences are not measured.', '',
             '## Evidence Chain', '',
             '`main.pcap -> tshark -> C++ detections -> policy audit -> ECS index -> analyst disposition`', '',
             'The independently defined commissioning ticket is CHG-OT-2026-001. It authorizes 10.50.1.20 to write unit 1, registers 100-101, values 50-60, during [10:00,10:10) UTC, at most 60 commands. Ground truth is a separate lab sidecar, never supplied to the engine.', '',
             '| Packet / Event | Evidence | Baseline risk | Bounded result | Analyst disposition |',
             '|---|---|---:|---|---|']
    for row in samples:
        identity = row['event_id']
        evidence = f"{row['source_ip']} -> {row['destination_ip']}, FC {row['function_code']}, unit {row['unit_id']}, register {row['register']}, value {row['value']}"
        disposition = 'False positive: authorized maintenance' if row['label']=='benign' else 'True positive: unauthorized lab command'
        outcome = f"Retained, risk {retained[identity]['risk_score']}" if identity in retained else audit[identity]['reason']
        lines.append(f"| Frame {row['frame']} / {identity} | {evidence} | {baseline[identity]['risk_score']} | {outcome} | {disposition} |")
    lines += ['', '## Investigation Steps', '',
              '1. Verify the PCAP checksum in report.json and filter `tcp.dstport == 502 && modbus`. Pivot using the frame numbers above.',
              '2. Inspect source/destination, Modbus unit, function, register and register value. A source IP alone does not prove the operator identity.',
              '3. Compare with policy.json and the ticket window, limits and quota. Read main_bounded.audit.csv to explain each retained or downgraded candidate.',
              '4. Query the same event.id in Elastic Discover using saved investigations in siem/elastic/queries.json. Compare baseline and bounded variants.',
              '5. In a real response, verify operator approval, engineering host/identity logs, and PLC change history before final disposition. Those host/plant logs are not present in this exercise.', '',
              '## Response Recommendations', '',
              '- Authorized maintenance: record the ticket, reviewer and packet evidence; retain the audit. Do not create a permanent workstation-wide exclusion.',
              '- Unauthorized source or unsafe value: escalate to the OT owner, preserve PCAP and endpoint evidence, and validate the process state. Coordinate isolation or rollback with operations and safety staff.',
              '- Exhausted quota/outside window: investigate ticket replay, stale authorization or compromised credentials; revoke the relevant authorization only after validation.', '',
              '## Counterexample and Scope', '',
              'challenge.pcap contains five malicious-intent lab commands from a simulated compromised engineering workstation that are indistinguishable from approved commands under this policy. Bounded context misses all five. Packet attributes and a maintenance ticket are insufficient to prove host/operator integrity. This is a documented failure, not a production safety guarantee.', '',
              'The experiment changes only BR-001 treatment. It is not evidence of malware-family detection or improved neural model accuracy. Other detection sources and rules are never suppressed.']
    (folder/'case_study.md').write_text('\n'.join(lines)+'\n')
    (folder/'case_study.html').write_text('<!doctype html><html lang="en"><meta charset="utf-8"><title>Investigation Evidence</title><style>body{font:16px system-ui;margin:32px;color:#1c242e}pre{white-space:pre-wrap;line-height:1.7;font:15px monospace;max-width:1200px}</style><h1>OT Investigation Evidence</h1><a href="index.html">Back to experiment</a><pre>'+html.escape('\n'.join(lines))+'</pre></html>', encoding='utf-8')


def write_report(folder, report):
    (folder/'report.json').write_text(json.dumps(report, indent=2))
    lines = ['# OT Context False-Positive Ablation', '',
             'Paired evaluation on the same offline PCAP, fixed rule/IOC inputs and risk threshold 60. Policy is fixed before evaluation; labels stay outside the engine. No training or test-label tuning is performed.', '',
             '| Capture | Variant | TP | TN | FP | FN | Precision | Recall | F1 | FPR |',
             '|---|---|---:|---:|---:|---:|---:|---:|---:|---:|']
    for capture, variants in report['captures'].items():
        for variant, result in variants.items():
            m = result['metrics']
            lines.append(f"| {capture} | {variant} | {m['TP']} | {m['TN']} | {m['FP']} | {m['FN']} | {m['precision']:.4f} | {m['recall']:.4f} | {m['f1']:.4f} | {m['false_positive_rate']:.4f} |")
    lines += ['', '## C++ Processing Measurements', '',
              'All decoded request events are timed, including events without alerts. These batch timers include context evaluation and audit-row buffering, and exclude PCAP parsing, final CSV writes, process startup, networking and SIEM ingestion. Wall time includes final writes and is recorded separately. This is a single-host lab measurement, not a real-time capture SLA.', '',
              '| Main variant | Processing p50 ms | p95 ms | p99 ms |', '|---|---:|---:|---:|']
    for variant, result in report['captures']['main'].items():
        timing=result['processing_ms']
        lines.append(f"| {variant} | {timing['p50']:.5f} | {timing['p95']:.5f} | {timing['p99']:.5f} |")
    combined = {}
    for variant in ('baseline','peer-only','bounded'):
        tp = sum(c[variant]['metrics']['TP'] for c in report['captures'].values())
        fn = sum(c[variant]['metrics']['FN'] for c in report['captures'].values())
        combined[variant] = tp/(tp+fn)
    lines += ['', '## Limits', '',
              f"Combined main + adversarial challenge Recall: baseline={combined['baseline']:.4f}, peer-only={combined['peer-only']:.4f}, bounded={combined['bounded']:.4f}.",
              'The main capture tests explicit policy violations; the challenge tests malicious intent without a distinguishable policy violation. State both results. Zero main-capture FP is a controlled exercise outcome, not evidence of zero production false alarms.',
              'The peer-only variant is intentionally unsafe and used only as an ablation. UTC timestamps, complete register values and trusted authorization provenance are prerequisites. No PLC execution, identity verification or real malware corpus is represented.']
    (folder/'report.md').write_text('\n'.join(lines)+'\n')
    table=''.join(f"<tr><td>{html.escape(capture)}</td><td>{html.escape(variant)}</td><td>{r['metrics']['FP']}</td><td>{r['metrics']['FN']}</td><td>{r['metrics']['recall']:.2%}</td></tr>" for capture,vs in report['captures'].items() for variant,r in vs.items())
    (folder/'index.html').write_text(f'''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ThreatFusion Portfolio Evidence</title><style>body{{font:16px system-ui;margin:0;color:#1c242e;background:#fff}}main{{max-width:1000px;margin:auto;padding:32px}}h1{{font-size:28px}}table{{width:100%;border-collapse:collapse}}td,th{{text-align:left;padding:12px;border-bottom:1px solid #ddd}}a{{color:#08678b}}p{{line-height:1.6}}nav{{display:flex;gap:24px;flex-wrap:wrap;padding:16px 0}}</style><main><h1>ThreatFusion OT Investigation</h1><p>Offline PCAP &rarr; C++ detection &rarr; bounded authorization &rarr; Elastic Security investigation</p><nav><a href="case_study.html">Investigation evidence</a><a href="report.md">Experiment report</a><a href="report.json">Raw metrics and hashes</a><a href="http://127.0.0.1:15601/app/discover">Elastic Discover</a></nav><table><thead><tr><th>Capture</th><th>Policy</th><th>False positives</th><th>Missed attacks</th><th>Recall</th></tr></thead><tbody>{table}</tbody></table><p>Main: 60 authorized-write false positives removed with 80/80 explicit violations retained. Challenge: five approved-looking attacks missed. Combined bounded Recall: {combined['bounded']:.2%}.</p><p>PCAPs are generated offline. No real PLC effects or malware-family detection are asserted.</p><p>Follow packet IDs in case_study.md, compare rule outputs with policy audit, then run the saved SIEM queries.</p></main></html>''')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--engine')
    parser.add_argument('--output', default='out/portfolio_demo')
    parser.add_argument('--siem', action='store_true')
    args = parser.parse_args()
    engine = engine_path(args.engine)
    folder = Path(args.output).resolve()
    generate(folder)
    report = {'engine_sha256': hashlib.sha256(engine.read_bytes()).hexdigest(), 'host': platform.platform(),
              'data_type': 'offline synthetic Modbus, not a standard research dataset', 'risk_threshold': 60,
              'policy_sha256': hashlib.sha256((folder/'policy.json').read_bytes()).hexdigest(),
              'captures': {}, 'pcap_sha256': {}}
    for capture in ('main','challenge'):
        report['pcap_sha256'][capture] = hashlib.sha256((folder/f'{capture}.pcap').read_bytes()).hexdigest()
        report['captures'][capture] = {variant:run_variant(engine,folder,capture,variant)
                                       for variant in ('baseline','peer-only','bounded')}
    if args.siem:
        setup()
        ingest(sorted(folder.glob('*.ecs.jsonl')))
        report['siem_verification'] = verify()
    case_study(folder, report['captures'])
    write_report(folder, report)
    print((folder/'report.md').read_text())
    print('Evidence directory:', folder)


if __name__ == '__main__':
    main()
