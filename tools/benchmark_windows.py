"""Evaluate the Windows EQL detections (siem/elastic/windows_rules.json) on OTRF datasets in Elasticsearch.

Every hit needs an analyst disposition in docs/benchmarks/windows_triage.csv. Unreviewed hits are
reported, so a rule change cannot silently add false positives. Ground truth is dataset-level: OTRF
publishes one ATT&CK mapping per capture, and each capture also contains background activity.
"""
import argparse
import csv
import hashlib
import json
from collections import Counter
from pathlib import Path
from attack_coverage import ENTERPRISE, TACTICS
from normalize_windows_events import read_zip
from siem_elastic import ES, KIBANA, api

ROOT = Path(__file__).resolve().parents[1]
INDEX = 'threatfusion-windows-otrf'
# attack_mappings from OTRF datasets/atomic/_metadata, read on 2026-09-30.
OTRF = {
    'psh_lsass_memory_dump_comsvcs': ('SDWIN-201018195009', 'T1003.001'),
    'empire_mimikatz_logonpasswords': ('SDWIN-190518202151', 'T1003.001'),
    'empire_schtasks_creation_standard_user': ('SDWIN-190319024742', 'T1053.005'),
    'empire_psexec_dcerpc_tcp_svcctl': ('SDWIN-190518210652', 'T1021'),
    'empire_launcher_vbs': ('SDWIN-190518182022', 'T1059.005'),
}
MAPPING = {'dynamic_templates': [{'strings': {'match_mapping_type': 'string',
                                               'mapping': {'type': 'keyword', 'ignore_above': 8191}}}],
           'properties': {'@timestamp': {'type': 'date'}, 'message': {'type': 'text'}}}


def bulk(index, documents):
    body = ''.join(json.dumps({'index': {'_index': index, '_id': d['event']['id']}}) + '\n' + json.dumps(d) + '\n'
                   for d in documents).encode()
    result = api(ES, '/_bulk', body, 'POST', 'application/x-ndjson')
    if result.get('errors'):
        failed = next(i['index'] for i in result['items'] if 'error' in i['index'])
        raise RuntimeError(f"Bulk indexing failed: {json.dumps(failed)[:500]}")


def ingest(zips, index):
    try:
        api(ES, f'/{index}', method='DELETE')
    except RuntimeError as error:
        if 'HTTP 404' not in str(error):
            raise
    api(ES, f'/{index}', {'settings': {'number_of_shards': 1, 'number_of_replicas': 0}, 'mappings': MAPPING}, 'PUT')
    for path in zips:
        batch = []
        for document in read_zip(path):
            batch.append(document)
            if len(batch) == 500:
                bulk(index, batch)
                batch = []
        if batch:
            bulk(index, batch)
    api(ES, f'/{index}/_refresh', method='POST')
    counts = api(ES, f'/{index}/_search', {'size': 0, 'aggs': {'d': {'terms': {'field': 'threatfusion.dataset', 'size': 50}}}})
    return {b['key']: b['doc_count'] for b in counts['aggregations']['d']['buckets']}


def evidence(source):
    data, process, code = source['winlog']['event_data'], source.get('process', {}), source['event']['code']
    if code == '10':
        detail = f"{data.get('SourceImage')} -> {data.get('TargetImage')} {data.get('GrantedAccess')}"
    else:
        detail = (process.get('command_line') or data.get('ImagePath') or data.get('ServiceFileName')
                  or data.get('TaskName') or '')
    parent = process.get('parent', {}).get('name')
    return ' '.join(filter(None, [code, source['host']['name'], parent and f'parent={parent}', detail[:160]]))


def evaluate(rules, index):
    hits = {}
    for rule in rules:
        result = api(ES, f'/{index}/_eql/search', {'query': rule['query'], 'size': 1000})
        hits[rule['id']] = [{'event_id': e['_source']['event']['id'], 'dataset': e['_source']['threatfusion']['dataset'],
                             'timestamp': e['_source']['@timestamp'], 'evidence': evidence(e['_source'])}
                            for e in result['hits'].get('events', [])]
    return hits


def threat_mapping(techniques):
    by_tactic = {}
    for technique in techniques:
        parent = technique.split('.')[0]
        entry = by_tactic.setdefault(ENTERPRISE[technique][1], {})
        item = entry.setdefault(parent, {'id': parent, 'name': ENTERPRISE[parent][0],
                                         'reference': f'https://attack.mitre.org/techniques/{parent}/', 'subtechnique': []})
        if '.' in technique:
            item['subtechnique'].append({'id': technique, 'name': ENTERPRISE[technique][0],
                                         'reference': f"https://attack.mitre.org/techniques/{technique.replace('.', '/')}/"})
    return [{'framework': 'MITRE ATT&CK',
             'tactic': {'id': tactic, 'name': TACTICS[tactic], 'reference': f'https://attack.mitre.org/tactics/{tactic}/'},
             'technique': list(techniques.values())} for tactic, techniques in by_tactic.items()]


def deploy(rules, index):
    """Create or replace the rules as native Elastic Security EQL detections over the lab index."""
    for rule in rules:
        rule_id = 'threatfusion-' + rule['id'].lower()
        try:
            api(KIBANA, '/api/detection_engine/rules?rule_id=' + rule_id, method='DELETE')
        except RuntimeError as error:
            if 'HTTP 404' not in str(error):
                raise
        api(KIBANA, '/api/detection_engine/rules', {
            'rule_id': rule_id, 'name': f"ThreatFusion {rule['id']} - {rule['name']}", 'description': rule['description'],
            'type': 'eql', 'language': 'eql', 'query': rule['query'], 'index': [index],
            'severity': rule['severity'], 'risk_score': rule['risk_score'], 'threat': threat_mapping(rule['techniques']),
            # OTRF captures date from 2020, so the lookback covers the recorded period.
            'enabled': True, 'interval': '5m', 'from': 'now-2500d', 'max_signals': 1000,
            'tags': ['ThreatFusion', 'Windows', 'OTRF lab data']}, 'POST')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--datasets', default=str(ROOT / 'datasets/Windows_OTRF'))
    parser.add_argument('--rules', default=str(ROOT / 'siem/elastic/windows_rules.json'))
    parser.add_argument('--triage', default=str(ROOT / 'docs/benchmarks/windows_triage.csv'))
    parser.add_argument('--report', default=str(ROOT / 'docs/benchmarks/windows_detection_report'))
    parser.add_argument('--index', default=INDEX)
    parser.add_argument('--deploy', action='store_true', help='Also create the rules in Elastic Security')
    args = parser.parse_args()
    rules = json.loads(Path(args.rules).read_text(encoding='utf-8'))
    zips = sorted(Path(args.datasets).glob('*.zip'))
    documents = ingest(zips, args.index)
    hits = evaluate(rules, args.index)
    triage = {}
    if Path(args.triage).exists():
        with Path(args.triage).open(newline='', encoding='utf-8') as handle:
            triage = {(r['rule_id'], r['event_id']): r for r in csv.DictReader(handle)}
    if args.deploy:
        deploy(rules, args.index)
    for rule_id, rule_hits in hits.items():
        for hit in rule_hits:
            hit['disposition'] = triage.get((rule_id, hit['event_id']), {}).get('disposition', 'UNREVIEWED')

    summary = {}
    for rule in rules:
        dispositions = Counter(triage.get((rule['id'], h['event_id']), {}).get('disposition', 'UNREVIEWED') for h in hits[rule['id']])
        reviewed = dispositions['TP'] + dispositions['FP']
        summary[rule['id']] = {'hits': len(hits[rule['id']]), 'TP': dispositions['TP'], 'FP': dispositions['FP'],
                               'unreviewed': dispositions['UNREVIEWED'],
                               'precision': dispositions['TP'] / reviewed if reviewed else None,
                               'datasets': dict(Counter(h['dataset'] for h in hits[rule['id']]))}
    coverage = {}
    for dataset, (otrf_id, technique) in OTRF.items():
        detected = sorted({r['id'] for r in rules for h in hits[r['id']] if h['dataset'] == dataset
                           and triage.get((r['id'], h['event_id']), {}).get('disposition') == 'TP'})
        exact = [r['id'] for r in rules if r['id'] in detected and technique in r['techniques']]
        coverage[dataset] = {'otrf_id': otrf_id, 'otrf_technique': technique, 'rules_with_tp': detected,
                             'rules_mapped_to_otrf_technique': exact}
    report = {'index': args.index, 'documents': documents,
              'dataset_sha256': {p.stem: hashlib.sha256(p.read_bytes()).hexdigest() for p in zips},
              'rules': summary, 'coverage': coverage, 'hits': hits}
    Path(f'{args.report}.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')

    lines = ['# Windows Detection Evaluation (OTRF Security-Datasets)', '',
             'Generated by `tools/benchmark_windows.py`. Six EQL rules from `siem/elastic/windows_rules.json` run on five OTRF '
             '[Security-Datasets](https://github.com/OTRF/Security-Datasets) captures (MIT licence) in Elasticsearch. '
             f"The captures hold {sum(documents.values()):,} events. Every hit is dispositioned by an analyst in "
             '[windows_triage.csv](windows_triage.csv).', '',
             '## Rules', '',
             '| Rule | Name | ATT&CK | Hits | TP | FP | Unreviewed | Precision |', '|---|---|---|---:|---:|---:|---:|---:|']
    for rule in rules:
        s = summary[rule['id']]
        precision = 'n/a' if s['precision'] is None else f"{s['precision']:.2f}"
        lines.append(f"| {rule['id']} | {rule['name']} | {', '.join(rule['techniques'])} | {s['hits']} | {s['TP']} | "
                     f"{s['FP']} | {s['unreviewed']} | {precision} |")
    lines += ['', 'Sysmon 1 and Security 4688 both record each process creation, so one process can produce two hits.', '',
              '## Expected False Positives in Production', '']
    lines += [f"- **{rule['id']}**: {rule['false_positives']}" for rule in rules]
    lines += ['', '## Coverage of OTRF Captures', '',
              '| Capture | OTRF ID | OTRF technique | Rules with true positives | Rule mapped to the OTRF technique |',
              '|---|---|---|---|---|']
    for dataset, c in coverage.items():
        lines.append(f"| `{dataset}` | {c['otrf_id']} | {c['otrf_technique']} | {', '.join(c['rules_with_tp']) or 'none'} | "
                     f"{', '.join(c['rules_mapped_to_otrf_technique']) or 'none'} |")
    lines += ['', '## Hits', '', '| Rule | Capture | Disposition | Evidence | Analyst reason |', '|---|---|---|---|---|']
    for rule in rules:
        for h in hits[rule['id']]:
            t = triage.get((rule['id'], h['event_id']), {})
            detail = h['evidence'].replace('|', '/')
            lines.append(f"| {rule['id']} | `{h['dataset']}` | {t.get('disposition', 'UNREVIEWED')} | `{detail}` | {t.get('reason', '')} |")
    lines += ['', '## Limits', '',
              '- Ground truth is per capture. OTRF gives one technique per capture, and each capture also contains normal background activity. '
              'Precision here is analyst-reviewed hits in these captures, not a false-positive rate on a production estate.',
              '- The captures come from one lab configuration (Sysmon and audit policy) recorded in 2020. '
              'Rules depending on 4688 command lines or Sysmon 10 need the same logging.',
              '- `empire_psexec_dcerpc_tcp_svcctl` is mapped by OTRF to T1021 Remote Services. WIN-004 detects the service-execution '
              'part (T1543.003, T1569.002), not the remote logon itself.',
              '- Brute force (4625) and Kerberoasting (4769) are not in these captures. Those rules remain untested.']
    Path(f'{args.report}.md').write_text('\n'.join(lines) + '\n', encoding='utf-8')
    print(json.dumps(summary, indent=1))


if __name__ == '__main__':
    main()
