"""Evaluate the Windows EQL and ES|QL detections (siem/elastic/windows_rules.json) in Elasticsearch.

Data: OTRF Security-Datasets zips (MIT, committed), EVTX-to-MITRE-Attack .evtx files (CC0, committed),
splunk/attack_data XML logs (Apache-2.0, committed) and EVTX-ATTACK-SAMPLES .evtx files (GPL-3.0, kept local;
rules without local samples are reported as not evaluated).

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
from normalize_windows_events import read_capture
from siem_elastic import ES, KIBANA, api

ROOT = Path(__file__).resolve().parents[1]
INDEX = 'threatfusion-windows-otrf'
# Capture -> (source, technique the source publishes for it). OTRF attack_mappings from datasets/atomic/_metadata,
# read on 2026-09-30; the other sources name the technique in their folder path, read on 2026-10-01.
# A technique outside the rules' scope marks a negative control.
CAPTURES = {
    'psh_lsass_memory_dump_comsvcs': ('OTRF SDWIN-201018195009', 'T1003.001'),
    'empire_mimikatz_logonpasswords': ('OTRF SDWIN-190518202151', 'T1003.001'),
    'empire_schtasks_creation_standard_user': ('OTRF SDWIN-190319024742', 'T1053.005'),
    'empire_psexec_dcerpc_tcp_svcctl': ('OTRF SDWIN-190518210652', 'T1021'),
    'empire_launcher_vbs': ('OTRF SDWIN-190518182022', 'T1059.005'),
    # EVTX-ATTACK-SAMPLES "Credential Access/kerberos_pwd_spray_4771.evtx"
    'kerberos_pwd_spray_4771': ('EVTX-ATTACK-SAMPLES', 'T1110.003'),
    'mdec_4769_kerberoast_low_encryption': ('EVTX-to-MITRE-Attack', 'T1558.003'),
    'mdec_4769_tgs_host_enumeration_bloodhound': ('EVTX-to-MITRE-Attack (negative control)', 'T1087'),
    'mdec_4776_4625_local_bruteforce': ('EVTX-to-MITRE-Attack', 'T1110.001'),
    'mdec_4625_denied_account_restriction': ('EVTX-to-MITRE-Attack (negative control)', 'T1078'),
    'splunk_t1558_003_unusual_kerberos_service_tickets': ('splunk/attack_data', 'T1558.003'),
    'splunk_t1110_003_purplesharp_invalid_users_ntlm': ('splunk/attack_data', 'T1110.003'),
    'splunk_t1110_003_purplesharp_valid_users_ntlm': ('splunk/attack_data', 'T1110.003'),
}
SAMPLE_FOLDERS = [ROOT / 'datasets/Windows_EVTX_CC0', ROOT / 'datasets/Windows_Splunk_attack_data']
MAPPING = {'dynamic_templates': [{'strings': {'match_mapping_type': 'string',
                                               'mapping': {'type': 'keyword', 'ignore_above': 8191}}}],
           'properties': {'@timestamp': {'type': 'date'}, 'message': {'type': 'text'},
                          'source': {'properties': {'ip': {'type': 'ip'}}}}}


def bulk(index, documents):
    body = ''.join(json.dumps({'index': {'_index': index, '_id': d['event']['id']}}) + '\n' + json.dumps(d) + '\n'
                   for d in documents).encode()
    result = api(ES, '/_bulk', body, 'POST', 'application/x-ndjson')
    if result.get('errors'):
        failed = next(i['index'] for i in result['items'] if 'error' in i['index'])
        raise RuntimeError(f"Bulk indexing failed: {json.dumps(failed)[:500]}")


def ingest(captures, index):
    try:
        api(ES, f'/{index}', method='DELETE')
    except RuntimeError as error:
        if 'HTTP 404' not in str(error):
            raise
    api(ES, f'/{index}', {'settings': {'number_of_shards': 1, 'number_of_replicas': 0}, 'mappings': MAPPING}, 'PUT')
    for path in captures:
        batch = []
        for document in read_capture(path):
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
    elif code == '4769':
        detail = (f"{data.get('TargetUserName')} -> {data.get('ServiceName')} enc={data.get('TicketEncryptionType')} "
                  f"from {data.get('IpAddress')}")
    else:
        detail = (process.get('command_line') or data.get('ImagePath') or data.get('ServiceFileName')
                  or data.get('TaskName') or '')
    parent = process.get('parent', {}).get('name')
    return ' '.join(filter(None, [code, source['host']['name'], parent and f'parent={parent}', detail[:160]]))


def esql_hits(rule, index):
    """Aggregating ES|QL rule: each result row (source, dataset, time window) is one hit."""
    result = api(ES, '/_query', {'query': rule['query'].replace(f'FROM {INDEX}', f'FROM {index}', 1)}, 'POST')
    names = [c['name'] for c in result['columns']]
    rows = [dict(zip(names, values)) for values in result['values']]
    counts = lambda r: ', '.join(f'{k} {v}' for k, v in r.items()
                                 if k not in ('source_ip', 'source', 'threatfusion.dataset', 'window', 'first_seen', 'last_seen'))
    return [{'event_id': f"{r.get('source_ip', r.get('source'))}@{r['window']}", 'dataset': r['threatfusion.dataset'],
             'timestamp': r['first_seen'],
             'evidence': f"{counts(r)} from {r.get('source_ip', r.get('source'))}, {r['first_seen']} to {r['last_seen']}"}
            for r in rows]


def evaluate(rules, index):
    hits = {}
    for rule in rules:
        if rule['language'] == 'esql':
            hits[rule['id']] = esql_hits(rule, index)
            continue
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
        query = ({'type': 'esql', 'language': 'esql', 'query': rule['query'].replace(f'FROM {INDEX}', f'FROM {index}', 1)}
                 if rule['language'] == 'esql' else {'type': 'eql', 'language': 'eql', 'query': rule['query'], 'index': [index]})
        api(KIBANA, '/api/detection_engine/rules', {
            'rule_id': rule_id, 'name': f"ThreatFusion {rule['id']} - {rule['name']}", 'description': rule['description'],
            **query,
            'severity': rule['severity'], 'risk_score': rule['risk_score'], 'threat': threat_mapping(rule['techniques']),
            # The public captures date from 2020, so the lookback covers the recorded period.
            'enabled': True, 'interval': '5m', 'from': 'now-2500d', 'max_signals': 1000,
            'tags': ['ThreatFusion', 'Windows', 'Public lab data']}, 'POST')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--datasets', default=str(ROOT / 'datasets/Windows_OTRF'))
    parser.add_argument('--evtx', default=str(ROOT / 'datasets/EVTX_ATTACK_SAMPLES'), help='Local .evtx samples (not committed)')
    parser.add_argument('--samples', nargs='*', default=[str(f) for f in SAMPLE_FOLDERS],
                        help='Folders of committed .evtx and Splunk XML .log samples')
    parser.add_argument('--rules', default=str(ROOT / 'siem/elastic/windows_rules.json'))
    parser.add_argument('--triage', default=str(ROOT / 'docs/benchmarks/windows_triage.csv'))
    parser.add_argument('--report', default=str(ROOT / 'docs/benchmarks/windows_detection_report'))
    parser.add_argument('--index', default=INDEX)
    parser.add_argument('--deploy', action='store_true', help='Also create the rules in Elastic Security')
    args = parser.parse_args()
    rules = json.loads(Path(args.rules).read_text(encoding='utf-8'))
    zips = sorted(Path(args.datasets).glob('*.zip'))
    evtx_files = sorted(Path(args.evtx).glob('*.evtx'))
    samples = sorted(f for folder in args.samples for f in Path(folder).iterdir() if f.suffix in ('.evtx', '.log'))
    captures = zips + samples + evtx_files
    documents = ingest(captures, args.index)
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
    for dataset, (source, technique) in CAPTURES.items():
        if dataset not in documents:
            coverage[dataset] = {'source': source, 'published_technique': technique, 'rules_with_tp': [], 'rules_with_fp': [],
                                 'rules_mapped_to_published_technique': [], 'note': 'sample not present locally; not evaluated'}
            continue
        dispositions = {d: sorted({r['id'] for r in rules for h in hits[r['id']] if h['dataset'] == dataset
                                   and triage.get((r['id'], h['event_id']), {}).get('disposition') == d}) for d in ('TP', 'FP')}
        exact = [r['id'] for r in rules if r['id'] in dispositions['TP'] and technique in r['techniques']]
        coverage[dataset] = {'source': source, 'published_technique': technique, 'rules_with_tp': dispositions['TP'],
                             'rules_with_fp': dispositions['FP'], 'rules_mapped_to_published_technique': exact}
    report = {'index': args.index, 'documents': documents,
              'dataset_sha256': {p.stem: hashlib.sha256(p.read_bytes()).hexdigest() for p in captures},
              'rules': summary, 'coverage': coverage, 'hits': hits}
    Path(f'{args.report}.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')

    evtx_note = (f"one [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) sample (GPL-3.0; kept local and "
                 f"not redistributed, SHA-256 in the JSON report)" if evtx_files else
                 'no local EVTX-ATTACK-SAMPLES file, so ES|QL rules that need one are not evaluated')
    lines = ['# Windows Detection Evaluation', '',
             f"Generated by `tools/benchmark_windows.py`. {len(rules)} rules from `siem/elastic/windows_rules.json` "
             f"({sum(r['language'] == 'eql' for r in rules)} EQL, {sum(r['language'] == 'esql' for r in rules)} ES|QL) run in Elasticsearch. "
             f"The data is {len(zips)} OTRF [Security-Datasets](https://github.com/OTRF/Security-Datasets) captures (MIT licence), "
             f"{sum(f.suffix == '.evtx' for f in samples)} [EVTX-to-MITRE-Attack](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack) "
             f"captures (CC0), {sum(f.suffix == '.log' for f in samples)} [splunk/attack_data](https://github.com/splunk/attack_data) "
             f"captures (Apache-2.0) and {evtx_note}. Together they hold {sum(documents.values()):,} events. "
             'Every hit is dispositioned by an analyst in [windows_triage.csv](windows_triage.csv). '
             'An ES|QL hit is one aggregated row (source, capture, five-minute window), not one event.', '',
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
    lines += ['', '## Coverage of Public Captures', '',
              'A negative control is a capture of related but different activity; a hit there is a false positive.', '',
              '| Capture | Source | Published technique | Rules with true positives | Rules with false positives | Rule mapped to the published technique |',
              '|---|---|---|---|---|---|']
    for dataset, c in coverage.items():
        lines.append(f"| `{dataset}` | {c['source']} | {c['published_technique']} | {', '.join(c['rules_with_tp']) or c.get('note', 'none')} | "
                     f"{', '.join(c['rules_with_fp']) or 'none'} | {', '.join(c['rules_mapped_to_published_technique']) or 'none'} |")
    lines += ['', '## Hits', '', '| Rule | Capture | Disposition | Evidence | Analyst reason |', '|---|---|---|---|---|']
    for rule in rules:
        for h in hits[rule['id']]:
            t = triage.get((rule['id'], h['event_id']), {})
            detail = h['evidence'].replace('|', '/')
            lines.append(f"| {rule['id']} | `{h['dataset']}` | {t.get('disposition', 'UNREVIEWED')} | `{detail}` | {t.get('reason', '')} |")
    lines += ['', '## Limits', '',
              '- Ground truth is per capture. OTRF gives one technique per capture, and each capture also contains normal background activity. '
              'Precision here is analyst-reviewed hits in these captures, not a false-positive rate on a production estate.',
              '- The OTRF captures come from one lab configuration (Sysmon and audit policy) recorded in 2020. '
              'Rules depending on 4688 command lines or Sysmon 10 need the same logging.',
              '- `empire_psexec_dcerpc_tcp_svcctl` is mapped by OTRF to T1021 Remote Services. WIN-004 detects the service-execution '
              'part (T1543.003, T1569.002), not the remote logon itself.',
              '- Each credential-access capture holds one short attack from one source, with almost no benign authentication '
              'around it. The captures prove the rule logic and its field names on real Windows output, not the thresholds on '
              'domain-controller volume.',
              '- `splunk_t1558_003_unusual_kerberos_service_tickets` was altered after capture. It requests RC4 tickets for service '
              'names such as `kr1btgt` and `krbtg2t` that the KDC grants with status 0x0, which a real KDC refuses for unknown SPNs. '
              'Its 159 lines hold 90 distinct events but only 44 distinct EventRecordIDs, so one record appears with several '
              'service names, and the 43-request burst shares one timestamp. Every record carries TicketOptions 0x60810010, as the '
              'unaltered krbtgt requests do. Identical lines are indexed once. The capture tests the count logic of WIN-008 and '
              'WIN-009, not realistic Kerberoasting of service accounts; its isolated hits outside the burst are dispositioned FP.',
              '- The EVTX-to-MITRE-Attack NTLM capture is named after 4776 and 4625 but holds only 4625 events, so WIN-011 is '
              'measured on the two splunk/attack_data captures alone.',
              '- `--deploy` gives the native rules a 2,500-day lookback so they reach the old captures. EQL rules deduplicate on the '
              'source event, but an aggregating ES|QL row has no source event, so WIN-007 and WIN-009 to WIN-011 raise the same '
              'alert again on every five-minute run. In production, set the lookback close to the run interval.']
    Path(f'{args.report}.md').write_text('\n'.join(lines) + '\n', encoding='utf-8')
    print(json.dumps(summary, indent=1))


if __name__ == '__main__':
    main()
