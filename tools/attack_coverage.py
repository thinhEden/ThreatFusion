"""Build the MITRE ATT&CK coverage report and an ATT&CK Navigator layer from data/attack_mapping.csv.

Technique names follow ATT&CK for ICS v19 (April 2026). Measured recall comes from the public-data
benchmark (docs/benchmarks/gas2015_context_report.json), so coverage claims stay tied to evidence.
"""
import argparse
import csv
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ATTACK_VERSION, NAVIGATOR_VERSION = '19', '5.3.2'

# Verified against attack.mitre.org on 2026-09-30.
TECHNIQUES = {
    'T1692.001': 'Unauthorized Message: Command Message',
    'T1692.002': 'Unauthorized Message: Reporting Message',
    'T0836': 'Modify Parameter',
    'T0843': 'Program Download',
    'T0888': 'Remote System Information Discovery',
    'T0846': 'Remote System Discovery',
    'T0814': 'Denial of Service',
    'T1693': 'Modify Firmware',
    'T0802': 'Automated Collection',
    'T0858': 'Change Operating Mode',
    'T0816': 'Device Restart/Shutdown',
}
SOFTWARE = {'S0603': 'Stuxnet', 'S1009': 'Triton', 'S0604': 'Industroyer', 'S1045': 'INCONTROLLER'}
# Enterprise techniques used by the Windows rules: ID -> (name, tactic). Verified on attack.mitre.org 2026-09-30.
ENTERPRISE = {
    'T1059': ('Command and Scripting Interpreter', 'TA0002'), 'T1059.001': ('PowerShell', 'TA0002'),
    'T1059.005': ('Visual Basic', 'TA0002'),
    'T1003': ('OS Credential Dumping', 'TA0006'), 'T1003.001': ('LSASS Memory', 'TA0006'),
    'T1543': ('Create or Modify System Process', 'TA0003'), 'T1543.003': ('Windows Service', 'TA0003'),
    'T1569': ('System Services', 'TA0002'), 'T1569.002': ('Service Execution', 'TA0002'),
    'T1053': ('Scheduled Task/Job', 'TA0003'), 'T1053.005': ('Scheduled Task', 'TA0003'),
    'T1021': ('Remote Services', 'TA0008'),
    'T1110': ('Brute Force', 'TA0006'), 'T1110.001': ('Password Guessing', 'TA0006'),
    'T1110.003': ('Password Spraying', 'TA0006'),
    'T1558': ('Steal or Forge Kerberos Tickets', 'TA0006'), 'T1558.003': ('Kerberoasting', 'TA0006'),
}
TACTICS = {'TA0002': 'Execution', 'TA0003': 'Persistence', 'TA0004': 'Privilege Escalation',
           'TA0006': 'Credential Access', 'TA0008': 'Lateral Movement'}

# MSU New Gas Pipeline 2015 attack categories (Morris taxonomy) expressed as ATT&CK for ICS techniques.
DATASET_TECHNIQUES = {
    'NMRI': ['T1692.002'], 'CMRI': ['T1692.002'],
    'MSCI': ['T1692.001'], 'MPCI': ['T1692.001', 'T0836'], 'MFCI': ['T1692.001'],
    'DoS': ['T0814'], 'Recon': ['T0846', 'T0888'],
}
COLORS = {'measured': '#2e8b57', 'indirect': '#9cc9a8', 'mapped': '#e0a526', 'gap': '#c0392b'}
LABELS = {'measured': 'Detected as this technique on public data',
          'indirect': 'Attack detected on public data, but labelled with another technique',
          'mapped': 'Rule mapped, not measured', 'gap': 'Attack present in public data, no detection'}


def load_mapping(path):
    with Path(path).open(newline='', encoding='utf-8') as handle:
        return list(csv.DictReader(handle))


def split_ids(value):
    return [i for i in (value or '').split('|') if i]


def technique_url(identifier):
    kind = 'software' if identifier.startswith('S') else 'techniques'
    return f"https://attack.mitre.org/{kind}/{identifier.replace('.', '/')}/"


def rule_inventory(root):
    """Every rule the engine can emit, so unmapped rules are visible instead of silently missing."""
    with (root / 'data/behavior_rules.csv').open(newline='', encoding='utf-8') as handle:
        behavior = [r['id'] for r in csv.DictReader(handle)]
    suricata = re.findall(r'sid:(\d+)', (root / 'rules/suricata/local_ics.rules').read_text(encoding='utf-8'))
    yara = re.findall(r'^rule\s+(\w+)', (root / 'rules/yara/ics_malware_indicators.yar').read_text(encoding='utf-8'), re.M)
    return {('behavior', i) for i in behavior} | {('suricata', i) for i in suricata} | {('yara', i) for i in yara}


def build(mapping, benchmark):
    by_technique = {}
    for row in mapping:
        for identifier in split_ids(row['techniques']):
            by_technique.setdefault(identifier, []).append(row)
    variants = benchmark['splits']['test']['variants']
    baseline = variants['baseline']
    categories = {}
    for category, techniques in DATASET_TECHNIQUES.items():
        for identifier in techniques:
            categories.setdefault(identifier, []).append(category)
    rows = []
    for identifier in sorted(set(by_technique) | set(categories)):
        present = [c for c in categories.get(identifier, []) if c in baseline['recall_by_category']]
        share = max((baseline['attack_ids_by_category'][c].get(identifier, 0) for c in present), default=0)
        if share > 0:
            status = 'measured'
        elif any(baseline['recall_by_category'][c] > 0 for c in present):
            status = 'indirect'
        elif present or identifier not in by_technique:
            status = 'gap'
        else:
            status = 'mapped'
        rows.append({'id': identifier, 'name': TECHNIQUES[identifier], 'status': status,
                     'rules': by_technique.get(identifier, []), 'categories': categories.get(identifier, []),
                     'share': share})
    return rows, variants


def write_layer(rows, recall, path):
    techniques = []
    for row in rows:
        rules = ', '.join(f"{r['source']}:{r['indicator']} ({r['confidence']})" for r in row['rules']) or 'no detection rule'
        measured = '; '.join(f"{c}: {100 * recall['baseline']['attack_ids_by_category'][c].get(row['id'], 0):.1f}% of test "
                             f"packets alerted as {row['id']} (baseline), any-alert recall "
                             f"{recall['baseline']['recall_by_category'][c]:.3f} baseline / "
                             f"{recall['envelope']['recall_by_category'][c]:.3f} envelope"
                             for c in row['categories'] if c in recall['baseline']['recall_by_category'])
        techniques.append({'techniqueID': row['id'], 'color': COLORS[row['status']], 'enabled': True,
                           'showSubtechniques': '.' in row['id'],
                           'comment': f"Rules: {rules}." + (f" Public data: {measured}." if measured else ''),
                           'links': [{'label': 'ATT&CK', 'url': technique_url(row['id'])}]})
    layer = {'name': 'ThreatFusion OT detection coverage', 'domain': 'ics-attack',
             'versions': {'attack': ATTACK_VERSION, 'navigator': NAVIGATOR_VERSION, 'layer': '4.5'},
             'description': 'Generated by tools/attack_coverage.py from data/attack_mapping.csv and the '
                            'MSU New Gas Pipeline 2015 benchmark. Colour shows evidence, not detection quality.',
             'techniques': techniques,
             'legendItems': [{'label': label, 'color': COLORS[status]} for status, label in LABELS.items()]}
    Path(path).write_text(json.dumps(layer, indent=2) + '\n', encoding='utf-8')
    return layer


def write_report(rows, recall, mapping, unmapped, path):
    lines = ['# MITRE ATT&CK Coverage', '',
             f'Generated by `tools/attack_coverage.py`. Technique IDs follow ATT&CK for ICS v{ATTACK_VERSION} (April 2026). '
             'Older sources cite T0855 Unauthorized Command Message, T0856 Spoof Reporting Message and T0857 System Firmware. '
             'v19 revoked them in favour of T1692.001, T1692.002 and T1693.001.', '',
             'The engine writes each alert\'s IDs to the `attack_techniques` column, to ECS `threat.technique.id` / '
             '`threat.software.id` in Elastic, and to the dashboard investigation panel. '
             'Import `threatfusion_ics_layer.json` into [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) to view the matrix.', '',
             '## Techniques', '',
             '| Technique | Name | Evidence | Detection sources (mapping confidence) |', '|---|---|---|---|']
    for row in rows:
        rules = ', '.join(f"`{r['source']}:{r['indicator']}` ({r['confidence']})" for r in row['rules']) or 'none'
        evidence = LABELS[row['status']] + (f" (best category: {100 * row['share']:.1f}% of packets)" if row['share'] else '')
        lines.append(f"| [{row['id']}]({technique_url(row['id'])}) | {row['name']} | {evidence} | {rules} |")
    lines += ['', '## Measured on Public Data', '',
              'MSU New Gas Pipeline 2015, test window, request packets. Recall per attack category, scored by the C++ engine '
              '([report](../benchmarks/gas2015_context_report.md)).', '',
              '| Category | Technique in data | IDs on baseline alerts | Recall: baseline | Envelope | Envelope + state review |',
              '|---|---|---|---:|---:|---:|']
    for category, techniques in DATASET_TECHNIQUES.items():
        values = [recall[v]['recall_by_category'].get(category) for v in ('baseline', 'envelope', 'envelope_state_review')]
        cells = ' | '.join('n/a' if v is None else f'{v:.3f}' for v in values)
        alerted = recall['baseline']['attack_ids_by_category'].get(category, {})
        ids = ', '.join(f'{i} {100 * share:.1f}%' for i, share in alerted.items()) or 'none'
        lines.append(f"| {category} | {', '.join(techniques)} | {ids} | {cells} |")
    lines += ['', 'The benchmark scores request packets only, and NMRI and CMRI appear only in response packets. '
              'No rule inspects reported process values, so T1692.002 is a gap. '
              'No behaviour rule covers the invalid function codes used by MFCI. '
              'DoS and MPCI writes are caught by the generic write rule (BR-001, T1692.001), so their own techniques '
              '(T0814, T0836) show as indirect.', '',
              '## Software', '', '| Software | Name | YARA rule |', '|---|---|---|']
    for row in mapping:
        for identifier in split_ids(row['software']):
            lines.append(f"| [{identifier}]({technique_url(identifier)}) | {SOFTWARE[identifier]} | `{row['indicator']}` ({row['confidence']}) |")
    lines += ['', 'The YARA rules are lab family indicators and have not been validated against real samples.', '',
              '## Unmapped Detections', '']
    no_technique = [f"`{r['source']}:{r['indicator']}`: {r['rationale']}" for r in mapping if r['confidence'] == 'none']
    lines += [f'- {item}' for item in no_technique + [f'`{s}:{i}`: missing from the mapping file' for s, i in sorted(unmapped)]]
    Path(path).write_text('\n'.join(lines) + '\n', encoding='utf-8')


def enterprise_section(rules, report, layer_path):
    """Windows host rules on public captures: ATT&CK Enterprise table and Navigator layer."""
    by_technique = {}
    for rule in rules:
        for technique in rule['techniques']:
            by_technique.setdefault(technique, []).append(rule['id'])
    lines = ['', '## Windows Host Detections (ATT&CK Enterprise)', '',
             'EQL and ES|QL rules in `siem/elastic/windows_rules.json` are evaluated on public Windows captures (OTRF, '
             'EVTX-to-MITRE-Attack, splunk/attack_data and a local EVTX-ATTACK-SAMPLES file) by `tools/benchmark_windows.py`. '
             'Every hit is analyst-dispositioned ([report](../benchmarks/windows_detection_report.md)). '
             'Import `threatfusion_enterprise_layer.json` into ATT&CK Navigator to view the Enterprise matrix.', '',
             '| Technique | Name | Rules | Distinct true-positive hits | Captures detected |', '|---|---|---|---:|---|']
    techniques = []
    for technique in sorted(by_technique):
        ids = by_technique[technique]
        tp = len({h['event_id'] for i in ids for h in report['hits'][i] if h.get('disposition') == 'TP'})
        captures = sorted({d for i in ids for d in report['rules'][i]['datasets']})
        lines.append(f"| [{technique}]({technique_url(technique)}) | {ENTERPRISE[technique][0]} | {', '.join(ids)} | {tp} | "
                     f"{', '.join(f'`{c}`' for c in captures) or 'none'} |")
        techniques.append({'techniqueID': technique, 'color': COLORS['measured' if tp else 'mapped'], 'enabled': True,
                           'showSubtechniques': '.' in technique,
                           'comment': f"Rules: {', '.join(ids)}. Distinct true-positive hits on public captures: {tp}.",
                           'links': [{'label': 'ATT&CK', 'url': technique_url(technique)}]})
    lines += ['', 'No rule covers T1021 Remote Services, the OTRF mapping for the PsExec capture. WIN-004 catches its service-execution step instead. '
              'An ES|QL hit is one aggregated row (source, capture, five-minute window), so its count is not an event count.']
    layer = {'name': 'ThreatFusion Windows host detections', 'domain': 'enterprise-attack',
             'versions': {'attack': ATTACK_VERSION, 'navigator': NAVIGATOR_VERSION, 'layer': '4.5'},
             'description': 'Generated by tools/attack_coverage.py from siem/elastic/windows_rules.json and the public-capture evaluation.',
             'techniques': techniques,
             'legendItems': [{'label': 'True positives on public captures', 'color': COLORS['measured']},
                             {'label': 'Rule mapped, not measured', 'color': COLORS['mapped']}]}
    Path(layer_path).write_text(json.dumps(layer, indent=2) + '\n', encoding='utf-8')
    return lines


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mapping', default=str(ROOT / 'data/attack_mapping.csv'))
    parser.add_argument('--benchmark', default=str(ROOT / 'docs/benchmarks/gas2015_context_report.json'))
    parser.add_argument('--output', default=str(ROOT / 'docs/attack'))
    parser.add_argument('--windows-rules', default=str(ROOT / 'siem/elastic/windows_rules.json'))
    parser.add_argument('--windows-report', default=str(ROOT / 'docs/benchmarks/windows_detection_report.json'))
    args = parser.parse_args()
    mapping = load_mapping(args.mapping)
    unknown = {i for r in mapping for i in split_ids(r['techniques'])} - set(TECHNIQUES)
    unknown |= {i for r in mapping for i in split_ids(r['software'])} - set(SOFTWARE)
    if unknown:
        raise ValueError(f'Unverified ATT&CK IDs in mapping: {sorted(unknown)}')
    unmapped = rule_inventory(ROOT) - {(r['source'], r['indicator']) for r in mapping}
    rows, recall = build(mapping, json.loads(Path(args.benchmark).read_text(encoding='utf-8')))
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    write_layer(rows, recall, output / 'threatfusion_ics_layer.json')
    write_report(rows, recall, mapping, unmapped, output / 'coverage.md')
    windows_rules = json.loads(Path(args.windows_rules).read_text(encoding='utf-8'))
    unknown = {t for r in windows_rules for t in r['techniques']} - set(ENTERPRISE)
    if unknown:
        raise ValueError(f'Unverified Enterprise IDs in Windows rules: {sorted(unknown)}')
    windows_report = json.loads(Path(args.windows_report).read_text(encoding='utf-8'))
    extra = enterprise_section(windows_rules, windows_report, output / 'threatfusion_enterprise_layer.json')
    with (output / 'coverage.md').open('a', encoding='utf-8') as handle:
        handle.write('\n'.join(extra) + '\n')
    print(f'{len(rows)} ICS techniques, {len(unmapped)} unmapped rules, {len(windows_rules)} Windows rules -> {output}')


if __name__ == '__main__':
    main()
