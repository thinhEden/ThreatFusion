"""Run the playbook hunting queries (siem/elastic/hunting_queries.json) and save the KQL ones in Kibana.

KQL is parsed by Kibana itself: each query runs as a detection-rule preview, which uses the same KQL library as
Discover. The ES|QL KQL() function runs as a cross-check, and disagreements are reported. EQL runs through
_eql/search. Expected counts per capture were taken from raw fields (winlog.event_data) or the raw files, not
from the ECS fields the queries use. A query with no positive example in the data has a control query that keeps
its fields and syntax but relaxes one clause, to show the query can match at all.
"""
import argparse
import json
import secrets

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from siem_elastic import ES, KIBANA, api

ROOT = Path(__file__).resolve().parents[1]
DATA_VIEWS = {'threatfusion-windows-otrf': ('threatfusion-windows', 'ThreatFusion Windows captures'),
              'threatfusion-alerts-*': ('threatfusion-alerts', 'ThreatFusion OT alerts')}


def resolve(query, parameters):
    for placeholder, value in (parameters or {}).items():
        query = query.replace(placeholder, value)
    if '<' in query and '>' in query.split('<', 1)[1]:
        raise ValueError(f'Unresolved placeholder in: {query}')
    return query


def field(source, dotted):
    for part in dotted.split('.'):
        source = source.get(part, {}) if isinstance(source, dict) else {}
    return source or None


PAGE = 100  # Documents per page in the rule executor's search, observed on Kibana 9.3.1.


def kibana_kql(entry, query, hint=()):
    """Counts as Kibana parses the KQL, one rule preview per capture or variant.

    A preview of the whole query wrote 272 alerts for 274 OT documents: the two it skipped share a timestamp with the
    document before a page boundary. Per-group previews stay within one page, and the whole-query total is kept to
    report the difference."""
    group = entry.get('group_by', 'threatfusion.dataset')
    whole = Counter(field(h, group) for h in preview_alerts(entry, query))
    counts = {}
    for value in sorted(set(whole) | set(hint)):
        n = count_within_pages(entry, f'({query}) and {group}: "{value}"')
        if n:
            counts[value] = n
    return counts, sum(whole.values())


def original_time(alert):
    return alert.get('kibana.alert.original_time') or field(alert, 'kibana.alert.original_time')


def count_within_pages(entry, query):
    """Split at the median source timestamp until every preview stays below one page."""
    alerts = preview_alerts(entry, query)
    if len(alerts) < PAGE:
        return len(alerts)
    stamps = sorted(original_time(a) for a in alerts)
    middle = stamps[len(stamps) // 2]
    if middle == stamps[0]:
        raise RuntimeError(f"{entry['id']}: over {PAGE} documents share {middle}; cannot split below one page")
    return (count_within_pages(entry, f'({query}) and @timestamp < "{middle}"')
            + count_within_pages(entry, f'({query}) and @timestamp >= "{middle}"'))


def preview_alerts(entry, query):
    """Sources of the alerts a query-rule preview writes over the whole capture period."""
    preview = api(KIBANA, '/api/detection_engine/rules/preview', {
        'type': 'query', 'language': 'kuery', 'query': query, 'index': [entry['index']], 'name': entry['id'],
        'description': 'Hunting query validation', 'risk_score': 1, 'severity': 'low', 'from': 'now-2500d',
        'interval': '5m', 'max_signals': 1000, 'invocationCount': 1,
        'timeframeEnd': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.000Z')}, 'POST')
    errors = [e for log in preview.get('logs', []) for e in log.get('errors', [])]
    if preview.get('isAborted') or errors:
        raise RuntimeError(f"Kibana preview failed for {entry['id']}: {errors}")
    # Preview alerts are not searchable until the index refreshes; reading early undercounted by one.
    api(ES, '/.preview.alerts-security.alerts-default/_refresh', method='POST')
    hits = api(ES, '/.preview.alerts-security.alerts-default/_search',
               {'size': 1000, 'query': {'term': {'kibana.alert.rule.uuid': preview['previewId']}}}, 'POST')['hits']['hits']
    return [h['_source'] for h in hits]


def esql_kql(entry, query):
    group = entry.get('group_by', 'threatfusion.dataset')
    result = api(ES, '/_query', {'query': f'FROM {entry["index"]} | WHERE KQL("""{query}""") '
                                          f'| STATS hits = COUNT(*) BY {group}'}, 'POST')
    return {row[1]: row[0] for row in result['values']}


def run(entry, query, expected):
    """Hit counts per capture (or per variant for the OT index), plus the ES|QL cross-check for KQL."""
    if entry['language'] == 'kql':
        esql = esql_kql(entry, query)
        counts, whole = kibana_kql(entry, query, set(expected) | set(esql))
        return {'observed': counts, 'esql_kql': esql, 'kibana_whole_query_alerts': whole}
    result = api(ES, f"/{entry['index']}/_eql/search", {'query': query, 'size': 1000}, 'POST')['hits']
    counts = Counter()
    for item in result.get('sequences', []) or result.get('events', []):
        source = (item['events'][0] if 'events' in item else item)['_source']
        counts[source['threatfusion']['dataset']] += 1
    return {'observed': dict(counts)}


def ensure_data_views():
    existing = {d['id'] for d in api(KIBANA, '/api/data_views')['data_view']}
    for index, (identifier, name) in DATA_VIEWS.items():
        if identifier not in existing:
            api(KIBANA, '/api/data_views/data_view', {'data_view': {'id': identifier, 'title': index, 'name': name,
                                                                    'timeFieldName': '@timestamp'}}, 'POST')


def save_searches(entries):
    """KQL hunts become Kibana saved searches (Discover sessions) with the validation values filled in."""
    records = []
    for entry in entries:
        if entry['language'] != 'kql':
            continue
        records.append({'type': 'search', 'id': entry['id'], 'attributes': {
            'title': entry['title'], 'description': f"{entry['playbook']} hunting query. Template: {entry['query']}",
            'columns': ['@timestamp', 'host.name', 'event.code', 'user.name', 'source.ip', 'process.command_line', 'threatfusion.dataset'],
            'sort': [['@timestamp', 'asc']],
            'kibanaSavedObjectMeta': {'searchSourceJSON': json.dumps({
                'query': {'query': resolve(entry['query'], entry.get('parameters')), 'language': 'kuery'},
                'filter': [], 'indexRefName': 'kibanaSavedObjectMeta.searchSourceJSON.index'})}},
            'references': [{'type': 'index-pattern', 'id': DATA_VIEWS[entry['index']][0],
                            'name': 'kibanaSavedObjectMeta.searchSourceJSON.index'}]})
    ndjson = ('\n'.join(json.dumps(record) for record in records) + '\n').encode()
    boundary = 'ThreatFusion' + secrets.token_hex(8)
    body = (f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="hunts.ndjson"\r\nContent-Type: application/ndjson\r\n\r\n'.encode()
            + ndjson + f'\r\n--{boundary}--\r\n'.encode())
    result = api(KIBANA, '/api/saved_objects/_import?overwrite=true', body, 'POST', f'multipart/form-data; boundary={boundary}')
    if not result.get('success'):
        raise RuntimeError('Saved search import failed: ' + json.dumps(result))
    return len(records)


def compare(expected, observed, minimum=False):
    """Exact counts, or with minimum=True at least the listed counts and none elsewhere."""
    keys = set(expected) | set(observed)
    if minimum:
        return (all(observed.get(k, 0) >= v for k, v in expected.items())
                and all(observed.get(k, 0) == 0 for k in keys - set(expected)))
    return all(expected.get(k, 0) == observed.get(k, 0) for k in keys)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--queries', default=str(ROOT / 'siem/elastic/hunting_queries.json'))
    parser.add_argument('--report', default=str(ROOT / 'docs/benchmarks/hunting_query_validation'))
    parser.add_argument('--no-save', action='store_true', help='Do not create Kibana saved searches')
    args = parser.parse_args()
    entries = json.loads(Path(args.queries).read_text(encoding='utf-8'))
    results = []
    for entry in entries:
        query = resolve(entry['query'], entry.get('parameters'))
        outcome = run(entry, query, entry['expect'])
        result = {'id': entry['id'], 'playbook': entry['playbook'], 'language': entry['language'], 'query': query,
                  'expected': entry['expect'], **outcome, 'passed': compare(entry['expect'], outcome['observed'])}
        if 'control' in entry:
            control_query = resolve(entry['control']['query'], entry.get('parameters'))
            minimum = 'expect_min' in entry['control']
            expected = entry['control']['expect_min' if minimum else 'expect']
            control = run(entry, control_query, expected)
            result['control'] = {'query': control_query, 'expected': expected, 'minimum': minimum, **control,
                                 'passed': compare(expected, control['observed'], minimum), 'why': entry['control']['why']}
            result['passed'] = result['passed'] and result['control']['passed']
        results.append(result)
    saved = 0
    if not args.no_save:
        ensure_data_views()
        saved = save_searches(entries)
    parts = [(r['id'], part, data) for r in results for part, data in (('hunt', r), ('control', r.get('control') or {}))
             if 'esql_kql' in data]
    disagreements = [(i, part) for i, part, data in parts if not compare(data['observed'], data['esql_kql'])]
    skipped = [(i, part, sum(data['observed'].values()), data['kibana_whole_query_alerts']) for i, part, data in parts
               if sum(data['observed'].values()) != data['kibana_whole_query_alerts']]
    report = {'queries': results, 'saved_searches': saved, 'passed': sum(r['passed'] for r in results),
              'kibana_esql_disagreements': disagreements, 'whole_query_preview_shortfall': skipped}
    Path(f'{args.report}.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')

    counts = lambda d: ', '.join(f'{k} {v}' for k, v in sorted(d.items())) or 'none'
    lines = ['# Playbook Hunting Query Validation', '',
             'Generated by `tools/validate_hunting_queries.py` from `siem/elastic/hunting_queries.json`. Kibana parses every KQL hunt: '
             'each runs as a detection-rule preview, which uses the same KQL library as Discover, and is saved in Kibana as a Discover '
             f"search ({saved} saved). The ES|QL `KQL()` function runs the same text as a cross-check. The EQL sequence runs through "
             '`_eql/search`; Discover cannot hold EQL.', '',
             'Expected counts come from raw fields (`winlog.event_data`) or the raw files, not from the ECS fields the hunts use. '
             'Placeholders such as `<host>` are filled with a value from the captures. When no capture holds a positive example, '
             'a control query keeps the fields and syntax but relaxes one clause, so an empty result cannot come from a wrong field.', '',
             f"**{report['passed']} of {len(results)} hunts match their expected counts.**", '',
             '| Hunt | Playbook | Expected | Observed | Control expected | Control observed | Result |',
             '|---|---|---|---|---|---|---|']
    for r in results:
        c = r.get('control')
        control_expected = (('at least ' if c['minimum'] else '') + counts(c['expected'])) if c else 'n/a'
        lines.append(f"| `{r['id']}` | {r['playbook']} | {counts(r['expected'])} | {counts(r['observed'])} | "
                     f"{control_expected} | {counts(c['observed']) if c else 'n/a'} | "
                     f"{'pass' if r['passed'] else '**FAIL**'} |")
    if disagreements:
        lines += ['', '### Kibana and ES|QL disagree', '',
                  'The ES|QL `KQL()` function returned different counts from Kibana for '
                  + ', '.join(f'`{i}` ({part})' for i, part in disagreements) + '. '
                  'In this run the difference comes from a backslash inside a wildcard pattern. In Elasticsearch 9.3.1, ES|QL `KQL()` needs four backslashes where '
                  'Kibana needs two to match one literal backslash, so a Windows-path hunt copied from Discover into ES|QL silently '
                  'returns nothing. The playbooks are written for Kibana.']
    if skipped:
        lines += ['', '### Rule previews skip documents that share a timestamp', '',
                  'Counts above come from one preview per capture or variant, split at the median timestamp while a piece holds 100 or more documents. One preview of the whole query wrote fewer alerts for '
                  + ', '.join(f'`{i}` ({part}: {whole} of {total})' for i, part, total, whole in skipped) + '. '
                  'In the OT index, every variant stores the same packets with the same timestamps. The documents a whole-query preview '
                  'missed each share the timestamp of the document before them at a page boundary, which is what paging on a '
                  'non-unique sort key does. A query rule that pages through bursts with identical timestamps may therefore not '
                  'alert on every matching document; this was observed in previews on Kibana 9.3.1 and not tested on scheduled rules.']
    lines += ['', '## Queries as Run', '']
    for r, entry in zip(results, entries):
        lines += [f"### `{r['id']}`", '', f"{entry['title']} ({entry['language'].upper()}, `{entry['index']}`).", '',
                  '```text', r['query'], '```', '']
        if entry.get('note'):
            lines += [entry['note'], '']
        if r.get('control'):
            lines += [f"Control: {r['control']['why']}", '', '```text', r['control']['query'], '```', '']
    lines += ['## Fixes Found by Running the Hunts', '',
              '- PB-02 used `file.path`, `file.extension` and `dns.question.name`, and PB-04 used `event.category` and `source.ip`. '
              'The Windows normalizer produced none of them, so these hunts could only return zero. '
              '`tools/normalize_windows_events.py` now maps Sysmon 11/23 to `file.*`, Sysmon 22 to `dns.question.name`, and '
              'authentication events to `event.category`, `event.outcome`, `user.*` and `source.ip`.',
              '- The PB-04 sequence joined on `source.ip` and `TargetUserName`. Local and many NTLM logons carry no address, so it '
              'joins on `host.name` and `user.name` instead.',
              '- The first version of this check ran KQL through ES|QL only, and the file-drop control failed because of the '
              'backslash difference above. The check now uses Kibana, and ES|QL is kept as a cross-check.',
              '- EQL `with runs=5` returns overlapping sequences that slide by one event: 8 failures for one account give several '
              'matches. The failures-then-success control therefore checks a minimum per capture and zero elsewhere, not an '
              'exact count; the first expectation (one match per account) was wrong.', '',
              '## Limits', '',
              '- An empty result for the Office, file-drop, lockout and failures-then-success hunts means the public captures hold no '
              'such activity. Their controls prove the query mechanics, not detection of a real phishing chain or a successful guess.',
              '- KQL is case-sensitive on keyword fields. `process.parent.name: "WINWORD.EXE"` matches the usual casing only.']
    Path(f'{args.report}.md').write_text('\n'.join(lines) + '\n', encoding='utf-8')
    print(json.dumps([(r['id'], r['passed'], r['observed']) for r in results], indent=1))


if __name__ == '__main__':
    main()
