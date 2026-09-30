"""Authenticated local Elastic Security lab, ECS export, ingestion, and verification."""
import argparse
import base64
import csv
import hashlib
import json
import secrets
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

ROOT = Path(__file__).resolve().parents[1]
ENV = ROOT / 'siem/elastic/.env'
COMPOSE = ROOT / 'siem/elastic/compose.yml'
ES = 'http://127.0.0.1:19200'
KIBANA = 'http://127.0.0.1:15601'


def credentials():
    return dict(line.split('=', 1) for line in ENV.read_text().splitlines() if '=' in line)


def api(base, path, body=None, method=None, content_type='application/json'):
    password = credentials()['ELASTIC_PASSWORD']
    headers = {'Authorization': 'Basic ' + base64.b64encode(('elastic:' + password).encode()).decode(),
               'Content-Type': content_type, 'kbn-xsrf': 'threatfusion'}
    payload = None if body is None else body if isinstance(body, bytes) else json.dumps(body).encode()
    request = Request(base + path, data=payload, headers=headers, method=method)
    try:
        with urlopen(request, timeout=30) as response:
            raw = response.read()
            return json.loads(raw) if raw else {}
    except HTTPError as error:
        detail = error.read().decode(errors='replace')[:1000]
        raise RuntimeError(f'Elastic API {path}: HTTP {error.code}: {detail}') from None


def wait_api(base, path, seconds=240):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            result = api(base, path)
            if base != KIBANA or result.get('status', {}).get('overall', {}).get('level') == 'available':
                return result
        except (OSError, URLError, TimeoutError, RuntimeError):
            pass
        time.sleep(2)
    raise TimeoutError(f'Service not ready: {base}{path}')


def compose(*args):
    subprocess.run(['docker', 'compose', '--env-file', str(ENV), '-f', str(COMPOSE), *args], check=True)


def setup():
    if not ENV.exists():
        ENV.parent.mkdir(parents=True, exist_ok=True)
        ENV.write_text('\n'.join(f'{key}={secrets.token_hex(24)}' for key in
                                 ('ELASTIC_PASSWORD', 'KIBANA_PASSWORD', 'KIBANA_KEY')) + '\n')
    compose('up', '-d', 'elasticsearch')
    wait_api(ES, '/_cluster/health')
    api(ES, '/_security/user/kibana_system/_password', {'password': credentials()['KIBANA_PASSWORD']}, 'POST')
    compose('up', '-d', 'kibana')
    wait_api(KIBANA, '/api/status')
    properties = {
        '@timestamp': {'type': 'date'}, 'event.id': {'type': 'keyword'},
        'event.kind': {'type': 'keyword'}, 'event.category': {'type': 'keyword'},
        'event.dataset': {'type': 'keyword'}, 'event.risk_score': {'type': 'float'},
        'source.ip': {'type': 'ip'}, 'destination.ip': {'type': 'ip'},
        'network.protocol': {'type': 'keyword'}, 'rule.id': {'type': 'keyword'},
        'threatfusion.variant': {'type': 'keyword'}, 'threatfusion.case': {'type': 'keyword'},
        'threatfusion.function_code': {'type': 'integer'}, 'threatfusion.unit_id': {'type': 'integer'},
        'threatfusion.register_address': {'type': 'integer'}, 'threatfusion.register_values': {'type': 'integer'},
        'threatfusion.latency_ms': {'type': 'float'}, 'message': {'type': 'text'},
    }
    api(ES, '/_index_template/threatfusion', {
        'index_patterns': ['threatfusion-alerts-*'],
        'template': {'settings': {'number_of_shards': 1, 'number_of_replicas': 0}, 'mappings': {'properties': properties}}}, 'PUT')
    api(KIBANA, '/api/data_views/data_view', {'data_view': {'id': 'threatfusion-alerts',
        'title': 'threatfusion-alerts-*', 'name': 'ThreatFusion OT Alerts', 'timeFieldName': '@timestamp'}, 'override': True}, 'POST')
    save_searches()
    ensure_detection_rule()
    print('Elastic Security ready: ' + KIBANA + '/app/security')
    print('Local credentials are in siem/elastic/.env (not printed and ignored by Git).')


def ensure_detection_rule():
    rule_id = 'threatfusion-contextual-ot'
    try:
        return api(KIBANA, '/api/detection_engine/rules?rule_id=' + rule_id)
    except RuntimeError as error:
        if 'HTTP 404' not in str(error):
            raise
    return api(KIBANA, '/api/detection_engine/rules', {
        'rule_id': rule_id, 'name': 'ThreatFusion - Retained OT command alerts',
        'description': 'Promote bounded-context external OT alerts into Elastic Security native detections. Offline lab data; no claim of real PLC compromise.',
        'type': 'query', 'language': 'kuery', 'query': 'threatfusion.variant: bounded and event.risk_score >= 60',
        'index': ['threatfusion-alerts-*'], 'severity': 'high', 'risk_score': 75,
        'enabled': True, 'interval': '1m', 'from': 'now-7d', 'max_signals': 1000,
        'tags': ['ThreatFusion', 'OT', 'Offline lab']}, 'POST')


def save_searches():
    searches = json.loads((ROOT / 'siem/elastic/queries.json').read_text())
    records = []
    for query in searches:
        records.append({'type': 'search', 'id': query['id'], 'attributes': {
            'title': query['title'], 'description': query['purpose'],
            'columns': ['@timestamp', 'event.id', 'source.ip', 'destination.ip', 'event.risk_score', 'threatfusion.variant', 'message'],
            'sort': [['@timestamp', 'asc']],
            'kibanaSavedObjectMeta': {'searchSourceJSON': json.dumps({'query': {'query': query['kql'], 'language': 'kuery'},
                'filter': [], 'indexRefName': 'kibanaSavedObjectMeta.searchSourceJSON.index'})}},
            'references': [{'type': 'index-pattern', 'id': 'threatfusion-alerts', 'name': 'kibanaSavedObjectMeta.searchSourceJSON.index'}]})
    ndjson = ('\n'.join(json.dumps(record) for record in records) + '\n').encode()
    boundary = 'ThreatFusion' + secrets.token_hex(8)
    body = (f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="queries.ndjson"\r\nContent-Type: application/ndjson\r\n\r\n'.encode()
            + ndjson + f'\r\n--{boundary}--\r\n'.encode())
    result = api(KIBANA, '/api/saved_objects/_import?overwrite=true', body, 'POST', f'multipart/form-data; boundary={boundary}')
    if not result.get('success'):
        raise RuntimeError('Saved query import failed: ' + json.dumps(result))


def utc_timestamp(value):
    try:
        return datetime.fromtimestamp(float(value), timezone.utc).isoformat()
    except ValueError:
        stamp = datetime.fromisoformat(value.replace('Z', '+00:00'))
        if stamp.tzinfo is None:
            raise ValueError('ECS export requires timezone-aware timestamps')
        return stamp.isoformat()


def ecs_document(alert, event, variant, capture):
    return {
        '@timestamp': utc_timestamp(alert['timestamp']),
        'event': {'id': alert['event_id'], 'kind': 'alert', 'category': ['intrusion_detection'],
                  'dataset': 'threatfusion.ot', 'risk_score': int(alert['risk_score'])},
        'source': {'ip': alert['src_ip']}, 'destination': {'ip': alert['dst_ip']},
        'network': {'protocol': alert['protocol']},
        'rule': {'id': alert['classification'], 'name': alert['classification']},
        'message': alert['reasons'],
        'threatfusion': {'variant': variant, 'case': capture, 'incident_id': alert['incident_id'],
                        'latency_ms': float(alert['latency_ms']), 'verdict': alert['verdict'],
                        'function_code': event['function_code'], 'unit_id': event['unit_id'],
                        'register_address': event['register_address'], 'register_values': event['register_values']},
    }


def export_alerts(alerts_path, events_path, output, variant, capture):
    events = {event['id']: event for event in (json.loads(line) for line in Path(events_path).read_text().splitlines())}
    with Path(alerts_path).open(newline='') as handle:
        docs = [ecs_document(alert, events[alert['event_id']], variant, capture) for alert in csv.DictReader(handle)]
    Path(output).parent.mkdir(parents=True, exist_ok=True)
    Path(output).write_text('\n'.join(json.dumps(doc) for doc in docs) + ('\n' if docs else ''))
    return docs


def ingest(paths):
    data = []
    for path in paths:
        for line in Path(path).read_text().splitlines():
            if not line.strip():
                continue
            doc = json.loads(line)
            identity = '|'.join([doc['threatfusion']['case'], doc['threatfusion']['variant'], doc['event']['id']])
            data.extend([json.dumps({'index': {'_index': 'threatfusion-alerts-lab',
                '_id': hashlib.sha256(identity.encode()).hexdigest()}}), json.dumps(doc)])
    if not data:
        return {'ingested': 0}
    result = api(ES, '/_bulk?refresh=wait_for', ('\n'.join(data) + '\n').encode(), 'POST', 'application/x-ndjson')
    if result.get('errors'):
        raise RuntimeError('Bulk indexing failed: ' + json.dumps([i for i in result['items'] if i['index'].get('error')])[:1000])
    rule = ensure_detection_rule()
    manual_run = api(KIBANA, '/api/detection_engine/rules/_bulk_action', {
        'action':'run', 'ids':[rule['id']],
        'run':{'start_date':'2026-09-30T09:58:00.000Z','end_date':'2026-09-30T10:15:00.000Z'}}, 'POST')
    if manual_run.get('success') is False:
        raise RuntimeError('Native detection rule manual run failed')
    return {'ingested': len(data) // 2, 'index_count': api(ES, '/threatfusion-alerts-*/_count')['count']}


def verify():
    result = api(ES, '/threatfusion-alerts-*/_search', {'size': 0, 'aggs': {'by_variant': {'terms': {'field': 'threatfusion.variant'}}}}, 'POST')
    queries = {
        'engineering_baseline': {'bool': {'filter': [{'term': {'source.ip':'10.50.1.20'}}, {'term': {'network.protocol':'modbus'}}, {'term': {'threatfusion.variant':'baseline'}}]}},
        'retained_contextual': {'bool': {'filter': [{'term': {'threatfusion.variant':'bounded'}}, {'range': {'event.risk_score':{'gte':60}}}]}},
        'unknown_source': {'term': {'source.ip':'10.50.1.99'}},
        'dangerous_values': {'range': {'threatfusion.register_values':{'gt':60}}},
        'counterexample': {'term': {'threatfusion.case':'challenge'}},
    }
    counts = {name:api(ES, '/threatfusion-alerts-*/_count', {'query':query}, 'POST')['count'] for name,query in queries.items()}
    try:
        native = api(ES, '/.alerts-security.alerts-default/_count',
            {'query':{'term':{'kibana.alert.rule.rule_id':'threatfusion-contextual-ot'}}}, 'POST')['count']
    except RuntimeError as error:
        if 'HTTP 404' not in str(error):
            raise
        native = 0
    return {'total': result['hits']['total']['value'], 'variants': result.get('aggregations',{}).get('by_variant',{}).get('buckets',[]),
            'native_security_alerts': native, 'investigation_query_counts': counts,
            'kibana': api(KIBANA, '/api/status')['status']['overall']['level']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['setup', 'ingest', 'verify', 'stop'])
    parser.add_argument('--input', nargs='*', default=[])
    parser.add_argument('--report')
    args = parser.parse_args()
    if args.command == 'setup':
        setup()
        return
    if args.command == 'stop':
        compose('stop')
        return
    result = ingest(args.input) if args.command == 'ingest' else verify()
    if args.report:
        Path(args.report).parent.mkdir(parents=True, exist_ok=True)
        Path(args.report).write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
