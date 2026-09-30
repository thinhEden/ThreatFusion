"""Evidence joins for the SOC workspace. Sources never join across captures."""
import csv
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path


def csv_data(path):
    if not path.exists():
        return []
    with path.open(encoding='utf-8-sig', newline='') as handle:
        return [r for r in csv.DictReader(handle) if None not in r and all(v is not None for v in r.values())]


def json_data(path, fallback=None):
    return json.loads(path.read_text(encoding='utf-8')) if path.exists() else fallback


def timestamp(value):
    if not value:
        return None
    try:
        return datetime.fromtimestamp(float(value), timezone.utc).isoformat()
    except (ValueError, OverflowError, OSError):
        try:
            date = datetime.fromisoformat(value.replace('Z','+00:00'))
            return date.isoformat() if date.tzinfo else None
        except ValueError:
            return None


def number(value):
    try:
        result = float(value)
        return result if result == result and abs(result) != float('inf') else None
    except (ValueError, TypeError):
        return None


def snapshot(source, portfolio, live_rows, total, store, imports_dir, events_path=None, audit_path=None):
    portfolio = Path(portfolio)
    kind = 'live' if source == 'live' else 'recorded_lab' if source in ('main','challenge') else 'imported'
    event_records, audits, truth, policy = [], [], {}, None
    if kind == 'recorded_lab':
        base_path = portfolio / f'{source}_baseline.alerts.csv'
        required = [base_path, portfolio/f'{source}_bounded.alerts.csv',
                    portfolio/f'{source}_bounded.audit.csv', portfolio/f'{source}_bounded.events.jsonl']
        if not all(path.is_file() for path in required):
            raise FileNotFoundError('Recorded lab outputs are missing. Run the portfolio workflow first.')
        candidates = csv_data(base_path)
        retained = {r['event_id']:r for r in csv_data(portfolio/f'{source}_bounded.alerts.csv')}
        events_path = portfolio/f'{source}_bounded.events.jsonl'
        audits = csv_data(portfolio/f'{source}_bounded.audit.csv')
        truth = {r['event_id']:r for r in json_data(portfolio/f'{source}_ground_truth.json', [])}
        policy = json_data(portfolio/'policy.json', {})
        total = len(candidates)
    elif kind == 'imported':
        events_path = None
        if source not in {r['id'] for r in store.imports()}:
            raise ValueError('Unknown source')
        candidates = csv_data(Path(imports_dir)/f'{source}.csv')
        retained = {r['event_id']:r for r in candidates}
        total = len(candidates)
    else:
        candidates = live_rows
        retained = {r['event_id']:r for r in candidates}
        audits = csv_data(Path(audit_path)) if audit_path else []
    if events_path and Path(events_path).is_file():
        with Path(events_path).open(encoding='utf-8') as handle:
            event_records = [json.loads(line) for line in handle if line.strip()]
    evidence = {r['id']:r for r in event_records}
    decisions = {r['event_id']:r for r in audits}
    states = store.states(source)
    rows = []
    for raw in candidates[-5000:]:
        identity = raw['event_id']
        digest = hashlib.sha256(json.dumps([source,identity,raw.get('timestamp'),raw.get('src_ip'),raw.get('dst_ip')]).encode()).hexdigest()[:32]
        decision = decisions.get(identity)
        event = evidence.get(identity)
        # Live audit files may outlive a capture. Require the same timestamp as well as ID.
        if kind == 'live':
            if decision and timestamp(decision.get('timestamp')) != timestamp(raw.get('timestamp')):
                decision = None
            if event and timestamp(event.get('timestamp')) != timestamp(raw.get('timestamp')):
                event = None
        action = 'suppressed' if decision and int(decision['suppressed_detections']) > 0 and identity not in retained else 'retained'
        active = retained.get(identity,raw)
        rows.append({
            'key':digest, 'event_id':identity, 'timestamp':timestamp(raw.get('timestamp')),
            'source_ip':raw.get('src_ip'), 'destination_ip':raw.get('dst_ip'),
            'protocol':raw.get('protocol') or 'Unknown', 'classification':raw.get('classification') or 'Unclassified',
            'severity':active.get('top_severity','unknown').lower(), 'risk':number(active.get('risk_score')),
            'baseline_risk':number(raw.get('risk_score')), 'latency_ms':number(active.get('latency_ms')),
            'reasons':active.get('reasons',''), 'attack':[i for i in (active.get('attack_techniques') or '').split('|') if i], 'context':action, 'audit':decision, 'evidence':event,
            'lab_reference':truth.get(identity) if kind == 'recorded_lab' else None,
            'triage':states.get(digest,{'status':'Open','owner':'','disposition':'Unreviewed','updated_at':None}),
            'raw':raw,
        })
    assets, flows = {}, {}
    observed = event_records or [{'src_ip':r['source_ip'],'dst_ip':r['destination_ip'],'protocol':r['protocol']} for r in rows]
    for event in observed:
        src, dst = event.get('src_ip'),event.get('dst_ip')
        for endpoint in (src,dst):
            if endpoint:
                assets.setdefault(endpoint, {'ip':endpoint,'requests':0,'alerts':0,'risk':None,'protocols':set()})
                assets[endpoint]['requests'] += 1
                assets[endpoint]['protocols'].add(event.get('protocol','Unknown'))
        if src and dst:
            key = (src,dst,event.get('protocol','Unknown'))
            flows[key] = flows.get(key,0)+1
    for row in rows:
        if row['context'] != 'retained': continue
        for endpoint in (row['source_ip'],row['destination_ip']):
            if endpoint in assets:
                assets[endpoint]['alerts'] += 1
                if row['risk'] is not None: assets[endpoint]['risk'] = max(assets[endpoint]['risk'] or 0,row['risk'])
    for asset in assets.values(): asset['protocols'] = sorted(asset['protocols'])
    stamps = sorted(r['timestamp'] for r in rows if r['timestamp'])
    return {
        'source':{'id':source,'kind':kind,'total':total,'returned':len(rows),'request_count':len(event_records) or None,
                  'from':stamps[0] if stamps else None,'to':stamps[-1] if stamps else None},
        'rows':rows, 'assets':list(assets.values()),
        'flows':[{'source':k[0],'destination':k[1],'protocol':k[2],'count':v} for k,v in flows.items()],
        'policy':policy, 'cases':store.cases(source),
    }
