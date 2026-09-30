"""Local dashboard API. Serves only measured alerts and on-disk rule definitions."""
import argparse
import csv
import hashlib
import mimetypes
import shutil
import io
import json
import re
import threading
from collections import deque
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs
from dashboard_store import WorkspaceStore
from dashboard_data import snapshot, json_data

ROOT = Path(__file__).resolve().parents[1]
HEADERS = 'incident_id,event_id,timestamp,src_ip,dst_ip,asset_role,protocol,classification,top_severity,asset_criticality,threat_severity,confidence_score,risk_score,latency_ms,verdict,reasons'
LOG_LOCK = threading.Lock()


def read_alerts(path, limit=5000):
    if not path.exists():
        return [], 0
    with LOG_LOCK, path.open(encoding='utf-8', newline='') as handle:
        text = handle.read()
    # The producer may still be appending the final physical line.
    if text and not text.endswith('\n'):
        text = text[:text.rfind('\n') + 1]
    rows = deque(maxlen=limit)
    total = 0
    for row in csv.DictReader(io.StringIO(text)):
        if None in row or any(v is None for v in row.values()):
            continue
        if row.get('event_id'):
            rows.append(row)
            total += 1
    return list(rows), total


def rule_registry():
    rules = []
    with (ROOT / 'data/behavior_rules.csv').open(encoding='utf-8', newline='') as handle:
        for row in csv.DictReader(handle):
            rules.append({'id': row['id'], 'name': row['name'], 'type': 'Behavior',
                          'category': row['tactic'], 'status': 'On disk',
                          'description': row['description'], 'syntax': row['conditions']})
    for path in (ROOT / 'rules').rglob('*.yar'):
        for match in re.finditer(r'^rule\s+(\w+).*?^}', path.read_text(), re.MULTILINE | re.DOTALL):
            rules.append({'id': match[1], 'name': match[1], 'type': 'YARA',
                          'category': 'File signature', 'status': 'On disk',
                          'description': str(path.relative_to(ROOT)), 'syntax': match[0]})
    for path in (ROOT / 'rules/suricata').glob('*.rules'):
        for line in path.read_text().splitlines():
            if line.startswith('alert '):
                sid = re.search(r'sid:(\d+)', line)
                msg = re.search(r'msg:"([^"]+)"', line)
                rules.append({'id': sid[1] if sid else path.name, 'name': msg[1] if msg else path.name,
                              'type': 'Suricata', 'category': 'Network signature', 'status': 'On disk',
                              'description': str(path.relative_to(ROOT)), 'syntax': line})
    return rules


class DashboardHandler(SimpleHTTPRequestHandler):
    alerts_file = ROOT / 'out/alerts_stream.csv'
    portfolio_dir = ROOT / 'out/portfolio_demo'
    state_file = ROOT / 'out/dashboard_state.sqlite3'
    imports_dir = ROOT / 'out/dashboard_imports'
    events_file = None
    audit_file = None
    default_source = 'live'

    def store(self):
        return WorkspaceStore(self.state_file)

    def workspace(self, source):
        if source not in ('live','main','challenge') and not re.fullmatch(r'import-[a-f0-9]{16}',source):
            raise ValueError('Invalid source')
        live, total = read_alerts(self.alerts_file) if source == 'live' else ([],0)
        return snapshot(source,self.portfolio_dir,live,total,self.store(),self.imports_dir,self.events_file,self.audit_file)

    def sources(self):
        rows = [{'id':'live','label':'Live stream','kind':'live','available':True}]
        rows += [{'id':capture,'label':'Lab / '+capture,'kind':'recorded_lab',
                  'available':(self.portfolio_dir/f'{capture}_baseline.alerts.csv').exists()} for capture in ('main','challenge')]
        rows += [{'id':row['id'],'label':row['name'],'kind':'imported','available':True} for row in self.store().imports()]
        return {'sources':rows,'default_source':self.default_source}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT / 'dashboard'), **kwargs)

    def json_response(self, body, status=200, total=None):
        data = json.dumps(body).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        if total is not None:
            self.send_header('X-Total-Alerts', str(total))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        try:
            self.get_route()
        except (ValueError, KeyError) as error:
            self.json_response({'error':str(error)},400)
        except FileNotFoundError as error:
            self.json_response({'error':str(error)},404)
        except OSError:
            self.json_response({'error':'Evidence storage unavailable'},503)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def get_route(self):
        route = urlparse(self.path).path
        query = parse_qs(urlparse(self.path).query)
        source = query.get('source',['live'])[0]
        if route == '/api/sources':
            self.json_response(self.sources())
        elif route == '/api/workspace':
            self.json_response(self.workspace(source))
        elif route == '/api/history':
            key = query.get('key',[''])[0]
            self.json_response(self.store().history(key))
        elif route == '/api/research':
            report = json_data(self.portfolio_dir/'report.json',None)
            if report is None: raise FileNotFoundError('Run the portfolio experiment to generate research results')
            self.json_response({'report':report,'verified_at':(self.portfolio_dir/'report.json').stat().st_mtime,
                                'has_video':(self.portfolio_dir/'portfolio_demo.webm').exists()})
        elif route.startswith('/api/artifacts/'):
            name = route.removeprefix('/api/artifacts/')
            allowed = {'main.pcap','challenge.pcap','case_study.md','report.md','report.json','portfolio_demo.webm','policy.json','experiment.png'}
            if name not in allowed: raise ValueError('Unknown evidence artifact')
            path = self.portfolio_dir/name
            if not path.is_file(): raise FileNotFoundError('Evidence artifact unavailable')
            self.send_response(200)
            self.send_header('Content-Type',mimetypes.guess_type(name)[0] or 'application/octet-stream')
            self.send_header('Content-Length',str(path.stat().st_size))
            self.send_header('Content-Disposition',f'inline; filename="{name}"')
            self.end_headers()
            with path.open('rb') as handle: shutil.copyfileobj(handle,self.wfile)
        elif route == '/api/alerts':
            rows, total = read_alerts(self.alerts_file)
            self.json_response(rows, total=total)
        elif route == '/api/rules':
            self.json_response(rule_registry())
        elif route == '/api/clear':
            self.json_response({'error': 'Use POST'}, 405)
        else:
            super().do_GET()

    def do_POST(self):
        origin = self.headers.get('Origin')
        if origin and urlparse(origin).netloc != self.headers.get('Host'):
            self.json_response({'error': 'Origin mismatch'}, 403)
            return
        try:
            self.post_route()
        except (ValueError, KeyError, TypeError) as error:
            self.json_response({'error':str(error)},400)
        except FileNotFoundError:
            self.json_response({'error':'Evidence source is unavailable'},404)

    def post_route(self):
        route = urlparse(self.path).path
        if route == '/api/clear':
            with LOG_LOCK:
                self.alerts_file.parent.mkdir(parents=True, exist_ok=True)
                self.alerts_file.write_text(HEADERS + '\n', encoding='utf-8')
            self.json_response({'success':True})
            return
        length = int(self.headers.get('Content-Length','0'))
        if length < 1 or length > 5_000_000: raise ValueError('Invalid request size')
        body = json.loads(self.rfile.read(length))
        if not isinstance(body,dict): raise ValueError('Expected a JSON object')
        if route == '/api/import':
            text = body.get('csv','').lstrip('\ufeff')
            reader = csv.DictReader(io.StringIO(text))
            if not reader.fieldnames or not {'event_id','timestamp','src_ip','dst_ip','risk_score'}.issubset(reader.fieldnames):
                raise ValueError('Import requires an engine alerts CSV with event_id, timestamp, src_ip, dst_ip and risk_score')
            rows = list(reader)
            if len(rows) > 5000 or any(None in r or any(v is None for v in r.values()) for r in rows):
                raise ValueError('Import must contain at most 5,000 complete rows')
            identity = 'import-'+hashlib.sha256(text.encode()).hexdigest()[:16]
            self.imports_dir.mkdir(parents=True,exist_ok=True)
            (self.imports_dir/f'{identity}.csv').write_text(text,encoding='utf-8')
            self.store().add_import(identity,str(body.get('name','Imported alerts'))[:100])
            self.json_response({'source':identity})
            return
        source = str(body.get('source',''))
        data = self.workspace(source)
        valid_keys = {r['key'] for r in data['rows']}
        keys = body.get('keys',[])
        if not isinstance(keys,list) or len(keys)>100 or any(not isinstance(k,str) or k not in valid_keys for k in keys):
            raise ValueError('Selected evidence is not in this source')
        keys = list(dict.fromkeys(keys))
        owner, actor, note = str(body.get('owner','')).strip(),str(body.get('actor','Local analyst')).strip(),str(body.get('note','')).strip()
        if len(owner)>80 or not actor or len(actor)>80 or len(note)>4000:
            raise ValueError('Owner/actor limited to 80 characters; notes to 4,000')
        if route == '/api/triage':
            self.store().update(source,keys,body.get('status','Open'),owner,body.get('disposition','Unreviewed'),note,actor)
            self.json_response({'success':True})
        elif route == '/api/cases':
            title = str(body.get('title',''))
            if len(title)>160: raise ValueError('Case title limited to 160 characters')
            identity = self.store().create_case(source,keys,title,owner,note,actor)
            self.json_response({'success':True,'id':identity})
        elif route == '/api/case-update':
            self.store().update_case(int(body['id']),source,body.get('status','Open'),owner,note,actor)
            self.json_response({'success':True})
        else:
            self.json_response({'error':'Not found'},404)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=8000)
    parser.add_argument('--alerts-file', type=Path, default=DashboardHandler.alerts_file)
    parser.add_argument('--portfolio-dir',type=Path,default=DashboardHandler.portfolio_dir)
    parser.add_argument('--state-file',type=Path,default=DashboardHandler.state_file)
    parser.add_argument('--imports-dir',type=Path,default=DashboardHandler.imports_dir)
    parser.add_argument('--events-file',type=Path)
    parser.add_argument('--audit-file',type=Path)
    parser.add_argument('--default-source',choices=['live','main','challenge'],default='live')
    args = parser.parse_args()
    DashboardHandler.alerts_file = args.alerts_file.resolve()
    DashboardHandler.portfolio_dir = args.portfolio_dir.resolve()
    DashboardHandler.state_file = args.state_file.resolve()
    DashboardHandler.imports_dir = args.imports_dir.resolve()
    DashboardHandler.events_file = args.events_file
    DashboardHandler.audit_file = args.audit_file
    DashboardHandler.default_source = args.default_source
    with ThreadingHTTPServer((args.host, args.port), DashboardHandler) as server:
        print(f'Dashboard: http://{args.host}:{args.port}', flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == '__main__':
    main()
