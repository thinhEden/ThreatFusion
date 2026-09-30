"""Local analyst workflow state, separate from detector evidence and labels."""
from contextlib import contextmanager
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3

STATUSES = {'Open', 'Investigating', 'Closed'}
DISPOSITIONS = {'Unreviewed', 'True positive', 'False positive', 'Benign activity', 'Undetermined'}


def now():
    return datetime.now(timezone.utc).isoformat()


class WorkspaceStore:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connection() as db:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS triage (
                  key TEXT PRIMARY KEY, source TEXT NOT NULL, status TEXT NOT NULL,
                  owner TEXT NOT NULL, disposition TEXT NOT NULL, updated_at TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS history (
                  id INTEGER PRIMARY KEY, key TEXT NOT NULL, actor TEXT NOT NULL,
                  action TEXT NOT NULL, note TEXT NOT NULL, created_at TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS cases (
                  id INTEGER PRIMARY KEY, source TEXT NOT NULL, title TEXT NOT NULL,
                  owner TEXT NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL,
                  updated_at TEXT NOT NULL, alert_keys TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS imports (
                  id TEXT PRIMARY KEY, name TEXT NOT NULL, created_at TEXT NOT NULL);
            ''')

    @contextmanager
    def connection(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def states(self, source):
        with self.connection() as db:
            return {r['key']: dict(r) for r in db.execute('SELECT * FROM triage WHERE source=?', (source,))}

    def history(self, key):
        with self.connection() as db:
            return [dict(r) for r in db.execute('SELECT * FROM history WHERE key=? ORDER BY id DESC LIMIT 100', (key,))]

    def update(self, source, keys, status, owner, disposition, note, actor):
        if status not in STATUSES or disposition not in DISPOSITIONS:
            raise ValueError('Invalid workflow state')
        if status == 'Closed' and (disposition == 'Unreviewed' or not note.strip()):
            raise ValueError('Closing requires a disposition and investigation note')
        if not keys or len(keys) > 100:
            raise ValueError('Select between 1 and 100 alerts')
        stamp = now()
        with self.connection() as db:
            for key in keys:
                before = db.execute('SELECT * FROM triage WHERE key=?', (key,)).fetchone()
                db.execute('INSERT OR REPLACE INTO triage VALUES (?,?,?,?,?,?)',
                           (key, source, status, owner, disposition, stamp))
                action = f"{before['status'] if before else 'Open'} -> {status}; owner: {owner or 'Unassigned'}; {disposition}"
                db.execute('INSERT INTO history(key,actor,action,note,created_at) VALUES (?,?,?,?,?)',
                           (key, actor, action, note, stamp))

    def cases(self, source):
        with self.connection() as db:
            rows = [dict(r) for r in db.execute('SELECT * FROM cases WHERE source=? ORDER BY id DESC', (source,))]
        for row in rows:
            row['alert_keys'] = json.loads(row['alert_keys'])
            row['case_id'] = f"CASE-{row['id']:04d}"
        return rows

    def create_case(self, source, keys, title, owner, note, actor):
        if not title.strip() or not keys:
            raise ValueError('Case title and at least one alert are required')
        stamp = now()
        with self.connection() as db:
            result = db.execute('INSERT INTO cases(source,title,owner,status,created_at,updated_at,alert_keys) VALUES (?,?,?,?,?,?,?)',
                                (source, title.strip(), owner, 'Open', stamp, stamp, json.dumps(keys)))
            case_id = result.lastrowid
            db.execute('INSERT INTO history(key,actor,action,note,created_at) VALUES (?,?,?,?,?)',
                       (f'case:{case_id}', actor, 'Case created', note, stamp))
        return case_id

    def update_case(self, case_id, source, status, owner, note, actor):
        if status not in STATUSES or not note.strip():
            raise ValueError('A valid status and update note are required')
        with self.connection() as db:
            existing = db.execute('SELECT * FROM cases WHERE id=? AND source=?', (case_id,source)).fetchone()
            if not existing:
                raise ValueError('Case not found in this source')
            stamp = now()
            db.execute('UPDATE cases SET status=?,owner=?,updated_at=? WHERE id=?', (status,owner,stamp,case_id))
            db.execute('INSERT INTO history(key,actor,action,note,created_at) VALUES (?,?,?,?,?)',
                       (f'case:{case_id}',actor,f"{existing['status']} -> {status}; owner: {owner or 'Unassigned'}",note,stamp))

    def imports(self):
        with self.connection() as db:
            return [dict(r) for r in db.execute('SELECT * FROM imports ORDER BY created_at DESC')]

    def add_import(self, identity, name):
        with self.connection() as db:
            db.execute('INSERT OR REPLACE INTO imports VALUES (?,?,?)', (identity,name,now()))
