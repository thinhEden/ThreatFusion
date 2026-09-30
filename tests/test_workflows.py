import csv
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from urllib.request import urlopen, Request
from urllib.error import HTTPError

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from normalize_swat import TAGS, convert
from train_lstm_autoencoder import make_windows
from benchmark_msu import metrics
from dashboard_server import DashboardHandler, ThreadingHTTPServer


class WorkflowTests(unittest.TestCase):
    def test_swat_features_scaler_and_duplicates(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            def write(name, label, readings):
                with (root / name).open('w', newline='') as handle:
                    writer = csv.writer(handle)
                    writer.writerow([' Timestamp', *TAGS, 'Normal/Attack'])
                    for second, value in readings:
                        writer.writerow([f'22/12/2015 4:00:{second:02d} PM', *([value] * len(TAGS)), label])
            write('normal.csv', 'Normal', [(0, 1), (1, 3), (1, 3)])
            write('attack.csv', 'Attack', [(2, 5)])
            summary = convert(root / 'normal.csv', root / 'train.jsonl', scaler_path=root / 'scaler.json', fit_scaler=True)
            self.assertEqual(summary['duplicate_rows_removed'], 1)
            convert(root / 'attack.csv', root / 'test.jsonl', scaler_path=root / 'scaler.json')
            event = json.loads((root / 'test.jsonl').read_text())
            self.assertEqual(len(event['extra_features']), 51)
            self.assertEqual(event['extra_features'][0], 2.0)
            self.assertEqual(event['protocol'], 'process')
            self.assertFalse(event['timestamp'].endswith('Z'))
            with self.assertRaisesRegex(ValueError, 'normal rows'):
                convert(root / 'attack.csv', root / 'invalid.jsonl', scaler_path=root / 'bad.json', fit_scaler=True)

    def test_training_windows_do_not_cross_attack_gaps_or_flows(self):
        def event(ip, label='benign'):
            return {'src_ip': ip, 'dst_ip': 'rtu', 'label': label, 'extra_features': [1, 2]}
        events = [event('a'), event('b'), event('a'), event('a', 'malicious'), event('a'), event('b')]
        windows = make_windows(events, 2)
        self.assertEqual(windows.shape, (2, 2, 9))

    def test_metrics_include_false_negative_warmup(self):
        self.assertEqual(metrics(['benign', 'malicious'], [False, False])['FN'], 1)

    def test_dashboard_empty_and_post_clear(self):
        with tempfile.TemporaryDirectory() as folder:
            old_path = DashboardHandler.alerts_file
            DashboardHandler.alerts_file = Path(folder) / 'alerts.csv'
            server = ThreadingHTTPServer(('127.0.0.1', 0), DashboardHandler)
            worker = threading.Thread(target=server.serve_forever)
            worker.start()
            url = f'http://127.0.0.1:{server.server_port}'
            try:
                self.assertEqual(json.load(urlopen(url + '/api/alerts')), [])
                with self.assertRaises(HTTPError) as error:
                    urlopen(url + '/api/clear')
                self.assertEqual(error.exception.code, 405)
                self.assertTrue(json.load(urlopen(Request(url + '/api/clear', method='POST')))['success'])
                self.assertEqual(json.load(urlopen(url + '/api/alerts')), [])
                # A current engine row after Clear must survive strict CSV parsing.
                with DashboardHandler.alerts_file.open('a', newline='') as handle:
                    csv.writer(handle).writerow(['INC-1', 'after-clear', '2026-09-30T10:00:00Z',
                        '10.0.0.1', '10.0.0.2', 'plc', 'modbus', 'Command Injection', 'high',
                        '4.6', '4.2', '0.8', '74', '0.01', 'malicious', 'behavior:BR-001', 'T1692.001'])
                after = json.load(urlopen(url + '/api/alerts'))
                self.assertEqual(len(after), 1)
                self.assertEqual(after[0]['attack_techniques'], 'T1692.001')
                rules = json.load(urlopen(url + '/api/rules'))
                self.assertTrue(rules)
                self.assertTrue(all(row['status'] == 'On disk' for row in rules))
            finally:
                server.shutdown()
                server.server_close()
                worker.join()
                DashboardHandler.alerts_file = old_path

    def test_batch_stream_real_model_parity_and_idle_stop(self):
        engine = Path(os.environ.get('THREATFUSION_ENGINE', ROOT / 'build-libtorch/Release/threatfusion.exe'))
        model = ROOT / 'out/benchmark_msu/command/model.pt'
        self.assertTrue(engine.exists(), 'Build the LibTorch engine before this integration test')
        self.assertTrue(model.exists(), 'Run the MSU benchmark before this integration test')
        with tempfile.TemporaryDirectory() as folder:
            work = Path(folder)
            events = []
            for index in range(20):
                events.append({'id': f'event-{index}', 'src_ip': '10.0.0.1', 'dst_ip': '10.0.0.2',
                               'timestamp': '', 'protocol': 'modbus', 'asset_role': 'rtu', 'function_code': 3,
                               'bytes': 8, 'label': 'malicious', 'extra_features': [30.0] * 5})
            lines = [json.dumps(e) for e in events]
            (work / 'events.jsonl').write_text('\n'.join(lines) + '\n')
            common = [str(engine.resolve()), '--iocs', str(ROOT / 'data/iocs.csv'),
                      '--rules', str(ROOT / 'data/behavior_rules.csv'), '--lstm', str(model)]
            subprocess.run(common + ['--events', str(work / 'events.jsonl'), '--format', 'jsonl'],
                           cwd=work, capture_output=True, check=True, timeout=30)
            with (work / 'out/alerts.csv').open() as handle:
                batch = list(csv.DictReader(handle))
            self.assertTrue(batch, 'Large process changes must trigger model inference')
            probe = socket.socket()
            probe.bind(('127.0.0.1', 0))
            port = probe.getsockname()[1]
            probe.close()
            process = subprocess.Popen(common + ['--mode', 'stream', '--port', str(port)], cwd=work,
                                       stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            client = None
            try:
                for _ in range(50):
                    try:
                        client = socket.create_connection(('127.0.0.1', port), timeout=.1)
                        break
                    except OSError:
                        time.sleep(.1)
                self.assertIsNotNone(client)
                payload = ('{}\n' + '\n'.join(lines) + '\n').encode()
                client.sendall(payload[:71])
                client.sendall(payload[71:])
                expected = len(batch)
                for _ in range(60):
                    path = work / 'out/alerts_stream.csv'
                    if path.exists() and len(path.read_text().splitlines()) >= expected + 1:
                        break
                    time.sleep(.05)
                # Keep the client connected: stop must interrupt blocked recv().
                try:
                    stdout, stderr = process.communicate('\n', timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    stdout, stderr = process.communicate()
                    self.fail(f'Idle stop hung. stdout={stdout!r} stderr={stderr!r}')
                self.assertEqual(process.returncode, 0, stderr)
                self.assertEqual(stderr.count('Rejected event'), 1, stderr)
                with path.open() as handle:
                    stream = list(csv.DictReader(handle))
                project = lambda rows: [(r['event_id'], r['risk_score'], r['reasons']) for r in rows]
                self.assertEqual(project(batch), project(stream))
            finally:
                if client is not None:
                    client.close()
                if process.poll() is None:
                    process.kill()
                    process.communicate()

    def test_stream_alert_log_survives_dashboard_clear_and_stats_count_events(self):
        # The engine keeps out/alerts_stream.csv open; the dashboard's Clear truncates it to a header.
        from dashboard_server import HEADERS
        engine = Path(os.environ.get('THREATFUSION_ENGINE', ROOT / 'build-libtorch/Release/threatfusion.exe'))
        self.assertTrue(engine.exists(), 'Build the engine before this integration test')
        with tempfile.TemporaryDirectory() as folder:
            work = Path(folder)
            probe = socket.socket()
            probe.bind(('127.0.0.1', 0))
            port = probe.getsockname()[1]
            probe.close()
            process = subprocess.Popen([str(engine.resolve()), '--mode', 'stream', '--port', str(port),
                                        '--iocs', str(ROOT / 'data/iocs.csv'), '--rules', str(ROOT / 'data/behavior_rules.csv'),
                                        '--stats', str(work / 'stats.csv'), '--stats-interval', '0.2'],
                                       cwd=work, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            write = lambda i: json.dumps({'id': f'write-{i}', 'src_ip': '10.0.0.5', 'dst_ip': '10.0.0.9', 'timestamp': '',
                                          'protocol': 'modbus', 'asset_role': 'plc', 'function_code': 16, 'bytes': 12}) + '\n'
            path = work / 'out/alerts_stream.csv'

            def rows(count):
                for _ in range(100):
                    if path.exists():
                        with path.open(newline='') as handle:
                            found = list(csv.DictReader(handle))
                        if len(found) >= count:
                            return found
                    time.sleep(.05)
                self.fail(f'Expected {count} stream alerts')

            client = None
            try:
                for _ in range(50):
                    try:
                        client = socket.create_connection(('127.0.0.1', port), timeout=.1)
                        break
                    except OSError:
                        time.sleep(.1)
                self.assertIsNotNone(client)
                client.sendall((write(1) + write(2)).encode())
                self.assertEqual([r['event_id'] for r in rows(2)], ['write-1', 'write-2'])
                path.write_text(HEADERS + '\n', encoding='utf-8')
                client.sendall(write(3).encode())
                cleared = rows(1)
                self.assertEqual([r['event_id'] for r in cleared], ['write-3'])
                self.assertEqual(path.read_text(encoding='utf-8').splitlines()[0], HEADERS)
                stdout, stderr = process.communicate('\n', timeout=10)
                self.assertEqual(process.returncode, 0, stderr)
                with (work / 'stats.csv').open(newline='') as handle:
                    last = list(csv.DictReader(handle))[-1]
                self.assertEqual((last['events'], last['alerts']), ('3', '3'))
                self.assertGreater(float(last['detect_ms_total']), 0)
            finally:
                if client is not None:
                    client.close()
                if process.poll() is None:
                    process.kill()
                    process.communicate()

    def test_stats_export_is_stream_only(self):
        engine = Path(os.environ.get('THREATFUSION_ENGINE', ROOT / 'build-libtorch/Release/threatfusion.exe'))
        result = subprocess.run([str(engine), '--stats', 'x.csv'], capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 1)
        self.assertIn('--stats is a stream-mode export', result.stderr)


if __name__ == '__main__':
    unittest.main()
