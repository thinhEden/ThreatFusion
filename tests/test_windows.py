import csv
import json
from pathlib import Path
import sys
import unittest
import tempfile
import subprocess
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'tools'))
from attack_coverage import ENTERPRISE
from normalize_windows_events import to_ecs, read_evtx, read_capture


class WindowsNormalizationTests(unittest.TestCase):
    def test_evtx_reader_preserves_adjacent_script_on_failure(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / 'capture.evtx'
            sibling = source.with_suffix('.read.ps1')
            sibling.write_text('user script')
            scripts = []
            def fail(command, **kwargs):
                script = Path(command[command.index('-File') + 1])
                scripts.append(script)
                self.assertNotEqual(script.parent, source.parent)
                self.assertTrue(script.is_file())
                raise subprocess.CalledProcessError(1, command)
            with patch('normalize_windows_events.subprocess.run', side_effect=fail):
                with self.assertRaises(subprocess.CalledProcessError):
                    list(read_evtx(source))
            self.assertEqual(sibling.read_text(), 'user script')
            self.assertFalse(scripts[0].exists())

    def test_process_fields_come_from_sysmon_4688_and_access_events(self):
        sysmon = to_ecs({'@timestamp': '2020-09-04T20:09:57.060Z', 'EventID': 1, 'Channel': 'Microsoft-Windows-Sysmon/Operational',
                         'Hostname': 'WS5', 'Image': 'C:\\Windows\\System32\\powershell.exe', 'CommandLine': 'powershell -enc AAA',
                         'ParentImage': 'C:\\Windows\\System32\\wscript.exe'}, 'capture')
        self.assertEqual((sysmon['process']['name'], sysmon['process']['parent']['name']), ('powershell.exe', 'wscript.exe'))
        self.assertEqual((sysmon['event']['code'], sysmon['threatfusion']['dataset']), ('1', 'capture'))
        security = to_ecs({'EventID': 4688, 'Channel': 'security', 'Hostname': 'WS5', 'TimeCreated': '2020-10-18 07:50:05.910',
                           'NewProcessName': 'C:\\Windows\\System32\\rundll32.exe', 'CommandLine': 'rundll32 comsvcs.dll MiniDump'}, 'c')
        self.assertEqual(security['winlog']['channel'], 'Security')
        self.assertEqual(security['@timestamp'], '2020-10-18T07:50:05.910000Z')
        self.assertEqual(security['process']['name'], 'rundll32.exe')
        access = to_ecs({'EventID': 10, 'Channel': 'Microsoft-Windows-Sysmon/Operational', 'Hostname': 'WS5', '@timestamp': 'x',
                         'SourceImage': 'C:\\Windows\\System32\\rundll32.exe', 'TargetImage': 'C:\\Windows\\system32\\lsass.exe',
                         'GrantedAccess': '0x1410'}, 'c')
        self.assertEqual((access['process']['name'], access['winlog']['event_data']['GrantedAccess']), ('rundll32.exe', '0x1410'))
        raw = {'EventID': 7045, 'Channel': 'System', 'Hostname': 'WS6', '@timestamp': 'x', 'ImagePath': '%COMSPEC% /C'}
        service = to_ecs(raw, 'c')
        self.assertNotIn('process', service)
        # Triage keys on event.id, so it must be stable per raw event and differ between events.
        self.assertEqual(service['event']['id'], to_ecs(dict(raw), 'c')['event']['id'])
        self.assertNotEqual(service['event']['id'], to_ecs(dict(raw, ImagePath='other'), 'c')['event']['id'])


    def test_ecs_fields_used_by_playbook_hunting_queries(self):
        failure = to_ecs({'@timestamp': 'x', 'EventID': 4625, 'Channel': 'Security', 'Hostname': 'WIN', 'TargetUserName': 'Admin',
                          'IpAddress': '-', 'SubStatus': '0xc000006a'}, 'c')
        self.assertEqual((failure['event']['category'], failure['event']['outcome'], failure['user']['name']),
                         (['authentication'], 'failure', 'Admin'))
        self.assertNotIn('source', failure)
        ticket = to_ecs({'@timestamp': 'x', 'EventID': 4769, 'Channel': 'Security', 'Hostname': 'DC',
                         'TargetUserName': 'admmig@OFFSEC.LAN', 'IpAddress': '::ffff:10.23.23.9', 'Status': '0x0'}, 'c')
        self.assertEqual((ticket['source']['ip'], ticket['user'], ticket['event']['outcome']),
                         ('10.23.23.9', {'name': 'admmig', 'domain': 'OFFSEC.LAN'}, 'success'))
        drop = to_ecs({'@timestamp': 'x', 'EventID': 11, 'Channel': 'Microsoft-Windows-Sysmon/Operational', 'Hostname': 'WS',
                       'TargetFilename': 'C:\\Users\\bob\\Downloads\\Invoice.HTA'}, 'c')
        self.assertEqual(drop['file'], {'path': 'C:\\Users\\bob\\Downloads\\Invoice.HTA', 'name': 'Invoice.HTA', 'extension': 'hta'})
        query = to_ecs({'@timestamp': 'x', 'EventID': 22, 'Channel': 'Microsoft-Windows-Sysmon/Operational', 'Hostname': 'WS',
                        'QueryName': 'example.org'}, 'c')
        self.assertEqual((query['dns']['question']['name'], query['event']['category']), ('example.org', ['network']))

    def test_splunk_xml_log_reader(self):
        line = ("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>4776</EventID>"
                "<TimeCreated SystemTime='2022-09-08T18:59:42.379857000Z'/><Channel>Security</Channel><Computer>dc.lab</Computer>"
                "</System><EventData><Data Name='TargetUserName'>JZLBZIIN</Data><Data Name='Workstation'>WIN-HOST</Data>"
                "<Data Name='Status'>0xc0000064</Data></EventData></Event>\n")
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'capture.log'
            path.write_text(line, encoding='utf-8')
            [document] = list(read_capture(path))
        self.assertEqual((document['event']['code'], document['host']['name'], document['threatfusion']['dataset']),
                         ('4776', 'dc.lab', 'capture'))
        self.assertEqual((document['winlog']['event_data']['Workstation'], document['event']['outcome']), ('WIN-HOST', 'failure'))
        self.assertEqual(document['@timestamp'], '2022-09-08T18:59:42.379857000Z')


class WindowsRuleTests(unittest.TestCase):
    rules = json.loads((ROOT/'siem/elastic/windows_rules.json').read_text(encoding='utf-8'))

    def test_rules_use_verified_attack_ids_and_document_false_positives(self):
        self.assertEqual(len({r['id'] for r in self.rules}), len(self.rules))
        for rule in self.rules:
            self.assertTrue(set(rule['techniques']) <= set(ENTERPRISE), rule['id'])
            self.assertTrue(rule['false_positives'], rule['id'])
            prefix = {'eql': 'any where', 'esql': 'FROM threatfusion-windows-otrf'}[rule['language']]
            self.assertTrue(rule['query'].startswith(prefix), rule['id'])

    def test_every_reported_hit_has_an_analyst_disposition(self):
        report = json.loads((ROOT/'docs/benchmarks/windows_detection_report.json').read_text(encoding='utf-8'))
        with (ROOT/'docs/benchmarks/windows_triage.csv').open(newline='', encoding='utf-8') as handle:
            triage = {(r['rule_id'], r['event_id']): r for r in csv.DictReader(handle)}
        hits = {(rule, h['event_id']) for rule, rule_hits in report['hits'].items() for h in rule_hits}
        self.assertEqual(hits, set(triage))
        self.assertTrue(all(r['disposition'] in {'TP', 'FP'} and r['reason'] for r in triage.values()))

    def test_hunting_queries_resolve_and_compare(self):
        from validate_hunting_queries import compare, resolve
        entries = json.loads((ROOT/'siem/elastic/hunting_queries.json').read_text(encoding='utf-8'))
        self.assertEqual(len({e['id'] for e in entries}), len(entries))
        for entry in entries:
            query = resolve(entry['query'], entry.get('parameters'))
            self.assertNotIn('<host', query, entry['id'])
            self.assertIn(entry['language'], {'kql', 'eql'})
            self.assertTrue(entry['expect'] or 'control' in entry or entry.get('note'), entry['id'])
        with self.assertRaises(ValueError):
            resolve('host.name: "<host>"', {})
        self.assertTrue(compare({'a': 2}, {'a': 2}))
        self.assertFalse(compare({'a': 2}, {'a': 2, 'b': 1}))
        self.assertTrue(compare({'a': 2}, {'a': 6}, minimum=True))
        self.assertFalse(compare({'a': 2}, {'a': 6, 'b': 1}, minimum=True))

    def test_enterprise_layer_is_valid(self):
        layer = json.loads((ROOT/'docs/attack/threatfusion_enterprise_layer.json').read_text(encoding='utf-8'))
        self.assertEqual((layer['domain'], layer['versions']['layer']), ('enterprise-attack', '4.5'))
        self.assertTrue({t['techniqueID'] for t in layer['techniques']} <= set(ENTERPRISE))


if __name__ == '__main__':
    unittest.main()
