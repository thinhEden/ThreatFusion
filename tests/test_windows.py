import csv
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'tools'))
from attack_coverage import ENTERPRISE
from normalize_windows_events import to_ecs


class WindowsNormalizationTests(unittest.TestCase):
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

    def test_enterprise_layer_is_valid(self):
        layer = json.loads((ROOT/'docs/attack/threatfusion_enterprise_layer.json').read_text(encoding='utf-8'))
        self.assertEqual((layer['domain'], layer['versions']['layer']), ('enterprise-attack', '4.5'))
        self.assertTrue({t['techniqueID'] for t in layer['techniques']} <= set(ENTERPRISE))


if __name__ == '__main__':
    unittest.main()
