import csv
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'tools'))
from attack_coverage import SOFTWARE, TECHNIQUES, load_mapping, rule_inventory, split_ids
from siem_elastic import attack_fields


class AttackMappingTests(unittest.TestCase):
    def test_every_rule_is_mapped_with_verified_ids(self):
        mapping = load_mapping(ROOT/'data/attack_mapping.csv')
        self.assertEqual(rule_inventory(ROOT) - {(r['source'], r['indicator']) for r in mapping}, set())
        for row in mapping:
            self.assertTrue(set(split_ids(row['techniques'])) <= set(TECHNIQUES), row)
            self.assertTrue(set(split_ids(row['software'])) <= set(SOFTWARE), row)
            self.assertIn(row['confidence'], {'high', 'medium', 'low', 'none'})
            self.assertEqual(row['confidence'] == 'none', not (row['techniques'] or row['software']), row)

    def test_navigator_layer_uses_ics_domain_and_verified_ids(self):
        layer = json.loads((ROOT/'docs/attack/threatfusion_ics_layer.json').read_text(encoding='utf-8'))
        self.assertEqual((layer['domain'], layer['versions']['layer']), ('ics-attack', '4.5'))
        self.assertTrue({t['techniqueID'] for t in layer['techniques']} <= set(TECHNIQUES))

    def test_ecs_threat_fields_split_techniques_and_software(self):
        self.assertEqual(attack_fields(''), {})
        self.assertEqual(attack_fields('S0603|T1692.001'),
                         {'threat': {'framework': 'MITRE ATT&CK', 'technique': {'id': ['T1692.001']},
                                     'software': {'id': ['S0603']}}})

    def test_cpp_engine_writes_attack_ids_to_alerts(self):
        engine = Path(os.environ.get('THREATFUSION_ENGINE', ROOT/'build-libtorch/Release/threatfusion.exe'))
        self.assertTrue(engine.is_file(), 'Build C++ first and set THREATFUSION_ENGINE if necessary')
        with tempfile.TemporaryDirectory() as folder:
            folder = Path(folder)
            (folder/'events.jsonl').write_text(json.dumps({'id': 'W1', 'protocol': 'modbus', 'function_code': 16,
                                                           'asset_role': 'plc', 'src_ip': '10.0.0.1', 'dst_ip': '10.0.0.2'}) + '\n')
            command = [str(engine), '--events', str(folder/'events.jsonl'), '--format', 'jsonl',
                       '--rules', str(ROOT/'data/behavior_rules.csv'), '--iocs', str(ROOT/'data/iocs.csv'),
                       '--alerts', str(folder/'alerts.csv'), '--incidents', str(folder/'incidents.csv'),
                       '--metrics', str(folder/'metrics.txt')]
            subprocess.run(command + ['--attack-map', str(ROOT/'data/attack_mapping.csv')],
                           check=True, capture_output=True, text=True, timeout=60, cwd=ROOT)
            with (folder/'alerts.csv').open(newline='') as handle:
                self.assertEqual([r['attack_techniques'] for r in csv.DictReader(handle)], ['T1692.001'])
            missing = subprocess.run(command + ['--attack-map', str(folder/'missing.csv')],
                                     capture_output=True, text=True, timeout=60, cwd=ROOT)
            self.assertNotEqual(missing.returncode, 0)


if __name__ == '__main__':
    unittest.main()
