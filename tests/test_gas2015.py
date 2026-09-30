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
from benchmark_gas2015 import derive_envelope
from normalize_gas2015 import read_arff, to_event, write_split

ATTRIBUTES = ['address', 'function', 'length', 'setpoint', 'gain', 'reset rate', 'deadband', 'cycle time', 'rate',
              'system mode', 'control scheme', 'pump', 'solenoid', 'pressure measurement', 'crc rate',
              'command response', 'time', 'binary result', 'categorized result', 'specific result']
ROWS = ['4,3,16,?,?,?,?,?,?,?,?,?,?,?,12869,1,1418682163.170388,0,0,0',
        '4,3,46,?,?,?,?,?,?,?,?,?,?,0.689655,12356,0,1418682163.269946,0,0,0',
        '4,16,90,10,115,0.2,0.5,1,0,0,1,0,0,?,17219,1,1418682164.995592,0,0,0',
        '4,16,90,12,113,0.3,0.4,0.9,0,2,0,1,1,?,17219,1,1418682165.5,0,0,0',
        '4,16,90,10,66,0.2,0.5,1,0,0,1,0,0,?,17219,1,1418682166.0,1,4,3']


def fixture(folder):
    path = Path(folder)/'gas.arff'
    header = ['@relation gas', ''] + [f"@attribute '{name}' real" for name in ATTRIBUTES] + ['@data']
    path.write_text('\n'.join(header + ROWS) + '\n', encoding='utf-8')
    return list(read_arff(path))


class GasPipeline2015Tests(unittest.TestCase):
    def test_events_carry_no_labels_and_keep_direction(self):
        with tempfile.TemporaryDirectory() as folder:
            rows = fixture(folder)
            command, response = to_event(rows[0], 1), to_event(rows[1], 2)
            self.assertNotIn('label', command)
            self.assertEqual((command['asset_role'], command['is_request'], command['src_ip']), ('plc', True, '10.0.0.1'))
            self.assertEqual((response['asset_role'], response['is_request']), ('hmi', False))
            self.assertEqual(command['process_values'], {})
            self.assertEqual(response['process_values'], {'pressure measurement': 0.689655})
            self.assertEqual(command['timestamp'], '2014-12-15T22:22:43Z')
            write_split(enumerate(rows, 1), Path(folder)/'events.jsonl', Path(folder)/'truth.csv')
            self.assertNotIn('malicious', (Path(folder)/'events.jsonl').read_text())
            with (Path(folder)/'truth.csv').open(newline='') as handle:
                truth = list(csv.DictReader(handle))
            self.assertEqual((truth[4]['label'], truth[4]['category']), ('malicious', 'MPCI'))

    def test_envelope_uses_value_sets_for_states_and_ranges_for_tuning(self):
        with tempfile.TemporaryDirectory() as folder:
            rows = fixture(folder)
            envelope = derive_envelope(rows[2:4], retain_state_changes=False)['operating_envelope']
            self.assertEqual(envelope['unit_id'], 4)
            self.assertEqual(envelope['parameters']['system mode'], {'values': [0.0, 2.0]})
            self.assertEqual(envelope['parameters']['gain'], {'min': 113.0, 'max': 115.0})
            with self.assertRaises(ValueError):
                derive_envelope(rows[:1], retain_state_changes=False)  # A read command has no control parameters.

    def test_cpp_engine_downgrades_only_writes_inside_envelope(self):
        engine = Path(os.environ.get('THREATFUSION_ENGINE', ROOT/'build-libtorch/Release/threatfusion.exe'))
        self.assertTrue(engine.is_file(), 'Build C++ first and set THREATFUSION_ENGINE if necessary')
        with tempfile.TemporaryDirectory() as folder:
            rows, folder = fixture(folder), Path(folder)
            (folder/'policy.json').write_text(json.dumps(derive_envelope(rows[2:4], retain_state_changes=False)))
            write_split([(3, rows[2]), (5, rows[4])], folder/'events.jsonl', folder/'truth.csv')
            subprocess.run([str(engine), '--events', str(folder/'events.jsonl'), '--format', 'jsonl',
                            '--rules', str(ROOT/'data/behavior_rules.csv'), '--iocs', str(ROOT/'data/iocs.csv'),
                            '--context', str(folder/'policy.json'), '--context-audit', str(folder/'audit.csv'),
                            '--alerts', str(folder/'alerts.csv'), '--incidents', str(folder/'incidents.csv'),
                            '--metrics', str(folder/'metrics.txt')],
                           check=True, capture_output=True, text=True, timeout=60, cwd=ROOT)
            with (folder/'alerts.csv').open(newline='') as handle:
                self.assertEqual([r['event_id'] for r in csv.DictReader(handle)], ['GP15-5'])
            with (folder/'audit.csv').open(newline='') as handle:
                reasons = {r['event_id']: r['reason'] for r in csv.DictReader(handle)}
            self.assertEqual(reasons['GP15-3'], 'Write inside commissioned operating envelope')
            self.assertEqual(reasons['GP15-5'], 'Parameter outside operating envelope: gain')


if __name__ == '__main__':
    unittest.main()
