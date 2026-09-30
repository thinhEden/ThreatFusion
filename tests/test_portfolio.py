import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'tools'))
from generate_ot_case import generate
from portfolio_demo import confusion
from siem_elastic import ecs_document, utc_timestamp


class PortfolioTests(unittest.TestCase):
    def test_deterministic_offline_capture(self):
        with tempfile.TemporaryDirectory() as directory:
            first, second = Path(directory)/'first', Path(directory)/'second'
            generate(first)
            generate(second)
            for capture in ('main', 'challenge'):
                self.assertEqual(hashlib.sha256((first/f'{capture}.pcap').read_bytes()).digest(),
                                 hashlib.sha256((second/f'{capture}.pcap').read_bytes()).digest())
            self.assertEqual(len(json.loads((first/'main_ground_truth.json').read_text())), 340)

    def test_ground_truth_is_only_an_evaluation_input(self):
        truth = [{'event_id':'packet','label':'malicious'}]
        self.assertEqual(confusion(truth, [])['FN'], 1)
        self.assertEqual(confusion(truth, [{'event_id':'packet','risk_score':'74'}])['TP'], 1)

    def test_ecs_utc_and_no_ground_truth(self):
        alert = {'event_id':'PCAP-1','timestamp':'1790762400','src_ip':'10.50.1.20','dst_ip':'10.50.2.10',
                 'protocol':'modbus','risk_score':'74','reasons':'BR-001','classification':'Command Injection',
                 'incident_id':'INC-1','latency_ms':'0','verdict':'malicious'}
        event = {'function_code':6,'unit_id':1,'register_address':100,'register_values':[55],'label':'malicious'}
        document = ecs_document(alert,event,'baseline','main')
        self.assertEqual(document['@timestamp'],'2026-09-30T10:00:00+00:00')
        self.assertEqual(document['threatfusion']['latency_ms'],0)
        self.assertNotIn('label',json.dumps(document))
        with self.assertRaises(ValueError):
            utc_timestamp('2026-09-30T10:00:00')

    def test_actual_cpp_pcap_ablation(self):
        engine = Path(os.environ.get('THREATFUSION_ENGINE',ROOT/'build-libtorch/Release/threatfusion.exe'))
        self.assertTrue(engine.is_file(), 'Build C++ first and set THREATFUSION_ENGINE if necessary')
        with tempfile.TemporaryDirectory() as folder:
            subprocess.run([sys.executable,str(ROOT/'tools/portfolio_demo.py'),'--engine',str(engine),'--output',folder],
                           check=True,capture_output=True,text=True,timeout=120,cwd=ROOT)
            report = json.loads((Path(folder)/'report.json').read_text())
            main = report['captures']['main']
            self.assertEqual(main['baseline']['metrics']['FP'],60)
            self.assertEqual(main['bounded']['metrics']['FP'],0)
            self.assertEqual(main['bounded']['metrics']['TP'],80)
            self.assertEqual(main['bounded']['metrics']['FN'],0)
            self.assertEqual(main['peer-only']['metrics']['FN'],50)
            self.assertEqual(report['captures']['challenge']['bounded']['metrics']['FN'],5)
            self.assertEqual(main['bounded']['suppressed_candidates'],60)
            # A host alert on the workstation at 10:01:30Z recovers the challenge and re-opens later maintenance writes.
            challenge = report['captures']['challenge']
            self.assertEqual((challenge['bounded-host']['metrics']['TP'], challenge['bounded-host']['metrics']['FN']), (5, 0))
            self.assertEqual((main['bounded-host']['metrics']['TP'], main['bounded-host']['metrics']['FP']), (80, 54))


if __name__ == '__main__':
    unittest.main()
