import json
from pathlib import Path
import sys
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import benchmark_engine_performance as performance


class PerformanceTests(unittest.TestCase):
    def test_default_model_is_copied_and_calibrated_from_evaluated_seed(self):
        experiment = {'feature_count': 23, 'target_validation_fpr': .01,
                      'per_seed': [{'seed': 2024, 'calibration': {'lstm': .09}}]}
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'lstm_seed2024.pt').write_bytes(b'torchscript artifact')
            metadata = root / 'lstm_seed2024.pt.json'
            metadata.write_text(json.dumps({'seed': 2024, 'feature_count': 23, 'anomaly_threshold': .003}))
            target = performance.prepare_performance_model(root, experiment)
            self.assertEqual(target.read_bytes(), b'torchscript artifact')
            prepared = json.loads(Path(str(target) + '.json').read_text())
            self.assertEqual(prepared['anomaly_threshold'], .09)
            with patch.object(performance, 'IF_SEED', experiment['per_seed'][0]['seed']):
                command = performance.scenarios(target)['full']
                self.assertEqual(command[command.index('--if-seed') + 1], str(prepared['seed']))
            self.assertEqual(json.loads(metadata.read_text())['anomaly_threshold'], .003)
            metadata.write_text(json.dumps({'seed': 1337, 'feature_count': 23}))
            with self.assertRaisesRegex(ValueError, 'seed or feature count'):
                performance.prepare_performance_model(root, experiment)

    def test_posix_final_accounting_does_not_sample_a_reaped_child(self):
        class Gone(Exception):
            pass

        sampler = performance.ProcessSampler.__new__(performance.ProcessSampler)
        sampler.pid, sampler._windows = 123, False
        sampler._last_sample = {'cpu_s': .1, 'working_set_mb': 20, 'private_mb': 15, 'peak_working_set_mb': None}
        sampler._psutil = SimpleNamespace(NoSuchProcess=Gone, ZombieProcess=Gone)
        sampler._process = Mock()
        sampler._process.memory_full_info.side_effect = Gone('exited during sample')
        process = Mock(returncode=None)
        usage = SimpleNamespace(ru_utime=.2, ru_stime=.1, ru_maxrss=30720)
        posix = SimpleNamespace(P_PID=1, WEXITED=2, WNOHANG=4, WNOWAIT=8,
                                waitid=Mock(side_effect=[None, SimpleNamespace(si_pid=123), SimpleNamespace(si_pid=123)]),
                                wait4=Mock(return_value=(123, 7 << 8, usage)),
                                WIFEXITED=lambda status: True, WEXITSTATUS=lambda status: status >> 8)
        with patch.object(performance, 'os', posix), patch.object(performance.sys, 'platform', 'linux'):
            self.assertTrue(sampler.running(process))
            self.assertFalse(sampler.running(process))
            final = sampler.finish(process)
        posix.wait4.assert_called_once_with(123, 0)
        process.poll.assert_not_called()
        process.wait.assert_not_called()
        self.assertEqual(process.returncode, 7)
        self.assertAlmostEqual(final['cpu_s'], .3)
        self.assertEqual(final['peak_working_set_mb'], 30)
        self.assertEqual(final['private_mb'], 15)

    def test_posix_shutdown_keeps_the_timeout_before_wait4(self):
        sampler = performance.ProcessSampler.__new__(performance.ProcessSampler)
        sampler.pid, sampler._windows = 123, False
        sampler.sample = Mock(return_value={'cpu_s': .1})
        sampler.running = Mock(return_value=True)
        process = Mock(args=['engine'])
        posix = SimpleNamespace(wait4=Mock())
        with patch.object(performance, 'os', posix), patch.object(performance.time, 'monotonic', side_effect=[0, 121]):
            with self.assertRaises(subprocess.TimeoutExpired):
                sampler.finish(process)
        posix.wait4.assert_not_called()


if __name__ == '__main__':
    unittest.main()
