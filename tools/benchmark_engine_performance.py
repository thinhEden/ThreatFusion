"""C++ engine performance: batch throughput, stream throughput, source cardinality and a fixed-rate soak.

Input is the Gas Pipeline 2015 test window prepared by tools/benchmark_gas2015_ai.py (real packets with the
23 AI features). CPU time and memory come from the OS for the engine process only (Windows: GetProcessTimes and
GetProcessMemoryInfo; elsewhere psutil). Stream counters come from the engine's own --stats export.
Numbers are from one machine; the report records it.
"""
import argparse
import csv
import ctypes
import hashlib
import json
import math
import os
import platform
import shutil
import socket
import statistics
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AI = ROOT / 'out/benchmark_gas2015_ai'
MB = 1024 * 1024


class ProcessSampler:
    """CPU seconds, working set and private bytes of one process."""

    def __init__(self, pid):
        self.pid = pid
        self._windows = os.name == 'nt'
        self._last_sample = {'cpu_s': 0.0, 'working_set_mb': 0.0, 'private_mb': 0.0,
                             'peak_working_set_mb': None}
        if self._windows:
            from ctypes import wintypes

            class Counters(ctypes.Structure):
                _fields_ = [('cb', wintypes.DWORD), ('PageFaultCount', wintypes.DWORD)] + [
                    (name, ctypes.c_size_t) for name in (
                        'PeakWorkingSetSize', 'WorkingSetSize', 'QuotaPeakPagedPoolUsage', 'QuotaPagedPoolUsage',
                        'QuotaPeakNonPagedPoolUsage', 'QuotaNonPagedPoolUsage', 'PagefileUsage', 'PeakPagefileUsage',
                        'PrivateUsage')]
            self._counters = Counters
            self._kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
            self._kernel32.OpenProcess.restype = wintypes.HANDLE
            self._kernel32.K32GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.POINTER(Counters), wintypes.DWORD]
            self._kernel32.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
            self._kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
            self._filetime = wintypes.FILETIME
            # PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ; the handle stays valid after the process exits.
            self._handle = self._kernel32.OpenProcess(0x1000 | 0x0010, False, pid)
            if not self._handle:
                raise OSError(ctypes.get_last_error(), 'OpenProcess failed')
        else:
            import psutil
            self._psutil = psutil
            self._process = psutil.Process(pid)

    def sample(self):
        if not self._windows:
            try:
                memory, cpu = self._process.memory_full_info(), self._process.cpu_times()
            except (self._psutil.NoSuchProcess, self._psutil.ZombieProcess):
                # Exit can race a live sample. Final CPU and peak RSS come from wait4(), not this snapshot.
                return dict(self._last_sample)
            self._last_sample = {'cpu_s': cpu.user + cpu.system, 'working_set_mb': memory.rss / MB,
                                 'private_mb': memory.uss / MB, 'peak_working_set_mb': None}
            return dict(self._last_sample)
        counters = self._counters()
        counters.cb = ctypes.sizeof(counters)
        if not self._kernel32.K32GetProcessMemoryInfo(self._handle, ctypes.byref(counters), counters.cb):
            raise OSError(ctypes.get_last_error(), 'GetProcessMemoryInfo failed')
        times = [self._filetime() for _ in range(4)]
        if not self._kernel32.GetProcessTimes(self._handle, *[ctypes.byref(t) for t in times]):
            raise OSError(ctypes.get_last_error(), 'GetProcessTimes failed')
        kernel, user = ((t.dwHighDateTime << 32 | t.dwLowDateTime) / 1e7 for t in times[2:])
        return {'cpu_s': kernel + user, 'working_set_mb': counters.WorkingSetSize / MB,
                'private_mb': counters.PrivateUsage / MB, 'peak_working_set_mb': counters.PeakWorkingSetSize / MB}

    def running(self, process):
        if self._windows:
            return process.poll() is None
        # Observe termination without reaping: wait4() must still collect this child's final accounting.
        return os.waitid(os.P_PID, self.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is None

    def finish(self, process):
        live = self.sample()
        if self._windows:
            process.wait(timeout=120)
            exited = self.sample()
            live.update(cpu_s=exited['cpu_s'], peak_working_set_mb=exited['peak_working_set_mb'])
        else:
            deadline = time.monotonic() + 120
            while self.running(process):
                if time.monotonic() >= deadline:
                    raise subprocess.TimeoutExpired(process.args, 120)
                time.sleep(.01)
            _, status, usage = os.wait4(self.pid, 0)
            process.returncode = os.WEXITSTATUS(status) if os.WIFEXITED(status) else -os.WTERMSIG(status)
            live.update(cpu_s=usage.ru_utime + usage.ru_stime,
                        peak_working_set_mb=usage.ru_maxrss / (MB if sys.platform == 'darwin' else 1024))
        return live

    def close(self):
        if self._windows and self._handle:
            self._kernel32.CloseHandle(self._handle)
            self._handle = None


def machine():
    info = {'platform': platform.platform(), 'processor': platform.processor(), 'logical_cpus': os.cpu_count(),
            'python': sys.version.split()[0]}
    if os.name == 'nt':
        class Status(ctypes.Structure):
            _fields_ = [('dwLength', ctypes.c_ulong), ('dwMemoryLoad', ctypes.c_ulong)] + [
                (n, ctypes.c_ulonglong) for n in ('ullTotalPhys', 'ullAvailPhys', 'ullTotalPageFile', 'ullAvailPageFile',
                                                  'ullTotalVirtual', 'ullAvailVirtual', 'ullAvailExtendedVirtual')]
        status = Status()
        status.dwLength = ctypes.sizeof(status)
        ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status))
        info['physical_memory_gb'] = round(status.ullTotalPhys / 1024 ** 3, 1)
        try:
            name = subprocess.run(['powershell', '-NoProfile', '-Command', '(Get-CimInstance Win32_Processor).Name'],
                                  capture_output=True, text=True, timeout=30).stdout.strip()
            info['processor'] = name or info['processor']
        except (OSError, subprocess.SubprocessError):
            pass
    return info


def percentile(values, q):
    ordered = sorted(values)
    return ordered[max(0, math.ceil(q * len(ordered)) - 1)]


IF_THRESHOLD = None  # Set in main from the AI benchmark calibration.
IF_SEED = 1337


def prepare_performance_model(folder, experiment):
    """Copy the first evaluated seed and apply its benign-validation loss threshold deterministically."""
    selected = experiment['per_seed'][0]
    source = folder / f"lstm_seed{selected['seed']}.pt"
    metadata_path = Path(str(source) + '.json')
    if not source.is_file() or not metadata_path.is_file():
        raise ValueError('Run benchmark_gas2015_ai.py first to create the evaluated LSTM artifacts')
    metadata = json.loads(metadata_path.read_text(encoding='utf-8'))
    if metadata.get('seed') != selected['seed'] or metadata.get('feature_count') != experiment['feature_count']:
        raise ValueError('Performance model seed or feature count does not match the AI evaluation')
    threshold = selected['calibration']['lstm']
    if not math.isfinite(threshold) or threshold <= 0:
        raise ValueError('LSTM calibration must be a finite positive reconstruction-loss threshold')
    target = folder / 'lstm_perf.pt'
    shutil.copyfile(source, target)
    metadata.update(anomaly_threshold=threshold,
                    threshold_source=f"benchmark_gas2015_ai seed {selected['seed']}, benign validation FPR "
                                     f"{experiment['target_validation_fpr']}")
    Path(str(target) + '.json').write_text(json.dumps(metadata, indent=2), encoding='utf-8')
    return target


def scenarios(model):
    """Engine arguments per configuration; each adds one layer to the previous one.
    `full-default-if` keeps the engine's uncalibrated 0.55 Isolation Forest threshold for comparison."""
    rules = ['--rules', str(ROOT / 'data/behavior_rules.csv'), '--iocs', str(ROOT / 'data/iocs.csv'),
             '--attack-map', str(ROOT / 'data/attack_mapping.csv')]
    context = ['--context', str(AI / 'policy_envelope.json')]
    baseline = ['--baseline', str(AI / 'train.jsonl'), '--baseline-format', 'jsonl', '--if-seed', str(IF_SEED)]
    calibrated = ['--if-threshold', repr(IF_THRESHOLD)]
    return {'rules': rules, 'rules+envelope': rules + context, 'rules+envelope+if': rules + context + baseline + calibrated,
            'full': rules + context + baseline + calibrated + ['--lstm', str(model)],
            'full-default-if': rules + context + baseline + ['--lstm', str(model)]}


def run_batch(engine, arguments, events, folder, name):
    folder.mkdir(parents=True, exist_ok=True)
    command = [str(engine), '--events', str(events), '--format', 'jsonl', *arguments,
               '--alerts', str(folder / f'{name}.alerts.csv'), '--incidents', str(folder / f'{name}.incidents.csv'),
               '--metrics', str(folder / f'{name}.metrics.txt'), '--timings', str(folder / f'{name}.timings.csv')]
    if '--context' in arguments:
        command += ['--context-audit', str(folder / f'{name}.audit.csv')]
    started = time.perf_counter()
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=folder)
    sampler, peak = ProcessSampler(process.pid), 0.0
    try:
        while sampler.running(process):
            peak = max(peak, sampler.sample()['working_set_mb'])
            time.sleep(.02)
        wall = time.perf_counter() - started
        final = sampler.finish(process)
    finally:
        sampler.close()
    out, err = process.communicate()
    if process.returncode:
        raise RuntimeError(f'{name} failed: {err.decode(errors="replace")[:500]}')
    with (folder / f'{name}.timings.csv').open(encoding='utf-8') as handle:
        timings = [float(line.split(',')[1]) for line in handle.readlines()[1:]]
    return {'wall_s': wall, 'cpu_s': final['cpu_s'],
            'peak_working_set_mb': final['peak_working_set_mb'] or peak, 'events': len(timings),
            'detect_ms_total': sum(timings), 'p50_ms': percentile(timings, .5), 'p95_ms': percentile(timings, .95),
            'p99_ms': percentile(timings, .99), 'max_ms': max(timings)}


def batch_phase(engine, model, folder, repeats):
    events = AI / 'test.events.jsonl'
    single = folder / 'one_event.jsonl'
    single.write_text(events.open(encoding='utf-8').readline(), encoding='utf-8')
    results = {}
    for name, arguments in scenarios(model).items():
        if name == 'full-default-if':
            continue
        startup = [run_batch(engine, arguments, single, folder / 'batch', f'{name}_startup')['wall_s'] for _ in range(repeats)]
        runs = [run_batch(engine, arguments, events, folder / 'batch', name) for _ in range(repeats)]
        median = {k: statistics.median(r[k] for r in runs) for k in runs[0]}
        results[name] = {**median, 'startup_s': statistics.median(startup), 'repeats': repeats,
                         'end_to_end_events_per_s': median['events'] / median['wall_s'],
                         'after_startup_events_per_s': median['events'] / max(median['wall_s'] - statistics.median(startup), 1e-9),
                         'detection_events_per_s': median['events'] / (median['detect_ms_total'] / 1000)}
        print(f"batch {name}: {results[name]['end_to_end_events_per_s']:.0f} ev/s end-to-end, "
              f"{results[name]['detection_events_per_s']:.0f} ev/s detection, peak {results[name]['peak_working_set_mb']:.0f} MB", flush=True)
    return results


class StreamEngine:
    def __init__(self, engine, arguments, folder, port):
        folder.mkdir(parents=True, exist_ok=True)
        # The engine appends to out/alerts_stream.csv; a file left by an earlier run would be counted again.
        for stale in (folder / 'out/alerts_stream.csv', folder / 'audit.csv', folder / 'stats.csv'):
            stale.unlink(missing_ok=True)
        self.stats = folder / 'stats.csv'
        command = [str(engine), '--mode', 'stream', '--port', str(port), *arguments,
                   '--stats', str(self.stats), '--stats-interval', '1']
        if '--context' in arguments:
            command += ['--context-audit', str(folder / 'audit.csv')]
        self.stderr = (folder / 'engine.stderr.log').open('w', encoding='utf-8')
        # Stream alerts go to out/alerts_stream.csv under the working directory; stdout echoes each alert.
        self.process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=self.stderr, cwd=folder)
        self.sampler = ProcessSampler(self.process.pid)
        deadline = time.time() + 300
        while True:
            try:
                self.socket = socket.create_connection(('127.0.0.1', port), timeout=5)
                break
            except OSError:
                if self.process.poll() is not None or time.time() > deadline:
                    raise RuntimeError('Stream engine did not start; see engine.stderr.log')
                time.sleep(.2)
        self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    def counters(self):
        """Last row of the engine's --stats export: (events, alerts, detect_ms_total)."""
        try:
            lines = self.stats.read_text(encoding='utf-8').strip().splitlines()
        except OSError:
            return 0, 0, 0.0
        if len(lines) < 2:
            return 0, 0, 0.0
        fields = lines[-1].split(',')
        return int(fields[2]), int(fields[3]), float(fields[4])

    def wait_for(self, count, timeout):
        deadline = time.time() + timeout
        while self.counters()[0] < count:
            if time.time() > deadline:
                raise RuntimeError(f'Engine processed {self.counters()[0]} of {count} events before timeout')
            time.sleep(.2)

    def stop(self):
        # Current memory reads as zero once the process has exited; CPU time and the peak stay readable.
        final = self.sampler.sample()
        self.socket.close()
        self.process.stdin.write(b'\n')
        self.process.stdin.flush()
        exited = self.sampler.finish(self.process)
        final.update(cpu_s=exited['cpu_s'], peak_working_set_mb=exited['peak_working_set_mb'])
        self.sampler.close()
        self.stderr.close()
        return final


def load_lines(path):
    return [line.rstrip('\n') for line in Path(path).open(encoding='utf-8') if line.strip()]


def stream_throughput(engine, model, folder, port, copies, repeats):
    """Median of `repeats` runs per configuration; single runs on this machine varied by up to 40%."""
    results = {}
    for name in ('rules+envelope', 'full', 'full-default-if'):
        runs = sorted((stream_run(engine, model, folder, port, copies, name) for _ in range(repeats)),
                      key=lambda r: r['events_per_s'])
        results[name] = {**runs[len(runs) // 2], 'repeats': repeats,
                         'events_per_s_range': [runs[0]['events_per_s'], runs[-1]['events_per_s']]}
        print(f"stream {name}: median {results[name]['events_per_s']:.0f} ev/s "
              f"({runs[0]['events_per_s']:.0f}-{runs[-1]['events_per_s']:.0f}), {results[name]['alerts']} alerts", flush=True)
    return results


def stream_run(engine, model, folder, port, copies, name):
    """Send the test window `copies` times as fast as TCP accepts it; throughput comes from engine counters."""
    lines = load_lines(AI / 'test.events.jsonl')
    payload = ('\n'.join(lines) + '\n').encode()
    engine_run = StreamEngine(engine, scenarios(model)[name], folder / f'stream_{name}', port)
    before = engine_run.sampler.sample()
    started = time.perf_counter()
    for _ in range(copies):
        engine_run.socket.sendall(payload)
    total = copies * len(lines)
    engine_run.wait_for(total, 3600)
    elapsed = time.perf_counter() - started
    events, alerts, detect_ms = engine_run.counters()
    final = engine_run.stop()
    with (folder / f'stream_{name}/out/alerts_stream.csv').open(newline='', encoding='utf-8') as handle:
        written = list(csv.DictReader(handle))
    sources = Counter(source for row in written for source in
                      {part.strip().split(':')[0] for part in row['reasons'].split(' | ')})
    return {'events': events, 'alerts': alerts, 'elapsed_s': elapsed, 'events_per_s': events / elapsed,
            'alerts_risk_60': sum(int(r['risk_score']) >= 60 for r in written),
            'alerts_by_detector': dict(sources.most_common()),
            'cpu_s': final['cpu_s'] - before['cpu_s'], 'cpu_pct_of_one_core': 100 * (final['cpu_s'] - before['cpu_s']) / elapsed,
            'detect_ms_mean': detect_ms / events, 'working_set_mb': final['working_set_mb'],
            'private_mb': final['private_mb'], 'peak_working_set_mb': final['peak_working_set_mb'],
            'detection_share_of_time': detect_ms / 1000 / elapsed}


def cardinality(engine, model, folder, port, sources):
    """Distinct source addresses, each sending one full LSTM window, then idle: does memory stay bounded?"""
    template = json.loads(load_lines(AI / 'test.events.jsonl')[0])
    engine_run = StreamEngine(engine, scenarios(model)['full'], folder / 'cardinality', port)
    engine_run.wait_for(0, 5)
    start = engine_run.sampler.sample()
    checkpoints, sent = [], 0
    for n in range(sources):
        address = f'10.{n >> 16 & 255}.{n >> 8 & 255}.{n & 255}'
        lines = []
        for step in range(10):
            event = dict(template, id=f'CARD-{n}-{step}', src_ip=address)
            lines.append(json.dumps(event, separators=(',', ':')))
        engine_run.socket.sendall(('\n'.join(lines) + '\n').encode())
        sent += 10
        if (n + 1) % (sources // 10) == 0:
            engine_run.wait_for(sent, 600)
            sample = engine_run.sampler.sample()
            checkpoints.append({'sources': n + 1, 'private_mb': sample['private_mb'], 'working_set_mb': sample['working_set_mb']})
    engine_run.stop()
    growth = checkpoints[-1]['private_mb'] - start['private_mb']
    result = {'sources': sources, 'events': sent, 'start_private_mb': start['private_mb'], 'checkpoints': checkpoints,
              'private_growth_mb': growth, 'bytes_per_source': growth * MB / sources}
    print(f"cardinality: {sources} sources -> +{growth:.1f} MB private ({result['bytes_per_source']:.0f} B/source)", flush=True)
    return result


def shifted(line, loop, span):
    """Replay a packet `loop` times later with a fresh id so time-based state keeps moving."""
    event = json.loads(line)
    event['id'] = f"{event['id']}-L{loop}"
    stamp = datetime.strptime(event['timestamp'], '%Y-%m-%dT%H:%M:%SZ') + timedelta(seconds=loop * span)
    event['timestamp'] = stamp.strftime('%Y-%m-%dT%H:%M:%SZ')
    return json.dumps(event, separators=(',', ':'))


def soak(engine, model, folder, port, seconds, rate, interval):
    lines = load_lines(AI / 'test.events.jsonl')
    first = datetime.strptime(json.loads(lines[0])['timestamp'], '%Y-%m-%dT%H:%M:%SZ')
    last = datetime.strptime(json.loads(lines[-1])['timestamp'], '%Y-%m-%dT%H:%M:%SZ')
    span = int((last - first).total_seconds()) + 1
    engine_run = StreamEngine(engine, scenarios(model)['full'], folder / 'soak', port)
    # Samples are appended as they are taken, so an interrupted soak still leaves its CPU and memory series.
    samples = (folder / 'soak' / 'timeline.jsonl').open('w', encoding='utf-8')
    timeline, sent, loop, position = [], 0, 0, 0
    started = time.perf_counter()
    previous_cpu, previous_time = engine_run.sampler.sample()['cpu_s'], started
    next_sample = started + interval
    tick = .01
    while True:
        now = time.perf_counter()
        elapsed = now - started
        if elapsed >= seconds:
            break
        due = int(elapsed * rate) - sent
        if due > 0:
            batch = []
            for _ in range(due):
                batch.append(lines[position] if loop == 0 else shifted(lines[position], loop, span))
                position += 1
                if position == len(lines):
                    position, loop = 0, loop + 1
            engine_run.socket.sendall(('\n'.join(batch) + '\n').encode())
            sent += due
        if now >= next_sample:
            sample = engine_run.sampler.sample()
            events, alerts, detect_ms = engine_run.counters()
            timeline.append({'t_s': round(elapsed, 1), 'sent': sent, 'processed': events, 'backlog': sent - events,
                             'alerts': alerts, 'detect_ms_total': detect_ms,
                             'cpu_pct_of_one_core': 100 * (sample['cpu_s'] - previous_cpu) / (now - previous_time),
                             'working_set_mb': sample['working_set_mb'], 'private_mb': sample['private_mb']})
            samples.write(json.dumps(timeline[-1]) + '\n')
            samples.flush()
            previous_cpu, previous_time = sample['cpu_s'], now
            next_sample += interval
        time.sleep(max(0.0, tick - (time.perf_counter() - now)))
    engine_run.wait_for(sent, 600)
    events, alerts, detect_ms = engine_run.counters()
    final = engine_run.stop()
    samples.close()
    alerts_file = folder / 'soak/out/alerts_stream.csv'
    return summarize_soak(timeline, seconds, rate, sent, events, alerts, detect_ms, final, loop,
                          alerts_file.stat().st_size if alerts_file.exists() else 0)


def slope_per_hour(points):
    """Least-squares slope of (seconds, value) points, in value units per hour."""
    n = len(points)
    if n < 2:
        return 0.0
    mean_t, mean_v = sum(t for t, _ in points) / n, sum(v for _, v in points) / n
    variance = sum((t - mean_t) ** 2 for t, _ in points)
    return 3600 * sum((t - mean_t) * (v - mean_v) for t, v in points) / variance if variance else 0.0


def summarize_soak(timeline, seconds, rate, sent, events, alerts, detect_ms, final, loops, alerts_bytes):
    warm = [p for p in timeline if p['t_s'] >= min(300, seconds / 4)]
    quarters = [timeline[i * len(timeline) // 4:(i + 1) * len(timeline) // 4] for i in range(4)]
    detect = []
    for previous, current in zip(timeline, timeline[1:]):
        processed = current['processed'] - previous['processed']
        if processed:
            detect.append((current['t_s'], (current['detect_ms_total'] - previous['detect_ms_total']) / processed))
    return {'duration_s': seconds, 'target_rate': rate, 'sent': sent, 'processed': events, 'lost': sent - events,
            'alerts': alerts, 'alerts_file_mb': alerts_bytes / MB, 'replay_loops': loops,
            'achieved_rate': events / seconds, 'max_backlog_events': max(p['backlog'] for p in timeline),
            'cpu_pct_mean': statistics.mean(p['cpu_pct_of_one_core'] for p in timeline),
            'cpu_pct_by_quarter': [statistics.mean(p['cpu_pct_of_one_core'] for p in q) for q in quarters],
            'private_mb_start': timeline[0]['private_mb'], 'private_mb_end': timeline[-1]['private_mb'],
            'private_mb_max': max(p['private_mb'] for p in timeline),
            'working_set_mb_max': max(p['working_set_mb'] for p in timeline),
            'private_mb_slope_per_hour_after_warmup': slope_per_hour([(p['t_s'], p['private_mb']) for p in warm]),
            'detect_ms_mean': detect_ms / events if events else None,
            'detect_ms_mean_by_quarter': [statistics.mean(v for t, v in detect if q[0]['t_s'] <= t <= q[-1]['t_s']) for q in quarters],
            'detect_ms_slope_per_hour': slope_per_hour(detect), 'samples': len(timeline),
            'final_private_mb': final['private_mb'], 'peak_working_set_mb': final['peak_working_set_mb']}


def render(report):
    m, b, s = report['machine'], report['batch'], report['stream']
    lines = ['# C++ Engine Performance', '',
             'Generated by `tools/benchmark_engine_performance.py`. Input: the Gas Pipeline 2015 test window '
             f"({b['rules']['events']:,} real Modbus RTU packets with 23 features each), prepared by `tools/benchmark_gas2015_ai.py`.", '',
             f"Machine: {m['processor']}, {m['logical_cpus']} logical CPUs, {m.get('physical_memory_gb', '?')} GB RAM, {m['platform']}. "
             'The engine processes events on one thread; LibTorch is limited to one thread. Other services (Elasticsearch, Kibana, '
             'Docker) were running, so these are single-host numbers, not a benchmark of the hardware.', '',
             '## Configurations', '',
             '- `rules`: IOC correlation, 13 behaviour rules and ATT&CK annotation.',
             '- `rules+envelope`: plus the OT operating-envelope context and its audit trail.',
             '- `rules+envelope+if`: plus the new-peer/flow/function baseline and Isolation Forest (100 trees), trained at startup on '
             f"the benign rows of a {report['training_events']:,}-packet labelled training input; malicious rows are excluded by the engine. "
             f"The threshold is calibrated in the AI benchmark ({report['if_threshold']:.4f}).",
             '- `full`: plus the LSTM autoencoder through TorchScript (window 10, 23 features, calibrated loss threshold).',
             "- `full-default-if` (stream only): `full` with the engine's uncalibrated default Isolation Forest threshold of 0.55.",
             '- Before a new run, the default LSTM artifact is copied from the first evaluated seed and its metadata receives '
             'that seed\'s validation-calibrated loss threshold. A custom `--model` must provide calibrated metadata. On Linux, '
             '`psutil` samples live memory and `wait4` collects final CPU and peak RSS before the child is reaped.', '',
             '## Batch Mode', '',
             f"Median of {b['rules']['repeats']} runs. End-to-end includes process start, model training, JSON parsing, detection and "
             'CSV output. Detection throughput counts only the per-event detection loop.', '',
             '| Configuration | Startup s | End-to-end ev/s | After-startup ev/s | Detection ev/s | p50 ms | p95 ms | p99 ms | max ms | Peak working set MB |',
             '|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|']
    for name, r in b.items():
        lines.append(f"| {name} | {r['startup_s']:.2f} | {r['end_to_end_events_per_s']:,.0f} | {r['after_startup_events_per_s']:,.0f} | "
                     f"{r['detection_events_per_s']:,.0f} | {r['p50_ms']:.4f} | {r['p95_ms']:.4f} | {r['p99_ms']:.4f} | {r['max_ms']:.3f} | "
                     f"{r['peak_working_set_mb']:.0f} |")
    lines += ['', 'Batch mode holds every input event in memory, so its peak working set grows with the input file. '
              'Stream mode below keeps no per-event history.', '',
              '## Stream Mode Throughput', '',
              f"The test window is sent {report['stream_copies']} time(s) over one TCP connection as fast as the engine reads it. "
              "Counts come from the engine's `--stats` export. Each configuration runs "
              f"{next(iter(s.values())).get('repeats', 1)} times; the table shows the run with the median throughput and the range "
              'across runs. Earlier single runs, taken while other work shared the machine, varied by up to 40%.', '',
              '| Configuration | Events | Alert rows | Risk >= 60 | Events/s (range) | CPU % of one core | Detection share of wall time | Mean detection ms | Working set MB |',
              '|---|---:|---:|---:|---:|---:|---:|---:|---:|']
    for name, r in s.items():
        low, high = r.get('events_per_s_range', [r['events_per_s']] * 2)
        lines.append(f"| {name} | {r['events']:,} | {r['alerts']:,} | {r['alerts_risk_60']:,} | {r['events_per_s']:,.0f} ({low:,.0f}-{high:,.0f}) | "
                     f"{r['cpu_pct_of_one_core']:.0f} | {r['detection_share_of_time']:.0%} | {r['detect_ms_mean']:.4f} | {r['working_set_mb']:.0f} |")
    lines += ['', 'The gap between detection time and wall time is parsing, the per-alert console line, the CSV append and the '
              'context audit row, all on the receiving thread. Alert rows by detector (an alert can carry several):', '']
    lines += [f"- `{name}`: " + ', '.join(f'{k} {v:,}' for k, v in r['alerts_by_detector'].items()) for name, r in s.items()]
    default, calibrated = s.get('full-default-if'), s.get('full')
    if default and calibrated:
        lines += ['', f"With the default 0.55 threshold, Isolation Forest fires on {default['alerts_by_detector'].get('isolation_forest', 0):,} of "
                  f"{default['events']:,} packets. The OT context only downgrades a write when no independent evidence is present, so these "
                  f"detections also keep writes the envelope approves: {default['alerts_risk_60']:,} alerts reach risk 60, against "
                  f"{calibrated['alerts_risk_60']:,} with the calibrated threshold. An uncalibrated model undoes the context's false-positive reduction."]
    if report.get('stream_before'):
        before = report['stream_before']
        lines += ['', '### Stream fixes found by this measurement', '',
                  'The first stream run, on the engine before these fixes, showed two faults. LibTorch thread limits are per OS thread, so '
                  'inference on the socket thread used every core and spun. Every alert also reopened the alert CSV, re-read its header and '
                  'closed it again. The engine now limits LibTorch on the inference thread and keeps the stream alert file open.', '',
                  '| Configuration | Events/s before | CPU % before | Events/s after | CPU % after |', '|---|---:|---:|---:|---:|']
        # The earlier `full` run used the default Isolation Forest threshold, so it compares with `full-default-if`.
        pairs = [('rules+envelope', 'rules+envelope'), ('full', 'full-default-if')]
        lines += [f"| {after} | {before[old]['events_per_s']:,.0f} | {before[old]['cpu_pct_of_one_core']:.0f} | "
                  f"{s[after]['events_per_s']:,.0f} | {s[after]['cpu_pct_of_one_core']:.0f} |"
                  for old, after in pairs if old in before and after in s]
        lines += ['', 'The earlier `full` run used the default Isolation Forest threshold, so it is compared with `full-default-if`. '
                  'The before column is a single run; the after column is the median above.']
    c = report.get('cardinality')
    if c:
        lines += ['', '## Source Cardinality', '',
                  f"{c['sources']:,} distinct source addresses each send one full LSTM window ({c['events']:,} events) to the `full` "
                  'configuration.', '',
                  '| Sources | Private MB |', '|---:|---:|']
        lines += [f"| {p['sources']:,} | {p['private_mb']:.1f} |" for p in c['checkpoints']]
        cap = report.get('lstm_max_flows', 4096)
        filled = next((p for p in c['checkpoints'] if p['sources'] >= cap), c['checkpoints'][-1])
        lines += ['', f"With the default cap of {cap:,} LSTM flows, private memory rises while the first sources fill the cap and then "
                  f"stays flat: {filled['private_mb'] - c['start_private_mb']:+.1f} MB up to {filled['sources']:,} sources, then "
                  f"{c['checkpoints'][-1]['private_mb'] - filled['private_mb']:+.1f} MB from there to {c['sources']:,}."]
        b0 = report.get('cardinality_before')
        if b0:
            lines += ['', f"Before the cap, the LSTM kept a window for every source it had ever seen: memory grew "
                      f"{b0['private_growth_mb']:.1f} MB for {b0['sources']:,} sources ({b0['bytes_per_source']:,.0f} bytes per source) "
                      'with no plateau, so a flood of spoofed source addresses could exhaust memory. The cap evicts the least recently '
                      'seen source, which restarts its 10-event warm-up; size it above the real number of sources.']
    k = report.get('soak')
    if k:
        lines += ['', '## Soak', '',
                  f"The `full` configuration ran for {k['duration_s'] / 3600:.2f} h at a fixed {k['target_rate']:,} events/s, replaying the "
                  f"test window {k['replay_loops']} times with fresh IDs and advancing timestamps. Samples every "
                  f"{report['soak_interval_s']} s.", '',
                  '| Measure | Value |', '|---|---:|',
                  f"| Events sent / processed / lost | {k['sent']:,} / {k['processed']:,} / {k['lost']:,} |",
                  f"| Achieved rate | {k['achieved_rate']:,.0f} events/s |",
                  f"| Largest backlog at a sample | {k['max_backlog_events']:,} events |",
                  f"| Alerts (alerts_stream.csv size) | {k['alerts']:,} ({k['alerts_file_mb']:.1f} MB) |",
                  f"| CPU, mean % of one core | {k['cpu_pct_mean']:.1f} |",
                  f"| CPU by quarter | {' / '.join(f'{v:.1f}' for v in k['cpu_pct_by_quarter'])} |",
                  f"| Private MB start / end / max | {k['private_mb_start']:.1f} / {k['private_mb_end']:.1f} / {k['private_mb_max']:.1f} |",
                  f"| Private MB trend after warm-up | {k['private_mb_slope_per_hour_after_warmup']:+.2f} MB/h |",
                  f"| Mean detection ms by quarter | {' / '.join(f'{v:.4f}' for v in k['detect_ms_mean_by_quarter'])} |",
                  f"| Detection time trend | {k['detect_ms_slope_per_hour']:+.5f} ms/h |"]
    lines += ['', '## Limits', '',
              '- One machine with other services running. Absolute numbers will differ elsewhere; ratios between configurations are '
              'more portable.',
              '- The engine is single-threaded per connection. Throughput above one core would need sharding by source or unit.',
              '- Stream throughput is measured on localhost TCP. It excludes capture, tshark decoding and SIEM shipping.',
              '- The soak covers the stated duration, not days or weeks. It replays one capture, so it exercises two source '
              'addresses; the cardinality test covers many sources separately.']
    return '\n'.join(lines) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--engine', required=True)
    parser.add_argument('--model', help='Custom calibrated TorchScript model; default: prepare the first evaluated AI seed')
    parser.add_argument('--output', default='out/perf')
    parser.add_argument('--report', default='docs/benchmarks/engine_performance')
    parser.add_argument('--phases', default='batch,stream,cardinality,soak')
    parser.add_argument('--repeats', type=int, default=3)
    parser.add_argument('--stream-copies', type=int, default=1)
    parser.add_argument('--stream-repeats', type=int, default=3)
    parser.add_argument('--sources', type=int, default=100000)
    parser.add_argument('--soak-seconds', type=int, default=3600)
    parser.add_argument('--soak-rate', type=int, default=1000)
    parser.add_argument('--soak-interval', type=int, default=10)
    parser.add_argument('--port', type=int, default=18090)
    parser.add_argument('--stream-before', help='JSON with stream results from an earlier engine build, for comparison')
    parser.add_argument('--cardinality-before', help='JSON with cardinality results from an earlier engine build')
    parser.add_argument('--render-only', action='store_true', help='Rewrite the Markdown report from the existing JSON')
    parser.add_argument('--if-threshold', type=float,
                        help='Calibrated Isolation Forest threshold; default: first evaluated seed of docs/benchmarks/gas2015_ai_report.json')
    args = parser.parse_args()
    global IF_THRESHOLD, IF_SEED
    experiment = json.loads((ROOT / 'docs/benchmarks/gas2015_ai_report.json').read_text(encoding='utf-8'))
    IF_SEED = experiment['per_seed'][0]['seed']
    IF_THRESHOLD = args.if_threshold if args.if_threshold is not None else experiment['per_seed'][0]['calibration']['isolation_forest']
    engine, folder = Path(args.engine).resolve(), Path(args.output).resolve()
    folder.mkdir(parents=True, exist_ok=True)
    phases = set(args.phases.split(','))
    report_path = Path(f'{args.report}.json')
    report = json.loads(report_path.read_text(encoding='utf-8')) if report_path.exists() else {}
    if args.render_only:
        Path(f'{args.report}.md').write_text(render(report), encoding='utf-8')
        return
    args.model = str(Path(args.model).resolve() if args.model else prepare_performance_model(AI, experiment))
    report.update({'machine': machine(), 'engine_sha256': hashlib.sha256(engine.read_bytes()).hexdigest(),
                   'if_threshold': IF_THRESHOLD, 'if_seed': IF_SEED, 'lstm_max_flows': 4096,
                   'model': Path(args.model).name, 'training_events': sum(1 for _ in (AI / 'train.jsonl').open(encoding='utf-8')),
                   'measured_at': datetime.now(timezone.utc).isoformat(timespec='seconds')})
    save = lambda: report_path.write_text(json.dumps(report, indent=2), encoding='utf-8')
    if args.stream_before:
        report['stream_before'] = json.loads(Path(args.stream_before).read_text(encoding='utf-8'))
    if args.cardinality_before:
        report['cardinality_before'] = json.loads(Path(args.cardinality_before).read_text(encoding='utf-8'))
    # Saved after every phase, so stopping the soak keeps the earlier results.
    if 'batch' in phases:
        report['batch'] = batch_phase(engine, args.model, folder, args.repeats)
        save()
    if 'stream' in phases:
        report['stream'] = stream_throughput(engine, args.model, folder, args.port, args.stream_copies, args.stream_repeats)
        report['stream_copies'] = args.stream_copies
        save()
    if 'cardinality' in phases:
        report['cardinality'] = cardinality(engine, args.model, folder, args.port + 1, args.sources)
        save()
    if 'soak' in phases:
        report['soak'] = soak(engine, args.model, folder, args.port + 2, args.soak_seconds, args.soak_rate, args.soak_interval)
        report['soak_interval_s'] = args.soak_interval
    save()
    if {'batch', 'stream'} <= set(report):
        Path(f'{args.report}.md').write_text(render(report), encoding='utf-8')
    print(json.dumps({k: report[k] for k in ('batch', 'stream', 'cardinality', 'soak') if k in report}, indent=1)[:3000])


if __name__ == '__main__':
    main()
