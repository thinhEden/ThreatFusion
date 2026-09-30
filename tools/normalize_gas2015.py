"""Convert the MSU New Gas Pipeline 2015 ARFF (IanArffDataset.arff) to ThreatFusion JSONL.

Source: Morris ICS datasets, Dataset 4 (Turnipseed 2015),
http://www.ece.uah.edu/~thm0009/icsdatasets/IanArffDataset.arff

Detection events carry no labels. Ground truth goes to a separate CSV so the engine never sees it.
Serial Modbus RTU has no IP addresses: 10.0.0.1 (master) and 10.0.0.2 (RTU) are display mappings.
"""
import argparse
import csv
import json
from datetime import datetime, timezone
from pathlib import Path

MASTER_IP, RTU_IP = '10.0.0.1', '10.0.0.2'
CATEGORIES = {0: 'Normal', 1: 'NMRI', 2: 'CMRI', 3: 'MSCI', 4: 'MPCI', 5: 'MFCI', 6: 'DoS', 7: 'Recon'}
CONTROL = ['setpoint', 'gain', 'reset rate', 'deadband', 'cycle time', 'rate',
           'system mode', 'control scheme', 'pump', 'solenoid']
PROCESS = CONTROL + ['pressure measurement']
TRUTH_FIELDS = ['event_id', 'epoch', 'label', 'category', 'specific']


def read_arff(path):
    """Yield one dict per data row; '?' becomes None and every attribute is numeric."""
    names = []
    with Path(path).open(encoding='utf-8') as handle:
        for line in handle:
            if line.lower().startswith('@attribute'):
                names.append(line.split("'")[1])
            elif line.lower().startswith('@data'):
                break
        for line in handle:
            line = line.strip()
            if not line or line.startswith('%'):
                continue
            values = [v.strip().strip("'") for v in line.split(',')]
            if len(values) != len(names):
                raise ValueError(f'Expected {len(names)} values, got {len(values)}: {line[:80]}')
            yield {n: None if v == '?' else float(v) for n, v in zip(names, values)}


def is_command(row):
    return row['command response'] == 1


def to_event(row, index):
    command = is_command(row)
    return {
        'id': f'GP15-{index}',
        'timestamp': datetime.fromtimestamp(row['time'], timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
        'src_ip': MASTER_IP if command else RTU_IP,
        'dst_ip': RTU_IP if command else MASTER_IP,
        'protocol': 'modbus',
        'function_code': int(row['function']),
        'asset_role': 'plc' if command else 'hmi',
        'bytes': int(row['length']),
        'action': 'request' if command else 'response',
        'unit_id': int(row['address']),
        'is_request': command,
        'process_values': {k: row[k] for k in PROCESS if row[k] is not None},
    }


def to_truth(row, index):
    return {'event_id': f'GP15-{index}', 'epoch': row['time'],
            'label': 'malicious' if row['binary result'] == 1 else 'benign',
            'category': CATEGORIES[int(row['categorized result'])],
            'specific': int(row['specific result'])}


def write_split(rows, events_path, truth_path):
    """Write label-free events and a separate ground-truth sidecar for (index, row) pairs."""
    with Path(events_path).open('w', encoding='utf-8') as events, \
         Path(truth_path).open('w', newline='', encoding='utf-8') as truth:
        writer = csv.DictWriter(truth, TRUTH_FIELDS)
        writer.writeheader()
        for index, row in rows:
            events.write(json.dumps(to_event(row, index), separators=(',', ':')) + '\n')
            writer.writerow(to_truth(row, index))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', default='datasets/MSU_ICS/GasPipeline2015/IanArffDataset.arff')
    parser.add_argument('--output', required=True, help='Label-free JSONL events')
    parser.add_argument('--truth', required=True, help='Ground-truth CSV kept outside the engine')
    args = parser.parse_args()
    write_split(enumerate(read_arff(args.input), 1), args.output, args.truth)


if __name__ == '__main__':
    main()
