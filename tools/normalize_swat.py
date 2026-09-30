"""Preserve SWaT process measurements; IPs are a display mapping, not packet evidence."""
import argparse
import csv
import hashlib
import json
import math
from pathlib import Path
from datetime import datetime

TAGS = 'FIT101 LIT101 MV101 P101 P102 AIT201 AIT202 AIT203 FIT201 MV201 P201 P202 P203 P204 P205 P206 DPIT301 FIT301 LIT301 MV301 MV302 MV303 MV304 P301 P302 AIT401 AIT402 FIT401 LIT401 P401 P402 P403 P404 UV401 AIT501 AIT502 AIT503 AIT504 FIT501 FIT502 FIT503 FIT504 P501 P502 PIT501 PIT502 PIT503 FIT601 P601 P602 P603'.split()


def timestamp(value):
    for fmt in ('%d/%m/%Y %I:%M:%S %p', '%Y-%m-%d %H:%M:%S', '%d/%m/%Y %H:%M:%S'):
        try:
            # Source timestamps have no timezone; do not mislabel them as UTC.
            return datetime.strptime(value.strip(), fmt).isoformat()
        except ValueError:
            pass
    raise ValueError(f'Unsupported SWaT timestamp: {value!r}')


def rows_from_csv(source, max_rows=0, start_row=1, stats=None):
    seen = {}
    emitted = 0
    with source.open(encoding='utf-8-sig', newline='') as handle:
        reader = csv.DictReader(handle)
        reader.fieldnames = [h.strip() for h in reader.fieldnames]
        missing = set(TAGS + ['Timestamp', 'Normal/Attack']) - set(reader.fieldnames)
        if missing:
            raise ValueError(f'Missing SWaT columns: {sorted(missing)}')
        for index, row in enumerate(reader, 1):
            if index < start_row:
                continue
            label = row['Normal/Attack'].strip().lower()
            if label not in ('normal', 'attack'):
                raise ValueError(f'Unknown label at row {index}: {label!r}')
            values = [float(row[tag]) for tag in TAGS]
            if not all(math.isfinite(v) for v in values):
                raise ValueError(f'Non-finite SWaT reading at row {index}')
            stamp = timestamp(row['Timestamp'])
            identity = json.dumps([stamp, values], separators=(',', ':'))
            key = hashlib.sha256(identity.encode()).hexdigest()
            if key in seen:
                if seen[key] != label:
                    raise ValueError(f'Conflicting labels for the same SWaT measurement at row {index}')
                if stats is not None:
                    stats['duplicate_rows_removed'] += 1
                continue
            seen[key] = label
            yield index, stamp, values, label, key
            emitted += 1
            if max_rows and emitted >= max_rows:
                return


def convert(input_path, output_path, max_rows=0, start_row=1, scaler_path=None, fit_scaler=False):
    source = Path(input_path)
    if not source.is_file():
        raise FileNotFoundError(f'SWaT CSV not found: {source}')
    if fit_scaler:
        if not scaler_path:
            raise ValueError('--fit-scaler requires --scaler')
        minima, maxima = [math.inf] * len(TAGS), [-math.inf] * len(TAGS)
        normal_count = 0
        for _, _, values, label, _ in rows_from_csv(source, max_rows, start_row):
            if label != 'normal':
                continue
            normal_count += 1
            minima = [min(lo, value) for lo, value in zip(minima, values)]
            maxima = [max(hi, value) for hi, value in zip(maxima, values)]
        if not normal_count:
            raise ValueError('Scaler fitting requires normal rows; attack-only CSV cannot train a baseline')
        scaler = {'tags': TAGS, 'minimum': minima,
                  'range': [hi - lo or 1.0 for lo, hi in zip(minima, maxima)],
                  'fit_source': str(source), 'normal_training_rows': normal_count}
        Path(scaler_path).parent.mkdir(parents=True, exist_ok=True)
        Path(scaler_path).write_text(json.dumps(scaler, indent=2), encoding='utf-8')
    elif scaler_path:
        scaler = json.loads(Path(scaler_path).read_text(encoding='utf-8'))
        if scaler['tags'] != TAGS:
            raise ValueError('SWaT scaler feature order does not match schema')
    else:
        raise ValueError('Provide --scaler fitted on a separate normal training file')
    if len(scaler['minimum']) != len(TAGS) or len(scaler['range']) != len(TAGS) or not all(v > 0 for v in scaler['range']):
        raise ValueError('Invalid SWaT scaler dimensions or ranges')
    destination = Path(output_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    summary = {'input': str(source), 'output': str(destination), 'events': 0,
               'duplicate_rows_removed': 0, 'feature_count': len(TAGS), 'normal': 0, 'attack': 0}
    with destination.open('w', encoding='utf-8') as handle:
        for index, stamp, values, label, key in rows_from_csv(source, max_rows, start_row, summary):
            event = {
                'id': f'SWAT-{key}', 'timestamp': stamp,
                'src_ip': 'swat-process', 'dst_ip': 'swat-treatment',
                'protocol': 'process', 'function_code': -1, 'asset_role': 'plc',
                'payload_hash': '', 'payload_path': '', 'bytes': 0,
                'action': 'measurement', 'label': 'benign' if label == 'normal' else 'malicious',
                'extra_features': [(v - lo) / span for v, lo, span in zip(values, scaler['minimum'], scaler['range'])],
                'feature_names': TAGS, 'source_row': index, 'source_file': source.name,
            }
            handle.write(json.dumps(event, separators=(',', ':')) + '\n')
            summary['events'] += 1
            summary[label] += 1
    if not summary['events']:
        raise ValueError('No SWaT rows selected')
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', required=True)
    parser.add_argument('--output')
    parser.add_argument('--scaler')
    parser.add_argument('--inspect', action='store_true', help='Validate raw CSV and count unique measurements without a scaler')
    parser.add_argument('--fit-scaler', action='store_true')
    parser.add_argument('--max-rows', type=int, default=0)
    parser.add_argument('--start-row', type=int, default=1)
    parser.add_argument('--summary')
    args = parser.parse_args()
    if args.max_rows < 0 or args.start_row < 1:
        parser.error('Row limits must be non-negative and start row must be >= 1')
    if args.inspect:
        summary = {'input': args.input, 'normal': 0, 'attack': 0, 'duplicate_rows_removed': 0, 'feature_count': len(TAGS)}
        for _, _, _, label, _ in rows_from_csv(Path(args.input), args.max_rows, args.start_row, summary):
            summary[label] += 1
    else:
        if not args.output or not args.scaler:
            parser.error('Conversion requires --output and --scaler')
        summary = convert(args.input, args.output, args.max_rows, args.start_row, args.scaler, args.fit_scaler)
    if args.summary:
        Path(args.summary).parent.mkdir(parents=True, exist_ok=True)
        Path(args.summary).write_text(json.dumps(summary, indent=2), encoding='utf-8')
    print(json.dumps(summary, indent=2))


if __name__ == '__main__':
    main()
