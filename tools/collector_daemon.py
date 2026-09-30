"""Replay normalized JSONL lazily over TCP with bounded connection retries."""
import argparse
import json
import socket
import time
from datetime import datetime
from pathlib import Path


def parse_iso_timestamp(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace('Z', '+00:00')).timestamp()
    except ValueError:
        try:
            return float(value)
        except ValueError:
            return None


def stream_events(file_path, host, port, rate, realtime_replay, connect_timeout=30):
    deadline = time.monotonic() + connect_timeout
    connection = None
    while connection is None:
        try:
            connection = socket.create_connection((host, port), timeout=2)
        except OSError:
            if time.monotonic() >= deadline:
                raise TimeoutError(f'Engine did not accept TCP connection at {host}:{port}')
            time.sleep(.2)
    previous = None
    count = 0
    with connection, Path(file_path).open(encoding='utf-8-sig') as handle:
        for line in handle:
            if not line.strip():
                continue
            event = json.loads(line)
            current = parse_iso_timestamp(event.get('timestamp', ''))
            if realtime_replay and previous is not None and current is not None:
                time.sleep(min(max(current - previous, 0), 10))
            elif not realtime_replay and count and rate > 0:
                time.sleep(1 / rate)
            connection.sendall((json.dumps(event, separators=(',', ':')) + '\n').encode('utf-8'))
            previous = current
            count += 1
    print(f'Sent {count} events to {host}:{port}')
    return count


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', required=True)
    parser.add_argument('--host', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=8080)
    parser.add_argument('--rate', type=float, default=10)
    parser.add_argument('--realtime', action='store_true')
    parser.add_argument('--connect-timeout', type=float, default=30)
    args = parser.parse_args()
    if args.connect_timeout <= 0 or args.rate < 0 or not 1 <= args.port <= 65535:
        parser.error('Invalid stream options')
    stream_events(args.input, args.host, args.port, args.rate, args.realtime, args.connect_timeout)


if __name__ == '__main__':
    main()
