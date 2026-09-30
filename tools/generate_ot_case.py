"""Deterministic offline Modbus PCAP, commissioning policy, and separate lab ground truth."""
import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from scapy.all import Ether, IP, TCP, PcapWriter, Raw
from scapy.contrib.modbus import ModbusADURequest, ModbusPDU06WriteSingleRegisterRequest, ModbusPDU03ReadHoldingRegistersRequest

PLC = '10.50.2.10'
ENGINEERING = '10.50.1.20'
HMI = '10.50.1.10'
def ethernet():
    return Ether(src='02:00:00:00:00:01', dst='02:00:00:00:00:02')
START = datetime(2026, 9, 30, 10, 0, tzinfo=timezone.utc).timestamp()


def specifications(challenge=False):
    if challenge:
        return [(START + 120 + i, ENGINEERING, 6, 100, 55, 1, 'malicious', 'approved_looking_compromised_endpoint') for i in range(5)]
    rows = [(START - 50 + i * 3, HMI, 3, 100, 0, 1, 'benign', 'normal_polling') for i in range(200)]
    rows += [(START + 60 + i * 5, ENGINEERING, 6, 100, 55, 1, 'benign', 'approved_maintenance') for i in range(60)]
    rows += [(START + 180 + i, '10.50.1.99', 6, 100, 55, 1, 'malicious', 'unauthorized_source') for i in range(20)]
    rows += [(START + 370 + i, ENGINEERING, 6, 100, 55, 2, 'malicious', 'wrong_unit') for i in range(10)]
    rows += [(START + 385 + i, ENGINEERING, 6, 400, 55, 1, 'malicious', 'outside_register_scope') for i in range(10)]
    rows += [(START + 400 + i, ENGINEERING, 6, 100, 900, 1, 'malicious', 'unsafe_value') for i in range(10)]
    rows += [(START + 420 + i, ENGINEERING, 6, 100, 55, 1, 'malicious', 'replayed_over_budget') for i in range(10)]
    rows += [(START + 610 + i, ENGINEERING, 6, 100, 55, 1, 'malicious', 'outside_maintenance_window') for i in range(10)]
    rows += [(START + 430 + i, '10.50.1.66', 6, 100, 55, 1, 'malicious', 'lab_ioc_source') for i in range(10)]
    return sorted(rows)


def create_capture(path, rows):
    ground_truth = []
    flows = {}
    frame = 0
    writer = PcapWriter(str(path), sync=True)
    def emit(packet, stamp):
        nonlocal frame
        packet.time = stamp
        writer.write(packet)
        frame += 1
    try:
        for transaction, (stamp, source, function, register, value, unit, label, scenario) in enumerate(rows, 1):
            if source not in flows:
                port, seq, server_seq = 40000 + len(flows), 1000, 5000
                emit(ethernet()/IP(src=source, dst=PLC)/TCP(sport=port, dport=502, seq=seq, flags='S'), stamp - .003)
                emit(ethernet()/IP(src=PLC, dst=source)/TCP(sport=502, dport=port, seq=server_seq, ack=seq+1, flags='SA'), stamp - .002)
                emit(ethernet()/IP(src=source, dst=PLC)/TCP(sport=port, dport=502, seq=seq+1, ack=server_seq+1, flags='A'), stamp - .001)
                flows[source] = [port, seq+1, server_seq+1]
            port, seq, server_seq = flows[source]
            pdu = ModbusPDU06WriteSingleRegisterRequest(registerAddr=register, registerValue=value) if function == 6 else ModbusPDU03ReadHoldingRegistersRequest(startAddr=register, quantity=1)
            payload = bytes(ModbusADURequest(transId=transaction, unitId=unit)/pdu)
            emit(ethernet()/IP(src=source, dst=PLC)/TCP(sport=port, dport=502, seq=seq, ack=server_seq, flags='PA')/Raw(payload), stamp)
            ground_truth.append({'event_id': f'PCAP-{frame}', 'frame': frame, 'timestamp': stamp,
                                 'source_ip': source, 'destination_ip': PLC, 'function_code': function,
                                 'register': register, 'value': value, 'unit_id': unit,
                                 'label': label, 'scenario': scenario})
            # FC6 responds by echoing the request; FC3 returns one holding register.
            response = payload if function == 6 else bytes(ModbusADURequest(transId=transaction, unitId=unit)/Raw(b'\x03\x02\x00\x37'))
            emit(ethernet()/IP(src=PLC, dst=source)/TCP(sport=502, dport=port, seq=server_seq, ack=seq+len(payload), flags='PA')/Raw(response), stamp + .002)
            emit(ethernet()/IP(src=source, dst=PLC)/TCP(sport=port, dport=502, seq=seq+len(payload), ack=server_seq+len(response), flags='A'), stamp + .003)
            flows[source] = [port, seq+len(payload), server_seq+len(response)]
    finally:
        writer.close()
    return ground_truth


def generate(folder):
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    policy = {'schema_version': 1, 'provenance': 'Independent simulated commissioning ticket; not learned from attack labels',
              'authorizations': [{'ticket_id': 'CHG-OT-2026-001', 'source_ip': ENGINEERING, 'destination_ip': PLC,
                'unit_id': 1, 'function_codes': [6], 'register_start': 100, 'register_end': 101,
                'value_min': 50, 'value_max': 60, 'start_utc': '2026-09-30T10:00:00Z',
                'end_utc': '2026-09-30T10:10:00Z', 'max_commands': 60}]}
    (folder / 'policy.json').write_text(json.dumps(policy, indent=2))
    # Constructed scenario: a real WIN-001 hit from OTRF (tools/benchmark_windows.py), re-timed and mapped to the
    # engineering workstation. It is evidence input for the correlation variant, not ground truth.
    (folder / 'host_alerts.csv').write_text(
        'host_ip,timestamp,rule_id,techniques,host_name,evidence,provenance\n'
        f'{ENGINEERING},2026-09-30T10:01:30Z,WIN-001,T1059.001,WORKSTATION6.theshire.local,'
        '"OTRF empire_psexec_dcerpc_tcp_svcctl event c56f10bb25afa2f79b30 (2020-09-20T16:16:57Z)",'
        '"Constructed: real detection re-timed and mapped to the lab engineering workstation"\n')
    (folder / 'lab_iocs.csv').write_text('type,value,severity,malware_family,description\nip,10.50.1.66,critical,Lab IOC,Offline exercise source; not a real malware IOC\n')
    for name, challenge in [('main', False), ('challenge', True)]:
        truth = create_capture(folder / f'{name}.pcap', specifications(challenge))
        (folder / f'{name}_ground_truth.json').write_text(json.dumps(truth, indent=2))
    print(f'Offline PCAP and separate ground truth: {folder}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', default='out/portfolio_demo')
    generate(parser.parse_args().output)
