"""Normalize OTRF Security-Datasets Windows logs (NXLog JSON in .zip) to ECS-style documents.

Raw event fields are kept verbatim under winlog.event_data. Process fields are filled from Sysmon 1,
Security 4688 and Sysmon 10 (the accessing process) so the same query works across sources.
Sources: OTRF Security-Datasets (MIT) zips, EVTX-ATTACK-SAMPLES .evtx files (GPL-3.0, kept local) and
EVTX-to-MITRE-Attack .evtx files (CC0) read with Get-WinEvent on Windows, and splunk/attack_data
XmlWinEventLog exports (Apache-2.0).
"""
import argparse
import hashlib
import ipaddress
import json
import subprocess
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PureWindowsPath
from xml.etree import ElementTree

CHANNELS = {'security': 'Security', 'system': 'System', 'windows powershell': 'Windows PowerShell'}
TOP_LEVEL = {'@timestamp', '@version', 'EventID', 'Channel', 'Hostname', 'Message', 'TimeCreated', 'EventTime',
             'EventReceivedTime', 'port', 'host', 'tags'}


def timestamp(raw):
    if raw.get('@timestamp'):
        return raw['@timestamp']
    # Some OTRF captures only carry TimeCreated without a zone; it is treated as UTC for ordering only.
    value = raw.get('TimeCreated') or raw.get('EventTime')
    return datetime.fromisoformat(value).replace(tzinfo=timezone.utc).isoformat().replace('+00:00', 'Z')


def process_fields(code, data):
    if code == '1':
        executable, command, parent, parent_command = data.get('Image'), data.get('CommandLine'), data.get('ParentImage'), data.get('ParentCommandLine')
    elif code == '4688':
        executable, command, parent, parent_command = data.get('NewProcessName'), data.get('CommandLine'), data.get('ParentProcessName'), None
    elif code == '10':
        executable, command, parent, parent_command = data.get('SourceImage'), None, None, None
    else:
        return {}
    process = {k: v for k, v in {'executable': executable, 'name': executable and PureWindowsPath(executable).name,
                                 'command_line': command}.items() if v}
    parent_fields = {k: v for k, v in {'executable': parent, 'name': parent and PureWindowsPath(parent).name,
                                       'command_line': parent_command}.items() if v}
    if parent_fields:
        process['parent'] = parent_fields
    return {'process': process} if process else {}


CATEGORY = {'1': 'process', '4688': 'process', '10': 'process', '3': 'network', '22': 'network', '11': 'file', '23': 'file',
            '7045': 'configuration', '4697': 'configuration', '4698': 'configuration', '4740': 'iam',
            **{code: 'authentication' for code in ('4624', '4625', '4648', '4768', '4769', '4771', '4776')}}


def ecs_fields(code, data):
    """ECS fields the playbook hunting queries use; raw values stay under winlog.event_data."""
    fields = {'event': {'category': [CATEGORY[code]]}} if code in CATEGORY else {'event': {}}
    if CATEGORY.get(code) == 'authentication':
        failed = code == '4625' or data.get('Status', '0x0').lower() != '0x0'
        fields['event']['outcome'] = 'failure' if failed else 'success'
        user = data.get('TargetUserName')
        if user and user != '-':
            name, _, domain = user.partition('@')
            fields['user'] = {k: v for k, v in {'name': name, 'domain': domain or data.get('TargetDomainName')}.items() if v}
        address = (data.get('IpAddress') or '').removeprefix('::ffff:')
        try:
            fields['source'] = {'ip': str(ipaddress.ip_address(address))}
        except ValueError:
            pass
    if code in ('11', '23') and data.get('TargetFilename'):
        path = PureWindowsPath(data['TargetFilename'])
        fields['file'] = {'path': str(path), 'name': path.name, 'extension': path.suffix.lstrip('.').lower()}
    if code == '22' and data.get('QueryName'):
        fields['dns'] = {'question': {'name': data['QueryName']}}
    return fields


def to_ecs(raw, dataset, source='windows.otrf'):
    channel = raw.get('Channel') or ''
    code = str(raw.get('EventID'))
    data = {k: str(v) for k, v in raw.items() if k not in TOP_LEVEL and v is not None}
    ecs = ecs_fields(code, data)
    document = {
        '@timestamp': timestamp(raw),
        'event': {'code': code, 'dataset': source,
                  'id': hashlib.sha256(json.dumps(raw, sort_keys=True).encode()).hexdigest()[:20]},
        'host': {'name': raw.get('Hostname')},
        'winlog': {'channel': CHANNELS.get(channel.lower(), channel), 'event_data': data},
        'message': raw.get('Message', ''),
        'threatfusion': {'dataset': dataset},
    }
    document['event'].update(ecs.pop('event'))
    document.update(ecs)
    document.update(process_fields(code, data))
    return document


def read_zip(path):
    dataset = Path(path).stem
    with zipfile.ZipFile(path) as bundle:
        for info in bundle.infolist():
            for line in bundle.read(info).decode('utf-8', 'replace').splitlines():
                if line.strip():
                    yield to_ecs(json.loads(line), dataset)


EVTX_SCRIPT = r"""
param($Path)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
Get-WinEvent -Path $Path -Oldest | ForEach-Object {
    $xml = [xml]$_.ToXml()
    $row = [ordered]@{ '@timestamp' = $_.TimeCreated.ToUniversalTime().ToString('o'); EventID = $_.Id;
                       Channel = $_.LogName; Hostname = $_.MachineName }
    foreach ($data in $xml.Event.EventData.Data) { if ($data.Name) { $row[$data.Name] = $data.'#text' } }
    $row | ConvertTo-Json -Compress
}
"""


def read_evtx(path):
    """Parse a .evtx file with the built-in Get-WinEvent (Windows only; no extra packages)."""
    with tempfile.TemporaryDirectory(prefix='threatfusion-evtx-') as folder:
        script = Path(folder) / 'read.ps1'
        script.write_text(EVTX_SCRIPT, encoding='utf-8')
        result = subprocess.run(['powershell', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
                                 '-File', str(script), '-Path', str(Path(path).resolve())],
                                capture_output=True, text=True, encoding='utf-8', check=True, timeout=300)
    for line in result.stdout.splitlines():
        if line.strip():
            yield to_ecs(json.loads(line), Path(path).stem, 'windows.evtx_attack_samples')


EVENT_NS = '{http://schemas.microsoft.com/win/2004/08/events/event}'


def read_xml_log(path):
    """Read a Splunk attack_data XmlWinEventLog export: one <Event> element per line."""
    for line in Path(path).open(encoding='utf-8'):
        if not line.strip():
            continue
        event = ElementTree.fromstring(line)
        system = event.find(EVENT_NS + 'System')
        raw = {'@timestamp': system.find(EVENT_NS + 'TimeCreated').get('SystemTime'),
               'EventID': int(system.findtext(EVENT_NS + 'EventID')), 'Channel': system.findtext(EVENT_NS + 'Channel'),
               'Hostname': system.findtext(EVENT_NS + 'Computer')}
        data = event.find(EVENT_NS + 'EventData')
        for item in (data if data is not None else []):
            if item.get('Name'):
                raw[item.get('Name')] = item.text
        yield to_ecs(raw, Path(path).stem, 'windows.splunk_attack_data')


def read_capture(path):
    """Dispatch on the file type: OTRF zip, .evtx or a Splunk XML log."""
    path = Path(path)
    if path.suffix == '.zip':
        return read_zip(path)
    return read_evtx(path) if path.suffix == '.evtx' else read_xml_log(path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', default='datasets/Windows_OTRF', help='A .zip or a folder of OTRF zips')
    parser.add_argument('--output', required=True, help='ECS JSONL output')
    args = parser.parse_args()
    source = Path(args.input)
    zips = sorted(source.glob('*.zip')) if source.is_dir() else [source]
    with Path(args.output).open('w', encoding='utf-8') as handle:
        for path in zips:
            for document in read_zip(path):
                handle.write(json.dumps(document, separators=(',', ':')) + '\n')


if __name__ == '__main__':
    main()
