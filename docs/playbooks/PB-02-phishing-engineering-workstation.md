# PB-02 Phishing Reaching an Engineering Workstation

| | |
|---|---|
| **Trigger** | User-reported email, mail gateway alert, or an Office process spawning a shell on an engineering workstation |
| **ATT&CK** | Enterprise [T1566.001](https://attack.mitre.org/techniques/T1566/001/) Spearphishing Attachment, [T1566.002](https://attack.mitre.org/techniques/T1566/002/) Spearphishing Link, [T1204.002](https://attack.mitre.org/techniques/T1204/002/) Malicious File; ICS [T0865](https://attack.mitre.org/techniques/T0865/) Spearphishing Attachment, [T0863](https://attack.mitre.org/techniques/T0863/) User Execution |
| **Roles** | SOC L1, SOC L2, email administrator, workstation owner, and the OT engineer if the host has OT access |

KQL below is a template for Winlogbeat/Sysmon ECS fields. It is not yet validated (see [README](README.md)).

## 1. Triage (DE.AE)

1. Get the original message as an `.eml` file, not a forward. A forward loses the headers.
2. Read the headers:
   - `Authentication-Results` (SPF, DKIM, DMARC)
   - the `Return-Path` / `From` mismatch
   - the `Received` chain, bottom-up, for the first external hop
   - `Reply-To` redirection
3. Extract the indicators: sender, subject, URLs (defang them), and attachment names with their SHA-256.
4. Ask the user: did they click, open, enable macros, or enter credentials?
5. If the recipient is an engineering workstation with OT access, raise severity to high at once.

## 2. Analysis (RS.AN, RS.MA)

1. **Attachment:** hash it. Scan it with `rules/yara/` and any approved threat-intelligence lookup. Detonate it only in an isolated sandbox, never on a plant host.
2. **URL:** resolve it and fetch it from an isolated analysis host. Check whether it harvests credentials.
3. **Scope:** find every recipient of the same sender, subject or attachment hash on the mail gateway.
4. **Endpoint execution evidence** on each recipient that opened the email:

```text
event.code: "1" and process.parent.name: ("WINWORD.EXE" or "EXCEL.EXE" or "OUTLOOK.EXE") and process.name: ("powershell.exe" or "cmd.exe" or "mshta.exe" or "wscript.exe" or "rundll32.exe")
event.code: "11" and file.path: (*\\Downloads\\* or *\\AppData\\Local\\Temp\\*) and file.extension: ("exe" or "dll" or "js" or "hta" or "lnk")
event.code: "22" and dns.question.name: "<phishing domain>"
```

5. **Credentials entered:** check `4624` sign-ins for that account from new sources (PB-04).
6. **OT pivot:** list the OT commands this workstation sent after the email arrived:

```text
source.ip: "<workstation IP>" and network.protocol: modbus
```

## 3. Containment and Eradication (RS.MI)

- Purge the message from every mailbox. Block the sender, domain, URL and hash at the gateway and proxy.
- Reset any credential that was entered, and revoke its sessions and tokens.
- If execution evidence exists, open PB-03.
- Isolating an engineering workstation can interrupt plant operations if it is running an HMI or project session. Coordinate isolation with operations.

## 4. Recovery (RC.RP)

Return the user and host to service only after PB-03 closes, or after analysis confirms nothing executed.

## 5. Communication (RS.CO, RC.CO)

- Tell the reporting user the outcome.
- Warn the other recipients.
- Tell the OT owner if an engineering account or host was involved.

## 6. Lessons Learned (ID.IM)

- Record why the gateway let the email through.
- Add confirmed hashes and IPs to `data/iocs.csv`; the engine matches IP, hash and protocol IOCs. Domains belong in the mail gateway and proxy block lists.

## Evidence to Preserve

The original `.eml`, attachment hashes and sandbox report, gateway logs, and Sysmon events from the recipient hosts.
