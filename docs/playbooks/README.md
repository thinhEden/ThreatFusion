# Incident Response Playbooks

These playbooks tell an analyst what to check, in what order, and when to escalate for the alerts ThreatFusion produces. The IT playbooks also cover the host evidence that the OT detections need but cannot see.

| ID | Playbook | Trigger | ATT&CK |
|---|---|---|---|
| [PB-01](PB-01-unauthorized-ot-command.md) | Unauthorized OT command | `BR-001`, `BR-003`, `BR-010`, Suricata 2100101/2100107/2100108 | ICS T1692.001, T0836 |
| [PB-02](PB-02-phishing-engineering-workstation.md) | Phishing reaching an engineering workstation | Reported email, mail gateway alert, suspicious Office child process | Enterprise T1566.001, T1566.002, T1204.002; ICS T0865, T0863 |
| [PB-03](PB-03-malware-engineering-workstation.md) | Malware on an engineering workstation | Encoded PowerShell, LSASS access, new service or task, YARA hit | Enterprise T1059.001, T1003.001, T1543.003, T1053.005; ICS T0853, T0843, T0889 |
| [PB-04](PB-04-brute-force-account-misuse.md) | Brute force and account misuse | Repeated 4625, lockouts, success after failures | Enterprise T1110.001, T1110.003, T1078; ICS T0859 |

## Structure

Each playbook follows the incident response functions of [NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final) (April 2025), which maps response to the CSF 2.0 categories:

| Section | CSF 2.0 category |
|---|---|
| Triage | DE.AE Adverse Event Analysis |
| Analysis | RS.AN Incident Analysis, RS.MA Incident Management |
| Containment and eradication | RS.MI Incident Mitigation |
| Recovery | RC.RP Incident Recovery Plan Execution |
| Communication | RS.CO, RC.CO |
| Lessons learned | ID.IM Improvement |

OT response follows [NIST SP 800-82 Rev. 3](https://csrc.nist.gov/pubs/sp/800/82/r3/final). Safety and process continuity come before evidence collection. No containment step that changes network paths or controller state is taken without the plant operations owner.

## Status of the Queries

- **PB-01:** runs against data that exists today: the context audit, the PCAP evidence and the `threatfusion-alerts-*` index.
- **PB-02 and PB-03:** alerts come from the EQL detections WIN-001 to WIN-006 in `siem/elastic/windows_rules.json`. They are validated on five OTRF captures and deployed to Elastic Security; see the [evaluation](../benchmarks/windows_detection_report.md).
- **PB-04:** Kerberos password spraying (4768/4771) is validated by WIN-007 on one EVTX-ATTACK-SAMPLES capture, kept locally because it is GPL-3.0. Kerberoasting (4769, WIN-008/WIN-009) and NTLM guessing and spraying (4625/4776, WIN-010/WIN-011) are validated on committed EVTX-to-MITRE-Attack (CC0) and splunk/attack_data (Apache-2.0) captures.
- **Hunting queries:** every KQL snippet in PB-02 to PB-04 is in `siem/elastic/hunting_queries.json`, saved in Kibana as a Discover search, and run against the captures by `tools/validate_hunting_queries.py`; see the [hunting validation](../benchmarks/hunting_query_validation.md). Running them found three hunts that used ECS fields the normalizer never produced; the normalizer now maps them.

The ATT&CK coverage of every rule is listed in [docs/attack/coverage.md](../attack/coverage.md).
