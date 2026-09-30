# PB-04 Brute Force and Account Misuse

| | |
|---|---|
| **Trigger** | A burst of `4625` failed logons, `4740` lockouts, `4771` Kerberos pre-authentication failures, or a success after a run of failures |
| **ATT&CK** | Enterprise [T1110.001](https://attack.mitre.org/techniques/T1110/001/) Password Guessing, [T1110.003](https://attack.mitre.org/techniques/T1110/003/) Password Spraying, [T1078](https://attack.mitre.org/techniques/T1078/) Valid Accounts; ICS [T0859](https://attack.mitre.org/techniques/T0859/) Valid Accounts |
| **Roles** | SOC L1, SOC L2, identity administrator, account owner |

Kerberos spraying is detected by WIN-007, an ES|QL rule counting distinct failed accounts per source. It is validated on one EVTX-ATTACK-SAMPLES capture: 9 accounts in 11 ms, then a successful TGT for one account. The KQL and EQL snippets below, and NTLM brute force (4625), remain unvalidated (see [README](README.md)).

## 1. Triage (DE.AE)

1. Classify the pattern:

| Pattern | Likely technique |
|---|---|
| One account, many failures | Password guessing (T1110.001) |
| One source, many accounts, few attempts each | Password spraying (T1110.003) |
| Failures followed by `4624` for the same account | Possible valid-account use (T1078): treat as compromised until disproved |

2. Read the `4625` sub-status:
   - `0xC000006A`: wrong password for a real account.
   - `0xC0000064`: the user name does not exist, which points to enumeration.
   - `0xC0000234`: the account is locked.

```text
event.code: "4625" and winlog.event_data.SubStatus: ("0xc000006a" or "0xc0000064")
event.code: "4740"
```

3. Check the logon type on any success:
   - `3`: network.
   - `10`: RemoteInteractive (RDP), [T1021.001](https://attack.mitre.org/techniques/T1021/001/).
   - `2`: interactive.

## 2. Analysis (RS.AN, RS.MA)

1. Look for success after failures from the same source:

```text
sequence by source.ip, winlog.event_data.TargetUserName with maxspan=10m
  [authentication where event.code == "4625"] with runs=5
  [authentication where event.code == "4624"]
```

2. Is the source internal, VPN or external? Is it expected for this user?
3. After a success, follow the account: which hosts it logged on to, and whether it created accounts ([T1136.001](https://attack.mitre.org/techniques/T1136/001/), `4720`) or changed group membership (`4732`).
4. If the account or host has OT access, list the OT commands sent from that host after the logon. Continue with PB-01.

## 3. Containment and Eradication (RS.MI)

- Block the source at the perimeter or VPN.
- Disable or reset a compromised account and revoke its sessions. Engineering accounts may be needed for plant operations; agree a replacement account with the OT owner first.
- Enforce lockout and MFA on the targeted service.

## 4. Recovery (RC.RP)

Re-enable the account with a new credential and MFA. Watch its logons for 14 days.

## 5. Communication (RS.CO, RC.CO)

- Tell the account owner and the identity team.
- Tell the OT owner if an engineering account was involved.

## 6. Lessons Learned (ID.IM)

- Record exposed services such as RDP or VPN without MFA.
- Record weak lockout thresholds.
- Tune alert thresholds from the observed attack rate, not the default.

## Evidence to Preserve

Security logs (`4625`, `4624`, `4740`, `4771`, `4776`) from domain controllers and targeted hosts, plus VPN and firewall logs for the source.
