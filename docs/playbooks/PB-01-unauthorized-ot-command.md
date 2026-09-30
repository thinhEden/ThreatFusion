# PB-01 Unauthorized OT Command

| | |
|---|---|
| **Trigger** | Retained alert from `BR-001` (Modbus write), `BR-003` (DNP3 operate), `BR-010` (IEC-104 control), or Suricata 2100101/2100107/2100108 |
| **ATT&CK for ICS** | [T1692.001](https://attack.mitre.org/techniques/T1692/001/) Unauthorized Message: Command Message; [T0836](https://attack.mitre.org/techniques/T0836/) Modify Parameter when a setpoint or tuning value changes |
| **Roles** | SOC L1 (triage), SOC L2 / incident handler (analysis), OT engineer and plant operations owner (decisions that touch the process) |
| **Target time** | Triage within 15 minutes; any out-of-envelope value is escalated immediately |

## 1. Triage (DE.AE)

1. Open the alert in the dashboard investigation panel. Record the event ID, source, destination, unit ID, function code, register or parameter values, and the ATT&CK IDs.
2. Read the context decision (`context_audit.csv`, or the Context tab). The reason tells you which branch applies:

| Context reason | Meaning | Next step |
|---|---|---|
| `Approved bounded register write; ticket constraints satisfied` | Suppressed: matches an active maintenance ticket | Spot-check the ticket; no alert |
| `Write inside commissioned operating envelope` | Suppressed: values are within the commissioned envelope | No alert, but see the limit in step 3 |
| `Parameter outside operating envelope: <name>` | Retained: a value outside the envelope | **Escalate now** (section 2) |
| `State change retained for review` | Retained: a valid value, but the state changed | Confirm with the operator log (section 2) |
| `Authorization constraints not satisfied` / `Authorization command budget exhausted` | Retained: ticket window, register, value or quota violated | Escalate to L2 |
| `Independent security evidence retained` | Retained: an IOC, Suricata hit or anomaly corroborates the write | Treat as a probable true positive |

3. **Limit:** the context cannot see intent. Commands from a compromised but authorized workstation pass the envelope. This happened for every MSCI attack on the public dataset, and for the lab challenge capture. If a host alert exists for the source workstation, treat a suppressed write as suspicious and open PB-03.

## 2. Analysis (RS.AN, RS.MA)

1. **Confirm the packet.** Filter the PCAP with `tcp.dstport == 502 && modbus` (Modbus/TCP) and pivot on the frame number shown in the case study. Check the function code, register and value.
2. **Check authorization.** Compare with `policy.json`: ticket window (UTC), source/destination pair, unit, register range, value bounds and command budget. For serial Modbus, compare with the envelope parameters in `docs/benchmarks/gas2015_context_report.json`.
3. **Ask operations.** Was an operator or engineer changing the process at that time? Get the HMI or operator log entry. On serial links the network cannot prove who sent the command.
4. **Look for corroboration** in Elastic (index `threatfusion-alerts-*`):

```text
threat.technique.id: "T1692.001" and threatfusion.variant: bounded
source.ip: "<source>" and event.risk_score >= 60
threatfusion.register_values > <upper engineering limit>
```

5. **Pivot to the host.** Check the source engineering workstation for PB-02 to PB-04 indicators around the command time.
6. **Decide:**
   - **True positive:** no ticket or operator record, a value outside limits, or host compromise evidence.
   - **Benign, authorized:** ticket or operator record matches every constraint. Record the evidence and the reviewer.
   - **Undetermined:** escalate to the incident handler. Do not close.

## 3. Containment and Eradication (RS.MI)

Every action here needs the operations owner's agreement (NIST SP 800-82r3).

1. Ask operations to put the affected process in a safe state using the plant procedure. Do not stop or isolate a controller from the SOC.
2. With operations' approval, block the unauthorized source at the OT boundary firewall or switch ACL. Do not remove the controller's own paths.
3. Restore setpoints and tuning parameters from the known-good configuration. Compare controller logic with the golden copy to rule out T0843 Program Download / T0889 Modify Program.
4. If the source workstation is implicated, run PB-03 on it before it reconnects.

## 4. Recovery (RC.RP)

- Operations confirms that process values are back inside the envelope for an agreed observation period.
- Keep the source block until the root cause is closed. Revoke or reissue any maintenance ticket involved.

## 5. Communication (RS.CO, RC.CO)

- Immediately: notify the plant operations owner and the OT engineer.
- If safety systems were affected or the process deviated: notify the site safety lead.
- Close with an incident summary covering timeline, packets, decision, actions and residual risk.

## 6. Lessons Learned (ID.IM)

- For a false positive caused by a missing ticket, fix the ticketing process. Do not widen the envelope.
- For a missed attack, record which evidence would have caught it: host telemetry, operator identity or process physics.
- Update `data/attack_mapping.csv` and rerun `tools/attack_coverage.py` when a rule changes.

## Evidence to Preserve

PCAP with SHA-256, alerts CSV, context audit, `policy.json` and the envelope version in force, the operator log extract, and the analyst notes and disposition stored in the dashboard.
