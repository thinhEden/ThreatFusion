# OT Command Investigation Case Study

This is an offline synthetic, protocol-valid Modbus exercise. Packets are not sent to a plant; physical consequences are not measured.

## Evidence Chain

`main.pcap -> tshark -> C++ detections -> policy audit -> ECS index -> analyst disposition`

The independently defined commissioning ticket is CHG-OT-2026-001. It authorizes 10.50.1.20 to write unit 1, registers 100-101, values 50-60, during [10:00,10:10) UTC, at most 60 commands. Ground truth is a separate lab sidecar, never supplied to the engine.

| Packet / Event | Evidence | Baseline risk | Bounded result | Analyst disposition |
|---|---|---:|---|---|
| Frame 118 / PCAP-118 | 10.50.1.20 -> 10.50.2.10, FC 6, unit 1, register 100, value 55 | 74 | Approved bounded register write; ticket constraints satisfied | False positive: authorized maintenance |
| Frame 316 / PCAP-316 | 10.50.1.99 -> 10.50.2.10, FC 6, unit 1, register 100, value 55 | 74 | Retained, risk 74 | True positive: unauthorized lab command |
| Frame 763 / PCAP-763 | 10.50.1.20 -> 10.50.2.10, FC 6, unit 1, register 100, value 900 | 74 | Retained, risk 74 | True positive: unauthorized lab command |
| Frame 811 / PCAP-811 | 10.50.1.20 -> 10.50.2.10, FC 6, unit 1, register 100, value 55 | 74 | Retained, risk 74 | True positive: unauthorized lab command |
| Frame 1003 / PCAP-1003 | 10.50.1.20 -> 10.50.2.10, FC 6, unit 1, register 100, value 55 | 74 | Retained, risk 74 | True positive: unauthorized lab command |

## Investigation Steps

1. Verify the PCAP checksum in report.json and filter `tcp.dstport == 502 && modbus`. Pivot using the frame numbers above.
2. Inspect source/destination, Modbus unit, function, register and register value. A source IP alone does not prove the operator identity.
3. Compare with policy.json and the ticket window, limits and quota. Read main_bounded.audit.csv to explain each retained or downgraded candidate.
4. Query the same event.id in Elastic Discover using saved investigations in siem/elastic/queries.json. Compare baseline and bounded variants.
5. In a real response, verify operator approval, engineering host/identity logs, and PLC change history before final disposition. Those host/plant logs are not present in this exercise.

## Response Recommendations

- Authorized maintenance: record the ticket, reviewer and packet evidence; retain the audit. Do not create a permanent workstation-wide exclusion.
- Unauthorized source or unsafe value: escalate to the OT owner, preserve PCAP and endpoint evidence, and validate the process state. Coordinate isolation or rollback with operations and safety staff.
- Exhausted quota/outside window: investigate ticket replay, stale authorization or compromised credentials; revoke the relevant authorization only after validation.

## Counterexample and Scope

challenge.pcap contains five malicious-intent lab commands from a simulated compromised engineering workstation that are indistinguishable from approved commands under this policy. Bounded context misses all five. Packet attributes and a maintenance ticket are insufficient to prove host/operator integrity. This is a documented failure, not a production safety guarantee. With host evidence (bounded-host: WIN-001 on the workstation at 10:01:30Z, a constructed scenario from an OTRF detection), 5 of 5 are retained with correlation HOST-OT-001, and 54 approved maintenance writes after the alert return to review. See PB-03.

The experiment changes only BR-001 treatment. It is not evidence of malware-family detection or improved neural model accuracy. Other detection sources and rules are never suppressed.
