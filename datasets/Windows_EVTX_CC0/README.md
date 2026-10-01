# EVTX-to-MITRE-Attack samples

These four `.evtx` files are unmodified copies from [mdecrevoisier/EVTX-to-MITRE-Attack](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack), released under CC0 1.0. They were downloaded on 2026-10-01 from commit `474856008f037ccd42753f02a631b42690195829`. Only the file names were changed, because the originals contain spaces and commas.

| File here | Path in EVTX-to-MITRE-Attack | Role | SHA-256 |
|---|---|---|---|
| `mdec_4769_kerberoast_low_encryption.evtx` | `TA0006-Credential Access/T1558-Steal or Forge Kerberos Tickets/ID4769-Kerberoast ticket with low encryption.evtx` | Kerberoasting (T1558.003) | `2c0360611fa5f43738e213638cf01a73c7701d8ddf510a3a03045a277739968a` |
| `mdec_4769_tgs_host_enumeration_bloodhound.evtx` | `TA0007-Discovery/T1087-Account discovery/ID4769-Kerberos TGS host enumeration (Bloodhound).evtx` | Negative control: many AES service tickets | `0ffd12cb62b2797e4e7a0675b132c27dfa5231b6b1a81cac92556335657d54bc` |
| `mdec_4776_4625_local_bruteforce.evtx` | `TA0006-Credential Access/T1110.xxx-Brut force/ID 4776,4625-AccountRestore local bruteforce.evtx` | Password guessing (T1110.001) | `83cc548d47150f1420bb47448f7a91c348a6c6f6890c2bb30abcab021b1a611a` |
| `mdec_4625_denied_account_restriction.evtx` | `TA0001-Initial access/T1078-Valid accounts/ID4625-failed login with denied access due to account restriction.evtx` | Negative control: two isolated failures | `06aec213c40fe5eece31c8958d3774381f28e2cd44b7e60f214217a344bc2574` |

Each file is 69,632 bytes. `tools/normalize_windows_events.py` reads them with the built-in `Get-WinEvent`, so evaluation needs Windows.
