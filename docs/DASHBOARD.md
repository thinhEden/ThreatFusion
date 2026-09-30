# SOC Workspace

The dashboard is a local analyst workspace over detector evidence. Its six views are the alert queue, investigation cases, observed endpoints, OT authorization policy, research evaluation, and the on-disk detection registry. It does not claim multi-user authentication, EDR response actions, live engine health, or synchronized case state in Elastic.

## Run

```powershell
python tools/dashboard_server.py --port 8031 --default-source main
```

Open `http://127.0.0.1:8031`. The `main` source is explicitly labeled recorded synthetic lab evidence. Run `tools/portfolio_demo.py` first when `out/portfolio_demo` is unavailable. The default without `--default-source` is `live`, reading `out/alerts_stream.csv`; empty streams stay empty. Optional `--events-file` and `--audit-file` attach live JSONL events and context decisions by event ID and matching timestamp. The UI does not invent suppression coverage when a live baseline candidate stream is unavailable.

All runtime React, fonts and icons are local, version-pinned assets. The checked-in compiled bundle makes Node unnecessary for serving. Rebuild after editing UI source:

```powershell
npm ci --prefix dashboard
npm run build --prefix dashboard
```

## Analyst Workflow

1. Select Live stream, Lab/main, Lab/challenge or an imported CSV. Each source has isolated triage and case records.
2. Filter by endpoint/event/ticket/reason, context decision, severity, workflow status and time range. The capture default avoids hiding historical lab evidence behind a recent-time filter. Sort by time/risk and export the filtered set.
3. Open an event. Evidence shows packet ID, endpoints, register/unit/function/value, detector reasons, recorded latency and raw fields. Context shows the ticket and retained/suppressed counts. Activity shows analyst history. Ground truth is folded under an explicitly marked lab reference, not assigned as an analyst verdict.
4. Assign an owner, add a note, and save a disposition. Closing requires a verdict and note. Bulk triage and case creation accept up to 100 selected alerts. Cases retain their linked alert IDs and update history.
5. Pivot to Elastic Discover using the selected packet ID, capture and absolute UTC time window. Endpoint addresses are observations, not verified plant inventory. Policy windows are recorded read-only values, not active authorizations to modify a PLC.
6. Use Evaluation for FP/FN/Recall comparisons, timing scope, recorded SIEM counts, PCAP/report downloads and the demo video. The compromised-endpoint failure is visible beside the main-capture result.

## Local State and Evidence

- Original PCAP, normalized events, alerts and ground-truth files are not changed by triage.
- SQLite stores analyst states, history and cases in `out/dashboard_state.sqlite3`. Local imports are stored in `out/dashboard_imports`. Use `--state-file` and `--imports-dir` to isolate testing or another local workspace.
- The actor name denotes a local workspace action, not an authenticated identity. Changes are not pushed into Elastic Cases or used to train the model.
- CSV imports require engine headers, support up to 5,000 rows and a 4.5 MB UI size limit, and never attach unrelated lab evidence. The live view shows at most the latest 5,000 rows and labels the truncation.
- APIs bind to loopback by default. Mutation requests check browser Origin; this is a single-user local tool, not a replacement for authentication or RBAC.

## Design Decisions

The alert queue is the primary screen. A neutral work surface, dark navigation rail, compact typography, green navigation accent and semantic severity colors form the visual system. Sections use borders and alignment rather than stacks of floating cards. Three summary values and one small activity plot support the queue; research and ticket details live in separate views. Tables have sticky headers, bounded scroll areas and pagination. A contextual investigation panel opens only after selecting evidence.

CSS tokens are in `dashboard/styles.css`; UI components are in `dashboard/soc`. Bootstrap Icons follow the existing project icon library. No gradients, glow, generated threat counters or decorative animations are used. Keyboard focus, labeled controls, dialog focus, Escape dismissal and mobile navigation are included. Dense tables remain horizontally scrollable on narrow displays.

## Verification

```powershell
.venv/Scripts/python.exe -m unittest discover -s tests -p test_dashboard_workspace.py -v
```

`tests/soc_workspace.cjs` verifies queue filtering, evidence joins, policy details, endpoint canvas, research, rule inspection, source switching and desktop/mobile overflow. `tests/soc_triage.cjs` verifies note/disposition persistence, case lifecycle, CSV imports, zero values, exports and API-error recovery against an isolated test server. These Playwright tests use the actual API, not demo rows injected into the frontend.

For example, start a test server on port 8032 with `--state-file out/soc_ui_qa/state.sqlite3 --imports-dir out/soc_ui_qa/imports --default-source main`, then run `node tests/soc_triage.cjs`. Set `PLAYWRIGHT_MODULE` to a bundled installation when Playwright is not on the normal module path. UI screenshots are saved under `out/soc_*.png`.
