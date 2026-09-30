import {
  useState,
  useEffect,
  useRef,
  Icon,
  Badge,
  Empty,
  Facts,
  Field,
  Modal,
  History,
  Download,
  fmt,
  time,
  api,
} from "./common.js";

export function Assets({ data, onPivot }) {
  const ref = useRef();
  useEffect(() => {
    const canvas = ref.current;
    if (!canvas) return;
    const draw = () => {
      const w = Math.max(650, canvas.parentElement.clientWidth),
        columns = Math.max(1, Math.floor(w / 190)),
        h = Math.max(240, Math.ceil(data.assets.length / columns) * 120),
        dpr = devicePixelRatio || 1;
      canvas.width = w * dpr;
      canvas.height = h * dpr;
      canvas.style.height = h + "px";
      const c = canvas.getContext("2d");
      c.scale(dpr, dpr);
      const n = data.assets.length;
      if (!n) return;
      const positions = new Map(
        data.assets.map((a, i) => [
          a.ip,
          {
            x: (((i % columns) + 0.5) * w) / columns,
            y: 50 + Math.floor(i / columns) * 120,
          },
        ]),
      );
      c.strokeStyle = "#c6ced2";
      c.lineWidth = 1;
      data.flows.forEach((f) => {
        const a = positions.get(f.source),
          b = positions.get(f.destination);
        if (!a || !b) return;
        c.beginPath();
        c.moveTo(a.x, a.y);
        c.lineTo(b.x, b.y);
        c.stroke();
      });
      data.assets.forEach((a) => {
        const p = positions.get(a.ip);
        c.fillStyle = a.alerts ? "#9b4939" : "#347360";
        c.beginPath();
        c.arc(p.x, p.y, 8, 0, Math.PI * 2);
        c.fill();
        c.textAlign = "center";
        c.fillStyle = "#343b40";
        c.font = "11px monospace";
        c.fillText(a.ip, p.x, p.y + 29);
        c.font = "11px system-ui";
        c.fillStyle = "#69717a";
        c.fillText(a.alerts + " retained", p.x, p.y + 46);
      });
    };
    draw();
    const observer = new ResizeObserver(draw);
    observer.observe(canvas.parentElement);
    return () => observer.disconnect();
  }, [data]);
  return (
    <>
      <div className="section-heading">
        <h2>Observed endpoints</h2>
        <span>
          {data.assets.length} endpoints · {data.flows.length} communication
          paths
        </span>
      </div>
      {!data.assets.length ? (
        <Empty title="No endpoints observed" />
      ) : (
        <>
          <div className="topology">
            <canvas
              role="img"
              aria-label="Observed endpoint connections"
              ref={ref}
            />
          </div>
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Endpoint</th>
                  <th>Protocol</th>
                  <th>Observed records</th>
                  <th>Retained alerts</th>
                  <th>Peak risk</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {data.assets.map((a) => (
                  <tr key={a.ip}>
                    <td className="mono">{a.ip}</td>
                    <td>{a.protocols.join(", ")}</td>
                    <td>{fmt(a.requests)}</td>
                    <td>{a.alerts}</td>
                    <td>{fmt(a.risk)}</td>
                    <td>
                      <button onClick={() => onPivot(a.ip)}>
                        View alerts
                        <Icon name="arrow-right" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="footnote">
            Endpoints are observed addresses. Asset ownership and process roles
            have not been verified.
          </p>
        </>
      )}
    </>
  );
}

export function Policies({ data, onPivot }) {
  const policies = data.policy?.authorizations || [];
  return (
    <>
      <div className="section-heading">
        <h2>OT authorizations</h2>
        <span>Recorded policy · read only</span>
      </div>
      {policies.length ? (
        policies.map((p) => (
          <section className="policy" key={p.ticket_id}>
            <div className="inline spread">
              <h3 className="mono">{p.ticket_id}</h3>
              <Badge value="Recorded" />
            </div>
            <Facts
              items={[
                ["Source", p.source_ip],
                ["Destination", p.destination_ip],
                ["Unit ID", p.unit_id],
                ["Function codes", p.function_codes.join(", ")],
                ["Register scope", p.register_start + " – " + p.register_end],
                ["Value bounds", p.value_min + " – " + p.value_max],
                ["Command budget", p.max_commands],
                ["Window start", time(p.start_utc) + " UTC"],
                ["Window end (exclusive)", time(p.end_utc) + " UTC"],
              ]}
            />
            <button onClick={() => onPivot(p.source_ip)}>
              Investigate workstation
              <Icon name="arrow-right" />
            </button>
          </section>
        ))
      ) : (
        <Empty title="No authorization policy linked">
          Select a recorded lab source to inspect its commissioning ticket.
        </Empty>
      )}
      <p className="notice">
        An approved-looking command may still be malicious. Independent security
        evidence is retained; a ticket does not verify workstation integrity.
      </p>
    </>
  );
}

export function Research() {
  const [state, setState] = useState(null),
    [error, setError] = useState(""),
    [capture, setCapture] = useState("main");
  useEffect(() => {
    api("/api/research")
      .then(setState)
      .catch((e) => setError(e.message));
  }, []);
  if (error) return <Empty title="Research unavailable">{error}</Empty>;
  if (!state)
    return (
      <p className="loading" role="status">
        Loading recorded results…
      </p>
    );
  const report = state.report,
    variants = report.captures[capture],
    pct = (v) => (v * 100).toFixed(2) + "%";
  const combined = Object.values(report.captures).reduce(
    (n, c) => ({
      tp: n.tp + c.bounded.metrics.TP,
      fn: n.fn + c.bounded.metrics.FN,
    }),
    { tp: 0, fn: 0 },
  );
  return (
    <>
      <div className="section-heading">
        <div>
          <h2>Context evaluation</h2>
          <p>Recorded offline Modbus experiment</p>
        </div>
        <Download name="report.json">Export results</Download>
      </div>
      <div className="tabs" role="tablist" aria-label="Experiment capture">
        {["main", "challenge"].map((c) => (
          <button
            key={c}
            role="tab"
            aria-selected={capture === c}
            onClick={() => setCapture(c)}
          >
            {c === "main" ? "Main capture" : "Compromised endpoint"}
          </button>
        ))}
      </div>
      <div className="table-scroll">
        <table>
          <thead>
            <tr>
              <th>Configuration</th>
              <th>TP</th>
              <th>FP</th>
              <th>FN</th>
              <th>Precision</th>
              <th>Recall</th>
              <th>F1</th>
            </tr>
          </thead>
          <tbody>
            {Object.entries(variants).map(([name, v]) => (
              <tr key={name}>
                <td>
                  <strong>
                    {name === "bounded"
                      ? "Bounded OT context"
                      : name === "baseline"
                        ? "Baseline rules"
                        : "Peer-only ablation"}
                  </strong>
                </td>
                {["TP", "FP", "FN"].map((k) => (
                  <td key={k}>{v.metrics[k]}</td>
                ))}
                {["precision", "recall", "f1"].map((k) => (
                  <td key={k}>{pct(v.metrics[k])}</td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="research-note">
        <Icon name="exclamation-triangle" />
        <div>
          <h3>
            Combined Recall: {pct(combined.tp / (combined.tp + combined.fn))}
          </h3>
          <p>
            The bounded policy misses {combined.fn} approved-looking attacks in
            the challenge. Zero false positives in the main lab does not
            establish production performance.
          </p>
        </div>
      </div>
      <section>
        <h3>C++ event processing</h3>
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Configuration</th>
                <th>P50</th>
                <th>P95</th>
                <th>P99</th>
              </tr>
            </thead>
            <tbody>
              {Object.entries(variants).map(([name, v]) => (
                <tr key={name}>
                  <td>{name}</td>
                  {["p50", "p95", "p99"].map((k) => (
                    <td key={k}>{fmt(v.processing_ms[k], 5)} ms</td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="footnote">
          Batch evaluation and audit buffering only. Capture parsing, final disk
          writes and SIEM ingestion are excluded.
        </p>
      </section>
      <section>
        <h3>Evidence package</h3>
        <div className="action-links">
          <Download name="case_study.md">Case study</Download>
          <Download name="report.md">Experiment report</Download>
          <Download name={capture + ".pcap"}>PCAP</Download>
          <Download name="policy.json">Policy</Download>
        </div>
        {state.has_video && (
          <details>
            <summary>Recorded investigation walkthrough</summary>
            <video
              controls
              preload="none"
              src="/api/artifacts/portfolio_demo.webm"
            />
          </details>
        )}
      </section>
      <section>
        <h3>SIEM verification snapshot</h3>
        <Facts
          items={[
            ["Indexed ECS documents", report.siem_verification?.total],
            [
              "Native Security Alerts",
              report.siem_verification?.native_security_alerts,
            ],
            [
              "Report file updated",
              time(new Date(state.verified_at * 1000)) + " UTC",
            ],
          ]}
        />
        <a
          className="button"
          href="http://127.0.0.1:15601/app/security/alerts"
          target="_blank"
          rel="noreferrer"
        >
          Open Elastic Security
          <Icon name="box-arrow-up-right" />
        </a>
        <p className="footnote">
          Counts are from the saved run, not a live health check.
        </p>
      </section>
    </>
  );
}

export function Rules() {
  const [rules, setRules] = useState(null),
    [error, setError] = useState(""),
    [query, setQuery] = useState(""),
    [selected, setSelected] = useState(null);
  useEffect(() => {
    api("/api/rules")
      .then(setRules)
      .catch((e) => setError(e.message));
  }, []);
  return (
    <>
      <div className="section-heading">
        <h2>Detection registry</h2>
        <span>Definitions on disk · runtime loading unverified</span>
      </div>
      <div className="toolbar">
        <label className="search">
          <Icon name="search" />
          <input
            aria-label="Search rules"
            placeholder="Find a rule or indicator"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
        </label>
      </div>
      {error ? (
        <p role="alert" className="error">
          {error}
        </p>
      ) : !rules ? (
        <p role="status">Loading rules…</p>
      ) : (
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Rule</th>
                <th>Name</th>
                <th>Engine</th>
                <th>Category</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {rules
                .filter((r) =>
                  JSON.stringify(r).toLowerCase().includes(query.toLowerCase()),
                )
                .map((r) => (
                  <tr key={r.id}>
                    <td className="mono">{r.id}</td>
                    <td>{r.name}</td>
                    <td>{r.type}</td>
                    <td>{r.category}</td>
                    <td>
                      <button
                        aria-label={"Inspect " + r.id}
                        onClick={() => setSelected(r)}
                      >
                        <Icon name="code-slash" />
                      </button>
                    </td>
                  </tr>
                ))}
            </tbody>
          </table>
        </div>
      )}
      {selected && (
        <Modal title={selected.id} onClose={() => setSelected(null)}>
          <div className="modal-body">
            <h3>{selected.name}</h3>
            <p>{selected.description}</p>
            <pre>{selected.syntax}</pre>
          </div>
        </Modal>
      )}
    </>
  );
}

export function Cases({ data, source, onRefresh, onAlert }) {
  const [chosen, setChosen] = useState(null),
    [entries, setEntries] = useState([]),
    [status, setStatus] = useState("Open"),
    [owner, setOwner] = useState(""),
    [note, setNote] = useState(""),
    [error, setError] = useState(""),
    [busy, setBusy] = useState(false);
  function select(c) {
    setChosen(c);
    setStatus(c.status);
    setOwner(c.owner);
    setNote("");
    setError("");
    setEntries([]);
    api("/api/history?key=case:" + c.id)
      .then(setEntries)
      .catch((e) => setError(e.message));
  }
  async function update(e) {
    e.preventDefault();
    setBusy(true);
    try {
      await api("/api/case-update", {
        source,
        id: chosen.id,
        status,
        owner,
        note,
      });
      await onRefresh();
      setChosen(null);
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <>
      <div className="section-heading">
        <h2>Investigation cases</h2>
        <span>{data.cases.length} cases in this source</span>
      </div>
      {!data.cases.length ? (
        <Empty title="No cases yet">
          Select alerts in the queue and create an investigation case.
        </Empty>
      ) : (
        <div className="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Case</th>
                <th>Title</th>
                <th>Status</th>
                <th>Owner</th>
                <th>Alerts</th>
                <th>Updated (UTC)</th>
              </tr>
            </thead>
            <tbody>
              {data.cases.map((c) => (
                <tr key={c.id}>
                  <td>
                    <button className="link mono" onClick={() => select(c)}>
                      {c.case_id}
                    </button>
                  </td>
                  <td>{c.title}</td>
                  <td>
                    <Badge value={c.status} />
                  </td>
                  <td>{c.owner || "Unassigned"}</td>
                  <td>{c.alert_keys.length}</td>
                  <td className="mono">{time(c.updated_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {chosen && (
        <Modal title={chosen.case_id} onClose={() => setChosen(null)}>
          <form className="modal-body" onSubmit={update}>
            <h3>{chosen.title}</h3>
            <div className="form-grid">
              <Field label="Case status">
                <select
                  value={status}
                  onChange={(e) => setStatus(e.target.value)}
                >
                  {["Open", "Investigating", "Closed"].map((v) => (
                    <option key={v}>{v}</option>
                  ))}
                </select>
              </Field>
              <Field label="Case owner">
                <input
                  maxLength={80}
                  value={owner}
                  onChange={(e) => setOwner(e.target.value)}
                />
              </Field>
            </div>
            <h3>Linked alerts</h3>
            <div className="linked">
              {chosen.alert_keys.map((key) => {
                const r = data.rows.find((r) => r.key === key);
                return r ? (
                  <button
                    type="button"
                    key={key}
                    onClick={() => {
                      setChosen(null);
                      onAlert(key);
                    }}
                  >
                    {r.event_id}
                    <Icon name="arrow-up-right" />
                  </button>
                ) : (
                  <span key={key}>Evidence outside current window</span>
                );
              })}
            </div>
            <Field label="Case update">
              <textarea
                required
                maxLength={4000}
                rows={3}
                value={note}
                onChange={(e) => setNote(e.target.value)}
              />
            </Field>
            {error && (
              <p className="error" role="alert">
                {error}
              </p>
            )}
            <button className="primary" disabled={busy}>
              Save case
            </button>
            <History entries={entries} />
          </form>
        </Modal>
      )}
    </>
  );
}
