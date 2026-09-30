import {
  useState,
  useEffect,
  useRef,
  Icon,
  Badge,
  Field,
  Facts,
  History,
  time,
  fmt,
  api,
  ElasticLink,
  Download,
  Empty,
} from "./common.js";

export function Investigation({
  row,
  rows,
  source,
  onClose,
  onSelect,
  onSave,
  onCase,
}) {
  const [tab, setTab] = useState("evidence"),
    [status, setStatus] = useState(row.triage.status),
    [owner, setOwner] = useState(row.triage.owner),
    [disposition, setDisposition] = useState(row.triage.disposition),
    [note, setNote] = useState(""),
    [entries, setEntries] = useState([]),
    [error, setError] = useState(""),
    [busy, setBusy] = useState(false);
  const ref = useRef();
  useEffect(() => {
    const previous = document.activeElement;
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    ref.current.focus({ preventScroll: true });
    const handler = (e) => {
      if (e.key === "Escape" && !document.querySelector("dialog[open]"))
        onClose();
    };
    document.addEventListener("keydown", handler);
    return () => {
      document.removeEventListener("keydown", handler);
      document.body.style.overflow = previousOverflow;
      if (previous?.isConnected) previous.focus({ preventScroll: true });
    };
  }, []);
  useEffect(() => {
    let active = true;
    api("/api/history?key=" + encodeURIComponent(row.key))
      .then((v) => {
        if (active) setEntries(v);
      })
      .catch((e) => {
        if (active) setError(e.message);
      });
    return () => {
      active = false;
    };
  }, [row.key, row.triage.updated_at]);
  const evidence = row.evidence,
    decision = row.audit;
  const peers = rows
    .filter(
      (r) =>
        r.key !== row.key &&
        r.source_ip === row.source_ip &&
        r.destination_ip === row.destination_ip,
    )
    .slice(0, 5);
  async function save(e) {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      await onSave({ keys: [row.key], status, owner, disposition, note });
      setNote("");
      setEntries(await api("/api/history?key=" + row.key));
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <aside
      className="investigation"
      role="region"
      aria-label="Alert investigation"
      tabIndex="-1"
      ref={ref}
    >
      <header className="drawer-head">
        <div>
          <small>INVESTIGATION</small>
          <h2>{row.event_id}</h2>
        </div>
        <button
          title="Close investigation"
          aria-label="Close investigation"
          onClick={onClose}
        >
          <Icon name="x-lg" />
        </button>
      </header>
      <div className="drawer-summary">
        <div className="inline">
          <Badge value={row.severity} />
          <Badge value={row.context} />
          <span className="mono">Risk {fmt(row.risk)}</span>
        </div>
        <h3>{row.classification}</h3>
        <p className="mono">
          {row.source_ip} <Icon name="arrow-right" /> {row.destination_ip}
        </p>
        <small>{time(row.timestamp)} UTC</small>
      </div>
      <div className="tabs" role="tablist" aria-label="Investigation sections">
        {["evidence", "context", "activity"].map((t) => (
          <button
            role="tab"
            aria-selected={tab === t}
            key={t}
            onClick={() => setTab(t)}
          >
            {t[0].toUpperCase() + t.slice(1)}
          </button>
        ))}
      </div>
      <div className="drawer-content">
        {tab === "evidence" && (
          <>
            <h3>Detection evidence</h3>
            <p className="reason">
              {row.reasons || "No detection reason supplied"}
            </p>
            <Facts
              items={[
                ["Protocol", row.protocol],
                [
                  "Packet",
                  row.event_id?.startsWith("PCAP-")
                    ? row.event_id.slice(5)
                    : null,
                ],
                ["Function code", evidence?.function_code],
                ["Unit ID", evidence?.unit_id],
                ["Register", evidence?.register_address],
                [
                  "Values",
                  evidence?.register_values?.length
                    ? evidence.register_values.join(", ")
                    : null,
                ],
                [
                  "Processing time",
                  row.latency_ms !== null
                    ? fmt(row.latency_ms, 4) + " ms"
                    : null,
                ],
              ]}
            />
            <div className="action-links">
              <ElasticLink row={row} source={source} />
              {["main", "challenge"].includes(source) && (
                <Download name={source + ".pcap"}>Packet capture</Download>
              )}
            </div>
            {peers.length > 0 && (
              <section>
                <h3>Related endpoint activity</h3>
                {peers.map((r) => (
                  <button
                    className="related"
                    key={r.key}
                    onClick={() => onSelect(r.key)}
                  >
                    <span className="mono">{r.event_id}</span>
                    <span>{time(r.timestamp, true)}</span>
                    <Badge value={r.context} />
                    <Icon name="chevron-right" />
                  </button>
                ))}
              </section>
            )}
            {row.lab_reference && (
              <details>
                <summary>Recorded lab reference</summary>
                <p className="notice">
                  Scenario label, not an analyst verdict.
                </p>
                <Facts
                  items={[
                    [
                      "Scenario",
                      row.lab_reference.scenario.replaceAll("_", " "),
                    ],
                    ["Ground truth", row.lab_reference.label],
                  ]}
                />
              </details>
            )}
            <details>
              <summary>Raw evidence</summary>
              <pre>
                {JSON.stringify({ alert: row.raw, event: evidence }, null, 2)}
              </pre>
            </details>
          </>
        )}
        {tab === "context" && (
          <>
            <h3>OT authorization decision</h3>
            {decision ? (
              <>
                <p
                  className={
                    "notice " + (row.context === "suppressed" ? "green" : "")
                  }
                >
                  {decision.reason}
                </p>
                <Facts
                  items={[
                    ["Ticket", decision.policy_id || "No matching ticket"],
                    ["Raw detections", decision.raw_detections],
                    ["Retained", decision.retained_detections],
                    ["Suppressed", decision.suppressed_detections],
                  ]}
                />
                <p>
                  Suppression changes the alert queue. The original packet and
                  candidate remain in the audit.
                </p>
              </>
            ) : (
              <Empty title="No linked context audit">
                No context decision is available for this event.
              </Empty>
            )}
          </>
        )}
        {tab === "activity" && (
          <>
            <h3>Analyst history</h3>
            <History entries={entries} />
          </>
        )}
        <section className="triage-section">
          <h3>Disposition</h3>
          <form onSubmit={save}>
            <div className="form-grid">
              <Field label="Status">
                <select
                  value={status}
                  onChange={(e) => setStatus(e.target.value)}
                >
                  {["Open", "Investigating", "Closed"].map((v) => (
                    <option key={v}>{v}</option>
                  ))}
                </select>
              </Field>
              <Field label="Assigned to">
                <input
                  maxLength={80}
                  value={owner}
                  onChange={(e) => setOwner(e.target.value)}
                  placeholder="Unassigned"
                />
              </Field>
            </div>
            <Field label="Analyst verdict">
              <select
                value={disposition}
                onChange={(e) => setDisposition(e.target.value)}
              >
                {[
                  "Unreviewed",
                  "True positive",
                  "False positive",
                  "Benign activity",
                  "Undetermined",
                ].map((v) => (
                  <option key={v}>{v}</option>
                ))}
              </select>
            </Field>
            <Field label="Investigation note">
              <textarea
                maxLength={4000}
                rows={3}
                value={note}
                onChange={(e) => setNote(e.target.value)}
                placeholder="Evidence and rationale"
              />
            </Field>
            {error && (
              <p role="alert" className="error">
                {error}
              </p>
            )}
            <div className="inline spread">
              <button type="button" onClick={() => onCase([row.key])}>
                <Icon name="folder-plus" />
                Create case
              </button>
              <button className="primary" disabled={busy}>
                {busy ? "Saving…" : "Save update"}
              </button>
            </div>
          </form>
        </section>
      </div>
    </aside>
  );
}
