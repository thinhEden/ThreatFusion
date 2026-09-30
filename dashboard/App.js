import {
  useState,
  useEffect,
  useRef,
  useMemo,
  Icon,
  Badge,
  Empty,
  Modal,
  Field,
  Trend,
  fmt,
  time,
  api,
  exportCsv,
} from "./soc/common.js";
import { Investigation } from "./soc/Investigation.js";
import { Assets, Policies, Research, Rules, Cases } from "./soc/Views.js";

const NAV = [
  ["queue", "shield-check", "Alert queue"],
  ["cases", "folder2-open", "Cases"],
  ["assets", "diagram-3", "Endpoints"],
  ["policies", "clipboard-check", "OT context"],
  ["research", "bar-chart-line", "Evaluation"],
  ["rules", "code-square", "Detection rules"],
];
const blank = {
  rows: [],
  assets: [],
  flows: [],
  cases: [],
  source: { kind: "live", total: 0 },
};
function App() {
  const [sources, setSources] = useState([]),
    [source, setSource] = useState(null),
    [data, setData] = useState(blank),
    [view, setView] = useState("queue");
  const [query, setQuery] = useState(""),
    [severity, setSeverity] = useState("all"),
    [status, setStatus] = useState("all"),
    [decision, setDecision] = useState("retained"),
    [windowFilter, setWindowFilter] = useState("all"),
    [sort, setSort] = useState("time-desc");
  const [selected, setSelected] = useState(new Set()),
    [focused, setFocused] = useState(null),
    [page, setPage] = useState(1),
    [paused, setPaused] = useState(false),
    [loading, setLoading] = useState(true),
    [error, setError] = useState(""),
    [lastUpdate, setLastUpdate] = useState(null),
    [toast, setToast] = useState("");
  const [modal, setModal] = useState(null),
    [form, setForm] = useState({}),
    [formError, setFormError] = useState(""),
    [saving, setSaving] = useState(false);
  const importRef = useRef(),
    generation = useRef(0),
    sourceRef = useRef(null),
    refreshRef = useRef();
  const notify = (message) => setToast(message);
  useEffect(() => {
    if (!toast) return;
    const t = setTimeout(() => setToast(""), 4500);
    return () => clearTimeout(t);
  }, [toast]);
  useEffect(() => {
    api("/api/sources")
      .then((s) => {
        setSources(s.sources);
        setSource(s.default_source);
      })
      .catch((e) => {
        setError(e.message);
        setLoading(false);
      });
  }, []);
  async function refresh() {
    const id = sourceRef.current;
    if (!id) return;
    const token = generation.current;
    try {
      const next = await api("/api/workspace?source=" + encodeURIComponent(id));
      if (token !== generation.current) return;
      setData(next);
      setError("");
      setLoading(false);
      setLastUpdate(new Date());
      return next;
    } catch (e) {
      if (token !== generation.current) return;
      setError(e.message);
      setLoading(false);
      throw e;
    }
  }
  refreshRef.current = refresh;
  useEffect(() => {
    sourceRef.current = source;
    generation.current++;
    setData(blank);
    setSelected(new Set());
    setFocused(null);
    setPage(1);
    setQuery("");
    setSeverity("all");
    setStatus("all");
    setDecision("retained");
    setWindowFilter("all");
    setLoading(true);
    setLastUpdate(null);
    setError("");
    if (source) refresh().catch(() => {});
  }, [source]);
  useEffect(() => {
    if (source !== "live" || paused) return;
    let running = false;
    const timer = setInterval(async () => {
      if (running) return;
      running = true;
      try {
        await refreshRef.current();
      } catch {
      } finally {
        running = false;
      }
    }, 3000);
    return () => clearInterval(timer);
  }, [source, paused]);
  const rows = data.rows,
    focus = rows.find((r) => r.key === focused);
  const visible = useMemo(() => {
    const cutoff =
      windowFilter === "all" ? null : Date.now() - Number(windowFilter) * 60000;
    return rows
      .filter(
        (r) =>
          (decision === "all" || r.context === decision) &&
          (severity === "all" || r.severity === severity) &&
          (status === "all" || r.triage.status === status) &&
          (!cutoff || (r.timestamp && +new Date(r.timestamp) >= cutoff)) &&
          [
            r.event_id,
            r.source_ip,
            r.destination_ip,
            r.reasons,
            r.triage.owner,
            r.classification,
            r.audit?.policy_id,
          ]
            .join(" ")
            .toLowerCase()
            .includes(query.toLowerCase()),
      )
      .sort((a, b) =>
        sort === "risk-desc"
          ? (b.risk ?? -1) - (a.risk ?? -1)
          : sort === "time-asc"
            ? String(a.timestamp || "").localeCompare(String(b.timestamp || ""))
            : String(b.timestamp || "").localeCompare(
                String(a.timestamp || ""),
              ),
      );
  }, [rows, query, severity, status, decision, windowFilter, sort]);
  useEffect(() => {
    setPage(1);
    setSelected(new Set());
  }, [query, severity, status, decision, windowFilter, source]);
  const pages = Math.max(1, Math.ceil(visible.length / 25)),
    current = Math.min(page, pages),
    pageRows = visible.slice((current - 1) * 25, current * 25);
  const live = source === "live",
    lab = data.source.kind === "recorded_lab",
    retained = rows.filter((r) => r.context === "retained"),
    suppressed = rows.length - retained.length;
  const pending = retained.filter((r) => r.triage.status === "Open").length,
    critical = retained.filter((r) => r.severity === "critical").length;
  function toggle(key) {
    setSelected((prev) => {
      const n = new Set(prev);
      n.has(key) ? n.delete(key) : n.add(key);
      return n;
    });
  }
  function openModal(type, keys = [...selected]) {
    setForm({
      keys,
      title: "",
      owner: "",
      status: "Investigating",
      disposition: "Unreviewed",
      note: "",
    });
    setFormError("");
    setModal(type);
  }
  async function saveTriage(fields) {
    await api("/api/triage", { source, ...fields });
    await refresh();
    notify("Analyst update saved");
  }
  async function submit(e) {
    e.preventDefault();
    setSaving(true);
    setFormError("");
    try {
      if (modal === "case") {
        await api("/api/cases", { source, ...form });
        await refresh();
      } else if (modal === "bulk") await saveTriage(form);
      else if (modal === "clear") {
        await api("/api/clear", {});
        await refresh();
      }
      setModal(null);
      setSelected(new Set());
      notify(
        modal === "case"
          ? "Case created"
          : modal === "clear"
            ? "Live stream cleared"
            : "Updates saved",
      );
    } catch (e) {
      setFormError(e.message);
    } finally {
      setSaving(false);
    }
  }
  async function importAlerts(event) {
    const file = event.target.files[0];
    if (!file) return;
    try {
      if (file.size > 4500000)
        throw new Error("CSV must be smaller than 4.5 MB");
      const result = await api("/api/import", {
        name: file.name,
        csv: await file.text(),
      });
      const next = await api("/api/sources");
      setSources(next.sources);
      setSource(result.source);
      setView("queue");
      notify("CSV imported");
    } catch (e) {
      notify(e.message);
    } finally {
      event.target.value = "";
    }
  }
  function pivot(value) {
    setView("queue");
    setQuery(value);
    setDecision("all");
    setFocused(null);
  }
  function openAlert(key) {
    setView("queue");
    setFocused(key);
  }
  const section = NAV.find((n) => n[0] === view);
  const activeFilters =
    query ||
    severity !== "all" ||
    status !== "all" ||
    decision !== "retained" ||
    windowFilter !== "all";
  return (
    <div className="shell">
      <a className="skip" href="#workspace">
        Skip to workspace
      </a>
      <aside className="rail">
        <a className="brand" href="#queue" onClick={() => setView("queue")}>
          <span className="brand-mark">
            <Icon name="shield-shaded" />
          </span>
          <span>
            THREATFUSION<small>OT SECURITY OPERATIONS</small>
          </span>
        </a>
        <div className="rail-label">WORKSPACE</div>
        <nav aria-label="Workspace">
          {NAV.map(([id, icon, label]) => (
            <button
              className={view === id ? "active" : ""}
              key={id}
              aria-current={view === id ? "page" : undefined}
              onClick={() => {
                setView(id);
                setFocused(null);
              }}
            >
              <Icon name={icon} />
              <span>{label}</span>
              {id === "queue" && <b>{retained.length}</b>}
              {id === "cases" && data.cases.length > 0 && (
                <b>{data.cases.length}</b>
              )}
            </button>
          ))}
        </nav>
        <div className="rail-bottom">
          <a
            href="http://127.0.0.1:15601/app/security/alerts"
            target="_blank"
            rel="noreferrer"
          >
            <Icon name="box-arrow-up-right" />
            Elastic Security
          </a>
          <div className="identity">
            <span>LA</span>
            <div>
              Local analyst<small>Local workspace</small>
            </div>
          </div>
        </div>
      </aside>
      <div className="work-area">
        <header className="topbar">
          <div className="breadcrumb">
            <span>Operations</span>
            <Icon name="chevron-right" />
            <strong>{section[2]}</strong>
          </div>
          <div className="top-actions">
            <span className={"connection " + (error ? "offline" : "")}>
              <span />
              {error
                ? "Data unavailable"
                : loading
                  ? "Connecting"
                  : live
                    ? "Stream API connected"
                    : "Evidence loaded"}
            </span>
            <span className="zone">UTC</span>
            <button
              title="Refresh data"
              aria-label="Refresh data"
              onClick={() => refresh().catch(() => {})}
            >
              <Icon name="arrow-clockwise" />
            </button>
            <button
              title="Import alerts CSV"
              aria-label="Import alerts CSV"
              onClick={() => importRef.current.click()}
            >
              <Icon name="upload" />
            </button>
            <input
              type="file"
              hidden
              ref={importRef}
              accept=".csv"
              onChange={importAlerts}
            />
          </div>
        </header>
        <div className="mobile-nav">
          <select
            aria-label="Workspace view"
            value={view}
            onChange={(e) => {
              setView(e.target.value);
              setFocused(null);
            }}
          >
            {NAV.map(([id, , label]) => (
              <option value={id} key={id}>
                {label}
              </option>
            ))}
          </select>
        </div>
        <main id="workspace">
          <div className="page-heading">
            <div>
              <div className="eyebrow">
                THREATFUSION / {live ? "MONITORING" : "EVIDENCE WORKSPACE"}
              </div>
              <h1>{section[2]}</h1>
            </div>
            <div className="source-control">
              <label htmlFor="source">Data source</label>
              <select
                id="source"
                value={source || ""}
                onChange={(e) => setSource(e.target.value)}
              >
                {!source && <option>Loading…</option>}
                {sources.map((s) => (
                  <option key={s.id} value={s.id} disabled={!s.available}>
                    {s.label}
                    {!s.available ? " (unavailable)" : ""}
                  </option>
                ))}
              </select>
            </div>
          </div>
          <div className="scope-line">
            <span>
              <Icon name={lab ? "file-earmark-check" : "broadcast"} />
              {lab
                ? "Recorded lab · synthetic Modbus"
                : live
                  ? "Live stream · latest 5,000 alert rows"
                  : "Imported evidence"}
            </span>
            <span>
              {data.source.from
                ? time(data.source.from) + " — " + time(data.source.to) + " UTC"
                : "No capture window available"}
            </span>
            {live && (
              <label className="pause">
                <input
                  type="checkbox"
                  checked={paused}
                  onChange={(e) => setPaused(e.target.checked)}
                />
                Pause updates
              </label>
            )}
          </div>
          {error && (
            <div className="error-banner" role="alert">
              <Icon name="exclamation-triangle" />
              <span>
                {error}
                {lastUpdate ? " · Showing last successful snapshot" : ""}
              </span>
              <button onClick={() => refresh().catch(() => {})}>Retry</button>
            </div>
          )}
          {loading ? (
            <div className="loading-state" role="status">
              <div className="skeleton" />
              <div className="skeleton" />
              <div className="skeleton" />
              <p>Loading evidence…</p>
            </div>
          ) : (
            <>
              {view === "queue" && (
                <>
                  <div className="metrics-strip">
                    <div>
                      <span>Retained alerts</span>
                      <strong>{fmt(retained.length)}</strong>
                      <small>{pending} awaiting review</small>
                    </div>
                    <div>
                      <span>Critical severity</span>
                      <strong className={critical ? "danger-text" : ""}>
                        {critical}
                      </strong>
                      <small>Retained detections</small>
                    </div>
                    <div>
                      <span>Context suppressed</span>
                      <strong>{lab ? fmt(suppressed) : "—"}</strong>
                      <small>
                        {lab
                          ? "Audit evidence preserved"
                          : "Audit coverage unavailable"}
                      </small>
                    </div>
                    <div className="trend-cell">
                      <div className="inline spread">
                        <span>Candidate activity</span>
                        <small>UTC · source scope</small>
                      </div>
                      <Trend rows={rows} />
                    </div>
                  </div>
                  <section className="queue">
                    <div className="toolbar">
                      <label className="search">
                        <Icon name="search" />
                        <input
                          value={query}
                          onChange={(e) => setQuery(e.target.value)}
                          aria-label="Search alerts"
                          placeholder="Search endpoint, event, ticket or reason"
                        />
                      </label>
                      <select
                        aria-label="Context filter"
                        value={decision}
                        onChange={(e) => setDecision(e.target.value)}
                      >
                        <option value="retained">Retained alerts</option>
                        <option value="suppressed">Context suppressed</option>
                        <option value="all">All candidates</option>
                      </select>
                      <select
                        aria-label="Severity filter"
                        value={severity}
                        onChange={(e) => setSeverity(e.target.value)}
                      >
                        <option value="all">All severities</option>
                        {["critical", "high", "medium", "low", "unknown"].map(
                          (v) => (
                            <option key={v}>{v}</option>
                          ),
                        )}
                      </select>
                      <select
                        aria-label="Status filter"
                        value={status}
                        onChange={(e) => setStatus(e.target.value)}
                      >
                        <option value="all">All statuses</option>
                        {["Open", "Investigating", "Closed"].map((v) => (
                          <option key={v}>{v}</option>
                        ))}
                      </select>
                      <select
                        aria-label="Time range"
                        value={windowFilter}
                        onChange={(e) => setWindowFilter(e.target.value)}
                      >
                        <option value="all">Entire capture</option>
                        <option value="15">Last 15 minutes</option>
                        <option value="60">Last hour</option>
                        <option value="1440">Last 24 hours</option>
                      </select>
                      <button
                        aria-label="Export filtered alerts"
                        title="Export filtered alerts"
                        disabled={!visible.length}
                        onClick={() => exportCsv(visible)}
                      >
                        <Icon name="download" />
                      </button>
                    </div>
                    <div className="queue-caption">
                      <span>
                        <strong>{visible.length}</strong> results
                        {selected.size > 0 &&
                          " · " + selected.size + " selected"}
                      </span>
                      <div className="inline">
                        {activeFilters && (
                          <button
                            className="link"
                            onClick={() => {
                              setQuery("");
                              setSeverity("all");
                              setStatus("all");
                              setDecision("retained");
                              setWindowFilter("all");
                            }}
                          >
                            Reset filters
                          </button>
                        )}
                        <select
                          aria-label="Sort alerts"
                          value={sort}
                          onChange={(e) => setSort(e.target.value)}
                        >
                          <option value="time-desc">Newest first</option>
                          <option value="time-asc">Oldest first</option>
                          <option value="risk-desc">Highest risk</option>
                        </select>
                      </div>
                    </div>
                    {selected.size > 0 && (
                      <div className="bulk-bar">
                        <span>{selected.size} selected</span>
                        <button
                          onClick={() => openModal("bulk")}
                          disabled={selected.size > 100}
                        >
                          <Icon name="person-check" />
                          Update triage
                        </button>
                        <button
                          onClick={() => openModal("case")}
                          disabled={selected.size > 100}
                        >
                          <Icon name="folder-plus" />
                          Create case
                        </button>
                        <button
                          className="link"
                          onClick={() => setSelected(new Set())}
                        >
                          Deselect
                        </button>
                      </div>
                    )}
                    {!visible.length ? (
                      <Empty
                        title={
                          rows.length
                            ? "No matching alerts"
                            : "No alerts in this source"
                        }
                      >
                        {rows.length
                          ? "Adjust your filters to see other evidence."
                          : live
                            ? "The stream has no recorded alerts."
                            : "No candidates were found in this evidence source."}
                      </Empty>
                    ) : (
                      <div className="table-scroll">
                        <table className="alert-table">
                          <thead>
                            <tr>
                              <th className="check">
                                <input
                                  aria-label="Select page"
                                  type="checkbox"
                                  checked={
                                    pageRows.length > 0 &&
                                    pageRows.every((r) => selected.has(r.key))
                                  }
                                  onChange={(e) =>
                                    setSelected((prev) => {
                                      const n = new Set(prev);
                                      pageRows.forEach((r) =>
                                        e.target.checked
                                          ? n.add(r.key)
                                          : n.delete(r.key),
                                      );
                                      return n;
                                    })
                                  }
                                />
                              </th>
                              <th>Severity</th>
                              <th>Time (UTC)</th>
                              <th>Detection / event</th>
                              <th>Source → destination</th>
                              <th>Risk</th>
                              <th>Context</th>
                              <th>Status / owner</th>
                              <th />
                            </tr>
                          </thead>
                          <tbody>
                            {pageRows.map((r) => (
                              <tr
                                key={r.key}
                                className={
                                  focused === r.key ? "selected-row" : ""
                                }
                              >
                                <td className="check">
                                  <input
                                    aria-label={"Select " + r.event_id}
                                    type="checkbox"
                                    checked={selected.has(r.key)}
                                    onChange={() => toggle(r.key)}
                                  />
                                </td>
                                <td>
                                  <Badge value={r.severity} />
                                </td>
                                <td className="mono">
                                  <span>{time(r.timestamp, true)}</span>
                                  <small>
                                    {r.timestamp?.slice(0, 10) ||
                                      "No timestamp"}
                                  </small>
                                </td>
                                <td>
                                  <button
                                    className="row-title"
                                    onClick={() => setFocused(r.key)}
                                  >
                                    {r.classification}
                                  </button>
                                  <small className="mono">
                                    {r.event_id} · {r.protocol}
                                  </small>
                                </td>
                                <td className="mono endpoints">
                                  <span>{r.source_ip || "Unknown"}</span>
                                  <small>
                                    <Icon name="arrow-return-right" />
                                    {r.destination_ip || "Unknown"}
                                  </small>
                                </td>
                                <td className="risk">
                                  <span>{fmt(r.risk)}</span>
                                  {r.risk !== null && (
                                    <meter
                                      min="0"
                                      max="100"
                                      value={r.risk}
                                      aria-label={"Risk " + r.event_id}
                                    />
                                  )}
                                </td>
                                <td>
                                  <Badge value={r.context} />
                                </td>
                                <td>
                                  <span className="status-text">
                                    {r.triage.status}
                                  </span>
                                  <small>
                                    {r.triage.owner || "Unassigned"}
                                  </small>
                                </td>
                                <td>
                                  <button
                                    aria-label={"Investigate " + r.event_id}
                                    title="Investigate alert"
                                    onClick={() => setFocused(r.key)}
                                  >
                                    <Icon name="chevron-right" />
                                  </button>
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    )}
                    <footer className="table-footer">
                      <span>
                        {visible.length
                          ? (current - 1) * 25 +
                            1 +
                            "–" +
                            Math.min(current * 25, visible.length) +
                            " of " +
                            visible.length
                          : "0 results"}
                      </span>
                      <div className="inline">
                        <button
                          title="Previous page"
                          aria-label="Previous page"
                          disabled={current === 1}
                          onClick={() => setPage(current - 1)}
                        >
                          <Icon name="chevron-left" />
                        </button>
                        <span>
                          Page {current} of {pages}
                        </span>
                        <button
                          title="Next page"
                          aria-label="Next page"
                          disabled={current === pages}
                          onClick={() => setPage(current + 1)}
                        >
                          <Icon name="chevron-right" />
                        </button>
                      </div>
                    </footer>
                  </section>
                </>
              )}
              {view === "cases" && (
                <Cases
                  data={data}
                  source={source}
                  onRefresh={refresh}
                  onAlert={openAlert}
                />
              )}
              {view === "assets" && <Assets data={data} onPivot={pivot} />}
              {view === "policies" && <Policies data={data} onPivot={pivot} />}
              {view === "research" && <Research />}
              {view === "rules" && <Rules />}
            </>
          )}
          <footer className="workspace-footer">
            <span>
              <Icon name="database-check" />
              Analyst decisions stored locally · not synchronized to Elastic
            </span>
            <span>
              {lastUpdate
                ? "Updated " + time(lastUpdate, true) + " UTC"
                : "No snapshot loaded"}
              {data.source.total > rows.length
                ? " · Results limited to latest " + rows.length
                : ""}
            </span>
          </footer>
        </main>
      </div>
      {focus && (
        <Investigation
          key={focus.key}
          row={focus}
          rows={rows}
          source={source}
          onClose={() => {
            setFocused(null);
          }}
          onSelect={setFocused}
          onSave={saveTriage}
          onCase={(keys) => openModal("case", keys)}
        />
      )}
      {modal && (
        <Modal
          title={
            modal === "case"
              ? "Create investigation case"
              : modal === "clear"
                ? "Clear live stream"
                : "Update selected alerts"
          }
          onClose={() => setModal(null)}
        >
          <form className="modal-body" onSubmit={submit}>
            <p>
              {form.keys?.length || 0} selected alert
              {form.keys?.length === 1 ? "" : "s"} ·{" "}
              {sources.find((s) => s.id === source)?.label}
            </p>
            {modal === "case" ? (
              <Field label="Case title">
                <input
                  required
                  maxLength={160}
                  value={form.title}
                  onChange={(e) => setForm({ ...form, title: e.target.value })}
                />
              </Field>
            ) : (
              <>
                <Field label="Status">
                  <select
                    value={form.status}
                    onChange={(e) =>
                      setForm({ ...form, status: e.target.value })
                    }
                  >
                    {["Open", "Investigating", "Closed"].map((v) => (
                      <option key={v}>{v}</option>
                    ))}
                  </select>
                </Field>
                <Field label="Disposition">
                  <select
                    value={form.disposition}
                    onChange={(e) =>
                      setForm({ ...form, disposition: e.target.value })
                    }
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
              </>
            )}
            <Field label="Owner">
              <input
                maxLength={80}
                value={form.owner}
                onChange={(e) => setForm({ ...form, owner: e.target.value })}
              />
            </Field>
            <Field label="Note">
              <textarea
                maxLength={4000}
                rows={3}
                value={form.note}
                onChange={(e) => setForm({ ...form, note: e.target.value })}
              />
            </Field>
            {formError && (
              <p role="alert" className="error">
                {formError}
              </p>
            )}
            <div className="inline end">
              <button type="button" onClick={() => setModal(null)}>
                Cancel
              </button>
              <button className="primary" disabled={saving}>
                {saving
                  ? "Saving…"
                  : modal === "case"
                    ? "Create case"
                    : "Save updates"}
              </button>
            </div>
          </form>
        </Modal>
      )}
      {toast && (
        <div className="toast" role="status">
          <Icon name="check-circle" />
          {toast}
          <button
            aria-label="Dismiss notification"
            onClick={() => setToast("")}
          >
            <Icon name="x" />
          </button>
        </div>
      )}
    </div>
  );
}
ReactDOM.createRoot(document.getElementById("root")).render(<App />);
