export const { useState, useEffect, useRef, useMemo } = React;
export const Icon = ({ name }) => (
  <i aria-hidden="true" className={"bi bi-" + name} />
);
export const Badge = ({ value, kind = "" }) => (
  <span
    className={
      "badge " +
      kind +
      " " +
      String(value || "unknown")
        .toLowerCase()
        .replaceAll(" ", "-")
    }
  >
    {value || "Unknown"}
  </span>
);
export function fmt(value, digits = 0) {
  return value === null || value === undefined
    ? "Unavailable"
    : Number(value).toLocaleString("en-US", { maximumFractionDigits: digits });
}
export function time(value, short = false) {
  if (!value) return "Unavailable";
  const d = new Date(value);
  return Number.isNaN(+d)
    ? "Unavailable"
    : d
        .toISOString()
        .replace("T", " ")
        .slice(short ? 11 : 0, 19);
}
export async function api(path, body) {
  const res = await fetch(path, {
    cache: "no-store",
    ...(body
      ? {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
        }
      : {}),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || "Request failed");
  return data;
}
export function ElasticLink({
  row,
  source,
  children = "Investigate in Elastic",
}) {
  const quote = (value) => JSON.stringify(String(value));
  const query = ["event.id: " + quote(row.event_id)];
  if (["main", "challenge"].includes(source))
    query.push("threatfusion.case: " + quote(source));
  // Discover accepts a Rison state, with apostrophes and exclamation marks escaped.
  const rison = (value) =>
    String(value).replaceAll("!", "!!").replaceAll("'", "!'");
  const a =
    "(index:'threatfusion-alerts',query:(language:kuery,query:'" +
    rison(query.join(" and ")) +
    "'))";
  const d = row.timestamp ? new Date(row.timestamp) : null;
  const g =
    d && !Number.isNaN(+d)
      ? "(time:(from:'" +
        new Date(+d - 300000).toISOString() +
        "',to:'" +
        new Date(+d + 300000).toISOString() +
        "'))"
      : "(time:(from:now-24h,to:now))";
  return (
    <a
      className="button"
      target="_blank"
      rel="noreferrer"
      href={
        "http://127.0.0.1:15601/app/discover#/?_g=" +
        encodeURIComponent(g) +
        "&_a=" +
        encodeURIComponent(a)
      }
    >
      {children}
      <Icon name="box-arrow-up-right" />
    </a>
  );
}
export function Empty({ title = "No results", children }) {
  return (
    <div className="empty">
      <Icon name="inbox" />
      <h3>{title}</h3>
      {children && <p>{children}</p>}
    </div>
  );
}
export function Download({ name, children }) {
  return (
    <a className="button" href={"/api/artifacts/" + name} download={name}>
      <Icon name="download" />
      {children}
    </a>
  );
}
export function Field({ label, children }) {
  const id = React.useId();
  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      {React.cloneElement(children, { id })}
    </div>
  );
}
export function Facts({ items }) {
  return (
    <dl className="facts">
      {items.map(([k, v]) => (
        <React.Fragment key={k}>
          <dt>{k}</dt>
          <dd>{v ?? "Unavailable"}</dd>
        </React.Fragment>
      ))}
    </dl>
  );
}
export function History({ entries }) {
  return (
    <div className="history">
      {entries.length ? (
        entries.map((e) => (
          <article key={e.id}>
            <div>
              <strong>{e.actor}</strong>
              <time>{time(e.created_at)}</time>
            </div>
            <p>{e.action}</p>
            {e.note && <blockquote>{e.note}</blockquote>}
          </article>
        ))
      ) : (
        <Empty title="No analyst activity" />
      )}
    </div>
  );
}
export function Modal({ title, onClose, children }) {
  const ref = useRef();
  useEffect(() => {
    const previous = document.activeElement;
    ref.current.showModal();
    return () => {
      if (previous?.isConnected) previous.focus();
    };
  }, []);
  return (
    <dialog
      className="modal"
      ref={ref}
      onCancel={(e) => {
        e.preventDefault();
        onClose();
      }}
    >
      <header>
        <h2>{title}</h2>
        <button aria-label="Close dialog" title="Close" onClick={onClose}>
          <Icon name="x-lg" />
        </button>
      </header>
      {children}
    </dialog>
  );
}
export function Trend({ rows }) {
  const ref = useRef();
  useEffect(() => {
    const canvas = ref.current;
    if (!canvas) return;
    const draw = () => {
      const w = canvas.parentElement.clientWidth,
        h = 92,
        dpr = window.devicePixelRatio || 1;
      canvas.width = w * dpr;
      canvas.height = h * dpr;
      const c = canvas.getContext("2d");
      c.scale(dpr, dpr);
      c.clearRect(0, 0, w, h);
      const stamps = rows
        .filter((r) => r.timestamp)
        .map((r) => +new Date(r.timestamp))
        .filter(Number.isFinite);
      if (!stamps.length) {
        c.fillStyle = "#69717a";
        c.font = "12px system-ui";
        c.fillText("No timestamped events", 8, 40);
        return;
      }
      const min = Math.min(...stamps),
        max = Math.max(...stamps),
        bins = Array.from({ length: 40 }, () => 0);
      stamps.forEach(
        (t) =>
          bins[Math.min(39, Math.floor(((t - min) / (max - min + 1)) * 40))]++,
      );
      const peak = Math.max(...bins);
      bins.forEach((v, i) => {
        c.fillStyle = "#2c7a65";
        c.fillRect(
          (i * w) / 40 + 2,
          66 - (v / peak) * 52,
          Math.max(2, w / 40 - 4),
          (v / peak) * 52,
        );
      });
      c.fillStyle = "#69717a";
      c.font = "11px monospace";
      c.fillText(time(new Date(min), true), 2, 87);
      c.textAlign = "right";
      c.fillText(time(new Date(max), true), w - 2, 87);
    };
    draw();
    const observer = new ResizeObserver(draw);
    observer.observe(canvas.parentElement);
    return () => observer.disconnect();
  }, [rows]);
  return (
    <canvas
      ref={ref}
      className="trend"
      role="img"
      aria-label="Alert distribution over the selected capture, UTC"
    />
  );
}
export function exportCsv(rows) {
  const headers = [
    "event_id",
    "timestamp",
    "source_ip",
    "destination_ip",
    "severity",
    "risk",
    "context",
    "status",
    "owner",
    "disposition",
  ];
  const quote = (v) => {
    let text = String(v ?? "");
    if (/^[=+@\-\t\r]/.test(text)) text = "'" + text;
    return '"' + text.replaceAll('"', '""') + '"';
  };
  const values = rows.map((r) => ({ ...r, ...r.triage }));
  const text = [headers, ...values.map((r) => headers.map((h) => r[h]))]
    .map((r) => r.map(quote).join(","))
    .join("\r\n");
  const url = URL.createObjectURL(new Blob([text], { type: "text/csv" }));
  const link = document.createElement("a");
  link.href = url;
  link.download = "threatfusion-filtered-alerts.csv";
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
