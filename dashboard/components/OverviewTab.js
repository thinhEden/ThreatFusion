// SOC Overview Tab Component
function RenderOverviewTab({
  alerts,
  incidents,
  totalAlertsCount,
  totalIncidentsCount,
  criticalCount,
  simActive,
  timeCanvas,
  severityCanvas,
  expandedIdx,
  setExpandedIdx,
  newAlertTs,
  assetList,
  filteredIncidents,
  detectionLatency
}) {
  // Group and count protocols dynamically from current alerts
  const protocolCounts = {};
  alerts.forEach(a => {
    let proto = (a.protocol || 'Unknown').toUpperCase();
    if (proto === 'MODBUS') proto = 'Modbus';
    else if (proto === 'DNP3') proto = 'DNP3';
    else if (proto === 'HTTP') proto = 'HTTP';
    else if (proto === 'TCP') proto = 'TCP';
    else if (proto === 'UDP') proto = 'UDP';
    else if (proto === 'S7COMM') proto = 'S7Comm';
    protocolCounts[proto] = (protocolCounts[proto] || 0) + 1;
  });

  const totalProtos = alerts.length || 1;
  const sortedProtos = Object.keys(protocolCounts).map(proto => ({
    name: proto,
    count: protocolCounts[proto]
  })).sort((a, b) => b.count - a.count);

  let displayedProtos = [];
  if (sortedProtos.length <= 4) {
    displayedProtos = sortedProtos;
  } else {
    displayedProtos = sortedProtos.slice(0, 3);
    const othersCount = sortedProtos.slice(3).reduce((sum, p) => sum + p.count, 0);
    displayedProtos.push({ name: 'Others', count: othersCount });
  }

  const finalProtocolData = alerts && alerts.length > 0
    ? displayedProtos.map(p => ({
        name: p.name,
        count: p.count,
        percentage: ((p.count / totalProtos) * 100).toFixed(1)
      }))
    : [];

  const getProtoColorClass = (name) => {
    const n = name.toUpperCase();
    if (n.includes('MODBUS')) return 'bg-sky-500';
    if (n.includes('DNP3')) return 'bg-amber-500';
    if (n.includes('S7COMM')) return 'bg-emerald-500';
    if (n.includes('HTTP')) return 'bg-blue-500';
    if (n.includes('TCP')) return 'bg-indigo-500';
    if (n.includes('UDP')) return 'bg-cyan-500';
    if (n.includes('SMB')) return 'bg-teal-500';
    return 'bg-slate-500';
  };

  return (
    <div className="space-y-6">
      {/* Grid 1: Metric Tiles */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-siemCard border border-siemBorder rounded p-4 flex flex-col justify-between h-24 shadow-sm hover:border-slate-800 transition">
          <span className="text-[10px] uppercase font-bold tracking-wider text-siemMuted">Active Alerts</span>
          <div className="flex justify-between items-baseline">
            <span className="text-2xl font-extrabold font-mono text-white">{totalAlertsCount}</span>
            <span className="text-[10px] text-siemMuted font-mono">{simActive ? 'Demo' : 'Observed alerts'}</span>
          </div>
        </div>
        <div className="bg-siemCard border border-siemBorder rounded p-4 flex flex-col justify-between h-24 shadow-sm hover:border-slate-800 transition">
          <span className="text-[10px] uppercase font-bold tracking-wider text-siemMuted">Alert Groups</span>
          <div className="flex justify-between items-baseline">
            <span className="text-2xl font-extrabold font-mono text-amber-500">{totalIncidentsCount}</span>
            <span className="text-[10px] text-amber-500/80 font-semibold">{incidents.filter(i=>i.status==='Open').length} pending triage</span>
          </div>
        </div>
        <div className={`bg-siemCard border border-siemBorder rounded p-4 flex flex-col justify-between h-24 shadow-sm hover:border-slate-800 transition ${criticalCount > 0 && simActive ? 'alert-pulse-active' : ''}`}>
          <span className="text-[10px] uppercase font-bold tracking-wider text-siemMuted">Critical Events</span>
          <div className="flex justify-between items-baseline">
            <span className="text-2xl font-extrabold font-mono text-rose-500">{criticalCount}</span>
            <span className="text-[10px] text-rose-500/80 font-bold uppercase tracking-wider">High Risk Action</span>
          </div>
        </div>
        <div className="bg-siemCard border border-siemBorder rounded p-4 flex flex-col justify-between h-24 shadow-sm hover:border-slate-800 transition">
          <span className="text-[10px] uppercase font-bold tracking-wider text-siemMuted">Detection Latency</span>
          <div className="flex justify-between items-baseline">
            <span className="text-2xl font-extrabold font-mono text-cyan-400">{detectionLatency === 'N/A' ? 'N/A' : detectionLatency + ' ms'}</span>
            <span className="text-[10px] text-siemMuted font-bold">Measured</span>
          </div>
        </div>
      </div>

      {/* Grid 2: Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <div className="lg:col-span-3 bg-siemCard border border-siemBorder rounded p-5 flex flex-col justify-between">
          <div>
            <span className="text-[10px] uppercase font-bold text-siemMuted tracking-wider block mb-1">OT Protocol Distribution</span>
            <h6 className="text-xs font-bold text-white mb-3">Alert protocol distribution</h6>
          </div>
          <div className="space-y-3.5 my-3">
            {finalProtocolData.map((proto, idx) => (
              <div key={idx} className="space-y-1">
                <div className="flex justify-between items-center text-xs">
                  <span className="font-semibold text-slate-300">{proto.name}</span>
                  <span className="font-mono text-[10px] text-siemMuted">
                    {proto.count > 0 ? `${proto.count} (${proto.percentage}%)` : `${proto.percentage}%`}
                  </span>
                </div>
                <div className="w-full bg-slate-950 h-1.5 rounded-full overflow-hidden border border-siemBorder/30">
                  <div 
                    className={`h-full rounded-full transition-all duration-500 ${getProtoColorClass(proto.name)}`}
                    style={{ width: `${proto.percentage}%` }}
                  ></div>
                </div>
              </div>
            ))}
          </div>
          <div className="text-[10px] text-siemMuted leading-relaxed pt-3 border-t border-siemBorder/60">
            {alerts.length ? 'Protocols present in observed alerts.' : 'No alerts available.'}
          </div>
        </div>

        <div className="lg:col-span-5 bg-siemCard border border-siemBorder rounded p-5">
          <div className="flex justify-between items-center mb-3">
            <span className="text-[10px] uppercase font-bold text-siemMuted tracking-wider">Alert Volume Activity</span>
          </div>
          <div className="h-44 relative">
            <canvas ref={timeCanvas}></canvas>
          </div>
        </div>

        <div className="lg:col-span-4 bg-siemCard border border-siemBorder rounded p-5">
          <div className="flex justify-between items-center mb-3">
            <span className="text-[10px] uppercase font-bold text-siemMuted tracking-wider">Severity Breakdown</span>
          </div>
          <div className="h-44 relative">
            <canvas ref={severityCanvas}></canvas>
          </div>
        </div>
      </div>

      {/* Grid 3: Expandable Alerts Stream */}
      <div className="bg-siemCard border border-siemBorder rounded p-5">
        <div className="flex justify-between items-center mb-4 pb-2 border-b border-siemBorder">
          <div>
            <h6 className="text-sm font-bold text-white">Alert Log Stream Explorer</h6>
            <span className="text-[10px] text-siemMuted">Click on any row to expand Raw JSON Payload</span>
          </div>
          <span className="text-[10px] text-siemMuted font-mono">Viewing last 15 entries</span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-siemBorder text-[10px] uppercase font-bold text-siemMuted tracking-wider">
                <th className="p-3 w-8"></th>
                <th className="p-3">Time</th>
                <th className="p-3">Severity</th>
                <th className="p-3">Detector</th>
                <th className="p-3">Source IP</th>
                <th className="p-3">Destination IP</th>
                <th className="p-3">Protocol</th>
                <th className="p-3">Risk</th>
                <th className="p-3">Reason</th>
              </tr>
            </thead>
            <tbody>
              {[...alerts].reverse().slice(0, 15).map((a, idx) => {
                const isExpanded = expandedIdx === idx;
                const sev = window.normalizeSeverity(a.severity);
                let sevColor = "text-yellow-500 bg-yellow-500/5 border border-yellow-500/20";
                if (sev === "Critical") sevColor = "text-rose-500 bg-rose-500/5 border border-rose-500/20";
                else if (sev === "High") sevColor = "text-orange-400 bg-orange-400/5 border border-orange-400/20";
                else if (sev === "Low") sevColor = "text-blue-400 bg-blue-400/5 border border-blue-400/20";

                const isNew = newAlertTs && a.timestamp === newAlertTs && idx === 0;

                return (
                  <React.Fragment key={idx}>
                    <tr 
                      onClick={() => setExpandedIdx(isExpanded ? null : idx)}
                      className={`border-b border-siemBorder text-xs hover:bg-siemHover transition cursor-pointer ${isExpanded ? 'bg-siemHover/50' : ''} ${isNew ? 'new-row-highlight' : ''}`}
                    >
                      <td className="p-3 text-center">
                        <i className={`bi text-siemMuted text-2xs ${isExpanded ? 'bi-chevron-down' : 'bi-chevron-right'}`}></i>
                      </td>
                      <td className="p-3 font-mono text-[11px] text-siemMuted">{window.formatTime(a.timestamp)}</td>
                      <td className="p-3">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${sevColor}`}>{sev}</span>
                      </td>
                      <td className="p-3 font-semibold">{a.detector}</td>
                      <td className="p-3 font-mono text-sky-400">{a.source_ip}</td>
                      <td className="p-3 font-mono text-sky-400">{a.destination_ip}</td>
                      <td className="p-3 font-mono text-siemMuted">{a.protocol}</td>
                      <td className="p-3 font-mono font-bold text-orange-400">{a.risk_score}</td>
                      <td className="p-3 text-siemMuted max-w-xs truncate">{a.description}</td>
                    </tr>
                    {isExpanded && (
                      <tr className="bg-slate-950/70 border-b border-siemBorder">
                        <td colSpan="9" className="p-4">
                          <div className="text-[10px] uppercase font-bold text-sky-400 mb-2 tracking-wider">Raw Telemetry & Detector Insights</div>
                          <pre className="font-mono text-[11px] text-emerald-500 bg-black/60 border border-siemBorder p-4 rounded leading-relaxed overflow-x-auto">
                            {JSON.stringify({
                              event_id: a.event_id,
                              timestamp: a.timestamp,
                              severity: a.severity,
                              detector: a.detector,
                              source: a.source_ip,
                              destination: a.destination_ip,
                              protocol: a.protocol,
                              risk_score: a.risk_score,
                              description: a.description,
                              telemetry_insights: a.payload
                            }, null, 2)}
                          </pre>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Grid 4: Assets & Incidents */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <div className="lg:col-span-7 bg-siemCard border border-siemBorder rounded p-5">
          <h6 className="text-sm font-bold text-white mb-3">Industrial OT Asset Inventory</h6>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-siemBorder text-[10px] uppercase font-bold text-siemMuted tracking-wider">
                  <th className="p-3">ID</th>
                  <th className="p-3">Asset Name</th>
                  <th className="p-3">IP Address</th>
                  <th className="p-3">Role</th>
                  <th className="p-3">Interface</th>
                  <th className="p-3">Risk Score</th>
                </tr>
              </thead>
              <tbody>
                {assetList.map((asset) => {
                  let statusColor = "text-emerald-500";
                  if (asset.status === "Alerting" || asset.status === "Compromised") statusColor = "text-rose-500";
                  else if (asset.status === "Idle") statusColor = "text-gray-500";

                  let riskColor = "bg-sky-500/20 text-sky-400 border border-sky-500/30";
                  if (asset.risk > 75) riskColor = "bg-rose-500/20 text-rose-500 border border-rose-500/30";
                  else if (asset.risk > 50) riskColor = "bg-orange-500/20 text-orange-400 border border-orange-500/30";

                  return (
                    <tr key={asset.id} className="border-b border-siemBorder hover:bg-siemHover/30">
                      <td className="p-3 font-mono font-bold">{asset.id}</td>
                      <td className="p-3 font-semibold text-gray-200">{asset.name}</td>
                      <td className="p-3 font-mono text-siemMuted">{asset.ip}</td>
                      <td className="p-3 text-siemMuted">{asset.role}</td>
                      <td className="p-3 font-semibold">
                        <span className={`mr-1.5 ${statusColor}`}>●</span>
                        <span className="text-[11px] text-gray-300">{asset.status}</span>
                      </td>
                      <td className="p-3">
                        <span className={`px-2 py-0.5 rounded font-mono text-[10px] font-bold ${riskColor}`}>{asset.risk ?? 'N/A'}</span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>

        <div className="lg:col-span-5 bg-siemCard border border-siemBorder rounded p-5">
          <div className="flex justify-between items-center mb-3">
            <h6 className="text-sm font-bold text-white">Incident List</h6>
          </div>
          <div className="overflow-y-auto max-h-72 space-y-3">
            {filteredIncidents.slice(0, 10).map((i, idx) => {
              const sev = window.normalizeSeverity(i.severity);
              let sevBadge = "text-yellow-500 bg-yellow-500/5 border border-yellow-500/20";
              if (sev === "Critical") sevBadge = "text-rose-500 bg-rose-500/5 border border-rose-500/20";
              else if (sev === "High") sevBadge = "text-orange-400 bg-orange-400/5 border border-orange-400/20";

              let statusBadge = "text-rose-400 bg-rose-500/5";
              if (i.status === "Investigating") statusBadge = "text-amber-400 bg-amber-500/5";
              else if (i.status === "Resolved") statusBadge = "text-emerald-400 bg-emerald-500/5";

              return (
                <div key={idx} className="bg-slate-950/40 border border-siemBorder/85 p-3.5 rounded flex flex-col justify-between gap-2">
                  <div className="flex justify-between items-center">
                    <span className="font-mono font-bold text-xs text-sky-400">{i.incident_id}</span>
                    <span className={`px-2 py-0.5 rounded text-[9px] font-bold uppercase ${sevBadge}`}>{sev}</span>
                  </div>
                  <div className="text-[11px] text-siemMuted flex justify-between">
                    <span>Events: <strong className="text-white font-mono">{i.event_count}</strong></span>
                    <span>Risk: <strong className="text-white font-mono">{i.risk_score}</strong></span>
                    <span>Status: <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold uppercase ${statusBadge}`}>{i.status}</span></span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
}

// Bind to window for global availability
window.RenderOverviewTab = RenderOverviewTab;
