// Global Helper functions
window.formatTime = function(isoStr) {
  if (!isoStr) return 'N/A';
  const d = new Date(isoStr);
  if (isNaN(d.getTime())) return isoStr;
  return d.toISOString().replace('T', ' ').substring(0, 19);
};

window.normalizeSeverity = function(sev) {
  if (!sev) return 'Unknown';
  const s = sev.toUpperCase().trim();
  if (s === 'CRITICAL' || s === 'MALICIOUS') return 'Critical';
  if (s === 'HIGH') return 'High';
  if (s === 'MEDIUM' || s === 'WARNING') return 'Medium';
  if (s === 'LOW' || s === 'BENIGN') return 'Low';
  return 'Unknown';
};

window.extractDetector = function(a) {
  if (a.detector) return a.detector;
  const reasonsStr = String(a.reasons || a.description || '').toLowerCase();
  if (reasonsStr.includes('isolation_forest')) {
    return 'Isolation Forest';
  }
  if (reasonsStr.includes('lstm')) {
    return 'LSTM Autoencoder';
  }
  if (reasonsStr.includes('yara')) {
    return 'YARA';
  }
  if (reasonsStr.includes('snort')) {
    return 'Snort';
  }
  if (reasonsStr.includes('suricata')) {
    return 'Suricata';
  }
  if (reasonsStr.includes('hybrid')) {
    return 'Hybrid Fusion';
  }
  if (reasonsStr.includes('ai_baseline')) {
    return 'AI Baseline';
  }
  return a.classification || 'Anomaly Detection';
};

window.mapAlert = function(a) {
  const number = value => value !== undefined && value !== null && value !== '' && Number.isFinite(Number(value)) ? Number(value) : null;
  return {
    event_id: a.event_id || a.eventid || null,
    incident_id: a.incident_id || a.incidentid || null,
    timestamp: a.timestamp || a.time || null,
    severity: a.top_severity || a.topseverity || a.severity || a.verdict || 'Unknown',
    detector: window.extractDetector(a),
    source_ip: a.src_ip || a.srcip || a.source_ip || a.sourceip || null,
    destination_ip: a.dst_ip || a.dstip || a.destination_ip || a.destinationip || null,
    protocol: a.protocol || 'Unknown',
    risk_score: number(a.risk_score ?? a.riskscore),
    latency_ms: number(a.latency_ms ?? a.latencyms),
    description: a.reasons || a.description || a.classification || '',
    classification: a.classification || 'Unclassified',
    payload: a,
  };
};

window.deriveAssets = function(alerts) {
  const assets = new Map();
  alerts.forEach(alert => [alert.source_ip, alert.destination_ip].filter(Boolean).forEach(ip => {
    if (!assets.has(ip)) assets.set(ip, { id: ip, ip, name: ip, role: 'Observed endpoint', status: 'Observed', risk: null });
    const asset = assets.get(ip);
    if (alert.risk_score !== null) asset.risk = Math.max(asset.risk ?? 0, alert.risk_score);
  }));
  return [...assets.values()];
};

window.deriveIncidents = function(alerts) {
  const groups = new Map();
  alerts.forEach(alert => {
    const key = alert.incident_id || [alert.source_ip, alert.destination_ip, alert.classification].join('|');
    if (!groups.has(key)) groups.set(key, { incident_id: alert.incident_id || 'GROUP-' + (groups.size + 1), severity: alert.severity, event_count: 0, risk_score: null, status: 'Open', first_seen: alert.timestamp, last_seen: alert.timestamp });
    const group = groups.get(key);
    group.event_count += 1;
    group.last_seen = alert.timestamp;
    if (alert.risk_score !== null && (group.risk_score === null || alert.risk_score > group.risk_score)) {
      group.risk_score = alert.risk_score;
      group.severity = alert.severity;
    }
  });
  return [...groups.values()];
};
