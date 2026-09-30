// Detection Rules Registry Component
function RenderRulesTab() {
  const [rules, setRules] = React.useState([]);
  const [selectedRule, setSelectedRule] = React.useState(null);
  React.useEffect(() => {
    let cancelled = false;
    fetch('/api/rules').then(res => res.json()).then(rows => {
      if (!cancelled) { setRules(rows); setSelectedRule(rows[0] || null); }
    }).catch(() => {});
    return () => { cancelled = true; };
  }, []);

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-bold text-white">Detection Rules Registry</h2>
        <p className="text-xs text-siemMuted">Configured rule files</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <div className="lg:col-span-7 bg-siemCard border border-siemBorder rounded p-5">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="border-b border-siemBorder text-[10px] uppercase font-bold text-siemMuted tracking-wider">
                <th className="p-3">Rule ID</th>
                <th className="p-3">Name</th>
                <th className="p-3">Type</th>
                <th className="p-3">Category</th>
                <th className="p-3">Status</th>
              </tr>
            </thead>
            <tbody>
              {rules.map(r => (
                <tr 
                  key={r.id} 
                  onClick={() => setSelectedRule(r)}
                  className={`border-b border-siemBorder hover:bg-siemHover transition cursor-pointer ${selectedRule?.id === r.id ? 'bg-siemHover/50' : ''}`}
                >
                  <td className="p-3 font-mono font-bold text-sky-400">{r.id}</td>
                  <td className="p-3 font-semibold text-gray-200">{r.name}</td>
                  <td className="p-3 text-siemMuted">{r.type}</td>
                  <td className="p-3 text-siemMuted">{r.category}</td>
                  <td className="p-3 font-semibold">
                    <span className="text-emerald-500 mr-1.5">●</span>
                    <span className="text-[11px] text-gray-300">{r.status}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="lg:col-span-5 bg-siemCard border border-siemBorder rounded p-5">
          {selectedRule ? (
            <div className="space-y-4">
              <div className="flex justify-between items-center pb-2 border-b border-siemBorder">
                <h6 className="text-xs uppercase font-bold text-sky-400">{selectedRule.id} syntax</h6>
                <span className="text-[10px] text-siemMuted font-mono">{selectedRule.type}</span>
              </div>
              <p className="text-xs text-gray-300 font-medium">{selectedRule.description}</p>
              <pre className="font-mono text-[11px] text-emerald-500 bg-slate-950 p-4 border border-siemBorder rounded whitespace-pre-wrap leading-relaxed">
                {selectedRule.syntax}
              </pre>
            </div>
          ) : (
            <div className="h-full flex flex-col items-center justify-center text-center p-6 text-siemMuted text-xs">
              <i className="bi bi-code-square text-2xl mb-2 text-siemMuted"></i>
              Select a rule from the registry list to inspect its compiled signature syntax or model parameters.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// Bind to window for global availability
window.RenderRulesTab = RenderRulesTab;
