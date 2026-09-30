function RenderMapTab({ alerts }) {
  const canvasRef = React.useRef(null);
  React.useEffect(() => {
    const canvas = canvasRef.current;
    const ctx = canvas.getContext('2d');
    const assets = window.deriveAssets(alerts);
    const resize = () => {
      canvas.width = canvas.parentElement.clientWidth;
      canvas.height = Math.max(300, Math.ceil(assets.length / Math.max(1, Math.floor(canvas.width / 180))) * 140);
      draw();
    };
    function draw() {
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      if (!assets.length) {
        ctx.fillStyle = '#7c8293';
        ctx.font = '14px sans-serif';
        ctx.textAlign = 'center';
        ctx.fillText('No observed endpoints', canvas.width / 2, 150);
        return;
      }
      const columns = Math.max(1, Math.floor(canvas.width / 180));
      const positions = new Map(assets.map((a, i) => [a.ip, {
        x: (i % columns + .5) * canvas.width / columns,
        y: 70 + Math.floor(i / columns) * 140,
      }]));
      const links = new Set();
      ctx.strokeStyle = '#394451';
      alerts.forEach(a => {
        const from = positions.get(a.source_ip), to = positions.get(a.destination_ip);
        const key = [a.source_ip, a.destination_ip].sort().join('|');
        if (!from || !to || links.has(key)) return;
        links.add(key);
        ctx.beginPath(); ctx.moveTo(from.x, from.y); ctx.lineTo(to.x, to.y); ctx.stroke();
      });
      assets.forEach(a => {
        const pos = positions.get(a.ip);
        ctx.fillStyle = '#11131a';
        ctx.strokeStyle = a.risk >= 60 ? '#ef4444' : '#06b6d4';
        ctx.lineWidth = 2;
        ctx.beginPath(); ctx.arc(pos.x, pos.y, 16, 0, Math.PI * 2); ctx.fill(); ctx.stroke();
        ctx.textAlign = 'center'; ctx.font = '12px monospace'; ctx.fillStyle = '#e2e4ea';
        ctx.fillText(a.ip, pos.x, pos.y + 38);
        ctx.font = '10px sans-serif'; ctx.fillStyle = '#7c8293';
        ctx.fillText(a.risk === null ? 'Risk unavailable' : 'Risk ' + a.risk, pos.x, pos.y + 56);
      });
    }
    resize();
    window.addEventListener('resize', resize);
    return () => window.removeEventListener('resize', resize);
  }, [alerts]);
  return (
    <div className="space-y-4">
      <h2 className="text-lg font-bold text-white">Observed OT Endpoints</h2>
      <div className="w-full min-w-0"><canvas ref={canvasRef} className="w-full block" /></div>
    </div>
  );
}
window.RenderMapTab = RenderMapTab;
