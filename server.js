// WAR-01 bkprobe app: serves the build-time measurement report collected in the RUN step.
const http = require('http');
const fs = require('fs');

const CANDIDATES = ['/app/probe-report.json', '/tmp/probe-report.json'];

function loadReport() {
  for (const p of CANDIDATES) {
    try { return { path: p, body: fs.readFileSync(p, 'utf8') }; } catch (e) {}
  }
  return { path: null, body: JSON.stringify({ note: 'no report file found', candidates: CANDIDATES }) };
}

const server = http.createServer((req, res) => {
  const r = loadReport();
  if (req.url === '/healthz' || req.url === '/health') { res.writeHead(200, { 'content-type': 'text/plain' }); res.end('ok'); return; }
  res.writeHead(200, { 'content-type': 'application/json', 'x-report-path': String(r.path) });
  res.end(r.body);
});

const port = Number(process.env.PORT || 8080);
server.listen(port, '0.0.0.0', () => console.log('bkprobe listening on ' + port));
