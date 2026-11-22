// WAR-01 buildkit measurement probe. Read-only: it never writes to a path that could be host-backed.
// Run inside a RUN step so every measurement comes from the build sandbox.
const fs = require('fs');
const path = require('path');
const net = require('net');

const MARK = 'war01-bkprobe-nonexistent';
const out = { ts: new Date().toISOString(), steps: [], errors: [] };

function step(name, fn) {
  try { out.steps.push({ name, data: fn() }); }
  catch (e) { out.errors.push({ name, errno: e.code || String(e.message) }); }
}

function readOrNull(p) {
  try { return fs.readFileSync(p); } catch (e) { return { errno: e.code }; }
}

function statOrNull(p) {
  try { const s = fs.statSync(p); return { mode: (s.mode & 0o777).toString(8), isDir: s.isDirectory(), dev: s.dev, ino: s.ino, uid: s.uid, gid: s.gid, size: s.size }; }
  catch (e) { return { errno: e.code }; }
}

// 1. Identity and sandbox security posture of this RUN step.
step('self-status', () => {
  const raw = fs.readFileSync('/proc/self/status', 'utf8');
  const want = ['Uid', 'Gid', 'CapEff', 'CapBnd', 'CapPrm', 'CapAmb', 'NoNewPrivs', 'Seccomp', 'Seccomp_filters', 'NStgid', 'NSpid', 'CapIgn'];
  const got = {};
  for (const line of raw.split('\n')) {
    const k = line.split(':')[0];
    if (want.includes(k)) got[k] = line.split(':').slice(1).join(':').trim();
  }
  return got;
});

// 2. PID namespace shape: /proc/1 tells whether the daemon shares this PID namespace.
step('pid-enumeration', () => {
  const pids = fs.readdirSync('/proc').filter(s => /^[0-9]+$/.test(s)).map(Number).sort((a, b) => a - b);
  const list = [];
  for (const pid of pids.slice(0, 64)) {
    let cmd = readOrNull(`/proc/${pid}/cmdline`);
    if (cmd && cmd.errno) cmd = { errno: cmd.errno };
    else cmd = { argv: cmd.toString('utf8').split('\0').filter(Boolean) };
    list.push({ pid, cmd });
  }
  return { pids: list, pidCount: pids.length, selfPid: process.pid };
});

step('proc1-cmdline', () => {
  const raw = readOrNull('/proc/1/cmdline');
  if (raw && raw.errno) return { errno: raw.errno };
  const argv = raw.toString('utf8').split('\0').filter(Boolean);
  return {
    argv,
    noProcessSandboxFlag: argv.some(a => a.includes('--oci-worker-no-process-sandbox')),
    isBuildkitd: argv.some(a => /buildkitd/.test(a)),
  };
});

// 3. Daemon root visibility: /proc/<pid>/root and /proc/<pid>/exe.
step('daemon-root-visibility', () => {
  const res = [];
  const pids = fs.readdirSync('/proc').filter(s => /^[0-9]+$/.test(s)).map(Number);
  for (const pid of pids.slice(0, 64)) {
    const exe = (() => { try { return { link: fs.readlinkSync(`/proc/${pid}/exe`) }; } catch (e) { return { errno: e.code }; } })();
    const rootStat = statOrNull(`/proc/${pid}/root`);
    const rootList = (() => { try { return fs.readdirSync(`/proc/${pid}/root`).slice(0, 25); } catch (e) { return { errno: e.code }; } })();
    const exeCandidate = statOrNull(`/proc/${pid}/root/usr/bin/buildkitd`);
    if (exe.errno && rootStat.errno && rootList.errno && exeCandidate.errno) continue;
    res.push({ pid, exe, rootStat, rootList, buildkitdBinary: exeCandidate });
  }
  return res;
});

// 4. Version string as seen from the sandbox: grep the daemon binary through /proc/<pid>/root.
step('version-from-daemon-binary', () => {
  const pids = fs.readdirSync('/proc').filter(s => /^[0-9]+$/.test(s)).map(Number);
  const found = [];
  for (const pid of pids.slice(0, 64)) {
    const p = `/proc/${pid}/root/usr/bin/buildkitd`;
    let fd;
    try { fd = fs.openSync(p, 'r'); } catch (e) { found.push({ pid, errno: e.code }); continue; }
    try {
      const buf = Buffer.alloc(4 * 1024 * 1024);
      const n = fs.readSync(fd, buf, 0, buf.length, 0);
      const s = buf.slice(0, n);
      const hits = [];
      const re = /v0\.[0-9]{1,3}\.[0-9]{1,3}/g;
      let m;
      while ((m = re.exec(s.toString('latin1'))) !== null && hits.length < 8) hits.push(m[0]);
      const sha = /sha[0-9a-f]{40}/.exec(s.toString('latin1'));
      found.push({ pid, bytesRead: n, versionHits: [...new Set(hits)], revision: sha ? sha[0] : null });
    } finally { fs.closeSync(fd); }
  }
  return found;
});

// 5. Socket and buildkit path candidates visible in the sandbox mount namespace.
step('path-candidates', () => {
  const cands = ['/.buildkit', '/run/buildkit', '/run/.buildkit', '/dev/.buildkit', '/tmp/.buildkit', '/tmp/buildkitd.sock',
    '/var/lib/buildkit', '/home/user/.local/share/buildkit', '/home/user'];
  const res = {};
  for (const c of cands) {
    const st = statOrNull(c);
    let listing;
    try { listing = fs.readdirSync(c).slice(0, 20); } catch (e) { listing = { errno: e.code }; }
    res[c] = { stat: st, listing };
  }
  return res;
});

// 6. Bounded scan for sockets/buildkit names on the sandbox root filesystem only.
step('bounded-filesystem-scan', () => {
  const roots = ['/', '/run', '/tmp', '/dev', '/var/lib', '/etc'];
  const hits = [];
  const seen = new Set();
  const dev = (() => { try { return fs.statSync('/').dev; } catch (e) { return null; } })();
  for (const root of roots) {
    let entries;
    try { entries = fs.readdirSync(root, { withFileTypes: true }); } catch (e) { hits.push({ path: root, errno: e.code }); continue; }
    const queue = entries.map(e2 => path.join(root, e2.name));
    let visited = 0;
    while (queue.length && visited < 4000 && hits.length < 60) {
      const p = queue.shift();
      visited++;
      const base = path.basename(p);
      if (/buildkit/i.test(base) || base.endsWith('.sock')) hits.push({ path: p, kind: base.endsWith('.sock') ? 'socket-or-sock-name' : 'name-match' });
      if (seen.has(p)) continue;
      seen.add(p);
      let es;
      try { es = fs.readdirSync(p, { withFileTypes: true }); } catch (e) { continue; }
      for (const e2 of es) {
        if (e2.isDirectory() && !e2.isSymbolicLink()) queue.push(path.join(p, e2.name));
      }
    }
  }
  return { sandboxRootDev: dev, visited: seen.size, hits };
});

// 7. mountinfo: the source of every mount, which is how the daemon state dir leaked.
step('mountinfo', () => {
  const raw = fs.readFileSync('/proc/self/mountinfo', 'utf8').split('\n').filter(Boolean);
  return {
    count: raw.length,
    buildkitRelated: raw.filter(l => /buildkit|overlay|runc/i.test(l)),
    raw,
  };
});

// 8. Host-path write measurement without mutating anything.
step('host-path-write-test', () => {
  const targets = ['/home/user/.local/share/buildkit', '/var/lib/buildkit', '/home/user/.local/share', '/home/user'];
  const pids = fs.readdirSync('/proc').filter(s => /^[0-9]+$/.test(s)).map(Number);
  for (const pid of pids.slice(0, 64)) {
    targets.push(`/proc/${pid}/root/home/user/.local/share/buildkit`);
    targets.push(`/proc/${pid}/root/var/lib/buildkit`);
  }
  const res = [];
  for (const t of targets) {
    let st;
    try { st = fs.statSync(t); } catch (e) { res.push({ path: t, statErrno: e.code }); continue; }
    let accessErrno = null;
    try { fs.accessSync(t, fs.constants.W_OK); } catch (e) { accessErrno = e.code; }
    let openErrno;
    try { const fd = fs.openSync(path.join(t, MARK), 'r'); fs.closeSync(fd); openErrno = 'opened-existing'; }
    catch (e) { openErrno = e.code; }
    let listing;
    try { listing = fs.readdirSync(t).slice(0, 12); } catch (e) { listing = { errno: e.code }; }
    res.push({
      path: t,
      isDir: st.isDirectory(),
      mode: (st.mode & 0o777).toString(8),
      uid: st.uid, gid: st.gid,
      dev: st.dev,
      sameDeviceAsSandboxRoot: (() => { try { return st.dev === fs.statSync('/').dev; } catch (e) { return null; } })(),
      writableByAccess: accessErrno === null,
      accessErrno,
      openMarkerErrno: openErrno,
      listing,
    });
  }
  return res;
});

// 8b. Isolation strength under NoProcessSandbox: can this step signal the daemon?
step('signal-reachability', () => {
  const res = [];
  const pids = fs.readdirSync('/proc').filter(x => /^[0-9]+$/.test(x)).map(Number);
  for (const pid of pids.slice(0, 64)) {
    let comm = null;
    try { comm = fs.readFileSync(`/proc/${pid}/comm`, 'utf8').trim(); } catch (e) { comm = { errno: e.code }; }
    let status = {};
    try {
      for (const line of fs.readFileSync(`/proc/${pid}/status`, 'utf8').split('\n')) {
        if (/^(Uid|Gid|NSpid|Seccomp|NoNewPrivs):/.test(line)) status[line.split(':')[0]] = line.split(':').slice(1).join(':').trim();
      }
    } catch (e) { status = { errno: e.code }; }
    let kill0;
    try { process.kill(pid, 0); kill0 = 'signal-0-accepted'; } catch (e) { kill0 = e.code; }
    res.push({ pid, comm, status, kill0 });
  }
  return res;
});

step('yama-and-kernel-limits', () => {
  const paths = ['/proc/sys/kernel/yama/ptrace_scope', '/proc/sys/kernel/unprivileged_userns_clone', '/proc/sys/user/max_user_namespaces', '/proc/sys/kernel/apparmor_restrict_unprivileged_userns'];
  const res = {};
  for (const p2 of paths) {
    const r = readOrNull(p2);
    res[p2] = (r && r.errno) ? r.errno : r.toString('utf8').trim();
  }
  const os = require('os');
  res.osFacts = { type: os.type(), release: os.release(), arch: os.arch(), machine: os.machine ? os.machine() : null };
  return res;
});

step('version-token-scan', () => {
  const res = [];
  const pids = fs.readdirSync('/proc').filter(x => /^[0-9]+$/.test(x)).map(Number);
  const re = /v?0\.[0-9]{1,3}\.[0-9]{1,3}|buildkit[^\s]{0,40}/g;
  for (const pid of pids.slice(0, 64)) {
    for (const f of ['cmdline', 'environ']) {
      const r = readOrNull(`/proc/${pid}/${f}`);
      if (r && r.errno) { if (f === 'cmdline') res.push({ pid, f, errno: r.errno }); continue; }
      const hits = [...new Set((r.toString('latin1').match(re) || []).slice(0, 10))];
      if (hits.length) res.push({ pid, f, hits });
    }
  }
  return res;
});

// 8c. Daemon-side visibility: the daemon mount table answers whether its state dir is a host bind mount.
step('daemon-mountinfo-and-cgroup', () => {
  const res = [];
  const pids = fs.readdirSync('/proc').filter(x => /^[0-9]+$/.test(x)).map(Number);
  for (const pid of pids.slice(0, 40)) {
    const mi = readOrNull(`/proc/${pid}/mountinfo`);
    const cg = readOrNull(`/proc/${pid}/cgroup`);
    const entry = { pid };
    if (mi.errno) entry.mountinfoErrno = mi.errno;
    else {
      const lines = mi.toString('utf8').split('\n').filter(Boolean);
      entry.mountinfoCount = lines.length;
      entry.mountinfoBuildkit = lines.filter(l => l.includes('buildkit') || l.includes('/home/user') || l.includes('/var/lib/buildkit')).slice(0, 12);
    }
    entry.cgroup = cg.errno ? cg.errno : cg.toString('utf8').split('\n').filter(Boolean).slice(0, 8);
    res.push(entry);
  }
  return res;
});

// 9. Sandbox egress: does the build step itself reach the internet (async, reported last).

function egressProbe(cb) {
  const sock = net.connect({ host: '1.1.1.1', port: 443, timeout: 4000 });
  sock.once('connect', () => { sock.destroy(); cb({ tcpConnect: 'ok' }); });
  sock.once('timeout', () => { sock.destroy(); cb({ tcpConnect: 'ETIMEDOUT' }); });
  sock.once('error', e => cb({ tcpConnectErrno: e.code }));
}

egressProbe(res => {
  out.steps.push({ name: 'sandbox-egress', data: res });
  const json = JSON.stringify(out, null, 1);
  try { fs.writeFileSync('/app/probe-report.json', json); } catch (e) { out.errors.push({ name: 'write-report', errno: e.code }); }
  try { fs.writeFileSync('/tmp/probe-report.json', json); } catch (e) {}
  console.log('WAR01-PROBE-REPORT-BEGIN');
  console.log(json);
  console.log('WAR01-PROBE-REPORT-END');
  process.exit(0);
});



