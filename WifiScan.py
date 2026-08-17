<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Wi-Fi Security Audit Console</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&family=IBM+Plex+Sans:wght@400;500;600&family=IBM+Plex+Mono:wght@400;500;600&display=swap');

:root{
  --bg:#0A1012;
  --panel:#111A1D;
  --panel-2:#0D1517;
  --line:#1E2B2E;
  --line-soft:#16211F;
  --text:#E7EFEC;
  --muted:#7E9793;
  --muted-2:#5B716D;
  --safe:#5FD9A0;
  --safe-dim:#5FD9A02a;
  --warn:#E8B84B;
  --warn-dim:#E8B84B2a;
  --danger:#E8614F;
  --danger-dim:#E8614F2a;
  --scan:#4FB0C7;
  --scan-dim:#4FB0C72a;
  --font-display:'Space Grotesk',sans-serif;
  --font-body:'IBM Plex Sans',sans-serif;
  --font-mono:'IBM Plex Mono',monospace;
}

*{box-sizing:border-box; margin:0; padding:0;}

body{
  background:
    radial-gradient(circle at 15% -10%, #14202318 0%, transparent 45%),
    radial-gradient(circle at 100% 20%, #4FB0C712 0%, transparent 40%),
    var(--bg);
  color:var(--text);
  font-family:var(--font-body);
  line-height:1.5;
  min-height:100vh;
  padding-bottom:80px;
}

::selection{ background:var(--scan); color:#08110F; }

/* ---------- scanline texture ---------- */
.scanlines{
  position:fixed; inset:0; pointer-events:none; z-index:50;
  background:repeating-linear-gradient(0deg, rgba(255,255,255,0.012) 0px, rgba(255,255,255,0.012) 1px, transparent 1px, transparent 3px);
  mix-blend-mode:overlay;
}

/* ---------- header / hero ---------- */
header{
  position:relative;
  border-bottom:1px solid var(--line);
  padding:28px 5vw 34px;
  overflow:hidden;
}
.top-row{
  display:flex; justify-content:space-between; align-items:flex-start;
  flex-wrap:wrap; gap:16px; margin-bottom:28px;
}
.brand{
  display:flex; align-items:center; gap:10px;
  font-family:var(--font-mono); font-size:12px; letter-spacing:.14em; color:var(--muted);
  text-transform:uppercase;
}
.brand .dot{
  width:8px; height:8px; border-radius:50%; background:var(--scan);
  box-shadow:0 0 0 3px var(--scan-dim);
  animation:pulse 2.2s ease-in-out infinite;
}
@keyframes pulse{
  0%,100%{ opacity:1; transform:scale(1); }
  50%{ opacity:.45; transform:scale(.72); }
}
.clock{
  font-family:var(--font-mono); font-size:12px; color:var(--muted-2); letter-spacing:.08em;
}

.hero-title{
  font-family:var(--font-display);
  font-weight:700;
  font-size:clamp(34px, 5.4vw, 62px);
  letter-spacing:-0.01em;
  line-height:1.02;
  max-width:820px;
}
.hero-title .line2{ color:var(--scan); }
.hero-sub{
  margin-top:14px; max-width:560px; color:var(--muted); font-size:15px;
}

/* radar sweep */
.sweep-wrap{
  position:absolute; right:-60px; top:-40px; width:340px; height:340px;
  opacity:.55; pointer-events:none;
}
@media (max-width:900px){ .sweep-wrap{ display:none; } }
.sweep-wrap svg{ width:100%; height:100%; }
.sweep-ring{ fill:none; stroke:var(--line); stroke-width:1; }
.sweep-arm{
  transform-origin:170px 170px;
  animation:spin 4s linear infinite;
}
@keyframes spin{ to{ transform:rotate(360deg); } }
.sweep-blip{ fill:var(--scan); animation:blip 4s linear infinite; }
@keyframes blip{ 0%,88%{opacity:0;} 90%,94%{opacity:1;} 96%,100%{opacity:0;} }

/* ---------- layout ---------- */
main{ max-width:1180px; margin:0 auto; padding:0 5vw; }
section{ padding:46px 0; border-bottom:1px solid var(--line-soft); }
section:last-of-type{ border-bottom:none; }

.eyebrow{
  font-family:var(--font-mono); font-size:11px; letter-spacing:.16em; text-transform:uppercase;
  color:var(--scan); margin-bottom:8px; display:flex; align-items:center; gap:8px;
}
.eyebrow::before{ content:''; width:16px; height:1px; background:var(--scan); }
h2{
  font-family:var(--font-display); font-weight:600; font-size:26px; margin-bottom:6px;
}
.section-sub{ color:var(--muted); font-size:14px; max-width:640px; margin-bottom:26px; }

/* ---------- form panel ---------- */
.panel{
  background:linear-gradient(180deg, var(--panel), var(--panel-2));
  border:1px solid var(--line); border-radius:10px;
}
.form-grid{
  display:grid; grid-template-columns:repeat(4, 1fr); gap:16px;
  padding:24px;
}
@media (max-width:820px){ .form-grid{ grid-template-columns:repeat(2,1fr); } }
.field{ display:flex; flex-direction:column; gap:6px; }
.field.span-2{ grid-column:span 2; }
.field label{
  font-family:var(--font-mono); font-size:10.5px; letter-spacing:.1em; text-transform:uppercase; color:var(--muted-2);
}
.field input[type=text], .field select{
  background:#0B1315; border:1px solid var(--line); color:var(--text);
  padding:10px 12px; border-radius:6px; font-family:var(--font-mono); font-size:13.5px;
  outline:none; transition:border-color .15s;
}
.field input[type=text]:focus, .field select:focus{ border-color:var(--scan); }
.field input::placeholder{ color:var(--muted-2); }

.range-row{ display:flex; align-items:center; gap:10px; }
.range-row input[type=range]{ flex:1; accent-color:var(--scan); }
.range-val{ font-family:var(--font-mono); font-size:13px; color:var(--scan); min-width:52px; text-align:right; }

.checkline{ display:flex; align-items:center; gap:8px; padding-top:8px; }
.checkline input{ accent-color:var(--scan); width:15px; height:15px; }
.checkline label{ font-size:13px; color:var(--muted); }

.form-actions{
  display:flex; justify-content:space-between; align-items:center;
  padding:16px 24px; border-top:1px solid var(--line-soft); flex-wrap:wrap; gap:12px;
}
.hint{ font-size:12px; color:var(--muted-2); }

/* ---------- import scan ---------- */
.cmd-tabs{ display:flex; gap:8px; flex-wrap:wrap; }
.cmd-tab{
  background:#0B1315; border:1px solid var(--line); color:var(--muted);
  font-family:var(--font-mono); font-size:12px; padding:7px 16px; border-radius:20px;
  transition:all .15s;
}
.cmd-tab.active{ border-color:var(--scan); color:var(--scan); background:var(--scan-dim); }
.cmd-box{
  display:flex; align-items:center; justify-content:space-between; gap:12px;
  background:#0B1315; border:1px solid var(--line); border-radius:6px; padding:12px 14px;
}
.cmd-box code{
  font-family:var(--font-mono); font-size:13px; color:var(--text);
  overflow-x:auto; white-space:nowrap; flex:1;
}
.field textarea{
  background:#0B1315; border:1px solid var(--line); color:var(--text);
  padding:10px 12px; border-radius:6px; font-family:var(--font-mono); font-size:12.5px;
  resize:vertical; outline:none; transition:border-color .15s;
}
.field textarea:focus{ border-color:var(--scan); }
.import-note{
  font-size:12.5px; color:var(--muted); background:var(--scan-dim); border:1px solid var(--line);
  border-radius:6px; padding:10px 12px; line-height:1.55;
}
.icon-btn.trusted{ border-color:var(--scan); color:var(--scan); }

button{ font-family:var(--font-body); cursor:pointer; border:none; }
.btn-primary{
  background:var(--scan); color:#062024; font-weight:600; font-size:13.5px;
  padding:11px 22px; border-radius:6px; letter-spacing:.01em;
  transition:transform .12s, box-shadow .12s;
}
.btn-primary:hover{ transform:translateY(-1px); box-shadow:0 6px 18px -6px var(--scan-dim); }
.btn-ghost{
  background:transparent; border:1px solid var(--line); color:var(--muted);
  padding:10px 18px; border-radius:6px; font-size:13px; transition:border-color .15s, color .15s;
}
.btn-ghost:hover{ border-color:var(--muted); color:var(--text); }

/* ---------- fleet score ---------- */
.score-row{ display:grid; grid-template-columns:260px 1fr; gap:24px; }
@media (max-width:820px){ .score-row{ grid-template-columns:1fr; } }
.gauge-card{
  background:linear-gradient(180deg, var(--panel), var(--panel-2));
  border:1px solid var(--line); border-radius:10px; padding:26px; text-align:center;
}
.gauge-card .label{ font-family:var(--font-mono); font-size:11px; letter-spacing:.12em; color:var(--muted-2); text-transform:uppercase; margin-bottom:14px; }
.gauge{ position:relative; width:180px; height:180px; margin:0 auto; }
.gauge svg{ width:100%; height:100%; transform:rotate(-90deg); }
.gauge-bg{ fill:none; stroke:var(--line); stroke-width:10; }
.gauge-fg{ fill:none; stroke-width:10; stroke-linecap:round; transition:stroke-dashoffset .6s ease, stroke .3s; }
.gauge-num{
  position:absolute; inset:0; display:flex; flex-direction:column; align-items:center; justify-content:center;
}
.gauge-num .n{ font-family:var(--font-display); font-size:38px; font-weight:700; }
.gauge-num .u{ font-family:var(--font-mono); font-size:10px; color:var(--muted-2); letter-spacing:.1em; }

.stat-grid{ display:grid; grid-template-columns:repeat(3, 1fr); gap:16px; }
@media (max-width:560px){ .stat-grid{ grid-template-columns:1fr; } }
.stat-card{
  background:linear-gradient(180deg, var(--panel), var(--panel-2));
  border:1px solid var(--line); border-radius:10px; padding:20px;
  display:flex; flex-direction:column; gap:10px; justify-content:space-between;
}
.stat-card .n{ font-family:var(--font-display); font-size:34px; font-weight:700; }
.stat-card .l{ font-family:var(--font-mono); font-size:11px; letter-spacing:.1em; color:var(--muted-2); text-transform:uppercase; }
.stat-card.crit .n{ color:var(--danger); }
.stat-card.warn .n{ color:var(--warn); }
.stat-card.ok .n{ color:var(--safe); }
.stat-bar{ height:3px; border-radius:3px; background:var(--line-soft); overflow:hidden; }
.stat-bar i{ display:block; height:100%; }
.stat-card.crit .stat-bar i{ background:var(--danger); }
.stat-card.warn .stat-bar i{ background:var(--warn); }
.stat-card.ok .stat-bar i{ background:var(--safe); }

/* ---------- network table ---------- */
.table-wrap{ overflow-x:auto; border:1px solid var(--line); border-radius:10px; }
table{ width:100%; border-collapse:collapse; min-width:820px; }
thead th{
  text-align:left; font-family:var(--font-mono); font-size:10.5px; letter-spacing:.1em; text-transform:uppercase;
  color:var(--muted-2); padding:14px 16px; background:var(--panel-2); border-bottom:1px solid var(--line);
}
tbody td{ padding:14px 16px; border-bottom:1px solid var(--line-soft); font-size:13.5px; vertical-align:top; }
tbody tr:last-child td{ border-bottom:none; }
tbody tr:hover{ background:#0F191B; }
.ssid-cell{ font-family:var(--font-mono); font-weight:600; }
.ssid-cell .badge-trust{
  font-family:var(--font-mono); font-size:9.5px; color:var(--scan); border:1px solid var(--scan); border-radius:20px;
  padding:1px 7px; margin-left:8px; letter-spacing:.06em;
}
.bssid-cell{ font-family:var(--font-mono); color:var(--muted); font-size:12.5px; }
.badge{
  display:inline-flex; align-items:center; gap:6px; font-family:var(--font-mono); font-size:11px;
  padding:4px 10px; border-radius:20px; letter-spacing:.04em; white-space:nowrap;
}
.badge::before{ content:''; width:6px; height:6px; border-radius:50%; }
.badge.crit{ background:var(--danger-dim); color:var(--danger); }
.badge.crit::before{ background:var(--danger); }
.badge.warn{ background:var(--warn-dim); color:var(--warn); }
.badge.warn::before{ background:var(--warn); }
.badge.ok{ background:var(--safe-dim); color:var(--safe); }
.badge.ok::before{ background:var(--safe); }
.signal-bars{ display:inline-flex; align-items:end; gap:2px; height:14px; }
.signal-bars i{ width:3px; background:var(--line); border-radius:1px; }
.signal-bars i:nth-child(1){ height:4px; } .signal-bars i:nth-child(2){ height:7px; }
.signal-bars i:nth-child(3){ height:10px; } .signal-bars i:nth-child(4){ height:14px; }
.signal-bars i.on{ background:var(--scan); }
.dbm{ font-family:var(--font-mono); font-size:11.5px; color:var(--muted); margin-left:6px; }
.row-actions{ display:flex; gap:8px; }
.icon-btn{
  background:transparent; border:1px solid var(--line); color:var(--muted-2); border-radius:6px;
  width:28px; height:28px; font-size:13px; display:flex; align-items:center; justify-content:center;
  transition:border-color .15s, color .15s;
}
.icon-btn:hover{ border-color:var(--danger); color:var(--danger); }
.empty-row td{ text-align:center; color:var(--muted-2); font-size:13px; padding:40px 16px; font-family:var(--font-mono); }

/* ---------- findings ---------- */
.findings-list{ display:flex; flex-direction:column; gap:12px; }
.finding{
  display:grid; grid-template-columns:56px 1fr; gap:16px;
  background:linear-gradient(180deg, var(--panel), var(--panel-2));
  border:1px solid var(--line); border-left:3px solid var(--muted-2);
  border-radius:8px; padding:18px 20px;
}
.finding.crit{ border-left-color:var(--danger); }
.finding.warn{ border-left-color:var(--warn); }
.finding.ok{ border-left-color:var(--safe); }
.finding .sev{
  font-family:var(--font-mono); font-size:10px; letter-spacing:.08em; text-transform:uppercase;
  align-self:start; padding-top:2px;
}
.finding.crit .sev{ color:var(--danger); }
.finding.warn .sev{ color:var(--warn); }
.finding.ok .sev{ color:var(--safe); }
.finding h4{ font-family:var(--font-display); font-size:15px; font-weight:600; margin-bottom:6px; }
.finding p{ font-size:13.5px; color:var(--muted); margin-bottom:8px; }
.finding .remediation{
  font-size:12.5px; color:var(--text); background:#0B1315; border:1px solid var(--line-soft);
  border-radius:6px; padding:10px 12px; font-family:var(--font-mono);
}
.finding .remediation b{ color:var(--scan); font-weight:600; }
.finding .net-ref{ font-family:var(--font-mono); font-size:11px; color:var(--muted-2); margin-top:8px; }

/* ---------- report panel ---------- */
.report-actions{ display:flex; gap:12px; margin-bottom:22px; flex-wrap:wrap; }
#reportOutput{
  background:var(--panel-2); border:1px solid var(--line); border-radius:10px;
  padding:28px 32px; font-family:var(--font-mono); font-size:12.5px; line-height:1.7;
  color:var(--muted); white-space:pre-wrap; max-height:560px; overflow-y:auto;
}
#reportOutput .r-title{ color:var(--text); font-size:15px; font-weight:600; font-family:var(--font-display); }
#reportOutput .r-crit{ color:var(--danger); }
#reportOutput .r-warn{ color:var(--warn); }
#reportOutput .r-ok{ color:var(--safe); }

footer{
  max-width:1180px; margin:0 auto; padding:30px 5vw 0; color:var(--muted-2); font-size:12px;
  font-family:var(--font-mono); display:flex; justify-content:space-between; flex-wrap:wrap; gap:10px;
}

@media print{
  header, .form-actions, .btn-ghost, .row-actions, #addForm, .report-actions, .scanlines{ display:none !important; }
  body{ background:#fff; color:#111; }
  .panel, .stat-card, .gauge-card, .finding, .table-wrap{ border-color:#ccc !important; background:#fff !important; }
}
</style>
</head>
<body>
<div class="scanlines"></div>

<header>
  <div class="sweep-wrap">
    <svg viewBox="0 0 340 340">
      <circle class="sweep-ring" cx="170" cy="170" r="150"/>
      <circle class="sweep-ring" cx="170" cy="170" r="105"/>
      <circle class="sweep-ring" cx="170" cy="170" r="60"/>
      <g class="sweep-arm">
        <line x1="170" y1="170" x2="170" y2="20" stroke="#4FB0C7" stroke-width="1.4" opacity="0.7"/>
      </g>
      <circle class="sweep-blip" cx="230" cy="95" r="4"/>
      <circle class="sweep-blip" cx="105" cy="230" r="3" style="animation-delay:1.3s"/>
      <circle class="sweep-blip" cx="255" cy="210" r="3.5" style="animation-delay:2.6s"/>
    </svg>
  </div>

  <div class="top-row">
    <div class="brand"><span class="dot"></span> WLAN-AUDIT / CONSOLE</div>
    <div class="clock" id="clock">-- : -- : --</div>
  </div>

  <h1 class="hero-title">Wi‑Fi Security<br><span class="line2">Audit Console.</span></h1>
  <p class="hero-sub">Log every access point in range, score it against known wireless weaknesses — open auth, WEP, TKIP, evil‑twin SSIDs — and generate a remediation‑ready report for the sites you're responsible for.</p>
</header>

<main>

  <!-- IMPORT SCAN -->
  <section id="importScan">
    <div class="eyebrow">Step 01</div>
    <h2>Scan for available networks</h2>
    <p class="section-sub">A web page can't query your Wi‑Fi radio directly — browsers block that on purpose, since it would let any site locate and fingerprint you by the access points nearby. Instead, run your OS's own scan command, paste the output here, and this tool will parse every visible network straight into the audit.</p>

    <div class="import-note">Works on Windows, macOS, and Linux — pick your OS below for the exact command, or paste plain CSV (<code>ssid,bssid,encryption,channel,signal_dbm,hidden</code>) if you already have data from another scanner.</div>

    <div class="panel" style="margin-top:16px;">
      <div style="padding:22px 24px; display:flex; flex-direction:column; gap:14px;">
        <div class="cmd-tabs" id="cmdTabs">
          <button class="cmd-tab active" data-os="windows">Windows</button>
          <button class="cmd-tab" data-os="mac">macOS</button>
          <button class="cmd-tab" data-os="linux">Linux</button>
        </div>
        <div class="cmd-box">
          <code id="cmdText">netsh wlan show networks mode=bssid</code>
          <button class="icon-btn" id="copyCmdBtn" title="Copy command">⧉</button>
        </div>
        <div class="hint" id="cmdHint">Run in Command Prompt or PowerShell, then copy the full output.</div>

        <div class="field">
          <label>Paste scan output</label>
          <textarea id="in-scanpaste" rows="9" placeholder="Paste terminal output here…"></textarea>
        </div>
      </div>

      <div class="form-actions">
        <span class="hint" id="importStatus">Format is auto-detected from what you paste.</span>
        <button class="btn-primary" id="importBtn">Parse &amp; import networks</button>
      </div>
    </div>
  </section>

  <!-- ADD NETWORK -->
  <section id="addForm">
    <div class="eyebrow">Step 02</div>
    <h2>Log a network manually</h2>
    <p class="section-sub">Enter what your wireless scanner (or OS Wi‑Fi list) shows for each access point. Mark your own authorized network so the tool can flag look‑alike or rogue broadcasts.</p>

    <div class="panel">
      <div class="form-grid">
        <div class="field">
          <label>SSID (network name)</label>
          <input type="text" id="in-ssid" placeholder="e.g. Office-5G">
        </div>
        <div class="field">
          <label>BSSID (AP MAC address)</label>
          <input type="text" id="in-bssid" placeholder="AA:BB:CC:11:22:33">
        </div>
        <div class="field">
          <label>Encryption</label>
          <select id="in-enc">
            <option value="OPEN">Open (none)</option>
            <option value="WEP">WEP</option>
            <option value="WPA-TKIP">WPA (TKIP)</option>
            <option value="WPA2-PSK" selected>WPA2‑Personal (PSK)</option>
            <option value="WPA2-ENT">WPA2‑Enterprise (802.1X)</option>
            <option value="WPA3">WPA3</option>
          </select>
        </div>
        <div class="field">
          <label>Channel</label>
          <input type="text" id="in-channel" placeholder="e.g. 6 or 149">
        </div>

        <div class="field">
          <label>Signal strength</label>
          <div class="range-row">
            <input type="range" id="in-signal" min="-95" max="-25" value="-60">
            <span class="range-val" id="in-signal-val">-60 dBm</span>
          </div>
        </div>
        <div class="field">
          <label>Vendor / OUI (optional)</label>
          <input type="text" id="in-vendor" placeholder="e.g. TP-Link, Cisco, Unknown">
        </div>
        <div class="field span-2">
          <label>Notes (optional)</label>
          <input type="text" id="in-notes" placeholder="e.g. Detected in lobby, unfamiliar device">
        </div>

        <div class="field">
          <div class="checkline">
            <input type="checkbox" id="in-hidden">
            <label for="in-hidden">SSID hidden / not broadcast</label>
          </div>
        </div>
        <div class="field">
          <div class="checkline">
            <input type="checkbox" id="in-trusted">
            <label for="in-trusted">This is our authorized network</label>
          </div>
        </div>
      </div>

      <div class="form-actions">
        <span class="hint">Rogue / evil‑twin detection compares every entry against networks marked "authorized."</span>
        <button class="btn-primary" id="addBtn">+ Add to audit</button>
      </div>
    </div>
  </section>

  <!-- FLEET SCORE -->
  <section>
    <div class="eyebrow">Step 03</div>
    <h2>Audit summary</h2>
    <p class="section-sub">A live risk score across every network you've logged, weighted toward the most severe finding present.</p>

    <div class="score-row">
      <div class="gauge-card">
        <div class="label">Fleet risk score</div>
        <div class="gauge">
          <svg viewBox="0 0 180 180">
            <circle class="gauge-bg" cx="90" cy="90" r="78"/>
            <circle class="gauge-fg" id="gaugeFg" cx="90" cy="90" r="78" stroke="#4FB0C7"
              stroke-dasharray="490" stroke-dashoffset="490"/>
          </svg>
          <div class="gauge-num"><span class="n" id="gaugeNum">--</span><span class="u">/ 100</span></div>
        </div>
      </div>

      <div class="stat-grid">
        <div class="stat-card crit">
          <div><div class="l">Critical findings</div><div class="n" id="critCount">0</div></div>
          <div class="stat-bar"><i id="critBar" style="width:0%"></i></div>
        </div>
        <div class="stat-card warn">
          <div><div class="l">Warnings</div><div class="n" id="warnCount">0</div></div>
          <div class="stat-bar"><i id="warnBar" style="width:0%"></i></div>
        </div>
        <div class="stat-card ok">
          <div><div class="l">Passing networks</div><div class="n" id="okCount">0</div></div>
          <div class="stat-bar"><i id="okBar" style="width:0%"></i></div>
        </div>
      </div>
    </div>
  </section>

  <!-- NETWORK TABLE -->
  <section>
    <div class="eyebrow">Step 04</div>
    <h2>Logged access points</h2>
    <p class="section-sub">Every network you've added, with its computed risk rating.</p>

    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>SSID</th>
            <th>BSSID</th>
            <th>Encryption</th>
            <th>Signal</th>
            <th>Channel</th>
            <th>Rating</th>
            <th></th>
          </tr>
        </thead>
        <tbody id="netTableBody">
          <tr class="empty-row"><td colspan="7">No networks logged yet — add your first detected AP above.</td></tr>
        </tbody>
      </table>
    </div>
  </section>

  <!-- FINDINGS -->
  <section>
    <div class="eyebrow">Step 05</div>
    <h2>Findings &amp; remediation</h2>
    <p class="section-sub">Auto‑generated per‑network guidance, ordered by severity.</p>

    <div class="findings-list" id="findingsList">
      <div class="finding ok"><div class="sev">Info</div><div><h4>No findings yet</h4><p>Add networks above to generate findings.</p></div></div>
    </div>
  </section>

  <!-- REPORT -->
  <section>
    <div class="eyebrow">Step 06</div>
    <h2>Audit report</h2>
    <p class="section-sub">Compile everything above into a shareable report for remediation planning.</p>

    <div class="report-actions">
      <button class="btn-primary" id="genReportBtn">Generate report</button>
      <button class="btn-ghost" id="downloadReportBtn">Download as .txt</button>
      <button class="btn-ghost" id="printBtn">Print / save as PDF</button>
    </div>

    <div id="reportOutput">Click "Generate report" once you've logged your networks.</div>
  </section>

</main>

<footer>
  <span>WLAN‑AUDIT CONSOLE — runs entirely in your browser, no data leaves this page.</span>
  <span id="footTimestamp">—</span>
</footer>

<script>
(function(){
  const state = { networks: [] };

  // ---- clock ----
  function tick(){
    const d = new Date();
    document.getElementById('clock').textContent = d.toLocaleTimeString([], {hour12:false});
    document.getElementById('footTimestamp').textContent = 'Session started ' + d.toLocaleString();
  }
  tick(); setInterval(tick, 1000);

  // ---- signal range readout ----
  const sigInput = document.getElementById('in-signal');
  const sigVal = document.getElementById('in-signal-val');
  sigInput.addEventListener('input', () => sigVal.textContent = sigInput.value + ' dBm');

  // ---- helpers ----
  function macValid(v){
    return /^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$/.test(v.trim());
  }

  function levenshtein(a, b){
    a = a.toLowerCase(); b = b.toLowerCase();
    const m = a.length, n = b.length;
    const dp = Array.from({length:m+1}, () => new Array(n+1).fill(0));
    for(let i=0;i<=m;i++) dp[i][0]=i;
    for(let j=0;j<=n;j++) dp[0][j]=j;
    for(let i=1;i<=m;i++){
      for(let j=1;j<=n;j++){
        dp[i][j] = a[i-1]===b[j-1] ? dp[i-1][j-1] : 1+Math.min(dp[i-1][j-1], dp[i-1][j], dp[i][j-1]);
      }
    }
    return dp[m][n];
  }

  const ENC_META = {
    'OPEN':      { label:'Open',            sev:'crit', base:5  },
    'WEP':       { label:'WEP',             sev:'crit', base:15 },
    'WPA-TKIP':  { label:'WPA (TKIP)',      sev:'warn', base:55 },
    'WPA2-PSK':  { label:'WPA2‑Personal',   sev:'ok',   base:80 },
    'WPA2-ENT':  { label:'WPA2‑Enterprise', sev:'ok',   base:90 },
    'WPA3':      { label:'WPA3',            sev:'ok',   base:97 },
  };

  // ---- scan import: OS command reference ----
  const OS_COMMANDS = {
    windows: { cmd:'netsh wlan show networks mode=bssid', hint:'Run in Command Prompt or PowerShell, then copy the full output.' },
    mac:     { cmd:'system_profiler SP AirPort_DataType', hint:'Run in Terminal. On older macOS you can also use the airport utility with -s.' },
    linux:   { cmd:'nmcli -f SSID,BSSID,CHAN,SIGNAL,SECURITY dev wifi list', hint:'Run in a terminal on a system with NetworkManager installed.' },
  };

  document.querySelectorAll('.cmd-tab').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.cmd-tab').forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      const os = tab.getAttribute('data-os');
      document.getElementById('cmdText').textContent = OS_COMMANDS[os].cmd;
      document.getElementById('cmdHint').textContent = OS_COMMANDS[os].hint;
    });
  });

  document.getElementById('copyCmdBtn').addEventListener('click', () => {
    const text = document.getElementById('cmdText').textContent;
    const btn = document.getElementById('copyCmdBtn');
    const done = () => { const old = btn.textContent; btn.textContent = '✓'; setTimeout(() => btn.textContent = old, 1200); };
    if(navigator.clipboard && navigator.clipboard.writeText){
      navigator.clipboard.writeText(text).then(done).catch(done);
    } else { done(); }
  });

  // ---- scan import: parsers ----
  function pctToDbm(pct){ return Math.round(pct/2 - 100); }

  function guessEncFromWindows(auth, enc){
    auth = (auth||'').toLowerCase(); enc = (enc||'').toLowerCase();
    if(auth.includes('wpa3')) return 'WPA3';
    if(auth.includes('wpa2') && auth.includes('enterprise')) return 'WPA2-ENT';
    if(auth.includes('wpa2')) return 'WPA2-PSK';
    if(auth.includes('wpa')) return 'WPA-TKIP';
    if(enc.includes('wep')) return 'WEP';
    if(auth.includes('open') && enc.includes('wep')) return 'WEP';
    if(auth.includes('open')) return 'OPEN';
    return 'WPA2-PSK';
  }

  function guessEncFromSecurityString(sec){
    sec = (sec||'').toUpperCase();
    if(sec.includes('WPA3')) return 'WPA3';
    if(sec.includes('WPA2') && sec.includes('ENT')) return 'WPA2-ENT';
    if(sec.includes('WPA2')) return 'WPA2-PSK';
    if(sec.includes('WPA')) return 'WPA-TKIP';
    if(sec.includes('WEP')) return 'WEP';
    if(sec === 'NONE' || sec === '--' || sec === '') return 'OPEN';
    return 'WPA2-PSK';
  }

  function parseWindowsNetsh(text){
    const lines = text.split(/\r?\n/);
    const results = [];
    let ssid = null, auth = '', enc = '';
    let pBssid = null, pSignal = null, pChannel = null;

    function flush(){
      if(pBssid){
        results.push({
          ssid: ssid || '', bssid: pBssid,
          enc: guessEncFromWindows(auth, enc),
          channel: pChannel || '',
          signal: pSignal != null ? pctToDbm(pSignal) : -60,
          hidden: !ssid,
        });
      }
      pBssid = null; pSignal = null; pChannel = null;
    }

    for(const raw of lines){
      const line = raw.trim();
      let m;
      if((m = line.match(/^SSID\s+\d+\s*:\s*(.*)$/))){ flush(); ssid = m[1].trim(); auth=''; enc=''; continue; }
      if((m = line.match(/^Authentication\s*:\s*(.+)$/i))){ auth = m[1].trim(); continue; }
      if((m = line.match(/^Encryption\s*:\s*(.+)$/i))){ enc = m[1].trim(); continue; }
      if((m = line.match(/^BSSID\s+\d+\s*:\s*([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})/))){ flush(); pBssid = m[1]; continue; }
      if((m = line.match(/^Signal\s*:\s*(\d+)%/i))){ pSignal = parseInt(m[1],10); continue; }
      if((m = line.match(/^Channel\s*:\s*(\d+)/i))){ pChannel = m[1]; continue; }
    }
    flush();
    return results;
  }

  function parseAirport(text){
    const lines = text.split(/\r?\n/).filter(l => l.trim().length);
    const results = [];
    for(const line of lines){
      if(/^\s*SSID\s+BSSID/i.test(line)) continue;
      const m = line.match(/^\s*(.*?)\s+([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})\s+(-?\d+)\s+(\S+)\s+\S+\s+\S+\s+(.+?)\s*$/);
      if(m){
        results.push({
          ssid: m[1].trim(), bssid: m[2],
          enc: guessEncFromSecurityString(m[5]),
          channel: m[4], signal: parseInt(m[3],10),
          hidden: m[1].trim() === '',
        });
      }
    }
    return results;
  }

  function parseNmcli(text){
    const lines = text.split(/\r?\n/).filter(l => l.trim().length);
    const results = [];
    for(const line of lines){
      if(/^\s*SSID\s+BSSID\s+CHAN\s+SIGNAL/i.test(line)) continue;
      const m = line.match(/^(.*?)\s{2,}([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})\s+(\S+)\s+(\d+)\s+(.+?)\s*$/);
      if(m){
        results.push({
          ssid: m[1].trim(), bssid: m[2],
          enc: guessEncFromSecurityString(m[5]),
          channel: m[3], signal: pctToDbm(parseInt(m[4],10)),
          hidden: m[1].trim() === '',
        });
      }
    }
    return results;
  }

  function parseCSVScan(text){
    const lines = text.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
    const results = [];
    for(const line of lines){
      if(/^ssid\s*,/i.test(line)) continue;
      const parts = line.split(',').map(p => p.trim());
      if(parts.length < 2) continue;
      const [ssid, bssid, encRaw, channel, signal, hiddenRaw] = parts;
      const encUp = (encRaw||'').toUpperCase().replace(/\s/g,'');
      const encKey = ENC_META[encUp] ? encUp : guessEncFromSecurityString(encRaw);
      results.push({
        ssid: ssid || '', bssid: bssid || '',
        enc: encKey, channel: channel || '',
        signal: signal ? parseInt(signal,10) : -60,
        hidden: /^y|true|1$/i.test(hiddenRaw||'') || !ssid,
      });
    }
    return results;
  }

  function detectAndParse(text){
    const firstLine = (text.split(/\r?\n/).find(l => l.trim().length) || '');
    if(firstLine.split(',').length >= 3) return { format:'CSV', rows: parseCSVScan(text) };
    if(/SSID\s+\d+\s*:/.test(text)) return { format:'Windows (netsh)', rows: parseWindowsNetsh(text) };
    if(/\bRSSI\b/i.test(text) && /\bBSSID\b/i.test(text)) return { format:'macOS (airport)', rows: parseAirport(text) };
    if(/\bCHAN\b/i.test(text) && /\bSIGNAL\b/i.test(text)) return { format:'Linux (nmcli)', rows: parseNmcli(text) };
    return { format:'CSV', rows: parseCSVScan(text) };
  }

  function setImportStatus(msg, sev){
    const el = document.getElementById('importStatus');
    el.textContent = msg;
    el.style.color = sev === 'ok' ? 'var(--safe)' : sev === 'crit' ? 'var(--danger)' : 'var(--muted)';
  }

  document.getElementById('importBtn').addEventListener('click', () => {
    const text = document.getElementById('in-scanpaste').value;
    if(!text.trim()){ setImportStatus('Paste some scan output first.', 'warn'); return; }

    const { format, rows } = detectAndParse(text);
    let added = 0, skipped = 0;

    rows.forEach(r => {
      if(!r.ssid && !r.bssid) return;
      const dup = state.networks.some(n => n.ssid.toLowerCase() === r.ssid.toLowerCase() && n.bssid.toLowerCase() === (r.bssid||'').toLowerCase());
      if(dup){ skipped++; return; }
      state.networks.push({
        id: 'n' + Date.now() + Math.random().toString(16).slice(2),
        ssid: r.ssid, bssid: r.bssid || '—',
        enc: ENC_META[r.enc] ? r.enc : 'WPA2-PSK',
        channel: r.channel || '',
        signal: (r.signal != null && !isNaN(r.signal)) ? r.signal : -60,
        vendor: '', notes: '', hidden: !!r.hidden, trusted: false,
      });
      added++;
    });

    if(added === 0 && skipped === 0){
      setImportStatus('Could not parse any networks (detected as ' + format + '). Check the format, or use the CSV layout instead.', 'crit');
    } else {
      setImportStatus(
        'Imported ' + added + ' network' + (added===1?'':'s') + ' as ' + format +
        (skipped ? ', skipped ' + skipped + ' duplicate' + (skipped===1?'':'s') : '') +
        '. Click ☆ next to your own network below to mark it authorized.', 'ok'
      );
      render();
    }
  });

  // ---- evaluate a single network against the fleet (for rogue/evil-twin detection) ----
  function evaluateNetwork(net, all){
    const findings = [];
    const encMeta = ENC_META[net.enc];
    let score = encMeta.base;
    let worstSev = encMeta.sev;

    if(net.enc === 'OPEN'){
      findings.push({ sev:'crit', title:'Open authentication',
        body:'This access point accepts connections with no encryption. Traffic (credentials, session data) can be read by anyone in range.',
        fix:'Reconfigure the AP for WPA2‑Personal at minimum, or WPA3/WPA2‑Enterprise for managed environments. Remove or isolate the SSID if it is not needed.' });
    }
    if(net.enc === 'WEP'){
      findings.push({ sev:'crit', title:'WEP encryption in use',
        body:'WEP\u2019s key scheduling is broken; keys can typically be recovered in minutes with widely available tools.',
        fix:'Replace WEP with WPA2 or WPA3 immediately. Treat this AP as compromised until upgraded.' });
    }
    if(net.enc === 'WPA-TKIP'){
      findings.push({ sev:'warn', title:'Legacy WPA/TKIP cipher',
        body:'TKIP has known cryptographic weaknesses and is deprecated by the Wi‑Fi Alliance.',
        fix:'Switch the AP to WPA2‑AES (CCMP) or WPA3. Most hardware from the last decade supports this without a firmware update.' });
    }
    if(net.enc === 'WPA2-PSK'){
      findings.push({ sev:'ok', title:'WPA2‑Personal (PSK)', 
        body:'Reasonable baseline security. Strength depends entirely on passphrase quality, which this tool cannot verify remotely.',
        fix:'Use a passphrase of 16+ random characters, rotate it if staff turnover occurs, and consider migrating to WPA3 or WPA2‑Enterprise for shared credentials.' });
    }
    if(net.enc === 'WPA2-ENT'){
      findings.push({ sev:'ok', title:'WPA2‑Enterprise (802.1X)',
        body:'Per‑user authentication via RADIUS. Strong choice for organizations, assuming certificate validation is enforced on clients.',
        fix:'Confirm client devices validate the RADIUS server certificate to prevent credential‑harvesting rogue APs.' });
    }
    if(net.enc === 'WPA3'){
      findings.push({ sev:'ok', title:'WPA3', 
        body:'Current-generation security with protection against offline dictionary attacks (SAE).',
        fix:'No action needed. Keep firmware current.' });
    }

    if(net.hidden){
      findings.push({ sev:'warn', title:'Hidden SSID',
        body:'Disabling SSID broadcast is not a real security control \u2014 the name is still sent in probe requests and association frames, and hiding it can make client devices less discriminating about which network they join.',
        fix:'Rely on strong encryption and authentication rather than SSID concealment. Re‑enable broadcast unless there is a specific operational reason not to.' });
      score -= 3;
    }

    if(Number(net.signal) >= -35){
      findings.push({ sev:'warn', title:'Unusually strong signal',
        body:'A signal this strong (' + net.signal + ' dBm) usually means the transmitter is very close \u2014 worth checking that it is a known, physically located device rather than something planted nearby.',
        fix:'Physically verify the source of this access point if its location is not already known.' });
      score -= 3;
    }

    // Evil-twin / rogue AP heuristic against trusted networks
    const trusted = all.filter(n => n.trusted && n.id !== net.id);
    for(const t of trusted){
      if(net.id === t.id) continue;
      const sameSSID = net.ssid.trim().toLowerCase() === t.ssid.trim().toLowerCase();
      const dist = levenshtein(net.ssid.trim(), t.ssid.trim());
      const nearSSID = !sameSSID && dist > 0 && dist <= 2 && net.ssid.trim().length > 2;
      const diffBSSID = net.bssid.trim().toLowerCase() !== t.bssid.trim().toLowerCase();

      if(sameSSID && diffBSSID && !net.trusted){
        findings.push({ sev:'crit', title:'Possible evil‑twin / rogue AP',
          body:'This network broadcasts the same SSID as your authorized network ("' + t.ssid + '") but from a different BSSID (' + net.bssid + ' vs ' + t.bssid + '). This is a classic rogue‑AP / evil‑twin pattern used to intercept credentials.',
          fix:'Do not connect. Physically locate the rogue transmitter, disable it if found on your premises, and notify staff not to join duplicate SSIDs. Consider enabling 802.11w (management frame protection) and rogue‑AP detection on your WLAN controller.' });
        score = Math.min(score, 12);
        worstSev = 'crit';
      } else if(nearSSID && !net.trusted){
        findings.push({ sev:'warn', title:'Look‑alike SSID',
          body:'"' + net.ssid + '" closely resembles your authorized network name "' + t.ssid + '" (' + dist + ' character difference). This can trick users into connecting to the wrong AP.',
          fix:'Investigate the source. If unauthorized, request takedown / disable it, and consider staff awareness training on verifying network names before connecting.' });
        score = Math.min(score, 45);
      }
    }

    // duplicate SSID among untrusted entries with different vendors -> flag too
    const sameSSIDOthers = all.filter(n => n.id !== net.id && n.ssid.trim().toLowerCase() === net.ssid.trim().toLowerCase() && n.bssid.trim().toLowerCase() !== net.bssid.trim().toLowerCase());
    if(sameSSIDOthers.length && !trusted.length && !net.trusted){
      findings.push({ sev:'warn', title:'Duplicate SSID, multiple BSSIDs',
        body:'Multiple access points are broadcasting "' + net.ssid + '" from different hardware addresses. This can be legitimate (a multi‑AP mesh/roaming setup) or a sign of AP spoofing.',
        fix:'Confirm with network ownership whether this is intentional (e.g. enterprise Wi‑Fi with multiple APs). If not expected, treat as a rogue‑AP indicator and investigate.' });
      score = Math.min(score, 60);
    }

    for(const f of findings){
      if(f.sev === 'crit') worstSev = 'crit';
      else if(f.sev === 'warn' && worstSev !== 'crit') worstSev = 'warn';
    }
    score = Math.max(0, Math.min(100, Math.round(score)));
    return { score, sev: worstSev, findings };
  }

  // ---- render ----
  function render(){
    const tbody = document.getElementById('netTableBody');
    const findingsList = document.getElementById('findingsList');

    if(state.networks.length === 0){
      tbody.innerHTML = '<tr class="empty-row"><td colspan="7">No networks logged yet — add your first detected AP above.</td></tr>';
      findingsList.innerHTML = '<div class="finding ok"><div class="sev">Info</div><div><h4>No findings yet</h4><p>Add networks above to generate findings.</p></div></div>';
      updateSummary([]);
      return;
    }

    let rowsHtml = '';
    let allFindingsHtml = [];
    const evalCache = [];

    state.networks.forEach(net => {
      const result = evaluateNetwork(net, state.networks);
      evalCache.push({ net, result });

      const encMeta = ENC_META[net.enc];
      const bars = Math.max(1, Math.min(4, Math.round((Number(net.signal)+95)/70*4)));
      let barsHtml = '';
      for(let i=1;i<=4;i++) barsHtml += '<i class="' + (i<=bars?'on':'') + '"></i>';

      rowsHtml += '<tr>' +
        '<td class="ssid-cell">' + escapeHtml(net.ssid || '(blank)') + (net.trusted ? '<span class="badge-trust">AUTHORIZED</span>' : '') + (net.hidden ? ' <span style="color:var(--muted-2);font-family:var(--font-mono);font-size:11px;">(hidden)</span>' : '') + '</td>' +
        '<td class="bssid-cell">' + escapeHtml(net.bssid || '—') + '</td>' +
        '<td>' + encMeta.label + '</td>' +
        '<td><span class="signal-bars">' + barsHtml + '</span><span class="dbm">' + net.signal + ' dBm</span></td>' +
        '<td class="bssid-cell">' + escapeHtml(net.channel || '—') + '</td>' +
        '<td><span class="badge ' + result.sev + '">' + (result.sev === 'crit' ? 'Critical' : result.sev === 'warn' ? 'Warning' : 'Pass') + ' · ' + result.score + '</span></td>' +
        '<td class="row-actions">' +
          '<button class="icon-btn' + (net.trusted ? ' trusted' : '') + '" data-trust="' + net.id + '" title="Toggle authorized">' + (net.trusted ? '★' : '☆') + '</button>' +
          '<button class="icon-btn" data-remove="' + net.id + '" title="Remove">✕</button>' +
        '</td>' +
      '</tr>';

      result.findings.forEach(f => {
        allFindingsHtml.push({ sev: f.sev, html:
          '<div class="finding ' + f.sev + '">' +
            '<div class="sev">' + (f.sev==='crit'?'Critical':f.sev==='warn'?'Warning':'Pass') + '</div>' +
            '<div><h4>' + escapeHtml(f.title) + '</h4>' +
              '<p>' + escapeHtml(f.body) + '</p>' +
              '<div class="remediation"><b>Remediation —</b> ' + escapeHtml(f.fix) + '</div>' +
              '<div class="net-ref">Network: ' + escapeHtml(net.ssid || '(blank)') + ' · ' + escapeHtml(net.bssid || '—') + '</div>' +
            '</div>' +
          '</div>'
        });
      });
    });

    tbody.innerHTML = rowsHtml;

    const sevOrder = { crit:0, warn:1, ok:2 };
    allFindingsHtml.sort((a,b) => sevOrder[a.sev]-sevOrder[b.sev]);
    findingsList.innerHTML = allFindingsHtml.map(f=>f.html).join('') || '<div class="finding ok"><div class="sev">Info</div><div><h4>No findings</h4><p>Nothing to report.</p></div></div>';

    document.querySelectorAll('[data-remove]').forEach(btn => {
      btn.addEventListener('click', () => {
        state.networks = state.networks.filter(n => n.id !== btn.getAttribute('data-remove'));
        render();
      });
    });

    document.querySelectorAll('[data-trust]').forEach(btn => {
      btn.addEventListener('click', () => {
        const net = state.networks.find(n => n.id === btn.getAttribute('data-trust'));
        if(net){ net.trusted = !net.trusted; render(); }
      });
    });

    updateSummary(evalCache);
  }

  function updateSummary(evalCache){
    const crit = evalCache.filter(e => e.result.sev==='crit').length;
    const warn = evalCache.filter(e => e.result.sev==='warn').length;
    const ok = evalCache.filter(e => e.result.sev==='ok').length;
    const total = evalCache.length;

    document.getElementById('critCount').textContent = crit;
    document.getElementById('warnCount').textContent = warn;
    document.getElementById('okCount').textContent = ok;
    document.getElementById('critBar').style.width = total ? (crit/total*100)+'%' : '0%';
    document.getElementById('warnBar').style.width = total ? (warn/total*100)+'%' : '0%';
    document.getElementById('okBar').style.width = total ? (ok/total*100)+'%' : '0%';

    const avg = total ? Math.round(evalCache.reduce((s,e)=>s+e.result.score,0)/total) : 0;
    const circumference = 490;
    const offset = total ? circumference - (avg/100*circumference) : circumference;
    const fg = document.getElementById('gaugeFg');
    fg.style.strokeDashoffset = offset;
    fg.style.stroke = avg >= 80 ? '#5FD9A0' : avg >= 50 ? '#E8B84B' : '#E8614F';
    document.getElementById('gaugeNum').textContent = total ? avg : '--';
    document.getElementById('gaugeNum').style.color = avg >= 80 ? '#5FD9A0' : avg >= 50 ? '#E8B84B' : '#E8614F';
  }

  function escapeHtml(s){
    return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  }

  // ---- add network ----
  document.getElementById('addBtn').addEventListener('click', () => {
    const ssid = document.getElementById('in-ssid').value.trim();
    const bssid = document.getElementById('in-bssid').value.trim();
    if(!ssid){ alert('Enter an SSID before adding this network.'); return; }
    if(bssid && !macValid(bssid)){ alert('BSSID should look like AA:BB:CC:11:22:33 (or leave it blank).'); return; }

    state.networks.push({
      id: 'n' + Date.now() + Math.random().toString(16).slice(2),
      ssid, bssid: bssid || '—',
      enc: document.getElementById('in-enc').value,
      channel: document.getElementById('in-channel').value.trim(),
      signal: document.getElementById('in-signal').value,
      vendor: document.getElementById('in-vendor').value.trim(),
      notes: document.getElementById('in-notes').value.trim(),
      hidden: document.getElementById('in-hidden').checked,
      trusted: document.getElementById('in-trusted').checked,
    });

    ['in-ssid','in-bssid','in-channel','in-vendor','in-notes'].forEach(id => document.getElementById(id).value = '');
    document.getElementById('in-hidden').checked = false;
    document.getElementById('in-trusted').checked = false;
    document.getElementById('in-enc').value = 'WPA2-PSK';
    document.getElementById('in-signal').value = -60;
    sigVal.textContent = '-60 dBm';

    render();
  });

  // ---- report generation ----
  function buildReportText(){
    const now = new Date();
    let lines = [];
    lines.push('WI-FI SECURITY AUDIT REPORT');
    lines.push('Generated: ' + now.toLocaleString());
    lines.push('Networks audited: ' + state.networks.length);
    lines.push('='.repeat(60));
    lines.push('');

    const evalCache = state.networks.map(net => ({ net, result: evaluateNetwork(net, state.networks) }));
    const crit = evalCache.filter(e => e.result.sev==='crit').length;
    const warn = evalCache.filter(e => e.result.sev==='warn').length;
    const ok = evalCache.filter(e => e.result.sev==='ok').length;
    const avg = evalCache.length ? Math.round(evalCache.reduce((s,e)=>s+e.result.score,0)/evalCache.length) : 0;

    lines.push('SUMMARY');
    lines.push('-'.repeat(60));
    lines.push('Fleet risk score : ' + avg + ' / 100');
    lines.push('Critical         : ' + crit);
    lines.push('Warnings         : ' + warn);
    lines.push('Passing          : ' + ok);
    lines.push('');
    lines.push('NETWORK INVENTORY');
    lines.push('-'.repeat(60));
    evalCache.forEach(({net, result}) => {
      lines.push('SSID: ' + net.ssid + (net.trusted ? '  [AUTHORIZED]' : ''));
      lines.push('  BSSID: ' + net.bssid + '   Channel: ' + (net.channel || '—') + '   Signal: ' + net.signal + ' dBm');
      lines.push('  Encryption: ' + ENC_META[net.enc].label + '   Hidden: ' + (net.hidden ? 'Yes' : 'No'));
      lines.push('  Rating: ' + result.sev.toUpperCase() + '  (score ' + result.score + '/100)');
      if(net.notes) lines.push('  Notes: ' + net.notes);
      lines.push('');
    });

    lines.push('FINDINGS & REMEDIATION');
    lines.push('-'.repeat(60));
    let allFindings = [];
    evalCache.forEach(({net, result}) => result.findings.forEach(f => allFindings.push({net, f})));
    const sevOrder = { crit:0, warn:1, ok:2 };
    allFindings.sort((a,b) => sevOrder[a.f.sev]-sevOrder[b.f.sev]);
    allFindings.forEach(({net, f}) => {
      lines.push('[' + f.sev.toUpperCase() + '] ' + f.title + '  (Network: ' + net.ssid + ')');
      lines.push('  Finding:     ' + f.body);
      lines.push('  Remediation: ' + f.fix);
      lines.push('');
    });

    if(!allFindings.length) lines.push('No findings recorded.');

    return lines.join('\n');
  }

  document.getElementById('genReportBtn').addEventListener('click', () => {
    if(state.networks.length === 0){
      document.getElementById('reportOutput').textContent = 'Add at least one network before generating a report.';
      return;
    }
    document.getElementById('reportOutput').textContent = buildReportText();
  });

  document.getElementById('downloadReportBtn').addEventListener('click', () => {
    if(state.networks.length === 0){ alert('Add at least one network first.'); return; }
    const text = buildReportText();
    const blob = new Blob([text], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'wifi-security-audit-report.txt';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  });

  document.getElementById('printBtn').addEventListener('click', () => window.print());

  render();
})();
</script>
</body>
</html>
