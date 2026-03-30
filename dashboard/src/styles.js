export function injectFonts() {
  if (document.getElementById("swarm-fonts")) return;
  const link = document.createElement("link");
  link.id   = "swarm-fonts";
  link.rel  = "stylesheet";
  link.href = "https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@400;600;900&family=DM+Mono:wght@300;400;500&display=swap";
  document.head.appendChild(link);
}

export function injectStyles() {
  if (document.getElementById("swarm-styles")) return;
  const style = document.createElement("style");
  style.id = "swarm-styles";
  style.textContent = CSS;
  document.head.appendChild(style);
}

const CSS = `
  :root {
    --bg:        #060810;
    --bg1:       #0b0f1a;
    --bg2:       #0f1525;
    --border:    #1a2540;
    --amber:     #f5a623;
    --amber-dim: #8a5e13;
    --green:     #39ff84;
    --green-dim: #1a6b3a;
    --red:       #ff3a5c;
    --blue:      #4fc3f7;
    --blue-dim:  #1a4a6b;
    --text:      #c8d8f0;
    --text-dim:  #4a6080;
    --font-mono: 'Share Tech Mono', monospace;
    --font-head: 'Orbitron', monospace;
    --font-data: 'DM Mono', monospace;
  }
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: var(--font-mono); overflow: hidden; }

  /* scanlines + vignette */
  .dash-root::before {
    content: '';
    position: fixed; inset: 0;
    background: repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0,0,0,0.07) 2px, rgba(0,0,0,0.07) 4px);
    pointer-events: none; z-index: 9999;
  }
  .dash-root::after {
    content: '';
    position: fixed; inset: 0;
    background: radial-gradient(ellipse at center, transparent 55%, rgba(0,0,0,0.6) 100%);
    pointer-events: none; z-index: 9998;
  }

  .dash-root {
    width: 100vw; height: 100vh;
    display: grid;
    grid-template-rows: 52px 1fr 1fr;
    grid-template-columns: 280px 1fr 1fr;
    gap: 1px;
    background: var(--border);
    overflow: hidden;
  }

  /* ── Panels ── */
  .panel { background: var(--bg1); display: flex; flex-direction: column; overflow: hidden; position: relative; }
  .panel-header { display: flex; align-items: center; gap: 8px; padding: 6px 12px; border-bottom: 1px solid var(--border); background: var(--bg); flex-shrink: 0; }
  .panel-title { font-family: var(--font-head); font-size: 9px; letter-spacing: 0.15em; color: var(--text-dim); text-transform: uppercase; flex: 1; }
  .panel-body { flex: 1; overflow: hidden; position: relative; }

  /* ── Topbar ── */
  .topbar {
    grid-column: 1 / -1;
    background: var(--bg);
    display: flex; align-items: center;
    padding: 0 16px; gap: 16px;
    border-bottom: 1px solid var(--border);
    position: relative;
  }
  .topbar::after {
    content: ''; position: absolute; bottom: 0; left: 0; right: 0; height: 1px;
    background: linear-gradient(90deg, transparent, var(--amber), transparent);
    opacity: 0.4;
  }
  .logo { font-family: var(--font-head); font-size: 15px; font-weight: 900; letter-spacing: 0.12em; color: var(--amber); text-shadow: 0 0 20px rgba(245,166,35,0.5); white-space: nowrap; }
  .logo span { color: var(--text-dim); font-weight: 400; }
  .topbar-divider { width: 1px; height: 24px; background: var(--border); flex-shrink: 0; }
  .topbar-stat { display: flex; flex-direction: column; gap: 1px; min-width: 52px; }
  .topbar-stat-label { font-size: 8px; color: var(--text-dim); letter-spacing: 0.1em; white-space: nowrap; }
  .topbar-stat-value { font-family: var(--font-head); font-size: 11px; color: var(--text); font-variant-numeric: tabular-nums; white-space: nowrap; }

  /* System status */
  .sys-status { display: flex; align-items: center; gap: 8px; font-family: var(--font-head); font-size: 10px; letter-spacing: 0.12em; }
  .status-dot { width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; animation: pulse-dot 1.6s ease-in-out infinite; }
  @keyframes pulse-dot { 0%,100%{opacity:1} 50%{opacity:0.7} }
  .status-IDLE        { background: var(--text-dim); color: var(--text-dim); animation: none; }
  .status-PENDING     { background: var(--amber); color: var(--amber); box-shadow: 0 0 8px var(--amber); }
  .status-DELIVERING  { background: var(--green); color: var(--green); box-shadow: 0 0 8px var(--green); }

  /* ── Buttons ── */
  .btn { font-family: var(--font-head); font-size: 9px; letter-spacing: 0.1em; padding: 4px 10px; border: 1px solid var(--border); background: transparent; color: var(--text-dim); cursor: pointer; transition: all 0.15s; white-space: nowrap; }
  .btn:hover { border-color: var(--amber); color: var(--amber); }
  .btn.active { background: rgba(245,166,35,0.12); border-color: var(--amber); color: var(--amber); }
  .btn.danger:hover { border-color: var(--red); color: var(--red); }
  .btn.small { padding: 2px 6px; font-size: 8px; }

  /* ── Indicators ── */
  .indicator { width: 6px; height: 6px; border-radius: 50%; flex-shrink: 0; }
  .ind-green { background: var(--green); box-shadow: 0 0 6px var(--green); }
  .ind-amber { background: var(--amber); box-shadow: 0 0 6px var(--amber); animation: blink 0.8s step-end infinite; }
  .ind-red   { background: var(--red);   box-shadow: 0 0 6px var(--red); }
  .ind-dim   { background: var(--text-dim); }
  @keyframes blink { 0%,100%{opacity:1} 50%{opacity:0} }

  /* ── Config drawer ── */
  .config-drawer {
    position: fixed; top: 52px; left: 0; right: 0; z-index: 1000;
    background: var(--bg1); border-bottom: 1px solid var(--border);
    padding: 10px 20px; display: flex; align-items: center; gap: 16px;
    flex-wrap: wrap;
  }
  .config-label { font-family: var(--font-head); font-size: 8px; letter-spacing: 0.12em; color: var(--text-dim); }
  .config-input {
    background: var(--bg); border: 1px solid var(--border); color: var(--text);
    font-family: var(--font-data); font-size: 10px; padding: 4px 10px; outline: none;
    width: 220px;
  }
  .config-input:focus { border-color: var(--amber-dim); }
  .config-select {
    background: var(--bg); border: 1px solid var(--border); color: var(--text-dim);
    font-family: var(--font-head); font-size: 9px; padding: 3px 8px; cursor: pointer;
  }
  .error-text { font-family: var(--font-data); font-size: 9px; color: var(--red); max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

  /* ── Grid placement ── */
  .net-panel { grid-column: 1; grid-row: 2; }
  .imu-panel { grid-column: 1; grid-row: 3; }
  .rep-panel { grid-column: 3; grid-row: 2 / 4; display: flex; flex-direction: column; }

  /* ── Shared content ── */
  .section-title { font-family: var(--font-head); font-size: 8px; letter-spacing: 0.15em; color: var(--text-dim); text-transform: uppercase; padding-bottom: 6px; border-bottom: 1px solid var(--border); }
  .no-data { display: flex; align-items: center; justify-content: center; height: 100%; font-size: 10px; color: var(--text-dim); letter-spacing: 0.15em; flex-direction: column; gap: 8px; }
  .empty-glyph { font-size: 28px; opacity: 0.2; }
  .kv-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 4px 16px; }
  .kv-row { display: flex; flex-direction: column; gap: 1px; padding: 6px 8px; background: var(--bg2); border-left: 2px solid var(--border); }
  .kv-key { font-size: 8px; letter-spacing: 0.1em; color: var(--text-dim); text-transform: uppercase; }
  .kv-val { font-family: var(--font-data); font-size: 12px; color: var(--text); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .kv-val.highlight { color: var(--amber); }
  .kv-val.green { color: var(--green); }
  .kv-val.red   { color: var(--red); }
  .kv-val.blue  { color: var(--blue); }

  /* ── Network topology ── */
  .node-selector { padding: 7px 10px; display: flex; flex-direction: column; gap: 5px; border-bottom: 1px solid var(--border); }
  .node-list { display: flex; flex-direction: column; gap: 3px; max-height: 110px; overflow-y: auto; }
  .node-item { display: flex; align-items: center; gap: 7px; padding: 4px 8px; background: var(--bg2); border: 1px solid var(--border); cursor: pointer; font-size: 10px; transition: border-color 0.15s; }
  .node-item:hover { border-color: var(--amber-dim); }
  .node-item.selected { border-color: var(--amber); background: rgba(245,166,35,0.04); }
  .node-role { font-family: var(--font-head); font-size: 7px; letter-spacing: 0.1em; padding: 2px 4px; border-radius: 2px; flex-shrink: 0; }
  .role-transporter { background: rgba(245,166,35,0.1); color: var(--amber); border: 1px solid rgba(245,166,35,0.3); }
  .topo-canvas { width: 100%; height: 100%; }

  /* ── DATA PACKET ANIMATIONS ── */
  @keyframes packet-flow-in {
    from { stroke-dashoffset: -12; }
    to { stroke-dashoffset: 0; }
  }
  .data-packet-stream {
    /* 2px dot, 10px gap */
    stroke-dasharray: 2 10; 
    /* The animation makes the dots move continuously */
    animation: packet-flow-in 0.6s linear infinite;
  }

  /* ── IMU ── */
  .imu-body { position: absolute; inset: 0; overflow: hidden; }
  .imu-cube-section { position: absolute; top: 0; left: 0; right: 0; height: 140px; display: flex; align-items: center; justify-content: center; border-bottom: 1px solid var(--border); }
  .imu-accel-section { position: absolute; top: 140px; left: 0; right: 0; height: 80px; padding: 7px 14px; border-bottom: 1px solid var(--border); }
  .imu-quat-section  { position: absolute; top: 220px; left: 0; right: 0; height: 70px; padding: 7px 14px; border-bottom: 1px solid var(--border); }
  .imu-serial-section { position: absolute; top: 290px; left: 0; right: 0; bottom: 0; padding: 8px 14px; display: flex; flex-direction: column; gap: 6px; }
  .cube-scene { perspective: 380px; width: 90px; height: 90px; }
  .cube { width: 100%; height: 100%; position: relative; transform-style: preserve-3d; transition: transform 0.06s linear; }
  .face { position: absolute; width: 90px; height: 90px; border: 1px solid rgba(245,166,35,0.3); background: rgba(245,166,35,0.03); display: flex; align-items: center; justify-content: center; font-family: var(--font-head); font-size: 7px; color: rgba(245,166,35,0.4); }
  .face-front  { transform: translateZ(45px); border-color: rgba(245,166,35,0.5); background: rgba(245,166,35,0.05); }
  .face-back   { transform: rotateY(180deg) translateZ(45px); }
  .face-right  { transform: rotateY(90deg) translateZ(45px); }
  .face-left   { transform: rotateY(-90deg) translateZ(45px); }
  .face-top    { transform: rotateX(90deg) translateZ(45px); }
  .face-bottom { transform: rotateX(-90deg) translateZ(45px); }
  .imu-row { display: flex; align-items: center; gap: 8px; margin-bottom: 3px; }
  .imu-label { width: 26px; color: var(--text-dim); font-size: 10px; }
  .imu-bar-bg { flex: 1; height: 4px; background: var(--bg2); border-radius: 2px; overflow: hidden; }
  .imu-bar-fill { height: 100%; border-radius: 2px; transition: width 0.1s linear; }
  .imu-val { width: 54px; text-align: right; font-family: var(--font-data); font-size: 10px; color: var(--text); }
  .quat-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 3px 10px; }
  .quat-item { display: flex; justify-content: space-between; font-size: 9px; }
  .quat-key { color: var(--text-dim); }
  .quat-val { font-family: var(--font-data); color: var(--amber); }
  .serial-log { flex: 1; overflow-y: auto; background: var(--bg); border: 1px solid var(--border); padding: 4px 8px; font-family: var(--font-data); font-size: 9px; color: var(--text-dim); line-height: 1.6; }
  .serial-log-line { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .serial-log-line.ok  { color: var(--green); opacity: 0.7; }
  .serial-log-line.err { color: var(--red); }

  /* ── Phase tracker ── */
  .phase-track { display: flex; align-items: center; gap: 0; }
  .phase-dot { width: 20px; height: 20px; border-radius: 50%; border: 2px solid var(--border); display: flex; align-items: center; justify-content: center; font-family: var(--font-head); font-size: 8px; color: var(--text-dim); background: var(--bg1); transition: all 0.3s; position: relative; z-index: 1; flex-shrink: 0; }
  .phase-dot.done   { border-color: var(--green); color: var(--green); }
  .phase-dot.active { border-color: var(--amber); color: var(--amber); animation: phase-pulse 1s ease-in-out infinite; }
  @keyframes phase-pulse { 0%,100%{box-shadow:0 0 10px rgba(245,166,35,0.5)} 50%{box-shadow:0 0 20px rgba(245,166,35,0.8)} }
  .phase-label { font-family: var(--font-head); font-size: 7px; letter-spacing: 0.08em; color: var(--text-dim); text-align: center; margin-top: 4px; }
  .phase-label.done   { color: var(--green-dim); }
  .phase-label.active { color: var(--amber); }
  .phase-line { flex: 1; height: 1px; background: var(--border); position: relative; overflow: hidden; margin-bottom: 22px; }
  .phase-line.done { background: var(--green-dim); }

  /* ── Verdict badges ── */
  .verdict-badge { padding: 2px 6px; font-family: var(--font-head); font-size: 8px; letter-spacing: 0.05em; border-radius: 2px; flex-shrink: 0; }
  .badge-drop    { background: rgba(255,58,92,0.15); color: var(--red); border: 1px solid rgba(255,58,92,0.3); }
  .badge-normal  { background: rgba(79,195,247,0.1); color: var(--blue); border: 1px solid rgba(79,195,247,0.2); }
  .badge-aligned  { background: rgba(57,255,132,0.1); color: var(--green); border: 1px solid rgba(57,255,132,0.2); }
  .badge-deviated { background: rgba(255,58,92,0.1); color: var(--red); border: 1px solid rgba(255,58,92,0.2); }
  .badge-silent   { background: rgba(74,96,128,0.15); color: var(--text-dim); border: 1px solid var(--border); }
  .badge-deposit-paid   { background: rgba(57,255,132,0.07); color: var(--green-dim); border: 1px solid rgba(57,255,132,0.15); font-size: 7px; padding: 1px 4px; }
  .badge-deposit-unpaid { background: rgba(245,166,35,0.07); color: var(--amber-dim); border: 1px solid rgba(245,166,35,0.15); font-size: 7px; padding: 1px 4px; }

  /* ── Pending event ── */
  .event-panel-body { padding: 12px 14px; height: 100%; display: flex; flex-direction: column; gap: 10px; overflow-y: auto; }
  .verdict-list { display: flex; flex-direction: column; gap: 3px; overflow-y: auto; max-height: 180px; }
  .verdict-row { display: flex; align-items: center; gap: 6px; padding: 5px 8px; background: var(--bg2); border: 1px solid var(--border); font-size: 10px; animation: row-in 0.3s ease; }
  @keyframes row-in { from{opacity:0;transform:translateX(-8px)} to{opacity:1;transform:translateX(0)} }

  /* ── RACE TO QUORUM METER ── */
  .tug-meter-wrapper { margin-top: 12px; margin-bottom: 8px; display: flex; flex-direction: column; gap: 6px; }
  .tug-meter-labels { display: flex; justify-content: space-between; width: 100%; font-family: var(--font-head); font-size: 8px; letter-spacing: 0.1em; color: var(--text-dim); }
  .tug-meter-labels .drop-label { color: var(--red); text-shadow: 0 0 6px rgba(255,58,92,0.3); }
  .tug-meter-labels .norm-label { color: var(--blue); text-shadow: 0 0 6px rgba(79,195,247,0.3); }
  .threshold-label { opacity: 0.6; }
  
  /* Made the track slightly taller (14px) and gave it a more visible background */
  .tug-meter-track { width: 100%; height: 14px; background: rgba(26, 37, 64, 0.4); border: 1px solid var(--border); border-radius: 3px; position: relative; overflow: hidden; box-shadow: inset 0 2px 4px rgba(0,0,0,0.5); }
  .tug-meter-fill { position: absolute; top: 0; bottom: 0; transition: width 0.5s cubic-bezier(0.4, 0, 0.2, 1); }
  
  /* Red grows from left edge inward */
  .drop-fill { left: 0; background: linear-gradient(90deg, rgba(255,58,92,0.3), var(--red)); box-shadow: 2px 0 8px rgba(255,58,92,0.4); }
  
  /* Blue grows from right edge inward */
  .norm-fill { right: 0; background: linear-gradient(-90deg, rgba(79,195,247,0.3), var(--blue)); box-shadow: -2px 0 8px rgba(79,195,247,0.4); }
  
  /* The center finish line */
  .tug-meter-center-line { position: absolute; left: 50%; top: 0; bottom: 0; width: 2px; background: rgba(255,255,255,0.8); box-shadow: 0 0 6px #fff; z-index: 2; }ug-meter-center-line { position: absolute; left: 50%; top: 0; bottom: 0; width: 2px; background: var(--text-dim); box-shadow: 0 0 4px var(--bg); z-index: 2; }

  /* Elapsed timer */
  .elapsed-badge { font-family: var(--font-data); font-size: 11px; color: var(--amber); font-variant-numeric: tabular-nums; }

  /* ── Settlement ledger ── */
  .ledger-toolbar { display: flex; align-items: center; gap: 8px; padding: 6px 12px; border-bottom: 1px solid var(--border); flex-shrink: 0; flex-wrap: wrap; }
  .filter-btn { font-family: var(--font-head); font-size: 8px; letter-spacing: 0.08em; padding: 3px 8px; border: 1px solid var(--border); background: transparent; color: var(--text-dim); cursor: pointer; transition: all 0.15s; }
  .filter-btn:hover { border-color: var(--amber-dim); color: var(--amber); }
  .filter-btn.active-all    { border-color: var(--text-dim); color: var(--text); }
  .filter-btn.active-drop   { border-color: var(--red); color: var(--red); background: rgba(255,58,92,0.06); }
  .filter-btn.active-normal { border-color: var(--blue); color: var(--blue); background: rgba(79,195,247,0.06); }
  .search-input { flex: 1; min-width: 80px; background: var(--bg2); border: 1px solid var(--border); color: var(--text); font-family: var(--font-data); font-size: 9px; padding: 3px 8px; outline: none; }
  .search-input:focus { border-color: var(--amber-dim); }
  .search-input::placeholder { color: var(--text-dim); }
  .settled-list { flex: 1; overflow-y: auto; padding: 8px 12px; display: flex; flex-direction: column; gap: 5px; }
  .settled-card { border: 1px solid var(--border); padding: 7px 10px; background: var(--bg2); cursor: pointer; transition: border-color 0.15s; }
  .settled-card:hover { border-color: var(--amber-dim); }
  .settled-card.selected { border-color: var(--amber); background: rgba(245,166,35,0.04); }
  .settled-card-top { display: flex; align-items: center; gap: 8px; margin-bottom: 4px; }
  .settled-verdict { font-family: var(--font-head); font-size: 9px; letter-spacing: 0.08em; }
  .verdict-DROP   { color: var(--red); }
  .verdict-NORMAL { color: var(--blue); }
  .settled-id { font-family: var(--font-data); font-size: 9px; color: var(--text-dim); flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .settled-time { font-size: 9px; color: var(--text-dim); flex-shrink: 0; }
  .settled-card-stats { display: flex; gap: 12px; font-size: 9px; color: var(--text-dim); }
  .settled-card-stats span { color: var(--text); }

  /* ── Reputation panel ── */
  .rep-toolbar { display: flex; align-items: center; gap: 6px; padding: 5px 12px; border-bottom: 1px solid var(--border); flex-shrink: 0; }
  .rep-list { flex: 1; overflow-y: auto; padding: 6px 12px; display: flex; flex-direction: column; gap: 3px; }
  .rep-row { display: flex; align-items: center; gap: 8px; padding: 5px 8px; background: var(--bg2); border: 1px solid var(--border); border-left-width: 3px; font-size: 10px; cursor: pointer; transition: border-right-color 0.15s; }
  .rep-row:hover { border-right-color: var(--amber-dim); }
  .rep-row.blacklisted { border-left-color: var(--red); opacity: 0.7; }
  .rep-row.healthy { border-left-color: var(--green); }
  .rep-row.warning { border-left-color: var(--amber); }
  .rep-pubkey { font-family: var(--font-data); font-size: 9px; color: var(--text-dim); flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .rep-bar-container { width: 60px; display: flex; flex-direction: column; gap: 2px; align-items: flex-end; }
  .rep-bar-bg { width: 60px; height: 3px; background: var(--bg); border-radius: 2px; overflow: hidden; }
  .rep-bar-fill { height: 100%; border-radius: 2px; transition: width 0.5s ease; }
  .rep-val { font-family: var(--font-data); font-size: 9px; }
  .rep-stake { font-family: var(--font-data); font-size: 9px; color: var(--text-dim); width: 56px; text-align: right; }
  .rep-escrow { font-family: var(--font-data); font-size: 9px; color: var(--amber-dim); width: 52px; text-align: right; }
  .rep-acc { font-size: 9px; width: 36px; text-align: right; }

  /* ── REPUTATION SPOTLIGHT & DELTAS ── */
  @keyframes flash-new-row {
    0% { background-color: rgba(245,166,35,0.3); border-left-color: var(--amber); }
    10% { transform: translateX(4px); }
    100% { background-color: var(--bg2); transform: translateX(0); border-left-color: var(--border); }
  }
  .flash-highlight { animation: flash-new-row 4s ease-out forwards; }

  @keyframes float-up-fade {
    0%   { opacity: 0; transform: translateY(0px) scale(0.8); }
    15%  { opacity: 1; transform: translateY(-8px) scale(1.1); }
    80%  { opacity: 1; transform: translateY(-16px) scale(1); }
    100% { opacity: 0; transform: translateY(-24px) scale(0.9); }
  }
  .delta-float {
    position: absolute; right: 0; bottom: 100%;
    font-family: var(--font-data); font-size: 11px; font-weight: bold;
    animation: float-up-fade 4s ease-out forwards;
    z-index: 10; pointer-events: none;
  }
  .delta-float.positive { color: var(--green); text-shadow: 0 0 6px rgba(57,255,132,0.6); }
  .delta-float.negative { color: var(--red); text-shadow: 0 0 6px rgba(255,58,92,0.6); }

  /* Agent detail drawer */
  .agent-drawer { padding: 10px 14px; background: var(--bg); border-top: 1px solid var(--amber-dim); flex-shrink: 0; animation: row-in 0.2s ease; }
  .agent-drawer-pubkey { font-family: var(--font-data); font-size: 8px; color: var(--text-dim); word-break: break-all; line-height: 1.5; margin-bottom: 6px; }
  .agent-drawer-stats { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 4px; }
  .agent-stat { display: flex; flex-direction: column; gap: 1px; padding: 4px 6px; background: var(--bg2); border: 1px solid var(--border); }
  .agent-stat-label { font-size: 7px; color: var(--text-dim); letter-spacing: 0.1em; }
  .agent-stat-value { font-family: var(--font-data); font-size: 10px; }

  /* ── Receipt panel ── */
  .receipt { padding: 10px 12px; height: 100%; overflow-y: auto; display: flex; flex-direction: column; gap: 8px; }
  .receipt-header { display: flex; align-items: center; gap: 10px; padding: 8px 10px; background: var(--bg2); border: 1px solid var(--border); }
  .receipt-verdict-big { font-family: var(--font-head); font-size: 16px; font-weight: 900; letter-spacing: 0.1em; }
  .cswarm-bar-bg { width: 100%; height: 5px; background: var(--bg); border-radius: 3px; overflow: hidden; margin-top: 2px; }
  .cswarm-bar-fill { height: 100%; border-radius: 3px; transition: width 0.6s ease; }
  .sig-display { font-family: var(--font-data); font-size: 8px; color: var(--text-dim); word-break: break-all; padding: 5px 8px; background: var(--bg2); border: 1px solid var(--border); line-height: 1.5; cursor: pointer; }
  .sig-display:hover { border-color: var(--amber-dim); color: var(--text); }
  .copy-hint { font-size: 7px; color: var(--text-dim); text-align: right; margin-top: 2px; }

  /* ── Scrollbars ── */
  ::-webkit-scrollbar { width: 4px; height: 4px; }
  ::-webkit-scrollbar-track { background: var(--bg1); }
  ::-webkit-scrollbar-thumb { background: var(--border); border-radius: 2px; }
  ::-webkit-scrollbar-thumb:hover { background: var(--amber-dim); }
`;