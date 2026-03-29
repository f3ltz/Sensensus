import { useState, useEffect, useRef, useCallback } from "react";

const fontLink = document.createElement("link");
fontLink.rel = "stylesheet";
fontLink.href = "https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Orbitron:wght@400;600;900&family=DM+Mono:wght@300;400;500&display=swap";
document.head.appendChild(fontLink);

const css = `
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

  .dash-root {
    width: 100vw; height: 100vh;
    display: grid;
    grid-template-rows: 52px 1fr 1fr;
    grid-template-columns: 280px 1fr 1fr;
    gap: 1px;
    background: var(--border);
    position: relative;
    overflow: hidden;
  }
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

  .panel { background: var(--bg1); display: flex; flex-direction: column; overflow: hidden; position: relative; }
  .panel-header { display: flex; align-items: center; gap: 8px; padding: 6px 12px; border-bottom: 1px solid var(--border); background: var(--bg); flex-shrink: 0; }
  .panel-title { font-family: var(--font-head); font-size: 9px; letter-spacing: 0.15em; color: var(--text-dim); text-transform: uppercase; flex: 1; }
  .panel-body { flex: 1; overflow: hidden; position: relative; padding: 0; }

  .topbar {
    grid-column: 1 / -1;
    background: var(--bg);
    display: flex; align-items: center;
    padding: 0 20px; gap: 24px;
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

  .sys-status { display: flex; align-items: center; gap: 8px; font-family: var(--font-head); font-size: 10px; letter-spacing: 0.12em; width: 152px; flex-shrink: 0; }
  .sys-status span { white-space: nowrap; overflow: hidden; display: inline-block; width: 116px; }
  .status-dot { width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; animation: pulse-dot 1.6s ease-in-out infinite; }
  @keyframes pulse-dot { 0%,100%{opacity:1} 50%{opacity:0.7} }
  .status-IDLE { background: var(--text-dim); color: var(--text-dim); animation: none; }
  .status-ANOMALY { background: var(--amber); color: var(--amber); box-shadow: 0 0 8px var(--amber); }
  .status-DELIVERING { background: var(--green); color: var(--green); box-shadow: 0 0 8px var(--green); }
  .status-FINALIZING { background: var(--blue); color: var(--blue); box-shadow: 0 0 8px var(--blue); }

  .topbar-divider { width: 1px; height: 24px; background: var(--border); }
  .topbar-stat { display: flex; flex-direction: column; gap: 1px; min-width: 52px; }
  .topbar-stat-label { font-size: 8px; color: var(--text-dim); letter-spacing: 0.1em; }
  .topbar-stat-value { font-family: var(--font-head); font-size: 11px; color: var(--text); font-variant-numeric: tabular-nums; white-space: nowrap; display: block; }

  .btn { font-family: var(--font-head); font-size: 9px; letter-spacing: 0.1em; padding: 4px 10px; border: 1px solid var(--border); background: transparent; color: var(--text-dim); cursor: pointer; transition: all 0.15s; }
  .btn:hover { border-color: var(--amber); color: var(--amber); }
  .btn.active { background: rgba(245,166,35,0.12); border-color: var(--amber); color: var(--amber); }
  .btn.danger:hover { border-color: var(--red); color: var(--red); }
  .btn.success { background: rgba(57,255,132,0.1); border-color: var(--green-dim); color: var(--green); }

  /* ── Explicit grid placement ── */
  /* Col 1 row 2: network topology */
  .net-panel { grid-column: 1; grid-row: 2; }
  /* Col 1 row 3: IMU */
  .imu-panel { grid-column: 1; grid-row: 3; }
  /* Col 3 rows 2-3: reputation + receipt (full height) */
  .rep-panel { grid-column: 3; grid-row: 2 / 4; }

  /* ── IMU ── */
  .imu-body { position: absolute; inset: 0; overflow: hidden; }
  /* Cube is smaller now (fits in half the left column height) */
  .imu-cube-section { position: absolute; top: 0; left: 0; right: 0; height: 150px; display: flex; align-items: center; justify-content: center; border-bottom: 1px solid var(--border); overflow: hidden; }
  .imu-section { position: absolute; left: 0; right: 0; padding: 7px 14px; border-bottom: 1px solid var(--border); overflow: hidden; }
  .imu-section-accel { top: 150px; height: 80px; }
  .imu-section-quat  { top: 230px; height: 74px; }
  .imu-conf-section { position: absolute; top: 304px; left: 0; right: 0; height: 46px; padding: 6px 14px; border-bottom: 1px solid var(--border); overflow: hidden; transition: opacity 0.3s ease; }
  .imu-conf-section.hidden { opacity: 0; pointer-events: none; }
  .serial-section { position: absolute; top: 350px; left: 0; right: 0; bottom: 0; padding: 8px 14px; display: flex; flex-direction: column; gap: 6px; }

  .cube-scene { perspective: 380px; width: 100px; height: 100px; position: relative; flex-shrink: 0; }
  .cube { width: 100%; height: 100%; position: relative; transform-style: preserve-3d; transition: transform 0.06s linear; }
  .face { position: absolute; width: 100px; height: 100px; border: 1px solid rgba(245,166,35,0.3); background: rgba(245,166,35,0.03); display: flex; align-items: center; justify-content: center; font-family: var(--font-head); font-size: 7px; letter-spacing: 0.1em; color: rgba(245,166,35,0.4); backface-visibility: visible; }
  .face-front  { transform: translateZ(50px); border-color: rgba(245,166,35,0.5); background: rgba(245,166,35,0.05); }
  .face-back   { transform: rotateY(180deg) translateZ(50px); }
  .face-right  { transform: rotateY(90deg) translateZ(50px); }
  .face-left   { transform: rotateY(-90deg) translateZ(50px); }
  .face-top    { transform: rotateX(90deg) translateZ(50px); }
  .face-bottom { transform: rotateX(-90deg) translateZ(50px); }

  .imu-readings { width: 100%; display: flex; flex-direction: column; gap: 4px; }
  .imu-row { display: flex; align-items: center; gap: 8px; font-size: 11px; }
  .imu-label { width: 26px; color: var(--text-dim); font-size: 10px; letter-spacing: 0.05em; }
  .imu-bar-bg { flex: 1; height: 4px; background: var(--bg2); border-radius: 2px; overflow: hidden; }
  .imu-bar-fill { height: 100%; border-radius: 2px; transition: width 0.1s linear; }
  .imu-val { width: 52px; text-align: right; font-family: var(--font-data); font-size: 10px; color: var(--text); letter-spacing: 0.02em; }

  .quat-grid { width: 100%; display: grid; grid-template-columns: 1fr 1fr; gap: 3px 10px; }
  .quat-item { display: flex; justify-content: space-between; font-size: 9px; }
  .quat-key { color: var(--text-dim); }
  .quat-val { font-family: var(--font-data); color: var(--amber); }

  /* ── Transporter selector ── */
  .node-selector { padding: 7px 10px; display: flex; flex-direction: column; gap: 5px; border-bottom: 1px solid var(--border); }
  .node-list { display: flex; flex-direction: column; gap: 3px; max-height: 120px; overflow-y: auto; }
  .node-item { display: flex; align-items: center; gap: 7px; padding: 4px 8px; background: var(--bg2); border: 1px solid var(--border); cursor: pointer; font-size: 10px; transition: border-color 0.15s; }
  .node-item:hover { border-color: var(--amber-dim); }
  .node-item.selected { border-color: var(--amber); background: rgba(245,166,35,0.04); }
  .node-item.blacklisted { opacity: 0.5; border-left: 3px solid var(--red); }
  .node-role { font-family: var(--font-head); font-size: 7px; letter-spacing: 0.1em; padding: 2px 4px; border-radius: 2px; flex-shrink: 0; }
  .role-transporter { background: rgba(245,166,35,0.1); color: var(--amber); border: 1px solid rgba(245,166,35,0.3); }
  .role-auditor     { background: rgba(79,195,247,0.1); color: var(--blue); border: 1px solid rgba(79,195,247,0.2); }

  /* ── TOPOLOGY ── */
  .topo-canvas { width: 100%; height: 100%; }

  /* ── ACTIVE EVENT ── */
  .event-panel-body { padding: 14px 16px; height: 100%; display: flex; flex-direction: column; gap: 10px; overflow-y: auto; }
  .phase-track { display: flex; align-items: center; gap: 0; padding-bottom: 4px; }
  .phase-dot { width: 20px; height: 20px; border-radius: 50%; border: 2px solid var(--border); display: flex; align-items: center; justify-content: center; font-family: var(--font-head); font-size: 8px; color: var(--text-dim); position: relative; z-index: 1; background: var(--bg1); transition: all 0.3s; }
  .phase-dot.done   { border-color: var(--green); color: var(--green); box-shadow: 0 0 8px rgba(57,255,132,0.3); }
  .phase-dot.active { border-color: var(--amber); color: var(--amber); box-shadow: 0 0 10px rgba(245,166,35,0.5); animation: phase-pulse 1s ease-in-out infinite; }
  @keyframes phase-pulse { 0%,100%{box-shadow:0 0 10px rgba(245,166,35,0.5)} 50%{box-shadow:0 0 20px rgba(245,166,35,0.8)} }
  .phase-label { font-family: var(--font-head); font-size: 7px; letter-spacing: 0.08em; color: var(--text-dim); text-align: center; }
  .phase-label.done   { color: var(--green-dim); }
  .phase-label.active { color: var(--amber); }
  .phase-line { flex: 1; height: 1px; background: var(--border); margin-bottom: 20px; position: relative; overflow: hidden; }

  .kv-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 4px 16px; }
  .kv-row { display: flex; flex-direction: column; gap: 1px; padding: 6px 8px; background: var(--bg2); border-left: 2px solid var(--border); }
  .kv-key { font-size: 8px; letter-spacing: 0.1em; color: var(--text-dim); text-transform: uppercase; }
  .kv-val { font-family: var(--font-data); font-size: 12px; color: var(--text); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .kv-val.highlight { color: var(--amber); }
  .kv-val.green { color: var(--green); }
  .kv-val.red   { color: var(--red); }

  .section-title { font-family: var(--font-head); font-size: 8px; letter-spacing: 0.15em; color: var(--text-dim); text-transform: uppercase; padding-bottom: 6px; border-bottom: 1px solid var(--border); }

  .verdict-list { display: flex; flex-direction: column; gap: 4px; overflow-y: auto; }
  .verdict-row { display: flex; align-items: center; gap: 8px; padding: 6px 10px; background: var(--bg2); border: 1px solid var(--border); font-size: 10px; animation: row-in 0.3s ease; }
  @keyframes row-in { from{opacity:0;transform:translateX(-8px)} to{opacity:1;transform:translateX(0)} }
  .verdict-badge { padding: 2px 6px; font-family: var(--font-head); font-size: 8px; letter-spacing: 0.05em; border-radius: 2px; flex-shrink: 0; }
  .badge-drop      { background: rgba(255,58,92,0.15); color: var(--red); border: 1px solid rgba(255,58,92,0.3); }
  .badge-normal    { background: rgba(79,195,247,0.1); color: var(--blue); border: 1px solid rgba(79,195,247,0.2); }
  .badge-aligned   { background: rgba(57,255,132,0.1); color: var(--green); border: 1px solid rgba(57,255,132,0.2); }
  .badge-deviated  { background: rgba(255,58,92,0.1); color: var(--red); border: 1px solid rgba(255,58,92,0.2); }

  /* ── SETTLED EVENTS ── */
  .settled-list { flex: 1; overflow-y: auto; padding: 10px 12px; display: flex; flex-direction: column; gap: 6px; }
  .settled-card { border: 1px solid var(--border); padding: 8px 10px; background: var(--bg2); cursor: pointer; transition: border-color 0.15s; animation: row-in 0.3s ease; }
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

  /* ── REPUTATION ── */
  .rep-list { flex: 1; overflow-y: auto; padding: 8px 12px; display: flex; flex-direction: column; gap: 4px; }
  .rep-row { display: flex; align-items: center; gap: 8px; padding: 6px 8px; background: var(--bg2); border: 1px solid var(--border); border-left-width: 3px; font-size: 10px; }
  .rep-row.blacklisted { border-left-color: var(--red); opacity: 0.7; }
  .rep-row.healthy { border-left-color: var(--green); }
  .rep-row.warning { border-left-color: var(--amber); }
  .rep-pubkey { font-family: var(--font-data); font-size: 9px; color: var(--text-dim); flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .rep-bar-container { width: 70px; display: flex; flex-direction: column; gap: 2px; align-items: flex-end; }
  .rep-val { font-family: var(--font-data); font-size: 9px; }
  .rep-bar-bg { width: 70px; height: 3px; background: var(--bg); border-radius: 2px; overflow: hidden; }
  .rep-bar-fill { height: 100%; border-radius: 2px; transition: width 0.5s ease; }
  .rep-stake { font-family: var(--font-data); font-size: 9px; color: var(--text-dim); width: 64px; text-align: right; }
  .rep-audits { font-size: 9px; color: var(--text-dim); width: 40px; text-align: right; }

  /* ── RECEIPT ── */
  .receipt { padding: 12px; height: 100%; overflow-y: auto; display: flex; flex-direction: column; gap: 10px; }
  .receipt-header { display: flex; align-items: center; gap: 10px; padding: 10px; background: var(--bg2); border: 1px solid var(--border); }
  .receipt-verdict-big { font-family: var(--font-head); font-size: 18px; font-weight: 900; letter-spacing: 0.1em; }
  .cswarm-bar-bg { width: 100%; height: 6px; background: var(--bg); border-radius: 3px; overflow: hidden; margin-top: 2px; }
  .cswarm-bar-fill { height: 100%; border-radius: 3px; transition: width 0.6s ease; }
  .sig-display { font-family: var(--font-data); font-size: 8px; color: var(--text-dim); word-break: break-all; padding: 6px 8px; background: var(--bg2); border: 1px solid var(--border); line-height: 1.5; }

  ::-webkit-scrollbar { width: 4px; height: 4px; }
  ::-webkit-scrollbar-track { background: var(--bg1); }
  ::-webkit-scrollbar-thumb { background: var(--border); border-radius: 2px; }
  ::-webkit-scrollbar-thumb:hover { background: var(--amber-dim); }

  .indicator { width: 6px; height: 6px; border-radius: 50%; flex-shrink: 0; }
  .ind-green { background: var(--green); box-shadow: 0 0 6px var(--green); }
  .ind-amber { background: var(--amber); box-shadow: 0 0 6px var(--amber); animation: blink 0.8s step-end infinite; }
  .ind-red   { background: var(--red);   box-shadow: 0 0 6px var(--red); }
  .ind-dim   { background: var(--text-dim); }
  @keyframes blink { 0%,100%{opacity:1} 50%{opacity:0} }

  .ticker { font-family: var(--font-data); font-size: 9px; color: var(--text-dim); }
  .no-data { display: flex; align-items: center; justify-content: center; height: 100%; font-size: 10px; color: var(--text-dim); letter-spacing: 0.15em; flex-direction: column; gap: 8px; }
  .empty-glyph { font-size: 28px; opacity: 0.2; }

  .serial-log { flex: 1; overflow-y: auto; background: var(--bg); border: 1px solid var(--border); padding: 4px 8px; font-family: var(--font-data); font-size: 9px; color: var(--text-dim); line-height: 1.6; }
  .serial-log-line { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .serial-log-line.ok  { color: var(--green); opacity: 0.7; }
  .serial-log-line.err { color: var(--red); }

  .pending-badge { padding: 1px 5px; font-family: var(--font-head); font-size: 8px; background: rgba(245,166,35,0.12); color: var(--amber); border: 1px solid var(--amber-dim); border-radius: 2px; }
`;

const styleEl = document.createElement("style");
styleEl.textContent = css;
document.head.appendChild(styleEl);

const shortKey = (hex) => hex ? `${hex.slice(0, 8)}…${hex.slice(-6)}` : "—";
const fmtTime  = (ts)  => new Date(ts * 1000).toLocaleTimeString("en-US", { hour12: false });
const clamp    = (v, lo, hi) => Math.max(lo, Math.min(hi, v));

function quatToCss(qw, qx, qy, qz) {
  const n = Math.sqrt(qw*qw + qx*qx + qy*qy + qz*qz) || 1;
  const [w, x, y, z] = [qw/n, qx/n, qy/n, qz/n];
  const m = [
    1-2*(y*y+z*z), 2*(x*y-z*w),   2*(x*z+y*w),   0,
    2*(x*y+z*w),   1-2*(x*x+z*z), 2*(y*z-x*w),   0,
    2*(x*z-y*w),   2*(y*z+x*w),   1-2*(x*x+y*y), 0,
    0,             0,             0,             1,
  ];
  return `matrix3d(${m.join(",")})`;
}

const FLOW_REST = "https://rest-testnet.onflow.org/v1/scripts";

function decodeCadence(v) {
  if (v === null || v === undefined) return null;
  switch (v.type) {
    case "String": return v.value;
    case "Bool":   return v.value;
    case "Int": case "Int8": case "Int16": case "Int32": case "Int64":
    case "UInt": case "UInt8": case "UInt16": case "UInt32": case "UInt64":
      return parseInt(v.value, 10);
    case "Fix64": case "UFix64": return parseFloat(v.value);
    case "Array":  return (v.value || []).map(item => decodeCadence(item));
    case "Dictionary": return (v.value || []).reduce((acc, kv) => {
      acc[decodeCadence(kv.key)] = decodeCadence(kv.value); return acc;
    }, {});
    case "Struct": case "Resource": case "Event":
      return (v.value?.fields || []).reduce((acc, f) => {
        acc[f.name] = decodeCadence(f.value); return acc;
      }, {});
    case "Optional": return v.value ? decodeCadence(v.value) : null;
    case "AnyStruct": return v.value !== undefined ? decodeCadence(v.value) : null;
    default: return v.value ?? null;
  }
}

async function runScript(contractAddr, scriptCadence, args = []) {
  const encoded     = btoa(unescape(encodeURIComponent(scriptCadence)));
  const encodedArgs = args.map(a => btoa(unescape(encodeURIComponent(JSON.stringify(a)))));
  const resp = await fetch(FLOW_REST, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ script: encoded, arguments: encodedArgs }),
  });
  if (!resp.ok) {
    let msg = `HTTP ${resp.status}`;
    try { const b = await resp.json(); msg = b.message || JSON.stringify(b).slice(0, 200); } catch(_) {}
    throw new Error(msg);
  }
  const text = await resp.text();
  let b64;
  try { const p = JSON.parse(text); b64 = typeof p === "string" ? p : (p?.value ?? ""); }
  catch { b64 = text.trim().replace(/^"|"$/g, ""); }
  if (!b64) return null;
  const bytes = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  const raw = JSON.parse(new TextDecoder("utf-8").decode(bytes));
  return decodeCadence(raw);
}

const makeAgentsScript = (addr) => `
import SwarmVerifierV4 from ${addr}
access(all) struct LocalAgent {
  access(all) let id: String
  access(all) let reputation: Fix64
  access(all) let stakedFlow: UFix64
  access(all) let isBlacklisted: Bool
  access(all) let totalAudits: UInt64
  access(all) let correctAudits: UInt64
  init(id:String,reputation:Fix64,stakedFlow:UFix64,isBlacklisted:Bool,totalAudits:UInt64,correctAudits:UInt64) {
    self.id=id;self.reputation=reputation;self.stakedFlow=stakedFlow
    self.isBlacklisted=isBlacklisted;self.totalAudits=totalAudits;self.correctAudits=correctAudits
  }
}
access(all) fun main(): [LocalAgent] {
  var rows: [LocalAgent] = []
  for id in SwarmVerifierV4.networkAgents.keys {
    let a = SwarmVerifierV4.networkAgents[id]!
    rows.append(LocalAgent(id:id,reputation:a.reputation,stakedFlow:a.stakedFlow,
      isBlacklisted:a.isBlacklisted,totalAudits:a.totalAudits,correctAudits:a.correctAudits))
  }
  return rows
}`.trim();

const makeAllEventsScript = (addr) => `
import SwarmVerifierV4 from ${addr}
access(all) struct LocalEvent {
  access(all) let eventId: String
  access(all) let transporterId: String
  access(all) let anomalyConfidence: UFix64
  access(all) let cswarm: UFix64
  access(all) let consensusVerdict: Bool
  access(all) let dropVotes: Int
  access(all) let totalVotes: Int
  access(all) let transporterSlashed: Bool
  access(all) let finalizedAt: UFix64
  access(all) let storachaCid: String
  init(eventId:String,transporterId:String,anomalyConfidence:UFix64,cswarm:UFix64,
    consensusVerdict:Bool,dropVotes:Int,totalVotes:Int,transporterSlashed:Bool,
    finalizedAt:UFix64,storachaCid:String) {
    self.eventId=eventId;self.transporterId=transporterId
    self.anomalyConfidence=anomalyConfidence;self.cswarm=cswarm
    self.consensusVerdict=consensusVerdict;self.dropVotes=dropVotes
    self.totalVotes=totalVotes;self.transporterSlashed=transporterSlashed
    self.finalizedAt=finalizedAt;self.storachaCid=storachaCid
  }
}
access(all) fun main(): [LocalEvent] {
  var rows: [LocalEvent] = []
  for id in SwarmVerifierV4.anomalyLedger.keys {
    let e = SwarmVerifierV4.anomalyLedger[id]!
    var dropCount: Int = 0
    for r in e.auditorResults { if r.verdict { dropCount = dropCount + 1 } }
    rows.append(LocalEvent(eventId:e.eventId,transporterId:e.transporterId,
      anomalyConfidence:e.anomalyConfidence,cswarm:e.cswarm,
      consensusVerdict:e.consensusVerdict,dropVotes:dropCount,
      totalVotes:e.auditorResults.length,transporterSlashed:e.transporterSlashed,
      finalizedAt:e.finalizedAt,storachaCid:e.storachaCid))
  }
  return rows
}`.trim();

const makeAuditorResultsScript = (addr) => `
import SwarmVerifierV4 from ${addr}
access(all) struct LocalAuditorResult {
  access(all) let auditorId: String
  access(all) let verdict: Bool
  access(all) let confidence: UFix64
  access(all) let reputationDelta: Fix64
  access(all) let outcome: String
  access(all) let depositPaid: UFix64
  access(all) let bidPrice: UFix64
  access(all) let totalReceived: UFix64
  init(auditorId:String,verdict:Bool,confidence:UFix64,reputationDelta:Fix64,
    outcome:String,depositPaid:UFix64,bidPrice:UFix64,totalReceived:UFix64) {
    self.auditorId=auditorId;self.verdict=verdict;self.confidence=confidence
    self.reputationDelta=reputationDelta;self.outcome=outcome
    self.depositPaid=depositPaid;self.bidPrice=bidPrice;self.totalReceived=totalReceived
  }
}
access(all) fun main(eventId: String): [LocalAuditorResult] {
  if SwarmVerifierV4.anomalyLedger[eventId] == nil { return [] }
  let e = SwarmVerifierV4.anomalyLedger[eventId]!
  var rows: [LocalAuditorResult] = []
  for r in e.auditorResults {
    rows.append(LocalAuditorResult(auditorId:r.auditorId,verdict:r.verdict,
      confidence:r.confidence,reputationDelta:r.reputationDelta,outcome:r.outcome,
      depositPaid:r.depositPaid,bidPrice:r.bidPrice,totalReceived:r.totalReceived))
  }
  return rows
}`.trim();

const makePendingScript = (addr) => `
import SwarmVerifierV4 from ${addr}
access(all) struct LocalPV {
  access(all) let auditorId: String
  access(all) let verdict: Bool
  access(all) let confidence: UFix64
  access(all) let silent: Bool
  init(auditorId:String,verdict:Bool,confidence:UFix64,silent:Bool) {
    self.auditorId=auditorId;self.verdict=verdict
    self.confidence=confidence;self.silent=silent
  }
}
access(all) fun main(eventId: String): [LocalPV] {
  if SwarmVerifierV4.pendingEvents[eventId] == nil { return [] }
  let ev = SwarmVerifierV4.pendingEvents[eventId]!
  var rows: [LocalPV] = []
  for id in ev.quorumIds {
    if let v = ev.verdicts[id] {
      rows.append(LocalPV(auditorId:id,verdict:v.verdict,confidence:v.confidence,silent:false))
    } else {
      rows.append(LocalPV(auditorId:id,verdict:false,confidence:0.0,silent:true))
    }
  }
  return rows
}`.trim();

const makePendingMetaScript = (addr) => `
import SwarmVerifierV4 from ${addr}
access(all) struct PendingMeta {
  access(all) let eventId: String
  access(all) let transporterId: String
  init(eventId: String, transporterId: String) {
    self.eventId = eventId
    self.transporterId = transporterId
  }
}
access(all) fun main(): [PendingMeta] {
  var rows: [PendingMeta] = []
  for id in SwarmVerifierV4.pendingEvents.keys {
    let e = SwarmVerifierV4.pendingEvents[id]!
    rows.append(PendingMeta(eventId: id, transporterId: e.transporterId))
  }
  return rows
}`.trim();

const makeTransporterIdsScript = (addr) => `
import SwarmVerifierV4 from ${addr}
access(all) fun main(): [String] {
  var seen: {String: Bool} = {}
  for id in SwarmVerifierV4.anomalyLedger.keys {
    seen[SwarmVerifierV4.anomalyLedger[id]!.transporterId] = true
  }
  for id in SwarmVerifierV4.pendingEvents.keys {
    seen[SwarmVerifierV4.pendingEvents[id]!.transporterId] = true
  }
  return seen.keys
}`.trim();

function parseCsvLine(line) {
  const parts = line.trim().split(",");
  if (parts.length < 8) return null;
  const [, ax, ay, az, qw, qx, qy, qz] = parts.map(Number);
  if ([ax, ay, az, qw, qx, qy, qz].some(isNaN)) return null;
  return { ax, ay, az, qw, qx, qy, qz };
}

function PanelHeader({ title, indicator, right }) {
  return (
    <div className="panel-header">
      {indicator && <div className={`indicator ${indicator}`} />}
      <span className="panel-title">{title}</span>
      {right}
    </div>
  );
}

function ImuCube({ quat }) {
  const { qw = 1, qx = 0, qy = 0, qz = 0 } = quat || {};
  return (
    <div className="cube-scene">
      <div className="cube" style={{ transform: quatToCss(qw, qx, qy, qz) }}>
        <div className="face face-front">FRONT</div>
        <div className="face face-back">BACK</div>
        <div className="face face-right">RIGHT</div>
        <div className="face face-left">LEFT</div>
        <div className="face face-top">TOP</div>
        <div className="face face-bottom">BOT</div>
      </div>
    </div>
  );
}

function NetworkTopology({ agents, selectedTransporter, transporterIds, activeQuorumIds }) {
  const svgRef = useRef(null);
  const [size, setSize] = useState({ w: 280, h: 200 });
  useEffect(() => {
    const el = svgRef.current?.parentElement;
    if (!el) return;
    const ro = new ResizeObserver(([e]) => setSize({ w: e.contentRect.width, h: e.contentRect.height }));
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  const { w, h } = size;
  const cx = w / 2, cy = h / 2;
  const tSet = new Set(transporterIds);
  const auditors = agents.filter(a =>
    !tSet.has(a.id) && (a.totalAudits > 0 || activeQuorumIds.has(a.id))
  );
  const r = Math.min(w, h) * 0.34;
  const selectedAgent = agents.find(a => a.id === selectedTransporter);

  return (
    <svg ref={svgRef} className="topo-canvas" style={{ position: "absolute", inset: 0 }}>
      <defs>
        <radialGradient id="tglow" cx="50%" cy="50%">
          <stop offset="0%"   stopColor="#f5a623" stopOpacity="0.4" />
          <stop offset="100%" stopColor="#f5a623" stopOpacity="0" />
        </radialGradient>
        <filter id="glow">
          <feGaussianBlur stdDeviation="2" result="blur" />
          <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
        </filter>
      </defs>
      <circle cx={cx} cy={cy} r={28} fill="url(#tglow)" />
      <circle cx={cx} cy={cy} r={18} fill="#0b0f1a" stroke="#f5a623" strokeWidth="1.5" filter="url(#glow)" />
      <text x={cx} y={cy-3} textAnchor="middle" dominantBaseline="middle" fill="#f5a623" fontSize="7" fontFamily="Orbitron" letterSpacing="0.05em">
        {selectedTransporter ? selectedTransporter.slice(0, 6) : "ALL"}
      </text>
      <text x={cx} y={cy+7} textAnchor="middle" dominantBaseline="middle" fill="#8a5e13" fontSize="6" fontFamily="Share Tech Mono">
        {selectedTransporter
          ? (selectedAgent ? `${selectedAgent.reputation >= 0 ? "+" : ""}${selectedAgent.reputation.toFixed(0)}R` : "TRANSPORTER")
          : `${transporterIds.length}T`}
      </text>
      {auditors.map((a, i) => {
        const angle  = (i / Math.max(auditors.length, 1)) * Math.PI * 2 - Math.PI / 2;
        const nx     = cx + r * Math.cos(angle);
        const ny     = cy + r * Math.sin(angle);
        const inLive = activeQuorumIds.has(a.id);
        const color  = a.isBlacklisted ? "#ff3a5c" : inLive ? "#f5a623" : a.reputation >= 0 ? "#39ff84" : "#f5a623";
        const radius = inLive ? 11 : 9;
        return (
          <g key={a.id}>
            <line x1={cx} y1={cy} x2={nx} y2={ny} stroke={color} strokeWidth={inLive ? 1 : 0.5}
              strokeDasharray={inLive ? "none" : "3 3"} opacity={inLive ? 0.7 : 0.25} />
            {inLive && <circle cx={nx} cy={ny} r={radius + 5} fill="none" stroke={color} strokeWidth="0.5" opacity="0.3" />}
            <circle cx={nx} cy={ny} r={radius} fill="#0b0f1a" stroke={color} strokeWidth={inLive ? 2 : 1.5} />
            <text x={nx} y={ny+1} textAnchor="middle" dominantBaseline="middle" fill={color} fontSize="6" fontFamily="Share Tech Mono">
              {a.id.slice(0, 4)}
            </text>
            <text x={nx} y={ny + radius + 9} textAnchor="middle"
              fill={a.reputation >= 0 ? "#1a6b3a" : "#8a5e13"} fontSize="6" fontFamily="DM Mono">
              {a.reputation >= 0 ? "+" : ""}{a.reputation.toFixed(0)}
            </text>
          </g>
        );
      })}
      {auditors.length === 0 && (
        <text x={cx} y={cy + 44} textAnchor="middle" fill="#4a6080" fontSize="9" fontFamily="Share Tech Mono" letterSpacing="0.1em">
          {agents.length > 0 ? "NO ACTIVE AUDITORS" : "AWAITING CHAIN DATA"}
        </text>
      )}
    </svg>
  );
}

function PhaseTracker({ hasPendingEvent, verdictCount, quorumSize }) {
  const phases = ["REGISTER", "DEPOSIT", "VERDICTS", "FINALIZE"];
  let activeIdx = -1;
  if (hasPendingEvent) {
    if (verdictCount === 0) activeIdx = 1;
    else if (verdictCount < quorumSize) activeIdx = 2;
    else activeIdx = 3;
  }
  return (
    <div className="phase-track">
      {phases.map((p, i) => {
        const st = i < activeIdx ? "done" : i === activeIdx ? "active" : "pending";
        return (
          <div key={p} style={{ display: "flex", alignItems: "center", flex: 1 }}>
            <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 4 }}>
              <div className={`phase-dot ${st}`}>{i + 1}</div>
              <div className={`phase-label ${st}`}>{p}</div>
            </div>
            {i < phases.length - 1 && (
              <div className="phase-line" style={{ flex: 1, height: 1, background: st === "done" ? "#1a6b3a" : "#1a2540", marginBottom: 20, position: "relative", overflow: "hidden" }}>
                {st === "active" && <div style={{ position: "absolute", inset: 0, background: "linear-gradient(90deg,#f5a623,transparent)", animation: "scan-line 1.5s linear infinite" }} />}
                {st === "done"   && <div style={{ position: "absolute", inset: 0, background: "#1a6b3a" }} />}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

function SerialImuPanel({ onImuUpdate }) {
  const [connected, setConnected] = useState(false);
  const [log,       setLog]       = useState([]);
  const [imu,       setImu]       = useState({ ax: 0, ay: 0, az: 9.81, qw: 1, qx: 0, qy: 0, qz: 0 });
  const [anomConf,  setAnonConf]  = useState(0);
  const portRef    = useRef(null);
  const readerRef  = useRef(null);
  const bufRef     = useRef("");

  const addLog = useCallback((msg, type = "dim") => {
    setLog(l => [{ msg, type, id: Date.now() + Math.random() }, ...l].slice(0, 40));
  }, []);

  const connect = async () => {
    if (!("serial" in navigator)) { addLog("Web Serial not supported (Chrome/Edge only)", "err"); return; }
    try {
      const port = await navigator.serial.requestPort();
      await port.open({ baudRate: 115200 });
      portRef.current = port;
      setConnected(true);
      addLog("Serial opened — reading IMU stream", "ok");
      readLoop(port);
    } catch (e) { addLog(`Connect failed: ${e.message}`, "err"); }
  };

  const disconnect = async () => {
    try { readerRef.current?.cancel(); await portRef.current?.close(); } catch(_) {}
    portRef.current = null; readerRef.current = null;
    setConnected(false); addLog("Disconnected");
  };

  const readLoop = async (port) => {
    const decoder = new TextDecoderStream();
    port.readable.pipeTo(decoder.writable).catch(() => {});
    const reader = decoder.readable.getReader();
    readerRef.current = reader;
    try {
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        bufRef.current += value;
        const lines = bufRef.current.split("\n");
        bufRef.current = lines.pop();
        for (const line of lines) {
          const t = line.trim();
          if (!t || t.startsWith("timestamp_ms")) continue;
          const p = parseCsvLine(t);
          if (p) {
            setImu(p); onImuUpdate(p);
            const ta = Math.sqrt(p.ax**2 + p.ay**2 + p.az**2);
            setAnonConf(clamp(1 - ta / 15, 0, 1));
          } else { addLog(t.slice(0, 60), "err"); }
        }
      }
    } catch (e) { if (e.name !== "AbortError") addLog(`Read error: ${e.message}`, "err"); }
    setConnected(false); addLog("Stream ended");
  };

  return (
    <>
      <div className="imu-cube-section"><ImuCube quat={imu} /></div>
      <div className="imu-section imu-section-accel">
        <div className="section-title" style={{ marginBottom: 5 }}>LINEAR ACCEL (m/s²)</div>
        {[{ label: "AX", val: imu.ax, color: "#ff3a5c" }, { label: "AY", val: imu.ay, color: "#39ff84" }, { label: "AZ", val: imu.az, color: "#4fc3f7" }].map(({ label, val, color }) => (
          <div className="imu-row" key={label}>
            <span className="imu-label">{label}</span>
            <div className="imu-bar-bg"><div className="imu-bar-fill" style={{ width: `${clamp((val/20+0.5)*100,0,100)}%`, background: color }} /></div>
            <span className="imu-val" style={{ color }}>{val.toFixed(4)}</span>
          </div>
        ))}
      </div>
      <div className="imu-section imu-section-quat">
        <div className="section-title" style={{ marginBottom: 5 }}>QUATERNION</div>
        <div className="quat-grid">
          {["qw","qx","qy","qz"].map(k => (
            <div className="quat-item" key={k}>
              <span className="quat-key">{k.toUpperCase()}</span>
              <span className="quat-val">{(imu[k]||0).toFixed(6)}</span>
            </div>
          ))}
        </div>
      </div>
      <div className={`imu-conf-section ${anomConf < 0.05 ? "hidden" : ""}`}>
        <div style={{ display:"flex", alignItems:"center", justifyContent:"space-between" }}>
          <span style={{ fontFamily:"Orbitron", fontSize:8, color:"#8a5e13", letterSpacing:"0.12em" }}>P(DROP) LOCAL</span>
          <span style={{ fontFamily:"Orbitron", fontSize:16, fontWeight:900, color:"#f5a623", textShadow:"0 0 18px rgba(245,166,35,0.55)" }}>{(anomConf*100).toFixed(1)}%</span>
        </div>
        <div style={{ width:"100%", height:3, background:"#0f1525", borderRadius:2, marginTop:4, overflow:"hidden" }}>
          <div style={{ height:"100%", borderRadius:2, width:`${anomConf*100}%`, background:"linear-gradient(90deg,#8a5e13,#f5a623)", transition:"width 0.4s ease" }} />
        </div>
      </div>
      <div className="serial-section">
        <div style={{ display:"flex", gap:6, alignItems:"center" }}>
          {!connected
            ? <button className="btn" onClick={connect}>⟳ CONNECT SERIAL</button>
            : <button className="btn danger" onClick={disconnect}>⏹ DISCONNECT</button>
          }
          {connected && <><div className="indicator ind-green" /><span style={{ fontFamily:"DM Mono", fontSize:9, color:"#39ff84" }}>115200 baud</span></>}
        </div>
        <div className="serial-log">
          {log.length === 0
            ? <div className="serial-log-line" style={{ color:"#1a2540" }}>— no data —</div>
            : log.map(l => <div key={l.id} className={`serial-log-line ${l.type}`}>{l.msg}</div>)
          }
        </div>
      </div>
    </>
  );
}

function TransporterSelector({ agents, transporterIds, selected, onSelect }) {
  const tSet = new Set(transporterIds);
  const transporterAgents = agents.filter(a => tSet.has(a.id));
  return (
    <div className="node-selector">
      <div style={{ fontFamily:"Orbitron", fontSize:8, letterSpacing:"0.12em", color:"#4a6080", marginBottom:2 }}>SELECT TRANSPORTER NODE</div>
      <div className="node-list">
        <div className={`node-item ${!selected ? "selected" : ""}`} onClick={() => onSelect(null)}>
          <span className="node-role role-transporter">ALL</span>
          <span style={{ fontFamily:"DM Mono", fontSize:9, color:"#4a6080" }}>All events</span>
          <span style={{ fontFamily:"DM Mono", fontSize:9, color:"#1a2540", marginLeft:"auto" }}>{transporterAgents.length} nodes</span>
        </div>
        {transporterAgents.map(a => (
          <div key={a.id} className={`node-item ${selected===a.id?"selected":""} ${a.isBlacklisted?"blacklisted":""}`} onClick={() => onSelect(a.id)}>
            <span className="node-role role-transporter">T</span>
            <span style={{ fontFamily:"DM Mono", fontSize:9, color:selected===a.id?"#f5a623":"#c8d8f0", flex:1 }}>{shortKey(a.id)}</span>
            <span style={{ fontFamily:"DM Mono", fontSize:9, color:a.reputation>=0?"#39ff84":"#f5a623" }}>{a.reputation>=0?"+":""}{a.reputation.toFixed(1)}R</span>
          </div>
        ))}
        {transporterIds.length === 0 && (
          <div style={{ fontFamily:"DM Mono", fontSize:9, color:"#1a2540", padding:"6px 0" }}>No transporter events on-chain yet</div>
        )}
      </div>
    </div>
  );
}

const DEFAULT_FLOW_ADDR = "0xfcd23c8d1553708a";

export default function SwarmDashboard() {
  const [flowAddr,   setFlowAddr]   = useState(DEFAULT_FLOW_ADDR);
  const [showConfig, setShowConfig] = useState(false);
  const flowAddrRef = useRef(flowAddr);
  useEffect(() => { flowAddrRef.current = flowAddr; }, [flowAddr]);

  const [flowAgents,     setFlowAgents]     = useState([]);
  const [flowEvents,     setFlowEvents]     = useState([]);
  const [flowVerdicts,   setFlowVerdicts]   = useState({});
  const [auditorCache,   setAuditorCache]   = useState({});
  const [flowError,      setFlowError]      = useState(null);
  const [flowLastOk,     setFlowLastOk]     = useState(null);
  const [flowRefresh,    setFlowRefresh]    = useState(0);
  const [pendingMeta,    setPendingMeta]    = useState([]);
  const [transporterIds, setTransporterIds] = useState([]);

  const [selectedTransporter, setSelectedTransporter] = useState(null);
  const [selectedEvent,       setSelectedEvent]       = useState(null);
  const [, setImuData] = useState({ ax: 0, ay: 0, az: 9.81, qw: 1, qx: 0, qy: 0, qz: 0 });

  useEffect(() => {
    let alive = true;
    const pollAgents = async () => {
      try {
        const rows = await runScript(flowAddrRef.current, makeAgentsScript(flowAddrRef.current));
        if (!alive) return;
        setFlowAgents((rows||[]).map(r => ({ id:r.id, reputation:r.reputation, stake:r.stakedFlow, isBlacklisted:r.isBlacklisted, totalAudits:r.totalAudits, correctAudits:r.correctAudits })));
        setFlowError(null); setFlowLastOk(Date.now());
      } catch(e) { if (alive) setFlowError(e.message); }
    };
    const pollEvents = async () => {
      try {
        const rows = await runScript(flowAddrRef.current, makeAllEventsScript(flowAddrRef.current));
        if (!alive) return;
        const events = (rows||[]).map(r => ({
          event_id: r.eventId, transporter_id: r.transporterId,
          anomaly_confidence: r.anomalyConfidence, cswarm: r.cswarm,
          consensus_verdict: r.consensusVerdict, drop_votes: r.dropVotes??0,
          total_votes: r.totalVotes??0, transporter_slashed: r.transporterSlashed,
          finalized_at: r.finalizedAt, storacha_cid: r.storachaCid,
        })).sort((a,b) => b.finalized_at - a.finalized_at).slice(0, 30);
        setFlowEvents(events); setFlowError(null); setFlowLastOk(Date.now());
      } catch(e) { if (alive) setFlowError(e.message); }
    };
    const pollPendingMeta = async () => {
      try {
        const rows = await runScript(flowAddrRef.current, makePendingMetaScript(flowAddrRef.current));
        if (!alive) return;
        setPendingMeta((rows||[]).map(r => ({ eventId:r.eventId, transporterId:r.transporterId })));
      } catch(_) {}
    };
    const pollTransporterIds = async () => {
      try {
        const ids = await runScript(flowAddrRef.current, makeTransporterIdsScript(flowAddrRef.current));
        if (!alive) return;
        setTransporterIds(ids||[]);
      } catch(_) {}
    };
    pollAgents(); pollEvents(); pollPendingMeta(); pollTransporterIds();
    const iA = setInterval(pollAgents,        12000);
    const iE = setInterval(pollEvents,         8000);
    const iP = setInterval(pollPendingMeta,    5000);
    const iT = setInterval(pollTransporterIds,30000);
    return () => { alive=false; clearInterval(iA); clearInterval(iE); clearInterval(iP); clearInterval(iT); };
  }, [flowRefresh]);

  useEffect(() => {
    if (pendingMeta.length === 0) return;
    let alive = true;
    const pollOne = async (eventId) => {
      try {
        const rows = await runScript(flowAddrRef.current, makePendingScript(flowAddrRef.current), [{ type:"String", value:eventId }]);
        if (!alive || !rows?.length) return;
        const map = {};
        rows.forEach(r => { map[r.auditorId] = { verdict:r.verdict, confidence:r.confidence, silent:r.silent }; });
        setFlowVerdicts(prev => ({ ...prev, [eventId]: map }));
      } catch(_) {}
    };
    const poll = () => pendingMeta.forEach(m => pollOne(m.eventId));
    poll();
    const iv = setInterval(poll, 3000);
    return () => { alive=false; clearInterval(iv); };
  }, [pendingMeta]);

  useEffect(() => {
    if (!selectedEvent) return;
    const id = selectedEvent.event_id;
    if (auditorCache[id]) return;
    runScript(flowAddrRef.current, makeAuditorResultsScript(flowAddrRef.current), [{ type:"String", value:id }])
      .then(rows => {
        const results = (rows||[]).map(r => ({ auditorId:r.auditorId, verdict:r.verdict, confidence:r.confidence, reputationDelta:r.reputationDelta, outcome:r.outcome, depositPaid:r.depositPaid, bidPrice:r.bidPrice, totalReceived:r.totalReceived }));
        if (results.length > 0) setAuditorCache(c => {
            const keys = Object.keys(c);
            // Keep only last 20 events in cache
            const trimmed = keys.length >= 20
                ? Object.fromEntries(keys.slice(-19).map(k => [k, c[k]]))
                : c;
            return { ...trimmed, [id]: results };
        });;
      }).catch(()=>{});
  }, [selectedEvent?.event_id]);

  const filteredEvents = selectedTransporter ? flowEvents.filter(e => e.transporter_id === selectedTransporter) : flowEvents;

  useEffect(() => {
    if (filteredEvents.length > 0 && (!selectedEvent || !filteredEvents.find(e => e.event_id === selectedEvent.event_id))) {
      setSelectedEvent(filteredEvents[0]);
    }
  }, [filteredEvents.length, selectedTransporter]);

  const selectedAuditorResults  = selectedEvent ? (auditorCache[selectedEvent.event_id] || null) : null;
  const visiblePending          = selectedTransporter ? pendingMeta.filter(m => m.transporterId === selectedTransporter) : pendingMeta;
  const activePendingKey        = visiblePending.length > 0 ? visiblePending[visiblePending.length - 1].eventId : null;
  const activePendingVerdicts   = activePendingKey ? (flowVerdicts[activePendingKey] || {}) : {};
  const verdictCount            = Object.keys(activePendingVerdicts).filter(k => !activePendingVerdicts[k].silent).length;
  const quorumSize              = Object.keys(activePendingVerdicts).length;
  const hasPending              = !!activePendingKey;
  const activeQuorumIds         = new Set(Object.keys(activePendingVerdicts));
  const flowIndicator           = flowError ? "ind-red" : flowLastOk ? "ind-green" : "ind-dim";

  return (
    <div className="dash-root">

      {/* ── TOPBAR ── */}
      <div className="topbar">
        <div className="logo">SWARM<span>VERIFIER</span></div>
        <div className="topbar-divider" />
        <div className="sys-status">
          <div className={`status-dot ${hasPending ? "status-DELIVERING" : "status-IDLE"}`} />
          <span style={{ color: hasPending ? "#39ff84" : "#4a6080" }}>{hasPending ? "PENDING" : "IDLE"}</span>
        </div>
        <div className="topbar-divider" />
        <div className="topbar-stat"><div className="topbar-stat-label">AGENTS</div><div className="topbar-stat-value">{flowAgents.length}</div></div>
        <div className="topbar-divider" />
        <div className="topbar-stat"><div className="topbar-stat-label">EVENTS</div><div className="topbar-stat-value">{flowEvents.length}</div></div>
        <div className="topbar-divider" />
        <div className="topbar-stat"><div className="topbar-stat-label">PENDING</div><div className="topbar-stat-value" style={{ color: hasPending?"#f5a623":"#4a6080" }}>{pendingMeta.length}</div></div>
        <div className="topbar-divider" />
        <div className="topbar-stat">
          <div className="topbar-stat-label">WATCHING</div>
          <div className="topbar-stat-value" style={{ fontSize:9, fontFamily:"DM Mono", color:selectedTransporter?"#f5a623":"#4a6080" }}>
            {selectedTransporter ? shortKey(selectedTransporter) : "ALL"}
          </div>
        </div>
        <div style={{ flex:1 }} />
        <div style={{ display:"flex", alignItems:"center", gap:5 }}>
          <div className={`indicator ${flowIndicator}`} />
          <span style={{ fontFamily:"DM Mono", fontSize:9, color:"#4a6080" }}>FLOW</span>
        </div>
        <div className="topbar-divider" />
        <button className="btn" onClick={() => setFlowRefresh(n => n+1)}>⟳ REFRESH</button>
        <button className="btn" onClick={() => setShowConfig(c => !c)}>⚙</button>
        <div className="topbar-divider" />
        <span className="ticker">{new Date().toLocaleTimeString("en-US", { hour12:false })}</span>
      </div>

      {/* ── CONFIG DRAWER ── */}
      {showConfig && (
        <div style={{ position:"fixed", top:52, left:0, right:0, zIndex:1000, background:"#0b0f1a", borderBottom:"1px solid #1a2540", padding:"10px 24px", display:"flex", alignItems:"center", gap:20 }}>
          <span style={{ fontFamily:"Orbitron", fontSize:9, color:"#4a6080", letterSpacing:"0.12em" }}>FLOW CONTRACT</span>
          <input value={flowAddr} onChange={e => { setFlowAddr(e.target.value); setFlowRefresh(n=>n+1); }}
            placeholder="0xfcd23c8d1553708a"
            style={{ background:"#060810", border:"1px solid #1a2540", color:"#c8d8f0", fontFamily:"DM Mono", fontSize:10, padding:"4px 10px", width:220, outline:"none" }} />
          {flowError && <span style={{ fontFamily:"DM Mono", fontSize:9, color:"#ff3a5c" }}>Flow: {flowError.slice(0,120)}</span>}
        </div>
      )}

      {/* ── COL 1 ROW 2 — NETWORK TOPOLOGY + TRANSPORTER SELECTOR ── */}
      <div className="panel net-panel">
        <PanelHeader
          title="Swarm Network · Flow"
          indicator={flowLastOk ? "ind-green" : flowError ? "ind-red" : "ind-dim"}
          right={<span style={{ fontFamily:"DM Mono", fontSize:9, color:"#4a6080" }}>{flowAgents.length} NODES</span>}
        />
        <div className="panel-body" style={{ display:"flex", flexDirection:"column" }}>
          <TransporterSelector agents={flowAgents} transporterIds={transporterIds} selected={selectedTransporter} onSelect={setSelectedTransporter} />
          <div style={{ flex:1, position:"relative" }}>
            <NetworkTopology agents={flowAgents} selectedTransporter={selectedTransporter} transporterIds={transporterIds} activeQuorumIds={activeQuorumIds} />
          </div>
        </div>
      </div>

      {/* ── COL 1 ROW 3 — IMU PANEL (serial) ── */}
      <div className="panel imu-panel">
        <PanelHeader title="IMU · BNO085 · Serial" indicator="ind-dim"
          right={<span style={{ fontFamily:"DM Mono", fontSize:9, color:"#4a6080" }}>Web Serial</span>} />
        <div className="panel-body">
          <div className="imu-body">
            <SerialImuPanel onImuUpdate={setImuData} />
          </div>
        </div>
      </div>

      {/* ── COL 2 ROW 2 — LIVE PENDING EVENT ── */}
      <div className="panel">
        <PanelHeader title="Live Pending Event · Flow" indicator={hasPending ? "ind-amber" : "ind-dim"}
          right={hasPending ? <span style={{ fontFamily:"DM Mono", fontSize:9, color:"#8a5e13" }}>{verdictCount}/{quorumSize} VERDICTS</span> : null} />
        <div className="panel-body">
          <div className="event-panel-body">
            {!hasPending ? (
              <div className="no-data"><div className="empty-glyph">◎</div><span>NO PENDING EVENTS ON-CHAIN</span></div>
            ) : (
              <>
                <PhaseTracker hasPendingEvent={hasPending} verdictCount={verdictCount} quorumSize={quorumSize} />
                <div className="kv-grid">
                  <div className="kv-row"><span className="kv-key">Event ID</span><span className="kv-val" style={{ fontSize:9, fontFamily:"DM Mono", color:"#4a6080" }}>{shortKey(activePendingKey)}</span></div>
                  <div className="kv-row"><span className="kv-key">Quorum</span><span className="kv-val">{quorumSize}</span></div>
                  <div className="kv-row"><span className="kv-key">Verdicts In</span><span className="kv-val highlight">{verdictCount} / {quorumSize}</span></div>
                  <div className="kv-row"><span className="kv-key">Pending Events</span><span className="kv-val" style={{ color:"#f5a623" }}>{pendingMeta.length}</span></div>
                </div>
                {quorumSize > 0 && (
                  <>
                    <div className="section-title">QUORUM VERDICTS</div>
                    <div className="verdict-list">
                      {Object.entries(activePendingVerdicts).map(([pub, v]) => (
                        <div className="verdict-row" key={pub} style={{ opacity: v.silent ? 0.4 : 1 }}>
                          {v.silent
                            ? <div className="verdict-badge" style={{ background:"rgba(74,96,128,0.15)", color:"#4a6080", border:"1px solid #1a2540" }}>WAIT</div>
                            : <div className={`verdict-badge ${v.verdict ? "badge-drop" : "badge-normal"}`}>{v.verdict ? "DROP" : "NORM"}</div>
                          }
                          <span style={{ fontFamily:"DM Mono", fontSize:9, color:"#4a6080", flex:1 }}>{shortKey(pub)}</span>
                          {!v.silent && <span style={{ fontFamily:"DM Mono", fontSize:10, color:"#c8d8f0" }}>{(v.confidence*100).toFixed(1)}%</span>}
                          {v.silent  && <span style={{ fontFamily:"DM Mono", fontSize:9, color:"#4a6080" }}>pending</span>}
                        </div>
                      ))}
                    </div>
                  </>
                )}
              </>
            )}
          </div>
        </div>
      </div>

      {/* ── COL 2 ROW 3 — SETTLEMENT LEDGER ── */}
      <div className="panel">
        <PanelHeader title="Settlement Ledger · Flow" indicator={flowIndicator}
          right={<span style={{ fontFamily:"DM Mono", fontSize:9, color:"#4a6080" }}>{flowLastOk ? new Date(flowLastOk).toLocaleTimeString("en-US",{hour12:false}) : "—"}</span>} />
        <div className="panel-body" style={{ display:"flex", flexDirection:"column" }}>
          {filteredEvents.length === 0 ? (
            <div className="no-data">
              <div className="empty-glyph">⬡</div>
              {flowError
                ? <span style={{ color:"#ff3a5c", fontSize:9, wordBreak:"break-word", padding:"0 16px", textAlign:"center" }}>{flowError}</span>
                : <span>{flowLastOk ? "NO EVENTS FOR SELECTION" : "FETCHING FROM FLOW…"}</span>
              }
            </div>
          ) : (
            <div className="settled-list">
              {filteredEvents.map(ev => (
                <div key={ev.event_id} className={`settled-card ${selectedEvent?.event_id===ev.event_id?"selected":""}`} onClick={() => setSelectedEvent(ev)}>
                  <div className="settled-card-top">
                    <span className={`settled-verdict verdict-${ev.consensus_verdict?"DROP":"NORMAL"}`}>{ev.consensus_verdict ? "● DROP" : "● NORMAL"}</span>
                    <span className="settled-id">{shortKey(ev.event_id)}</span>
                    <span className="settled-time">{fmtTime(ev.finalized_at)}</span>
                  </div>
                  <div className="settled-card-stats">
                    <span>Cswarm <span>{(ev.cswarm*100).toFixed(1)}%</span></span>
                    <span>Drop <span>{ev.drop_votes}/{ev.total_votes}</span></span>
                    <span>Conf <span>{(ev.anomaly_confidence*100).toFixed(1)}%</span></span>
                    {ev.transporter_slashed && <span style={{ color:"#ff3a5c" }}>⚡ SLASHED</span>}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* ── COL 3 ROWS 2-3 — REPUTATION + RECEIPT ── */}
      <div className="panel rep-panel" style={{ display:"flex", flexDirection:"column" }}>

        {/* Reputation top half */}
        <div style={{ flex:1, display:"flex", flexDirection:"column", overflow:"hidden", borderBottom:"1px solid var(--border)" }}>
          <PanelHeader title="Reputation Ledger · Flow" indicator={flowIndicator}
            right={<span style={{ fontFamily:"DM Mono", fontSize:9, color:"#4a6080" }}>α=10  β=5  τ=−50</span>} />
          <div style={{ flex:1, overflow:"hidden", display:"flex", flexDirection:"column" }}>
            {flowAgents.length === 0 ? (
              <div className="no-data"><span>{flowError ? `ERROR: ${flowError.slice(0,80)}` : flowLastOk ? "NO AGENTS REGISTERED" : "FETCHING…"}</span></div>
            ) : (
              <div className="rep-list">
                <div style={{ display:"flex", gap:8, padding:"0 0 4px", marginBottom:2, borderBottom:"1px solid var(--border)" }}>
                  <span style={{ fontSize:8, color:"#4a6080", fontFamily:"Orbitron", flex:1, letterSpacing:"0.1em" }}>NODE ID</span>
                  <span style={{ fontSize:8, color:"#4a6080", fontFamily:"Orbitron", width:70, textAlign:"right", letterSpacing:"0.1em" }}>REP</span>
                  <span style={{ fontSize:8, color:"#4a6080", fontFamily:"Orbitron", width:64, textAlign:"right", letterSpacing:"0.1em" }}>STAKE</span>
                  <span style={{ fontSize:8, color:"#4a6080", fontFamily:"Orbitron", width:44, textAlign:"right", letterSpacing:"0.1em" }}>AUDITS</span>
                  <span style={{ fontSize:8, color:"#4a6080", fontFamily:"Orbitron", width:40, textAlign:"right", letterSpacing:"0.1em" }}>ACC</span>
                </div>
                {flowAgents.map(a => {
                  const rep      = a.reputation || 0;
                  const repClass = a.isBlacklisted ? "blacklisted" : rep < 0 ? "warning" : "healthy";
                  const repColor = a.isBlacklisted ? "#ff3a5c" : rep < 0 ? "#f5a623" : "#39ff84";
                  const barW     = clamp((rep + 100) / 200 * 100, 0, 100);
                  const acc      = a.totalAudits > 0 ? Math.round((a.correctAudits / a.totalAudits) * 100) : 0;
                  const isAuditor = !new Set(transporterIds).has(a.id);
                  return (
                    <div className={`rep-row ${repClass}`} key={a.id}>
                      <span className="rep-pubkey">{shortKey(a.id)}</span>
                      <div className="rep-bar-container">
                        <span className="rep-val" style={{ color:repColor }}>{rep>=0?"+":""}{rep.toFixed(1)}</span>
                        <div className="rep-bar-bg"><div className="rep-bar-fill" style={{ width:`${barW}%`, background:repColor }} /></div>
                      </div>
                      <span className="rep-stake">{(a.stake||0).toFixed(1)} ◎</span>
                      <span style={{ fontFamily:"DM Mono", fontSize:9, width:44, textAlign:"right", color:"#4a6080" }}>
                        {isAuditor ? a.totalAudits : ""}
                      </span>
                      <span className="rep-audits" style={{ color: !isAuditor ? "#1a2540" : acc>=80?"#39ff84":acc>=50?"#f5a623":"#ff3a5c" }}>
                        {isAuditor ? `${acc}%` : "—"}
                      </span>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>

        {/* Settlement receipt bottom half */}
        <div style={{ flex:1, display:"flex", flexDirection:"column", overflow:"hidden" }}>
          <PanelHeader title="Settlement Receipt · Flow" indicator={selectedEvent ? "ind-green" : "ind-dim"} />
          <div className="panel-body">
            {!selectedEvent ? (
              <div className="no-data"><span>SELECT AN EVENT</span></div>
            ) : (
              <div className="receipt">
                <div className="receipt-header">
                  <div>
                    <div className={`receipt-verdict-big verdict-${selectedEvent.consensus_verdict?"DROP":"NORMAL"}`}>
                      {selectedEvent.consensus_verdict ? "DROP CONFIRMED" : "NO ANOMALY"}
                    </div>
                    <div style={{ fontFamily:"DM Mono", fontSize:9, color:"#4a6080", marginTop:2 }}>
                      {fmtTime(selectedEvent.finalized_at)} · {shortKey(selectedEvent.transporter_id)}
                    </div>
                  </div>
                  <div style={{ flex:1 }}>
                    <div style={{ display:"flex", justifyContent:"space-between", fontSize:8, color:"#4a6080", fontFamily:"Orbitron", letterSpacing:"0.1em" }}>
                      <span>C_SWARM</span>
                      <span style={{ color:"#4fc3f7" }}>{(selectedEvent.cswarm*100).toFixed(2)}%</span>
                    </div>
                    <div className="cswarm-bar-bg">
                      <div className="cswarm-bar-fill" style={{ width:`${selectedEvent.cswarm*100}%`, background:"linear-gradient(90deg,#1a4a6b,#4fc3f7)" }} />
                    </div>
                    <div style={{ display:"flex", gap:12, marginTop:6 }}>
                      <span style={{ fontSize:9, color:"#4a6080" }}>Drop <span style={{ color:"#c8d8f0" }}>{selectedEvent.drop_votes}/{selectedEvent.total_votes}</span></span>
                      {selectedEvent.transporter_slashed && <span style={{ fontSize:9, color:"#ff3a5c", fontFamily:"Orbitron" }}>⚡ T.SLASHED</span>}
                    </div>
                  </div>
                </div>
                {selectedAuditorResults === null ? (
                  <div style={{ fontSize:9, color:"#4a6080", fontFamily:"DM Mono" }}>FETCHING AUDITOR RESULTS…</div>
                ) : selectedAuditorResults.length === 0 ? (
                  <div style={{ fontSize:9, color:"#4a6080", fontFamily:"DM Mono" }}>NO AUDITOR DATA ON-CHAIN</div>
                ) : (
                  selectedAuditorResults.map(r => {
                    const aligned = r.outcome === "aligned";
                    const silent  = r.outcome === "silent";
                    return (
                      <div key={r.auditorId} style={{ display:"flex", alignItems:"center", gap:8, padding:"5px 8px", background:"var(--bg2)", borderLeft:`3px solid ${aligned?"var(--green)":silent?"var(--text-dim)":"var(--red)"}`, fontSize:9 }}>
                        <span style={{ fontFamily:"DM Mono", color:"#4a6080", flex:1 }}>{shortKey(r.auditorId)}</span>
                        <span className={`verdict-badge ${r.verdict?"badge-drop":"badge-normal"}`}>{r.verdict?"DROP":"NORM"}</span>
                        <span style={{ fontFamily:"DM Mono", color:"#c8d8f0", width:44, textAlign:"right" }}>{(r.confidence*100).toFixed(1)}%</span>
                        <span style={{ fontFamily:"DM Mono", width:48, textAlign:"right", color:r.reputationDelta>=0?"#39ff84":"#ff3a5c" }}>
                          {r.reputationDelta>=0?"+":""}{r.reputationDelta?.toFixed(2)}
                        </span>
                        <span style={{ fontFamily:"DM Mono", width:60, textAlign:"right", color:"#4a6080" }}>{r.totalReceived.toFixed(3)} ◎</span>
                      </div>
                    );
                  })
                )}
                {selectedEvent.storacha_cid && selectedEvent.storacha_cid !== "" && (
                  <div>
                    <div className="section-title" style={{ marginBottom:4 }}>STORACHA CID</div>
                    <div className="sig-display">{selectedEvent.storacha_cid}</div>
                  </div>
                )}
                <div>
                  <div className="section-title" style={{ marginBottom:4 }}>EVENT ID (submissionSig)</div>
                  <div className="sig-display">{selectedEvent.event_id}</div>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

    </div>
  );
}