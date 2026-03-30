import { useState, useEffect } from "react";
import {  fmtTime, copyToClipboard, getNodeAlias } from "../utils.js";

function CopyField({ label, value }) {
  const [copied, setCopied] = useState(false);
  const handle = async () => {
    await copyToClipboard(value);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };
  return (
    <div>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 3 }}>
        <div className="section-title">{label}</div>
        <button className="btn small" onClick={handle}>{copied ? "✓ COPIED" : "COPY"}</button>
      </div>
      <div className="sig-display" onClick={handle} title="Click to copy">{value}</div>
    </div>
  );
}

function AnimatedNumber({ value, duration = 1000, decimals = 3, prefix = "", isNegative = false }) {
  const [displayVal, setDisplayVal] = useState(0);

  useEffect(() => {
    let startTime;
    let animationFrame;
    const startVal = displayVal;

    const tick = (timestamp) => {
      if (!startTime) startTime = timestamp;
      const progress = Math.min((timestamp - startTime) / duration, 1);
      
      // Easing function for a nice slow-down effect at the end (easeOutQuart)
      const ease = 1 - Math.pow(1 - progress, 4);
      const current = startVal + (value - startVal) * ease;
      
      setDisplayVal(current);

      if (progress < 1) {
        animationFrame = requestAnimationFrame(tick);
      } else {
        setDisplayVal(value); // Ensure it ends exactly on the target
      }
    };

    animationFrame = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(animationFrame);
  }, [value, duration]);

  const color = isNegative ? "#ff3a5c" : displayVal > 0 ? "#39ff84" : "#c8d8f0";

  return (
    <span style={{ color, fontVariantNumeric: "tabular-nums" }}>
      {prefix}{displayVal.toFixed(decimals)}
    </span>
  );
}

function AuditorResultRow({ r }) {
  const aligned  = r.outcome === "aligned";
  const silent   = r.outcome === "silent";
  const deviated = r.outcome === "deviated";

  const borderColor = aligned ? "var(--green)" : silent ? "var(--text-dim)" : "var(--red)";

  return (
    <div style={{
      display: "flex", alignItems: "center", gap: 7, padding: "5px 8px",
      background: "var(--bg2)", borderLeft: `3px solid ${borderColor}`,
      fontSize: 9, marginBottom: 2,
    }}>
      <span style={{ fontFamily: "DM Mono", color: "#4a6080", flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
        {getNodeAlias(r.auditorId, "Auditor")}
      </span>
      <div className={`verdict-badge ${r.verdict ? "badge-drop" : "badge-normal"}`}>
        {r.verdict ? "DROP" : "NORM"}
      </div>
      <span style={{ fontFamily: "DM Mono", color: "#c8d8f0", width: 40, textAlign: "right" }}>
        {(r.confidence * 100).toFixed(1)}%
      </span>
      <span style={{ fontFamily: "DM Mono", width: 46, textAlign: "right" }}>
        <AnimatedNumber 
          value={r.reputationDelta} 
          decimals={2} 
          prefix={r.reputationDelta > 0 ? "+" : ""} 
          isNegative={r.reputationDelta < 0} 
        />
      </span>
      <span style={{ fontFamily: "DM Mono", width: 56, textAlign: "right", color: aligned ? "#c8d8f0" : "#4a6080" }}>
        <AnimatedNumber value={r.totalReceived} decimals={3} /> ◎
      </span>
      <span style={{
        fontFamily: "Orbitron", fontSize: 7, letterSpacing: "0.06em",
        color: aligned ? "#39ff84" : silent ? "#4a6080" : "#ff3a5c",
        width: 44, textAlign: "right",
      }}>
        {r.outcome.toUpperCase()}
      </span>
    </div>
  );
}

export default function ReceiptPanel({ selectedEvent, auditorResults }) {
  if (!selectedEvent) {
    return (
      <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}>
        <div className="panel-header">
          <div className="indicator ind-dim" />
          <span className="panel-title">Settlement Receipt · Flow</span>
        </div>
        <div className="panel-body">
          <div className="no-data"><span>SELECT AN EVENT</span></div>
        </div>
      </div>
    );
  }

  const { consensus_verdict: drop, cswarm, drop_votes, total_votes,
          anomaly_confidence, transporter_slashed, finalized_at,
          event_id, transporter_id, storacha_cid } = selectedEvent;

  const alignedCount  = (auditorResults ?? []).filter((r) => r.outcome === "aligned").length;
  const totalPaid     = (auditorResults ?? []).reduce((s, r) => s + r.totalReceived, 0);

  return (
    <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}>
      <div className="panel-header">
        <div className="indicator ind-green" />
        <span className="panel-title">Settlement Receipt · Flow</span>
        <span style={{ fontFamily: "DM Mono", fontSize: 9, color: "#4a6080" }}>
          {fmtTime(finalized_at)}
        </span>
      </div>

      <div className="panel-body">
        <div className="receipt">

          {/* Verdict + cswarm */}
          <div className="receipt-header">
            <div>
              <div className={`receipt-verdict-big verdict-${drop ? "DROP" : "NORMAL"}`}>
                {drop ? "DROP CONFIRMED" : "NO ANOMALY"}
              </div>
              <div style={{ fontFamily: "DM Mono", fontSize: 9, color: "#4a6080", marginTop: 2 }}>
                {getNodeAlias(transporter_id, "Transporter")}
                {transporter_slashed && <span style={{ color: "#ff3a5c", marginLeft: 8 }}>⚡ SLASHED</span>}
              </div>
            </div>
            <div style={{ flex: 1 }}>
              <div style={{ display: "flex", justifyContent: "space-between", fontSize: 8, color: "#4a6080", fontFamily: "Orbitron", letterSpacing: "0.1em" }}>
                <span>C_SWARM</span>
                <span style={{ color: "#4fc3f7" }}>{(cswarm * 100).toFixed(2)}%</span>
              </div>
              <div className="cswarm-bar-bg">
                <div className="cswarm-bar-fill" style={{ width: `${cswarm * 100}%`, background: "linear-gradient(90deg,#1a4a6b,#4fc3f7)" }} />
              </div>
              <div style={{ display: "flex", gap: 12, marginTop: 5, fontSize: 9, color: "#4a6080" }}>
                <span>Drop <span style={{ color: "#c8d8f0" }}>{drop_votes}/{total_votes}</span></span>
                <span>Conf <span style={{ color: "#c8d8f0" }}>{(anomaly_confidence * 100).toFixed(1)}%</span></span>
                <span>Aligned <span style={{ color: "#c8d8f0" }}>{alignedCount}/{total_votes}</span></span>
                <span>Paid <span style={{ color: "#c8d8f0" }}><AnimatedNumber value={totalPaid || 0} decimals={3} /> ◎</span></span>
              </div>
            </div>
          </div>

          {/* Per-auditor results */}
          {auditorResults === null ? (
            <div style={{ fontSize: 9, color: "#4a6080", fontFamily: "DM Mono" }}>FETCHING AUDITOR RESULTS…</div>
          ) : auditorResults.length === 0 ? (
            <div style={{ fontSize: 9, color: "#4a6080", fontFamily: "DM Mono" }}>NO AUDITOR DATA ON-CHAIN</div>
          ) : (
            <div>
              <div className="section-title" style={{ marginBottom: 6 }}>AUDITOR BREAKDOWN</div>
              {auditorResults.map((r) => <AuditorResultRow key={r.auditorId} r={r} />)}
            </div>
          )}

          {/* Storacha CID */}
          {storacha_cid && storacha_cid !== "" && (
            <CopyField label="STORACHA CID" value={storacha_cid} />
          )}

          {/* Event ID */}
          <CopyField label="EVENT ID (submissionSig)" value={event_id} />

        </div>
      </div>
    </div>
  );
}
