import { useState, useEffect } from "react";
import { shortKey, fmtDuration, getNodeAlias } from "../utils.js";

const PHASES = ["REGISTER", "DEPOSIT", "VERDICTS", "FINALIZE"];

function PhaseTracker({ depositCount, verdictCount, quorumSize }) {
  // Which phase are we in?
  // 0 = waiting for registerAnomaly (no quorum yet)
  // 1 = waiting for deposits (quorum exists, deposits < quorum)
  // 2 = waiting for verdicts (deposits done, verdicts < quorum)
  // 3 = ready to finalize
  let active = 0;
  if (quorumSize > 0) active = 1;
  if (depositCount >= quorumSize && quorumSize > 0) active = 2;
  if (verdictCount >= quorumSize && quorumSize > 0) active = 3;

  return (
    <div className="phase-track" style={{ paddingBottom: 20 }}>
      {PHASES.map((label, i) => {
        const state = i < active ? "done" : i === active ? "active" : "pending";
        return (
          <div key={label} style={{ display: "flex", alignItems: "center", flex: 1 }}>
            <div style={{ display: "flex", flexDirection: "column", alignItems: "center" }}>
              <div className={`phase-dot ${state}`}>{i + 1}</div>
              <div className={`phase-label ${state}`}>{label}</div>
            </div>
            {i < PHASES.length - 1 && (
              <div className={`phase-line ${state === "done" ? "done" : ""}`} style={{ flex: 1 }} />
            )}
          </div>
        );
      })}
    </div>
  );
}

function ElapsedTimer({ registeredAt }) {
  const [elapsed, setElapsed] = useState(0);
  useEffect(() => {
    if (!registeredAt) return;
    const update = () => setElapsed(Date.now() / 1000 - registeredAt);
    update();
    const iv = setInterval(update, 1000);
    return () => clearInterval(iv);
  }, [registeredAt]);

  const color = elapsed > 50 ? "#ff3a5c" : elapsed > 30 ? "#f5a623" : "#39ff84";
  return (
    <span className="elapsed-badge" style={{ color }}>
      {fmtDuration(elapsed)}
    </span>
  );
}

function VerdictRow({ auditorId, data }) {
  const { verdict, confidence, hasDeposit, silent } = data;
  return (
    <div className="verdict-row" style={{ opacity: silent ? 0.5 : 1 }}>
      {/* Deposit status */}
      <div className={`verdict-badge ${hasDeposit ? "badge-deposit-paid" : "badge-deposit-unpaid"}`}
        title={hasDeposit ? "Deposit locked on-chain" : "Deposit not yet recorded"}>
        {hasDeposit ? "DEP✓" : "DEP?"}
      </div>

      {/* Verdict */}
      {silent ? (
        <div className="verdict-badge badge-silent">WAIT</div>
      ) : (
        <div className={`verdict-badge ${verdict ? "badge-drop" : "badge-normal"}`}>
          {verdict ? "DROP" : "NORM"}
        </div>
      )}

      <span style={{ fontFamily: "DM Mono", fontSize: 9, color: "#4a6080", flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
        {getNodeAlias(auditorId, "Auditor")}
      </span>

      {silent ? (
        <span style={{ fontFamily: "DM Mono", fontSize: 9, color: "#4a6080" }}>pending</span>
      ) : (
        <span style={{ fontFamily: "DM Mono", fontSize: 10, color: "#c8d8f0", flexShrink: 0 }}>
          {(confidence * 100).toFixed(1)}%
        </span>
      )}
    </div>
  );
}

export default function PendingEventPanel({ pendingMeta, pendingVerdicts, selectedTransporter }) {
  const visible = (selectedTransporter
  ? pendingMeta.filter((m) => m.transporterId === selectedTransporter)
  : pendingMeta
	).sort((a, b) => b.registeredAt - a.registeredAt);  // ← newest first

  // Show the most recently registered pending event
  const [selectedIdx, setSelectedIdx] = useState(0);
  useEffect(() => setSelectedIdx(0), [visible.length]);

  const active = visible[selectedIdx] ?? null;

  if (!active) {
    return (
      <div className="panel">
        <div className="panel-header">
          <div className="indicator ind-dim" />
          <span className="panel-title">Live Pending Event · Flow</span>
        </div>
        <div className="panel-body">
          <div className="no-data">
            <div className="empty-glyph">◎</div>
            <span>NO PENDING EVENTS ON-CHAIN</span>
          </div>
        </div>
      </div>
    );
  }

  const verdictMap = pendingVerdicts[active.eventId] || {};
  const verdictCount  = Object.values(verdictMap).filter((v) => !v.silent).length;
  const depositCount  = Object.values(verdictMap).filter((v) => v.hasDeposit).length;

  return (
    <div className="panel">
      <div className="panel-header">
        <div className="indicator ind-amber" />
        <span className="panel-title">Live Pending Event · Flow</span>
        {/* Event selector if multiple pending */}
        {visible.length > 1 && (
          <div style={{ display: "flex", gap: 3 }}>
            {visible.map((_, i) => (
              <button key={i} className={`btn small ${i === selectedIdx ? "active" : ""}`}
                onClick={() => setSelectedIdx(i)}>
                {i + 1}
              </button>
            ))}
          </div>
        )}
        <span style={{ fontFamily: "DM Mono", fontSize: 9, color: "#8a5e13" }}>
          {verdictCount}/{active.quorumSize} verdicts
        </span>
      </div>

      <div className="panel-body">
        <div className="event-panel-body">

          {/* Phase tracker */}
          <PhaseTracker
            depositCount={depositCount}
            verdictCount={verdictCount}
            quorumSize={active.quorumSize}
          />

          {/* Key metrics */}
          <div className="kv-grid">
            <div className="kv-row">
              <span className="kv-key">Event ID</span>
              <span className="kv-val" style={{ fontSize: 9, fontFamily: "DM Mono", color: "#4a6080" }}>
                {shortKey(active.eventId)}
              </span>
            </div>
            <div className="kv-row">
              <span className="kv-key">Elapsed</span>
              <ElapsedTimer registeredAt={active.registeredAt} />
            </div>
            <div className="kv-row">
              <span className="kv-key">Quorum Size</span>
              <span className="kv-val">{active.quorumSize}</span>
            </div>
            <div className="kv-row">
              <span className="kv-key">Deposits</span>
              <span className={`kv-val ${depositCount >= active.quorumSize ? "green" : "highlight"}`}>
                {depositCount} / {active.quorumSize}
              </span>
            </div>
            <div className="kv-row">
              <span className="kv-key">Verdicts In</span>
              <span className={`kv-val ${verdictCount >= active.quorumSize ? "green" : "highlight"}`}>
                {verdictCount} / {active.quorumSize}
              </span>
            </div>
            <div className="kv-row">
              <span className="kv-key">Pending Total</span>
              <span className="kv-val" style={{ color: "#f5a623" }}>{pendingMeta.length}</span>
            </div>
          </div>

          {/* Per-auditor status */}
          {Object.keys(verdictMap).length > 0 && (
            <>
              <div className="section-title">QUORUM STATUS</div>
              <div className="verdict-list">
                {Object.entries(verdictMap).map(([pub, data]) => (
                  <VerdictRow key={pub} auditorId={pub} data={data} />
                ))}
              </div>
            </>
          )}

        </div>
      </div>
    </div>
  );
}