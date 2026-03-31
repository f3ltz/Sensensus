import { useState, useMemo } from "react";
import { clamp, shortKey, copyToClipboard, getNodeAlias } from "../utils.js";

const SORT_OPTIONS = [
  { key: "reputation", label: "REP" },
  { key: "stake",      label: "STAKE" },
  { key: "accuracy",   label: "ACC%" },
  { key: "audits",     label: "AUDITS" },
];


function AgentDrawer({ agent, transporterIds }) {
  const [copied, setCopied] = useState(false);
  const isAuditor = !new Set(transporterIds).has(agent.id);
  const acc = agent.totalAudits > 0
    ? Math.round((agent.correctAudits / agent.totalAudits) * 100)
    : null;

  const handleCopy = async () => {
    await copyToClipboard(agent.id);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };
  

  return (
    <div className="agent-drawer">
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 6 }}>
        <span style={{ fontFamily: "Orbitron", fontSize: 8, color: "#4a6080", letterSpacing: "0.12em" }}>
          {isAuditor ? "AUDITOR" : "TRANSPORTER"} · FULL PUBKEY
        </span>
        <button className="btn small" onClick={handleCopy}>
          {copied ? "✓ COPIED" : "COPY"}
        </button>
      </div>
      <div className="agent-drawer-pubkey">
        <strong style={{ color: "#c8d8f0", fontSize: "10px" }}>
          {getNodeAlias(agent.id, isAuditor ? "Auditor" : "Transporter")}
        </strong>
        <br />
        <span style={{ opacity: 0.6 }}>{agent.id}</span>
      </div>
      <div className="agent-drawer-stats">
        <div className="agent-stat">
          <span className="agent-stat-label">REPUTATION</span>
          <span className="agent-stat-value" style={{ color: agent.reputation >= 0 ? "#39ff84" : "#f5a623" }}>
            {agent.reputation >= 0 ? "+" : ""}{agent.reputation.toFixed(2)}
          </span>
        </div>
        <div className="agent-stat">
          <span className="agent-stat-label">STAKE (◎)</span>
          <span className="agent-stat-value">{agent.stake.toFixed(2)}</span>
        </div>
        <div className="agent-stat">
          <span className="agent-stat-label">ESCROW (◎)</span>
          <span className="agent-stat-value" style={{ color: agent.escrow > 0 ? "#f5a623" : undefined }}>
            {agent.escrow.toFixed(2)}
          </span>
        </div>
        {isAuditor && (
          <>
            <div className="agent-stat">
              <span className="agent-stat-label">AUDITS</span>
              <span className="agent-stat-value">{agent.totalAudits}</span>
            </div>
            <div className="agent-stat">
              <span className="agent-stat-label">CORRECT</span>
              <span className="agent-stat-value">{agent.correctAudits}</span>
            </div>
            <div className="agent-stat">
              <span className="agent-stat-label">ACCURACY</span>
              <span className="agent-stat-value" style={{
                color: acc === null ? "#4a6080" : acc >= 80 ? "#39ff84" : acc >= 50 ? "#f5a623" : "#ff3a5c"
              }}>
                {acc !== null ? `${acc}%` : "—"}
              </span>
            </div>
          </>
        )}
      </div>
    </div>
  );
}

export default function ReputationPanel({ agents, transporterIds, highlightedIds, recentDeltas, lastOk, error }) {
  const [sortKey,    setSortKey]    = useState("reputation");
  const [expandedId, setExpandedId] = useState(null);

  const sorted = useMemo(() => {
    const tSet = new Set(transporterIds);
    return [...agents].sort((a, b) => {
      const aHigh = highlightedIds?.has(a.id) ? 1 : 0;
      const bHigh = highlightedIds?.has(b.id) ? 1 : 0;
      if (aHigh !== bHigh) return bHigh - aHigh;

      if (sortKey === "reputation") return b.reputation - a.reputation;
      if (sortKey === "stake")      return b.stake - a.stake;
      if (sortKey === "audits")     return b.totalAudits - a.totalAudits;
      if (sortKey === "accuracy") {
        const accA = a.totalAudits > 0 ? a.correctAudits / a.totalAudits : -1;
        const accB = b.totalAudits > 0 ? b.correctAudits / b.totalAudits : -1;
        return accB - accA;
      }
      return 0;
    });
  }, [agents, sortKey, transporterIds, highlightedIds]);

  const tSet          = new Set(transporterIds);
  const flowIndicator = error ? "ind-red" : lastOk ? "ind-green" : "ind-dim";
  const expandedAgent = agents.find((a) => a.id === expandedId) ?? null;

  return (
    <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden", borderBottom: "1px solid var(--border)" }}>
      <div className="panel-header">
        <div className={`indicator ${flowIndicator}`} />
        <span className="panel-title">Reputation Ledger · Flow</span>
        <span style={{ fontFamily: "DM Mono", fontSize: 9, color: "#4a6080" }}>α=10  β=5</span>
      </div>

      {/* Sort controls */}
      <div className="rep-toolbar">
        <span style={{ fontFamily: "Orbitron", fontSize: 7, color: "#4a6080", letterSpacing: "0.1em" }}>SORT</span>
        {SORT_OPTIONS.map(({ key, label }) => (
          <button
            key={key}
            className={`btn small ${sortKey === key ? "active" : ""}`}
            onClick={() => setSortKey(key)}
          >
            {label}
          </button>
        ))}
      </div>

      {/* Column headers */}
      
<div style={{ display: "flex", gap: 8, padding: "2px 8px 4px 12px", borderBottom: "1px solid var(--border)", flexShrink: 0 }}>
  <span style={{ fontFamily: "Orbitron", fontSize: 7, color: "#4a6080", letterSpacing: "0.1em", flex: 1 }}>NODE ID</span>
  <span style={{ fontFamily: "Orbitron", fontSize: 7, color: "#4a6080", letterSpacing: "0.1em", width: 60, textAlign: "right" }}>REP</span>
  <span style={{ fontFamily: "Orbitron", fontSize: 7, color: "#4a6080", letterSpacing: "0.1em", width: 56, textAlign: "right" }}>STAKE◎</span>
  <span style={{ fontFamily: "Orbitron", fontSize: 7, color: "#4a6080", letterSpacing: "0.1em", width: 52, textAlign: "right" }}>ESC◎</span>
  <span style={{ fontFamily: "Orbitron", fontSize: 7, color: "#4a6080", letterSpacing: "0.1em", width: 36, textAlign: "right" }}>ACC</span>
</div>

      {agents.length === 0 ? (
        <div className="no-data" style={{ flex: 1 }}>
          <span>{error ? `Error: ${error.slice(0, 80)}` : lastOk ? "NO AGENTS REGISTERED" : "FETCHING…"}</span>
        </div>
      ) : (
        <div className="rep-list">
          {sorted.map((a) => {
            const isAuditor = !tSet.has(a.id);
            const rep       = a.reputation ?? 0;
            const repClass  = a.isBlacklisted ? "blacklisted" : rep < 0 ? "warning" : "healthy";
            const repColor  = a.isBlacklisted ? "#ff3a5c" : rep < 0 ? "#f5a623" : "#39ff84";
            const barW      = clamp((rep + 100) / 200 * 100, 0, 100);
            const acc       = a.totalAudits > 0 ? Math.round((a.correctAudits / a.totalAudits) * 100) : null;
            const isExpanded = expandedId === a.id;
            const role = isAuditor ? "Auditor" : "Transporter";
            const alias = getNodeAlias(a.id, role);
            const isHighlighted = highlightedIds?.has(a.id);
            const delta = recentDeltas?.[a.id];

            return (
              <div
                key={a.id}
                className={`rep-row ${repClass} ${isHighlighted ? "flash-highlight" : ""}`}
                onClick={() => setExpandedId(isExpanded ? null : a.id)}
                title="Click to expand"
              >
                <div className="rep-pubkey" title={`Full ID: ${a.id}`} style={{ display: 'flex', flexDirection: 'column' }}>
                  <span style={{ color: "var(--text)", fontSize: "10px" }}>{alias}</span>
                  <span style={{ fontSize: "7px", opacity: 0.5 }}>{shortKey(a.id, 5, 4)}</span>
                </div>

                <div className="rep-bar-container" style={{ position: "relative" }}>

                  {/* THE FLOATING DELTA ANIMATION */}
                  {delta !== undefined && delta !== 0 && (
                    <span className={`delta-float ${delta > 0 ? "positive" : "negative"}`}>
                      {delta > 0 ? "+" : ""}{delta.toFixed(2)}{delta > 0 ? " ▲" : " ▼"}
                    </span>
                  )}

                  <span className="rep-val" style={{ color: repColor }}>
                    {rep >= 0 ? "+" : ""}{rep.toFixed(1)}
                  </span>
                  <div className="rep-bar-bg">
                    <div className="rep-bar-fill" style={{ width: `${barW}%`, background: repColor }} />
                  </div>
                </div>

                <span className="rep-stake">{(a.stake ?? 0).toFixed(1)}</span>

                <span className="rep-escrow" title="Locked escrow">
                  {(a.escrow ?? 0) > 0 ? (a.escrow).toFixed(2) : "—"}
                </span>

                <span className="rep-acc" style={{
                  color: !isAuditor ? "#1a2540" : acc === null ? "#4a6080" : acc >= 80 ? "#39ff84" : acc >= 50 ? "#f5a623" : "#ff3a5c"
                }}>
                  {isAuditor ? (acc !== null ? `${acc}%` : "—") : "T"}
                </span>
              </div>
            );
          })}
        </div>
      )}

      {/* Agent detail drawer */}
      {expandedAgent && (
        <AgentDrawer agent={expandedAgent} transporterIds={transporterIds} />
      )}
    </div>
  );
}