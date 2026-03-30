import { useState, useEffect, useRef } from "react";
import { shortKey, clamp, getNodeAlias } from "../utils.js";

function TransporterSelector({ agents, transporterIds, selected, onSelect }) {
  const tSet         = new Set(transporterIds);
  const transporters = agents.filter((a) => tSet.has(a.id));

  return (
    <div className="node-selector">
      <div style={{ fontFamily: "Orbitron", fontSize: 8, letterSpacing: "0.12em", color: "#4a6080", marginBottom: 2 }}>
        SELECT TRANSPORTER
      </div>
      <div className="node-list">
        <div className={`node-item ${!selected ? "selected" : ""}`} onClick={() => onSelect(null)}>
          <span className="node-role role-transporter" style={{ padding: "2px 5px" }}>ALL</span>
          <span style={{ fontFamily: "DM Mono", fontSize: 9, color: "#4a6080", flex: 1 }}>All events</span>
          <span style={{ fontFamily: "DM Mono", fontSize: 9, color: "#1a2540" }}>{transporters.length} nodes</span>
        </div>
        {transporters.map((a) => (
          <div
            key={a.id}
            className={`node-item ${selected === a.id ? "selected" : ""} ${a.isBlacklisted ? "blacklisted" : ""}`}
            onClick={() => onSelect(a.id)}
          >
            <span className="node-role role-transporter">T</span>
            <span style={{ fontFamily: "DM Mono", fontSize: 9, color: selected === a.id ? "#f5a623" : "#c8d8f0", flex: 1 }}>
              {getNodeAlias(a.id, "Transporter")}
            </span>
            <span style={{ fontFamily: "DM Mono", fontSize: 9, color: a.reputation >= 0 ? "#39ff84" : "#f5a623" }}>
              {a.reputation >= 0 ? "+" : ""}{a.reputation.toFixed(1)}R
            </span>
          </div>
        ))}
        {transporterIds.length === 0 && (
          <div style={{ fontFamily: "DM Mono", fontSize: 9, color: "#1a2540", padding: "4px 0" }}>
            No transporter events on-chain yet
          </div>
        )}
      </div>
    </div>
  );
}

function TopologyCanvas({ agents, selectedTransporter, transporterIds, activeQuorumIds }) {
  const svgRef = useRef(null);
  const [size, setSize] = useState({ w: 280, h: 200 });

  useEffect(() => {
    const el = svgRef.current?.parentElement;
    if (!el) return;
    const ro = new ResizeObserver(([e]) =>
      setSize({ w: e.contentRect.width, h: e.contentRect.height })
    );
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  const { w, h } = size;
  const cx       = w / 2;
  const cy       = h / 2;
  const tSet     = new Set(transporterIds);
  const auditors = agents.filter((a) => !tSet.has(a.id));
  const r        = Math.min(w, h) * 0.36;
  const selAgent = agents.find((a) => a.id === selectedTransporter);

  return (
    <svg ref={svgRef} className="topo-canvas" style={{ position: "absolute", inset: 0 }}>
      <defs>
        <radialGradient id="tglow" cx="50%" cy="50%">
          <stop offset="0%"   stopColor="#f5a623" stopOpacity="0.35" />
          <stop offset="100%" stopColor="#f5a623" stopOpacity="0" />
        </radialGradient>
      </defs>

      {/* Transporter hub */}
      <circle cx={cx} cy={cy} r={30} fill="url(#tglow)" />
      <circle cx={cx} cy={cy} r={18} fill="#0b0f1a" stroke="#f5a623" strokeWidth="1.5" />
      <text x={cx} y={cy - 4} textAnchor="middle" dominantBaseline="middle"
        fill="#f5a623" fontSize="12" fontFamily="Orbitron">
        {selectedTransporter ? getNodeAlias(selectedTransporter, "Transporter").split('-')[1] : "ALL"}
      </text>
      <text x={cx} y={cy + 6} textAnchor="middle" dominantBaseline="middle"
        fill="#8a5e13" fontSize="6" fontFamily="Share Tech Mono">
        {selectedTransporter
          ? selAgent ? `${selAgent.reputation >= 0 ? "+" : ""}${selAgent.reputation.toFixed(0)}R` : "T"
          : `${transporterIds.length} T`}
      </text>

      {/* Auditor nodes */}
      {auditors.map((a, i) => {
        const angle  = (i / Math.max(auditors.length, 1)) * Math.PI * 2 - Math.PI / 2;
        const nx     = cx + r * Math.cos(angle);
        const ny     = cy + r * Math.sin(angle);
        const inLive = activeQuorumIds.has(a.id);
        const color  = a.isBlacklisted ? "#ff3a5c" : inLive ? "#f5a623" : a.reputation >= 0 ? "#39ff84" : "#f5a623";
        const radius = inLive ? 11 : 9;
        const acc    = a.totalAudits > 0 ? Math.round((a.correctAudits / a.totalAudits) * 100) : null;
        const alias = getNodeAlias(a.id, "Auditor");
        const shortName = alias.split('-')[1];

        return (
          <g key={a.id}>
            <line x1={cx} y1={cy} x2={nx} y2={ny}
              stroke={color} strokeWidth={inLive ? 1 : 0.4}
              strokeDasharray={inLive ? "none" : "3 3"}
              opacity={inLive ? 0.7 : 0.2} />
            {inLive && (
              <circle cx={nx} cy={ny} r={radius + 5}
                fill="none" stroke={color} strokeWidth="0.5" opacity="0.35" />
            )}
            <circle cx={nx} cy={ny} r={radius}
              fill="#0b0f1a" stroke={color} strokeWidth={inLive ? 2 : 1.5} />
            <text x={nx} y={ny + 1} textAnchor="middle" dominantBaseline="middle"
              fill={color} fontSize="9" fontFamily="Share Tech Mono">
              {shortName}
            </text>
            {/* Accuracy below node */}
            {acc !== null && (
              <text x={nx} y={ny + radius + 8} textAnchor="middle"
                fill={acc >= 80 ? "#1a6b3a" : acc >= 50 ? "#8a5e13" : "#661525"} fontSize="6" fontFamily="DM Mono">
                {acc}%
              </text>
            )}
            {/* Reputation delta ring color */}
            <text x={nx} y={ny + radius + (acc !== null ? 17 : 8)} textAnchor="middle"
              fill={a.reputation >= 0 ? "#1a6b3a" : "#8a5e13"} fontSize="6" fontFamily="DM Mono">
              {a.reputation >= 0 ? "+" : ""}{a.reputation.toFixed(0)}R
            </text>
          </g>
        );
      })}

      {auditors.length === 0 && (
        <text x={cx} y={cy + 46} textAnchor="middle"
          fill="#1a2540" fontSize="9" fontFamily="Share Tech Mono" letterSpacing="0.1em">
          {agents.length > 0 ? "NO AUDITORS YET" : "AWAITING CHAIN DATA"}
        </text>
      )}
    </svg>
  );
}

export default function NetworkTopology({
  agents,
  events,
  transporterIds,
  selectedTransporter,
  onSelectTransporter,
  activeQuorumIds,
  lastOk,
  error,
}) {
  return (
    <div className="panel net-panel">
      <div className="panel-header">
        <div className={`indicator ${error ? "ind-red" : lastOk ? "ind-green" : "ind-dim"}`} />
        <span className="panel-title">Swarm Network · Flow</span>
        <span style={{ fontFamily: "DM Mono", fontSize: 9, color: "#4a6080" }}>{agents.length} nodes</span>
      </div>
      <div className="panel-body" style={{ display: "flex", flexDirection: "column" }}>
        <TransporterSelector
          agents={agents}
          transporterIds={transporterIds}
          selected={selectedTransporter}
          onSelect={onSelectTransporter}
        />
        <div style={{ flex: 1, position: "relative" }}>
          <TopologyCanvas
            agents={agents}
            selectedTransporter={selectedTransporter}
            transporterIds={transporterIds}
            activeQuorumIds={activeQuorumIds}
          />
        </div>
      </div>
    </div>
  );
}
