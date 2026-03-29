import { computeStats, shortKey } from "../utils.js";

function Stat({ label, value, color }) {
  return (
    <div className="topbar-stat">
      <div className="topbar-stat-label">{label}</div>
      <div className="topbar-stat-value" style={color ? { color } : undefined}>{value}</div>
    </div>
  );
}

export default function TopBar({
  agents,
  events,
  pendingCount,
  hasPending,
  selectedTransporter,
  loading,
  lastOk,
  error,
  flowAddr,
  onFlowAddrChange,
  intervalMs,
  onIntervalChange,
  onRefresh,
  showConfig,
  onToggleConfig,
}) {
  const stats = computeStats(events);

  const flowStatus = error ? "ind-red" : lastOk ? "ind-green" : "ind-dim";
  const sysState   = hasPending ? "PENDING" : "IDLE";

  return (
    <div className="topbar">
      <div className="logo">SWARM<span>VERIFIER</span></div>
      <div className="topbar-divider" />

      {/* System state */}
      <div className="sys-status">
        <div className={`status-dot status-${hasPending ? "PENDING" : "IDLE"}`} />
        <span style={{ color: hasPending ? "#f5a623" : "#4a6080" }}>{sysState}</span>
      </div>
      <div className="topbar-divider" />

      {/* Chain stats */}
      <Stat label="AGENTS"   value={agents.length} />
      <Stat label="EVENTS"   value={events.length} />
      <Stat label="PENDING"  value={pendingCount} color={pendingCount > 0 ? "#f5a623" : undefined} />
      <div className="topbar-divider" />

      {/* Derived stats */}
      <Stat label="DROP RATE"   value={events.length ? `${stats.dropRate.toFixed(0)}%` : "—"} color={stats.dropRate > 50 ? "#ff3a5c" : "#4fc3f7"} />
      <Stat label="AVG CSWARM" value={events.length ? `${stats.avgCswarm.toFixed(1)}%` : "—"} />
      <Stat label="SLASHES"    value={stats.slashCount} color={stats.slashCount > 0 ? "#ff3a5c" : undefined} />
      <div className="topbar-divider" />

      {selectedTransporter && (
        <>
          <Stat label="WATCHING" value={shortKey(selectedTransporter)} color="#f5a623" />
          <div className="topbar-divider" />
        </>
      )}

      <div style={{ flex: 1 }} />

      {/* Flow connection */}
      <div style={{ display: "flex", alignItems: "center", gap: 5 }}>
        <div className={`indicator ${flowStatus}`} />
        <span style={{ fontFamily: "DM Mono", fontSize: 9, color: "#4a6080" }}>
          {loading ? "SYNCING…" : lastOk ? new Date(lastOk).toLocaleTimeString("en-US", { hour12: false }) : "FLOW"}
        </span>
      </div>
      <div className="topbar-divider" />

      <button className={`btn ${loading ? "active" : ""}`} onClick={onRefresh} disabled={loading}>
        ⟳ REFRESH
      </button>
      <button className={`btn ${showConfig ? "active" : ""}`} onClick={onToggleConfig}>⚙</button>

      {/* Config drawer (rendered here so it sits just below topbar) */}
      {showConfig && (
        <div className="config-drawer">
          <span className="config-label">CONTRACT</span>
          <input
            className="config-input"
            value={flowAddr}
            onChange={(e) => onFlowAddrChange(e.target.value)}
            placeholder="0xfcd23c8d1553708a"
          />
          <span className="config-label">POLL</span>
          <select
            className="config-select"
            value={intervalMs}
            onChange={(e) => onIntervalChange(Number(e.target.value))}
          >
            <option value={5000}>5 s</option>
            <option value={8000}>8 s</option>
            <option value={15000}>15 s</option>
            <option value={30000}>30 s</option>
          </select>
          {error && <span className="error-text">Error: {error}</span>}
        </div>
      )}
    </div>
  );
}