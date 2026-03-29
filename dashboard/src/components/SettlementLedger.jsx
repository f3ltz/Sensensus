import { useState, useMemo } from "react";
import { shortKey, fmtTime } from "../utils.js";

function SettledCard({ event, selected, onClick }) {
  const { consensus_verdict: drop, cswarm, drop_votes, total_votes,
          anomaly_confidence, transporter_slashed, finalized_at, event_id } = event;
  return (
    <div className={`settled-card ${selected ? "selected" : ""}`} onClick={onClick}>
      <div className="settled-card-top">
        <span className={`settled-verdict verdict-${drop ? "DROP" : "NORMAL"}`}>
          {drop ? "● DROP" : "● NORMAL"}
        </span>
        <span className="settled-id">{shortKey(event_id)}</span>
        {transporter_slashed && (
          <span style={{ fontFamily: "Orbitron", fontSize: 8, color: "#ff3a5c" }}>⚡</span>
        )}
        <span className="settled-time">{fmtTime(finalized_at)}</span>
      </div>
      <div className="settled-card-stats">
        <span>Cswarm <span>{(cswarm * 100).toFixed(1)}%</span></span>
        <span>Drop <span>{drop_votes}/{total_votes}</span></span>
        <span>Conf <span>{(anomaly_confidence * 100).toFixed(1)}%</span></span>
      </div>
    </div>
  );
}

export default function SettlementLedger({
  events,
  selectedTransporter,
  selectedEvent,
  onSelectEvent,
  lastOk,
  error,
}) {
  const [filter, setFilter] = useState("all");   // "all" | "drop" | "normal"
  const [search, setSearch] = useState("");

  const filtered = useMemo(() => {
    let list = selectedTransporter
      ? events.filter((e) => e.transporter_id === selectedTransporter)
      : events;

    if (filter === "drop")   list = list.filter((e) => e.consensus_verdict);
    if (filter === "normal") list = list.filter((e) => !e.consensus_verdict);

    if (search.trim()) {
      const q = search.trim().toLowerCase();
      list = list.filter(
        (e) =>
          e.event_id.toLowerCase().includes(q) ||
          e.transporter_id.toLowerCase().includes(q)
      );
    }

    return list;
  }, [events, selectedTransporter, filter, search]);

  const flowIndicator = error ? "ind-red" : lastOk ? "ind-green" : "ind-dim";

  return (
    <div className="panel">
      <div className="panel-header">
        <div className={`indicator ${flowIndicator}`} />
        <span className="panel-title">Settlement Ledger · Flow</span>
        <span style={{ fontFamily: "DM Mono", fontSize: 9, color: "#4a6080" }}>
          {filtered.length}/{events.length}
        </span>
      </div>

      {/* Filter toolbar */}
      <div className="ledger-toolbar">
        {[["all", "ALL"], ["drop", "DROP"], ["normal", "NORMAL"]].map(([val, label]) => (
          <button
            key={val}
            className={`filter-btn ${filter === val ? `active-${val}` : ""}`}
            onClick={() => setFilter(val)}
          >
            {label}
          </button>
        ))}
        <input
          className="search-input"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search event ID or transporter…"
        />
        {search && (
          <button className="btn small" onClick={() => setSearch("")}>✕</button>
        )}
      </div>

      <div className="panel-body" style={{ display: "flex", flexDirection: "column" }}>
        {filtered.length === 0 ? (
          <div className="no-data">
            <div className="empty-glyph">⬡</div>
            {error ? (
              <span style={{ color: "#ff3a5c", fontSize: 9, padding: "0 16px", textAlign: "center" }}>
                {error}
              </span>
            ) : (
              <span>{lastOk ? "NO MATCHING EVENTS" : "FETCHING FROM FLOW…"}</span>
            )}
          </div>
        ) : (
          <div className="settled-list">
            {filtered.map((ev) => (
              <SettledCard
                key={ev.event_id}
                event={ev}
                selected={selectedEvent?.event_id === ev.event_id}
                onClick={() => onSelectEvent(ev)}
              />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}