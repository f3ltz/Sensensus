import { useState, useEffect } from "react";
import { injectFonts, injectStyles } from "./styles.js";
import { useFlowData } from "./hooks/useFlowData.js";
import TopBar           from "./components/TopBar.jsx";
import NetworkTopology  from "./components/NetworkTopology.jsx";
import SerialImuPanel   from "./components/SerialImuPanel.jsx";
import PendingEventPanel from "./components/PendingEventPanel.jsx";
import SettlementLedger from "./components/SettlementLedger.jsx";
import ReputationPanel  from "./components/ReputationPanel.jsx";
import ReceiptPanel     from "./components/ReceiptPanel.jsx";

injectFonts();
injectStyles();

const DEFAULT_ADDR = "0xfcd23c8d1553708a";

export default function App() {
  const [flowAddr,    setFlowAddr]    = useState(DEFAULT_ADDR);
  const [intervalMs,  setIntervalMs]  = useState(8000);
  const [showConfig,  setShowConfig]  = useState(false);
  const [refreshKey,  setRefreshKey]  = useState(0);

  const [selectedTransporter, setSelectedTransporter] = useState(null);
  const [selectedEvent,       setSelectedEvent]       = useState(null);

  const {
    agents, events, pendingMeta, pendingVerdicts,
    transporterIds, auditorCache, fetchAuditorResults,
    error, lastOk, loading,
  } = useFlowData(flowAddr, refreshKey, intervalMs);

  // Auto-select first event when filter changes
  const filteredEvents = selectedTransporter
    ? events.filter((e) => e.transporter_id === selectedTransporter)
    : events;

  useEffect(() => {
    if (
      filteredEvents.length > 0 &&
      (!selectedEvent || !filteredEvents.find((e) => e.event_id === selectedEvent.event_id))
    ) {
      setSelectedEvent(filteredEvents[0]);
    }
  }, [filteredEvents.length, selectedTransporter]);

  // Lazy-load auditor results when a settled event is selected
  useEffect(() => {
    if (selectedEvent) fetchAuditorResults(selectedEvent.event_id);
  }, [selectedEvent?.event_id]);

  // Which auditors are active in a quorum right now (for topology)
  // Which auditors are active in a quorum right now (for topology)
  const activeQuorumIds = new Set();
  const streamingQuorumIds = new Set();

  pendingMeta.forEach((m) => {
    // If a transporter is selected globally, filter out other transporters' events
    if (selectedTransporter && m.transporterId !== selectedTransporter) return;

    const vMap = pendingVerdicts[m.eventId] ?? {};
    const qIds = Object.keys(vMap);
    
    // 1. Highlight them as part of an active pending event
    qIds.forEach((id) => activeQuorumIds.add(id));

    const depositCount = Object.values(vMap).filter((v) => v.hasDeposit).length;
    const verdictCount = Object.values(vMap).filter((v) => !v.silent).length;

 
    // 2. Only trigger Data Packets during the VERDICTS phase 
    // (Deposits >= Quorum, but Verdicts < Quorum)
    if (m.quorumSize > 0 && depositCount >= m.quorumSize && verdictCount < m.quorumSize) {
      qIds.forEach((id) => {
        // Only stream data to auditors who haven't locked in a verdict yet
        if (vMap[id]?.silent !== false) {
          streamingQuorumIds.add(id);
        }
      });
    }
  });

  const hasPending = pendingMeta.length > 0;

  const selectedAuditorResults = selectedEvent
    ? (auditorCache[selectedEvent.event_id] ?? null)
    : null;

  // --- SPOTLIGHT NEW EVENTS ---
  const latestEvent = events[0] ?? null;
  // If the event finished in the last 15 seconds, flag it as "Recent"
  const isLatestRecent = latestEvent && (Date.now() / 1000 - latestEvent.finalized_at < 15);

  // Auto-fetch results for the recent event so we can show the floating deltas
  useEffect(() => {
    if (isLatestRecent) fetchAuditorResults(latestEvent.event_id);
  }, [latestEvent?.event_id, isLatestRecent]);

  // Extract the specific nodes involved and their reputation changes
  const latestResults = isLatestRecent ? (auditorCache[latestEvent.event_id] || []) : [];
  const highlightedIds = new Set();
  const recentDeltas = {};

  if (isLatestRecent) {
    highlightedIds.add(latestEvent.transporter_id);
    if (latestEvent.transporter_slashed) recentDeltas[latestEvent.transporter_id] = -5.0; // Transporter penalty

    latestResults.forEach((r) => {
      highlightedIds.add(r.auditorId);
      recentDeltas[r.auditorId] = r.reputationDelta;
    });
  }
  // ----------------------------

  return (
    <div className="dash-root">

      <TopBar
        agents={agents}
        events={events}
        pendingCount={pendingMeta.length}
        hasPending={hasPending}
        selectedTransporter={selectedTransporter}
        loading={loading}
        lastOk={lastOk}
        error={error}
        flowAddr={flowAddr}
        onFlowAddrChange={(v) => { setFlowAddr(v); setRefreshKey((n) => n + 1); }}
        intervalMs={intervalMs}
        onIntervalChange={setIntervalMs}
        onRefresh={() => setRefreshKey((n) => n + 1)}
        showConfig={showConfig}
        onToggleConfig={() => setShowConfig((v) => !v)}
      />

      {/* Left column */}
      <NetworkTopology
        agents={agents}
        events={events}
        transporterIds={transporterIds}
        selectedTransporter={selectedTransporter}
        onSelectTransporter={setSelectedTransporter}
        activeQuorumIds={activeQuorumIds}
        streamingQuorumIds={streamingQuorumIds}
        lastOk={lastOk}
        error={error}
      />

      <SerialImuPanel onImuUpdate={() => {}} />

      {/* Center column */}
      <PendingEventPanel
        pendingMeta={pendingMeta}
        pendingVerdicts={pendingVerdicts}
        selectedTransporter={selectedTransporter}
      />

      <SettlementLedger
        events={events}
        selectedTransporter={selectedTransporter}
        selectedEvent={selectedEvent}
        onSelectEvent={setSelectedEvent}
        lastOk={lastOk}
        error={error}
      />

      {/* Right column (full height, split internally) */}
      <div className="panel rep-panel">
        <ReputationPanel
          agents={agents}
          transporterIds={transporterIds}
          highlightedIds={highlightedIds}
          recentDeltas={recentDeltas}
          lastOk={lastOk}
          error={error}
        />
        <ReceiptPanel
          selectedEvent={selectedEvent}
          auditorResults={selectedAuditorResults}
        />
      </div>

    </div>
  );
}
