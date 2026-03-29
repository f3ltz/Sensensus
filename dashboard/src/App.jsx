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
  const activeQuorumIds = new Set(
    pendingMeta.flatMap((m) =>
      Object.keys(pendingVerdicts[m.eventId] ?? {})
    )
  );

  const hasPending = pendingMeta.length > 0;

  const selectedAuditorResults = selectedEvent
    ? (auditorCache[selectedEvent.event_id] ?? null)
    : null;

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
