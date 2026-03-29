import { useState, useEffect, useRef, useCallback } from "react";
import {
  runScript,
  makeAgentsScript,
  makeAllEventsScript,
  makeAuditorResultsScript,
  makePendingMetaScript,
  makePendingVerdictsScript,
  makeTransporterIdsScript,
} from "../cadence.js";

const MAX_CACHE_SIZE = 30;

export function useFlowData(flowAddr, refreshKey, intervalMs = 8000) {
  const addrRef = useRef(flowAddr);
  useEffect(() => { addrRef.current = flowAddr; }, [flowAddr]);

  const [agents,         setAgents]         = useState([]);
  const [events,         setEvents]         = useState([]);
  const [pendingMeta,    setPendingMeta]    = useState([]);
  const [pendingVerdicts, setPendingVerdicts] = useState({});  // eventId → {auditorId → row}
  const [transporterIds, setTransporterIds] = useState([]);
  const [auditorCache,   setAuditorCache]   = useState({});   // eventId → results[]
  const [error,          setError]          = useState(null);
  const [lastOk,         setLastOk]         = useState(null);
  const [loading,        setLoading]        = useState(false);

  // Polling refs so we can cancel on unmount
  const aliveRef = useRef(true);
  useEffect(() => { aliveRef.current = true; return () => { aliveRef.current = false; }; }, []);

  const safeSet = (setter) => (val) => { if (aliveRef.current) setter(val); };

  // ── Agents ──────────────────────────────────────────────────────────────────
  const pollAgents = useCallback(async () => {
    try {
      const rows = await runScript(addrRef.current, makeAgentsScript(addrRef.current));
      safeSet(setAgents)(
        (rows || []).map((r) => ({
          id:            r.id,
          reputation:    r.reputation,
          stake:         r.stakedFlow,
          escrow:        r.escrowBalance,
          isBlacklisted: r.isBlacklisted,
          totalAudits:   r.totalAudits,
          correctAudits: r.correctAudits,
        }))
      );
      safeSet(setError)(null);
      safeSet(setLastOk)(Date.now());
    } catch (e) { safeSet(setError)(e.message); }
  }, []);

  // ── Settled events ─────────────────────────────────────────────────────────
  const pollEvents = useCallback(async () => {
    try {
      const rows = await runScript(addrRef.current, makeAllEventsScript(addrRef.current));
      const mapped = (rows || [])
        .map((r) => ({
          event_id:            r.eventId,
          transporter_id:      r.transporterId,
          anomaly_confidence:  r.anomalyConfidence,
          cswarm:              r.cswarm,
          consensus_verdict:   r.consensusVerdict,
          drop_votes:          r.dropVotes ?? 0,
          total_votes:         r.totalVotes ?? 0,
          transporter_slashed: r.transporterSlashed,
          finalized_at:        r.finalizedAt,
          storacha_cid:        r.storachaCid,
        }))
        .sort((a, b) => b.finalized_at - a.finalized_at)
        .slice(0, 50);
      safeSet(setEvents)(mapped);
      safeSet(setLastOk)(Date.now());
    } catch (e) { safeSet(setError)(e.message); }
  }, []);

  // ── Pending events meta ────────────────────────────────────────────────────
  const pollPendingMeta = useCallback(async () => {
    try {
      const rows = await runScript(addrRef.current, makePendingMetaScript(addrRef.current));
      safeSet(setPendingMeta)(
        (rows || []).map((r) => ({
          eventId:       r.eventId,
          transporterId: r.transporterId,
          quorumSize:    r.quorumSize,
          verdictCount:  r.verdictCount,
          depositCount:  r.depositCount,
          registeredAt:  r.registeredAt,
        }))
      );
    } catch (_) {}
  }, []);

  // ── Live verdicts for all pending events ───────────────────────────────────
  const pollPendingVerdicts = useCallback(async (metas) => {
    if (!metas.length) return;
    await Promise.allSettled(
      metas.map(async ({ eventId }) => {
        try {
          const rows = await runScript(
            addrRef.current,
            makePendingVerdictsScript(addrRef.current),
            [{ type: "String", value: eventId }]
          );
          if (!rows?.length) return;
          const map = {};
          rows.forEach((r) => {
            map[r.auditorId] = {
              verdict:    r.verdict,
              confidence: r.confidence,
              hasDeposit: r.hasDeposit,
              silent:     r.silent,
            };
          });
          safeSet(setPendingVerdicts)((prev) => ({ ...prev, [eventId]: map }));
        } catch (_) {}
      })
    );
  }, []);

  // ── Transporter IDs ────────────────────────────────────────────────────────
  const pollTransporterIds = useCallback(async () => {
    try {
      const ids = await runScript(addrRef.current, makeTransporterIdsScript(addrRef.current));
      safeSet(setTransporterIds)(ids || []);
    } catch (_) {}
  }, []);

  // ── Initial + refresh ──────────────────────────────────────────────────────
  useEffect(() => {
    setLoading(true);
    Promise.all([pollAgents(), pollEvents(), pollPendingMeta(), pollTransporterIds()])
      .finally(() => safeSet(setLoading)(false));

    const iAgents    = setInterval(pollAgents,         12_000);
    const iEvents    = setInterval(pollEvents,          intervalMs);
    const iPending   = setInterval(pollPendingMeta,     4_000);
    const iTransport = setInterval(pollTransporterIds, 30_000);
    return () => { clearInterval(iAgents); clearInterval(iEvents); clearInterval(iPending); clearInterval(iTransport); };
  }, [refreshKey, intervalMs]);

  // ── Poll verdicts whenever pendingMeta changes ─────────────────────────────
  useEffect(() => {
    if (!pendingMeta.length) return;
    pollPendingVerdicts(pendingMeta);
    const iv = setInterval(() => pollPendingVerdicts(pendingMeta), 3_000);
    return () => clearInterval(iv);
  }, [pendingMeta]);

  // ── Lazy-load auditor results for a specific settled event ─────────────────
  const fetchAuditorResults = useCallback(async (eventId) => {
    if (!eventId || auditorCache[eventId]) return;
    try {
      const rows = await runScript(
        addrRef.current,
        makeAuditorResultsScript(addrRef.current),
        [{ type: "String", value: eventId }]
      );
      const results = (rows || []).map((r) => ({
        auditorId:       r.auditorId,
        verdict:         r.verdict,
        confidence:      r.confidence,
        reputationDelta: r.reputationDelta,
        outcome:         r.outcome,
        depositPaid:     r.depositPaid,
        bidPrice:        r.bidPrice,
        totalReceived:   r.totalReceived,
      }));
      if (results.length) {
        safeSet(setAuditorCache)((prev) => {
          const keys    = Object.keys(prev);
          const trimmed = keys.length >= MAX_CACHE_SIZE
            ? Object.fromEntries(keys.slice(-(MAX_CACHE_SIZE - 1)).map((k) => [k, prev[k]]))
            : prev;
          return { ...trimmed, [eventId]: results };
        });
      }
    } catch (_) {}
  }, [auditorCache]);

  return {
    agents,
    events,
    pendingMeta,
    pendingVerdicts,
    transporterIds,
    auditorCache,
    fetchAuditorResults,
    error,
    lastOk,
    loading,
  };
}