export const FLOW_REST = "https://rest-testnet.onflow.org/v1/scripts";

export function decodeCadence(v) {
  if (v === null || v === undefined) return null;
  switch (v.type) {
    case "String": return v.value;
    case "Bool":   return v.value;
    case "Int": case "Int8": case "Int16": case "Int32": case "Int64":
    case "UInt": case "UInt8": case "UInt16": case "UInt32": case "UInt64":
      return parseInt(v.value, 10);
    case "Fix64": case "UFix64": return parseFloat(v.value);
    case "Array":  return (v.value || []).map((item) => decodeCadence(item));
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

export async function runScript(contractAddr, scriptCadence, args = []) {
  const encoded     = btoa(unescape(encodeURIComponent(scriptCadence)));
  const encodedArgs = args.map((a) => btoa(unescape(encodeURIComponent(JSON.stringify(a)))));
  const resp = await fetch(FLOW_REST, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ script: encoded, arguments: encodedArgs }),
  });
  if (!resp.ok) {
    let msg = `HTTP ${resp.status}`;
    try { const b = await resp.json(); msg = b.message || JSON.stringify(b).slice(0, 200); } catch (_) {}
    throw new Error(msg);
  }
  const text = await resp.text();
  let b64;
  try { const p = JSON.parse(text); b64 = typeof p === "string" ? p : (p?.value ?? ""); }
  catch { b64 = text.trim().replace(/^"|"$/g, ""); }
  if (!b64) return null;
  const bytes = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  const raw   = JSON.parse(new TextDecoder("utf-8").decode(bytes));
  return decodeCadence(raw);
}

// ─── Scripts ─────────────────────────────────────────────────────────────────

// Includes escrowBalance (new vs original) for locked-funds visibility
export const makeAgentsScript = (addr) => `
import SwarmVerifierV4 from ${addr}
access(all) struct LocalAgent {
  access(all) let id: String
  access(all) let reputation: Fix64
  access(all) let stakedFlow: UFix64
  access(all) let escrowBalance: UFix64
  access(all) let isBlacklisted: Bool
  access(all) let totalAudits: UInt64
  access(all) let correctAudits: UInt64
  init(id:String,reputation:Fix64,stakedFlow:UFix64,escrowBalance:UFix64,
      isBlacklisted:Bool,totalAudits:UInt64,correctAudits:UInt64) {
    self.id=id;self.reputation=reputation;self.stakedFlow=stakedFlow
    self.escrowBalance=escrowBalance;self.isBlacklisted=isBlacklisted
    self.totalAudits=totalAudits;self.correctAudits=correctAudits
  }
}
access(all) fun main(): [LocalAgent] {
  var rows: [LocalAgent] = []
  for id in SwarmVerifierV4.networkAgents.keys {
    let a = SwarmVerifierV4.networkAgents[id]!
    rows.append(LocalAgent(id:id,reputation:a.reputation,stakedFlow:a.stakedFlow,
      escrowBalance:a.escrowBalance,isBlacklisted:a.isBlacklisted,
      totalAudits:a.totalAudits,correctAudits:a.correctAudits))
  }
  return rows
}`.trim();

export const makeAllEventsScript = (addr) => `
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

export const makeAuditorResultsScript = (addr) => `
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

// Includes registeredAt + quorumSize + verdictCount (new) for elapsed-time display
export const makePendingMetaScript = (addr) => `
import SwarmVerifierV4 from ${addr}
access(all) struct PendingMeta {
  access(all) let eventId: String
  access(all) let transporterId: String
  access(all) let quorumSize: Int
  access(all) let verdictCount: Int
  access(all) let depositCount: Int
  access(all) let registeredAt: UFix64
  init(eventId:String,transporterId:String,quorumSize:Int,verdictCount:Int,
      depositCount:Int,registeredAt:UFix64) {
    self.eventId=eventId;self.transporterId=transporterId
    self.quorumSize=quorumSize;self.verdictCount=verdictCount
    self.depositCount=depositCount;self.registeredAt=registeredAt
  }
}
access(all) fun main(): [PendingMeta] {
  var rows: [PendingMeta] = []
  for id in SwarmVerifierV4.pendingEvents.keys {
    let e = SwarmVerifierV4.pendingEvents[id]!
    rows.append(PendingMeta(eventId:id,transporterId:e.transporterId,
      quorumSize:e.quorumIds.length,verdictCount:e.verdicts.length,
      depositCount:e.deposits.length,registeredAt:e.registeredAt))
  }
  return rows
}`.trim();

export const makePendingVerdictsScript = (addr) => `
import SwarmVerifierV4 from ${addr}
access(all) struct LocalPV {
  access(all) let auditorId: String
  access(all) let verdict: Bool
  access(all) let confidence: UFix64
  access(all) let hasDeposit: Bool
  access(all) let silent: Bool
  init(auditorId:String,verdict:Bool,confidence:UFix64,hasDeposit:Bool,silent:Bool) {
    self.auditorId=auditorId;self.verdict=verdict
    self.confidence=confidence;self.hasDeposit=hasDeposit;self.silent=silent
  }
}
access(all) fun main(eventId: String): [LocalPV] {
  if SwarmVerifierV4.pendingEvents[eventId] == nil { return [] }
  let ev = SwarmVerifierV4.pendingEvents[eventId]!
  var rows: [LocalPV] = []
  for id in ev.quorumIds {
    let hasDep = ev.deposits[id] != nil
    if let v = ev.verdicts[id] {
      rows.append(LocalPV(auditorId:id,verdict:v.verdict,confidence:v.confidence,
        hasDeposit:hasDep,silent:false))
    } else {
      rows.append(LocalPV(auditorId:id,verdict:false,confidence:0.0,
        hasDeposit:hasDep,silent:true))
    }
  }
  return rows
}`.trim();

export const makeTransporterIdsScript = (addr) => `
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