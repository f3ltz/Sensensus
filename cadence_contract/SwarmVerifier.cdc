// SwarmVerifierV3.cdc — PL_Genesis Hackathon 2026
//
// Economic model (deposit update):
//
//   Phase 1   — registerAnomaly: transporter locks sum(bidPrices) from stake.
//   Phase 1.5 — recordDeposit:   transporter locks depositPerAuditor (0.5 FLOW)
//               from each auditor's stake after they pay at POST /pay.
//               CSV is only released after this TX seals.
//   Phase 2   — submitVerdict: requires deposit on record (contract enforces).
//   Phase 3   — finalizeEvent: three-way disbursement:
//
//     ALIGNED  → auditor receives deposit + bid
//     DEVIATED → auditor receives deposit only; bid returned to transporter
//     SILENT   → auditor receives nothing; deposit + bid returned to transporter
//
//   Transporter additionally slashed if consensus contradicts their claim.
//
// NOTE: Real @FlowToken.Vault movement is simulated as UFix64 accounting.
// NOTE: No ECDSA-P256 precompile in Cadence 1.0 — sigs stored for off-chain audit.

access(all) contract SwarmVerifierV3 {

    access(all) let alpha:              Fix64    //  10.0  reputation reward
    access(all) let beta:               Fix64    //   5.0  deviation penalty
    access(all) let blacklistThreshold: Fix64    // -50.0  reputation floor
    access(all) let minimumStake:       UFix64   //  10.0  FLOW to register
    access(all) let verdictTimeoutSecs: UFix64   //  60.0  force-finalize window
    access(all) let depositPerAuditor:  UFix64   //   0.5  commitment bond per job

    access(all) let GatewayStoragePath: StoragePath
    access(all) let GatewayPublicPath:  PublicPath

    access(all) var networkAgents: {String: AgentRecord}
    access(all) var pendingEvents: {String: PendingEvent}
    access(all) var anomalyLedger: {String: AnomalyEvent}

    // ── AgentRecord ───────────────────────────────────────────────────────────

    access(all) struct AgentRecord {
        access(all) let nodeId:        String
        access(all) var reputation:    Fix64
        access(all) var stakedFlow:    UFix64
        access(all) var escrowBalance: UFix64
        access(all) var isBlacklisted: Bool
        access(all) var totalAudits:   UInt64
        access(all) var correctAudits: UInt64

        init(id: String, stake: UFix64) {
            self.nodeId = id; self.reputation = 0.0; self.stakedFlow = stake
            self.escrowBalance = 0.0; self.isBlacklisted = false
            self.totalAudits = 0; self.correctAudits = 0
        }

        access(contract) fun lockEscrow(amount: UFix64) {
            pre { self.stakedFlow >= self.escrowBalance + amount:
                "Insufficient stake: need ".concat((self.escrowBalance+amount).toString())
                .concat(" have ").concat(self.stakedFlow.toString()) }
            self.escrowBalance = self.escrowBalance + amount
        }
        access(contract) fun releaseEscrow(amount: UFix64) {
            self.escrowBalance = amount > self.escrowBalance ? 0.0 : self.escrowBalance - amount
        }
        access(contract) fun receivePayment(amount: UFix64) { self.stakedFlow = self.stakedFlow + amount }
        access(contract) fun slashStake(amount: UFix64) {
            self.stakedFlow = amount >= self.stakedFlow ? 0.0 : self.stakedFlow - amount
        }
        access(contract) fun applyReputationDelta(delta: Fix64) {
            self.reputation = self.reputation + delta
            if self.reputation < SwarmVerifierV3.blacklistThreshold {
                self.isBlacklisted = true
                emit AgentBlacklisted(nodeId: self.nodeId, reputation: self.reputation, stakedFlow: self.stakedFlow)
            }
        }
        access(contract) fun recordAudit(wasCorrect: Bool) {
            self.totalAudits = self.totalAudits + 1
            if wasCorrect { self.correctAudits = self.correctAudits + 1 }
        }
    }

    // ── PendingVerdict ────────────────────────────────────────────────────────

    access(all) struct PendingVerdict {
        access(all) let auditorId:        String
        access(all) let verdict:          Bool
        access(all) let confidence:       UFix64
        access(all) let payloadSignature: String
        access(all) let verdictSignature: String
        access(all) let submittedAt:      UFix64

        init(auditorId: String, verdict: Bool, confidence: UFix64,
             payloadSignature: String, verdictSignature: String) {
            self.auditorId = auditorId; self.verdict = verdict
            self.confidence = confidence; self.payloadSignature = payloadSignature
            self.verdictSignature = verdictSignature
            self.submittedAt = getCurrentBlock().timestamp
        }   
    }

    // ── PendingEvent ──────────────────────────────────────────────────────────

    access(all) struct PendingEvent {
        access(all) let eventId:           String
        access(all) let transporterId:     String
        access(all) let submissionSig:     String
        access(all) let anomalyConfidence: UFix64
        access(all) let registeredAt:      UFix64
        access(all) let quorumIds:         [String]
        // auditorId → bid price (FLOW). Parallel to quorumIds. Set at registerAnomaly.
        access(all) var bidPrices:         {String: UFix64}
        // auditorId → deposit amount. Populated in Phase 1.5 as each auditor pays.
        // submitVerdict pre-condition requires an entry here.
        access(all) var deposits:          {String: UFix64}
        access(all) var verdicts:          {String: PendingVerdict}
        access(all) var finalized:         Bool

        init(transporterId: String, submissionSig: String, anomalyConfidence: UFix64,
             quorumIds: [String], bidPrices: {String: UFix64}) {
            self.eventId = submissionSig; self.transporterId = transporterId
            self.submissionSig = submissionSig; self.anomalyConfidence = anomalyConfidence
            self.registeredAt = getCurrentBlock().timestamp; self.quorumIds = quorumIds
            self.bidPrices = bidPrices; self.deposits = {}
            self.verdicts = {}; self.finalized = false
        }

        access(contract) fun recordDeposit(auditorId: String, amount: UFix64) {
            pre {
                self.deposits[auditorId] == nil: "Deposit already recorded"
                self.bidPrices[auditorId] != nil: "Auditor not in quorum"
            }
            self.deposits[auditorId] = amount
        }
        access(contract) fun addVerdict(v: PendingVerdict) { self.verdicts[v.auditorId] = v }
        access(contract) fun markFinalized() { self.finalized = true }

        access(all) fun isReadyToFinalize(): Bool {
            if self.verdicts.length >= self.quorumIds.length { return true }
            return getCurrentBlock().timestamp - self.registeredAt >= SwarmVerifierV3.verdictTimeoutSecs
        }

        access(all) fun totalBidEscrow(): UFix64 {
            var total: UFix64 = 0.0
            for id in self.quorumIds { total = total + (self.bidPrices[id] ?? 0.0) }
            return total
        }
    }

    // ── AuditorResult ─────────────────────────────────────────────────────────

    access(all) struct AuditorResult {
        access(all) let auditorId:        String
        access(all) let verdict:          Bool
        access(all) let confidence:       UFix64
        access(all) let payloadSignature: String
        access(all) let verdictSignature: String
        access(all) let reputationDelta:  Fix64
        access(all) let outcome:          String   // "aligned" | "deviated" | "silent"
        access(all) let depositPaid:      UFix64
        access(all) let bidPrice:         UFix64
        access(all) let totalReceived:    UFix64

        init(auditorId: String, verdict: Bool, confidence: UFix64,
             payloadSignature: String, verdictSignature: String,
             reputationDelta: Fix64, outcome: String,
             depositPaid: UFix64, bidPrice: UFix64, totalReceived: UFix64) {
            self.auditorId = auditorId; self.verdict = verdict; self.confidence = confidence
            self.payloadSignature = payloadSignature; self.verdictSignature = verdictSignature
            self.reputationDelta = reputationDelta; self.outcome = outcome
            self.depositPaid = depositPaid; self.bidPrice = bidPrice; self.totalReceived = totalReceived
        }
    }

    // ── AnomalyEvent ──────────────────────────────────────────────────────────

    access(all) struct AnomalyEvent {
        access(all) let eventId:            String
        access(all) let transporterId:      String
        access(all) let submissionSig:      String
        access(all) let anomalyConfidence:  UFix64
        access(all) let cswarm:             UFix64
        access(all) let consensusVerdict:   Bool
        access(all) let dropVotes:          Int
        access(all) let totalVotes:         Int
        access(all) let auditorResults:     [AuditorResult]
        access(all) let transporterSlashed: Bool
        access(all) let finalizedAt:        UFix64
        access(all) var storachaCid:        String

        init(eventId: String, transporterId: String, submissionSig: String,
             anomalyConfidence: UFix64, cswarm: UFix64, consensusVerdict: Bool,
             dropVotes: Int, totalVotes: Int, auditorResults: [AuditorResult],
             transporterSlashed: Bool) {
            self.eventId = eventId; self.transporterId = transporterId
            self.submissionSig = submissionSig; self.anomalyConfidence = anomalyConfidence
            self.cswarm = cswarm; self.consensusVerdict = consensusVerdict
            self.dropVotes = dropVotes; self.totalVotes = totalVotes
            self.auditorResults = auditorResults; self.transporterSlashed = transporterSlashed
            self.finalizedAt = getCurrentBlock().timestamp; self.storachaCid = ""
        }
        access(contract) fun setCid(cid: String) { self.storachaCid = cid }
    }

    // ── Cadence events ────────────────────────────────────────────────────────

    access(all) event AgentRegistered(nodeId: String, stakedFlow: UFix64)
    access(all) event AnomalyRegistered(eventId: String, transporterId: String,
        anomalyConf: UFix64, quorumSize: Int, totalBidEscrow: UFix64)
    access(all) event DepositRecorded(eventId: String, auditorId: String, amount: UFix64)
    access(all) event VerdictSubmitted(eventId: String, auditorId: String,
        verdict: Bool, verdictN: Int, quorumN: Int)
    access(all) event AnomalySettled(eventId: String, transporterId: String,
        consensusVerdict: Bool, cswarm: UFix64, dropVotes: Int, totalVotes: Int,
        transporterSlashed: Bool)
    access(all) event AgentBlacklisted(nodeId: String, reputation: Fix64, stakedFlow: UFix64)
    access(all) event EventCidUpdated(eventId: String, cid: String)

    // ── Gateway resource ──────────────────────────────────────────────────────

    access(all) resource Gateway {

        // Phase 1: lock sum(bidPrices) from transporter stake
        access(all) fun registerAnomaly(
            transporterId: String, submissionSig: String,
            anomalyConfidence: UFix64, quorumIds: [String], bidPrices: [UFix64]
        ) {
            pre {
                quorumIds.length > 0:                                    "Empty quorum"
                quorumIds.length == bidPrices.length:                    "Parallel array length mismatch"
                anomalyConfidence >= 0.0 && anomalyConfidence <= 1.0:   "Confidence out of range"
                SwarmVerifierV3.networkAgents[transporterId] != nil:     "Transporter not registered"
                !SwarmVerifierV3.networkAgents[transporterId]!.isBlacklisted: "Transporter blacklisted"
                SwarmVerifierV3.pendingEvents[submissionSig] == nil:     "Duplicate submissionSig"
                SwarmVerifierV3.anomalyLedger[submissionSig] == nil:     "Event already finalized"
            }

            var bidMap: {String: UFix64} = {}
            var totalBidEscrow: UFix64 = 0.0
            var i = 0
            while i < quorumIds.length {
                bidMap[quorumIds[i]] = bidPrices[i]
                totalBidEscrow = totalBidEscrow + bidPrices[i]
                i = i + 1
            }

            var transporter = SwarmVerifierV3.networkAgents[transporterId]!
            transporter.lockEscrow(amount: totalBidEscrow)
            SwarmVerifierV3.networkAgents[transporterId] = transporter

            SwarmVerifierV3.pendingEvents[submissionSig] = PendingEvent(
                transporterId: transporterId, submissionSig: submissionSig,
                anomalyConfidence: anomalyConfidence, quorumIds: quorumIds, bidPrices: bidMap
            )

            emit AnomalyRegistered(eventId: submissionSig, transporterId: transporterId,
                anomalyConf: anomalyConfidence, quorumSize: quorumIds.length,
                totalBidEscrow: totalBidEscrow)
        }

        // Phase 1.5: lock depositPerAuditor from auditor stake.
        // Called by Pico after nonce sig verified at POST /pay.
        // CSV only streamed after this TX seals.
        access(all) fun recordDeposit(eventId: String, auditorId: String) {
            pre {
                SwarmVerifierV3.pendingEvents[eventId] != nil:               "Event not found"
                !SwarmVerifierV3.pendingEvents[eventId]!.finalized:          "Event finalized"
                SwarmVerifierV3.networkAgents[auditorId] != nil:             "Auditor not registered"
                !SwarmVerifierV3.networkAgents[auditorId]!.isBlacklisted:    "Auditor blacklisted"
                SwarmVerifierV3.pendingEvents[eventId]!.deposits[auditorId] == nil: "Deposit already recorded"
                SwarmVerifierV3.pendingEvents[eventId]!.bidPrices[auditorId] != nil: "Auditor not in quorum"
            }

            let amount = SwarmVerifierV3.depositPerAuditor

            var auditor = SwarmVerifierV3.networkAgents[auditorId]!
            auditor.lockEscrow(amount: amount)
            SwarmVerifierV3.networkAgents[auditorId] = auditor

            var ev = SwarmVerifierV3.pendingEvents[eventId]!
            ev.recordDeposit(auditorId: auditorId, amount: amount)
            SwarmVerifierV3.pendingEvents[eventId] = ev

            emit DepositRecorded(eventId: eventId, auditorId: auditorId, amount: amount)
        }

        // Post-consensus: record Storacha CID
        access(all) fun updateEventCid(eventId: String, cid: String) {
            pre {
                SwarmVerifierV3.anomalyLedger[eventId] != nil: "Event not finalized"
                cid.length > 0: "Empty CID"
            }
            var ev = SwarmVerifierV3.anomalyLedger[eventId]!
            ev.setCid(cid: cid)
            SwarmVerifierV3.anomalyLedger[eventId] = ev
            emit EventCidUpdated(eventId: eventId, cid: cid)
        }
    }

    // ── Phase 2: submitVerdict ────────────────────────────────────────────────

    access(all) fun submitVerdict(
        eventId: String, auditorId: String, verdict: Bool, confidence: UFix64,
        payloadSignature: String, verdictSignature: String
    ) {
        pre {
            confidence >= 0.0 && confidence <= 1.0:                          "Confidence out of range"
            SwarmVerifierV3.pendingEvents[eventId] != nil:                   "Event not found"
            !SwarmVerifierV3.pendingEvents[eventId]!.finalized:              "Already finalized"
            SwarmVerifierV3.networkAgents[auditorId] != nil:                 "Auditor not registered"
            !SwarmVerifierV3.networkAgents[auditorId]!.isBlacklisted:        "Auditor blacklisted"
            SwarmVerifierV3.pendingEvents[eventId]!.verdicts[auditorId] == nil: "Already submitted"
            SwarmVerifierV3.pendingEvents[eventId]!.deposits[auditorId] != nil: "No deposit — pay first"
            payloadSignature.length > 0:                                     "Empty payloadSignature"
        }

        var inQuorum = false
        for id in SwarmVerifierV3.pendingEvents[eventId]!.quorumIds {
            if id == auditorId { inQuorum = true; break }
        }
        assert(inQuorum, message: "Auditor not in declared quorum")

        var ev = SwarmVerifierV3.pendingEvents[eventId]!
        ev.addVerdict(v: PendingVerdict(auditorId: auditorId, verdict: verdict,
            confidence: confidence, payloadSignature: payloadSignature,
            verdictSignature: verdictSignature))
        SwarmVerifierV3.pendingEvents[eventId] = ev

        emit VerdictSubmitted(eventId: eventId, auditorId: auditorId, verdict: verdict,
            verdictN: ev.verdicts.length, quorumN: ev.quorumIds.length)
    }

    // ── Phase 3: finalizeEvent ────────────────────────────────────────────────

    access(all) fun finalizeEvent(eventId: String) {
        pre {
            SwarmVerifierV3.pendingEvents[eventId] != nil:      "Event not found"
            !SwarmVerifierV3.pendingEvents[eventId]!.finalized: "Already finalized"
        }

        let pendingEvent = SwarmVerifierV3.pendingEvents[eventId]!
        assert(pendingEvent.isReadyToFinalize(), message: "Not ready to finalize")

        // Cswarm + consensus
        var confidenceSum: UFix64 = 0.0
        var dropVotes: Int = 0
        let n = pendingEvent.quorumIds.length
        for id in pendingEvent.quorumIds {
            if let v = pendingEvent.verdicts[id] {
                confidenceSum = confidenceSum + v.confidence
                if v.verdict { dropVotes = dropVotes + 1 }
            }
        }
        let cswarm: UFix64         = confidenceSum / UFix64(n)
        let consensusVerdict: Bool = dropVotes > (n / 2)
        let cswarmF                = Fix64(cswarm)

        // Per-auditor disbursement
        var auditorResults:      [AuditorResult] = []
        var transporterRecovery: UFix64 = 0.0

        for id in pendingEvent.quorumIds {
            let submitted  = pendingEvent.verdicts[id]
            let deposit    = pendingEvent.deposits[id]  ?? 0.0
            let bid        = pendingEvent.bidPrices[id] ?? 0.0
            let silent     = submitted == nil
            let verdict    = submitted?.verdict    ?? false
            let confidence = submitted?.confidence ?? 0.0
            let payloadSig = submitted?.payloadSignature ?? ""
            let verdictSig = submitted?.verdictSignature ?? ""
            let aligned    = !silent && (verdict == consensusVerdict)

            var delta: Fix64 = SwarmVerifierV3.alpha * (cswarmF - Fix64(confidence))
            if !aligned { delta = delta - SwarmVerifierV3.beta }

            var auditorAgent = SwarmVerifierV3.networkAgents[id]!
            auditorAgent.applyReputationDelta(delta: delta)
            auditorAgent.recordAudit(wasCorrect: aligned)

            var totalReceived: UFix64 = 0.0
            var outcome: String = ""

            if silent {
                // Forfeits everything → transporter
                outcome = "silent"
                auditorAgent.releaseEscrow(amount: deposit)
                transporterRecovery = transporterRecovery + deposit + bid
            } else if aligned {
                // Gets deposit back + bid
                outcome = "aligned"
                totalReceived = deposit + bid
                auditorAgent.releaseEscrow(amount: deposit)
                auditorAgent.receivePayment(amount: totalReceived)
            } else {
                // Gets deposit back; bid → transporter
                outcome = "deviated"
                totalReceived = deposit
                auditorAgent.releaseEscrow(amount: deposit)
                auditorAgent.receivePayment(amount: deposit)
                transporterRecovery = transporterRecovery + bid
            }

            SwarmVerifierV3.networkAgents[id] = auditorAgent

            auditorResults.append(AuditorResult(
                auditorId: id, verdict: verdict, confidence: confidence,
                payloadSignature: payloadSig, verdictSignature: verdictSig,
                reputationDelta: delta, outcome: outcome,
                depositPaid: deposit, bidPrice: bid, totalReceived: totalReceived
            ))
        }

        // Transporter escrow release + false-positive slash
        let totalBidEscrow = pendingEvent.totalBidEscrow()
        var transporterAgent = SwarmVerifierV3.networkAgents[pendingEvent.transporterId]!
        transporterAgent.releaseEscrow(amount: totalBidEscrow)
        if transporterRecovery > 0.0 { transporterAgent.receivePayment(amount: transporterRecovery) }

        var transporterSlashed = false
        if (pendingEvent.anomalyConfidence >= 0.85) != consensusVerdict {
            let paidToAuditors = totalBidEscrow - transporterRecovery
            if paidToAuditors > 0.0 { transporterAgent.slashStake(amount: paidToAuditors) }
            transporterSlashed = true
        }
        SwarmVerifierV3.networkAgents[pendingEvent.transporterId] = transporterAgent

        SwarmVerifierV3.anomalyLedger[eventId] = AnomalyEvent(
            eventId: eventId, transporterId: pendingEvent.transporterId,
            submissionSig: pendingEvent.submissionSig,
            anomalyConfidence: pendingEvent.anomalyConfidence,
            cswarm: cswarm, consensusVerdict: consensusVerdict,
            dropVotes: dropVotes, totalVotes: n,
            auditorResults: auditorResults, transporterSlashed: transporterSlashed
        )

        var mutableEvent = pendingEvent
        mutableEvent.markFinalized()
        SwarmVerifierV3.pendingEvents[eventId] = mutableEvent

        emit AnomalySettled(eventId: eventId, transporterId: pendingEvent.transporterId,
            consensusVerdict: consensusVerdict, cswarm: cswarm,
            dropVotes: dropVotes, totalVotes: n, transporterSlashed: transporterSlashed)
    }

    // ── Public registration ───────────────────────────────────────────────────

    access(all) fun registerNode(nodeId: String, stake: UFix64) {
        pre {
            self.networkAgents[nodeId] == nil: "Already registered"
            stake >= self.minimumStake:
                "Stake below minimum (".concat(self.minimumStake.toString())
                .concat("), got ").concat(stake.toString())
        }
        self.networkAgents[nodeId] = AgentRecord(id: nodeId, stake: stake)
        emit AgentRegistered(nodeId: nodeId, stakedFlow: stake)
    }

    // ── Read-only helpers ─────────────────────────────────────────────────────

    access(all) fun getReputation(nodeId: String): Fix64?  { return self.networkAgents[nodeId]?.reputation }
    access(all) fun getStake(nodeId: String):      UFix64? { return self.networkAgents[nodeId]?.stakedFlow }
    access(all) fun isBlacklisted(nodeId: String): Bool    { return self.networkAgents[nodeId]?.isBlacklisted ?? false }
    access(all) fun getDepositAmount():            UFix64  { return self.depositPerAuditor }
    access(all) fun getAnomalyEvent(eventId: String): AnomalyEvent? { return self.anomalyLedger[eventId] }
    access(all) fun getPendingEvent(eventId: String): PendingEvent? { return self.pendingEvents[eventId] }

    // Weighted quorum scoring. score = wPrice*(1/bid) + wRep*rep + wStake*stake
    access(all) fun scoreAuditors(candidates: [String], bidPrices: [UFix64],
        wPrice: UFix64, wRep: UFix64, wStake: UFix64, n: Int): [String] {
        pre { candidates.length == bidPrices.length: "Parallel array mismatch" }

        var eligible: [{String: AnyStruct}] = []
        var i = 0
        while i < candidates.length {
            let id = candidates[i]
            if let record = self.networkAgents[id] {
                if !record.isBlacklisted && bidPrices[i] > 0.0 {
                    let repPart: UFix64 = record.reputation > 0.0
                        ? UFix64(Fix64(wRep) * record.reputation) : 0.0
                    let score = UFix64(wPrice) / bidPrices[i] + repPart
                              + UFix64(wStake) * record.stakedFlow / 100.0
                    eligible.append({"id": id, "score": score})
                }
            }
            i = i + 1
        }
        var k = 1
        while k < eligible.length {
            let cur = eligible[k]; let cs = cur["score"]! as! UFix64; var m = k - 1
            while m >= 0 {
                if (eligible[m]["score"]! as! UFix64) < cs { eligible[m+1] = eligible[m]; m = m - 1 }
                else { break }
            }
            eligible[m+1] = cur; k = k + 1
        }
        var result: [String] = []; var r = 0
        while r < eligible.length && r < n { result.append(eligible[r]["id"]! as! String); r = r + 1 }
        return result
    }

    // ── Init ──────────────────────────────────────────────────────────────────

    init() {
        self.alpha = 10.0; self.beta = 5.0; self.blacklistThreshold = -50.0
        self.minimumStake = 10.0; self.verdictTimeoutSecs = 60.0; self.depositPerAuditor = 0.5
        self.networkAgents = {}; self.pendingEvents = {}; self.anomalyLedger = {}
        self.GatewayStoragePath = /storage/SwarmGatewayV2
        self.GatewayPublicPath  = /public/SwarmGatewayV2
        self.account.storage.save(<- create Gateway(), to: self.GatewayStoragePath)
    }
}
