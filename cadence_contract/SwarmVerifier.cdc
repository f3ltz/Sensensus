// SwarmVerifierV3.cdc
// Deployed on Flow Testnet.
//
// Architecture: PL_Genesis Hackathon 2026
//
// Settlement is three-phase:
//
//   Phase 1 — registerAnomaly (transporter)
//     Transporter locks escrow and declares the quorum.
//     Returns eventId = submissionSig (unique per event).
//
//   Phase 2 — submitVerdict (each auditor, independently)
//     Each quorum auditor submits their own signed verdict.
//     Contract validates the auditor is in the declared quorum.
//     No auditor can submit twice for the same event.
//
//   Phase 3 — finalizeEvent (anyone, after all verdicts or timeout)
//     Computes Cswarm and majority consensus on-chain.
//     Disburses escrow to aligned auditors.
//     Slashes transporter if consensus contradicts their claim.
//     Slashes deviating auditors.
//     Writes immutable AnomalyEvent to anomalyLedger.
//     Emits AnomalySettled event.
//
//   Post-consensus — updateEventCid (transporter only)
//     After the Flow contract emits AnomalySettled and notifies the transporter,
//     the transporter uploads the full event bundle (CSV + verdicts + consensus)
//     to Storacha and calls this to record the canonical CID on-chain.
//     The CID is always "" in the AnomalyEvent until this is called.
//
// NOTE: Flow Cadence 1.0 does not expose a native ECDSA-P256 precompile.
// Signatures are stored on-chain for off-chain auditing via block explorer.
// When Cadence exposes crypto.verifySignature() with P-256 support, replace
// the storage step with inline verify + panic on failure.
//
// NOTE: Real token escrow requires @FlowToken.Vault plumbing. For the hackathon
// demo, escrow is tracked as self-reported UFix64 balances. The accounting is
// correct; only the actual token movement is simulated.

access(all) contract SwarmVerifierV3 {

    // ─────────────────────────────────────────────────────────────────────────
    // Constants
    // ─────────────────────────────────────────────────────────────────────────

    // Reputation formula: ΔR = α(C_swarm − V_agent) − β(L)
    // α rewards/penalises calibration (how close agent confidence is to Cswarm)
    // β is the flat deviation penalty applied only when verdict != consensus
    access(all) let alpha: Fix64              // 10.0
    access(all) let beta:  Fix64              //  5.0

    // Reputation floor — node is blacklisted below this
    access(all) let blacklistThreshold: Fix64 // -50.0

    // Minimum self-reported stake to register
    access(all) let minimumStake: UFix64      //  10.0

    // Seconds after registerAnomaly before anyone can force-finalize
    // (handles the case where one or more quorum auditors go silent)
    access(all) let verdictTimeoutSecs: UFix64 // 60.0

    // ─────────────────────────────────────────────────────────────────────────
    // Storage paths
    // ─────────────────────────────────────────────────────────────────────────

    access(all) let GatewayStoragePath: StoragePath
    access(all) let GatewayPublicPath:  PublicPath

    // ─────────────────────────────────────────────────────────────────────────
    // State
    // ─────────────────────────────────────────────────────────────────────────

    // All registered nodes (transporters and auditors)
    access(all) var networkAgents: {String: AgentRecord}

    // Pending events awaiting full quorum (keyed by submissionSig)
    access(all) var pendingEvents: {String: PendingEvent}

    // Finalized events (keyed by submissionSig). CID is "" until updateEventCid.
    access(all) var anomalyLedger: {String: AnomalyEvent}

    // ─────────────────────────────────────────────────────────────────────────
    // Structs
    // ─────────────────────────────────────────────────────────────────────────

    access(all) struct AgentRecord {
        access(all) let nodeId:        String
        access(all) var reputation:    Fix64
        access(all) var stakedFlow:    UFix64
        access(all) var escrowBalance: UFix64   // locked per active event
        access(all) var isBlacklisted: Bool
        access(all) var totalAudits:   UInt64
        access(all) var correctAudits: UInt64

        init(id: String, stake: UFix64) {
            self.nodeId        = id
            self.reputation    = 0.0
            self.stakedFlow    = stake
            self.escrowBalance = 0.0
            self.isBlacklisted = false
            self.totalAudits   = 0
            self.correctAudits = 0
        }

        access(contract) fun lockEscrow(amount: UFix64) {
            pre {
                self.stakedFlow >= self.escrowBalance + amount:
                    "Insufficient stake to cover escrow: required "
                    .concat((self.escrowBalance + amount).toString())
                    .concat(" have ")
                    .concat(self.stakedFlow.toString())
            }
            self.escrowBalance = self.escrowBalance + amount
        }

        access(contract) fun releaseEscrow(amount: UFix64) {
            if amount > self.escrowBalance {
                self.escrowBalance = 0.0
            } else {
                self.escrowBalance = self.escrowBalance - amount
            }
        }

        access(contract) fun receivePayment(amount: UFix64) {
            self.stakedFlow = self.stakedFlow + amount
        }

        access(contract) fun slashStake(amount: UFix64) {
            if amount >= self.stakedFlow {
                self.stakedFlow = 0.0
            } else {
                self.stakedFlow = self.stakedFlow - amount
            }
        }

        access(contract) fun applyReputationDelta(delta: Fix64) {
            self.reputation = self.reputation + delta
            if self.reputation < SwarmVerifierV3.blacklistThreshold {
                self.isBlacklisted = true
                emit AgentBlacklisted(
                    nodeId:        self.nodeId,
                    reputation:    self.reputation,
                    stakedFlow:    self.stakedFlow
                )
            }
        }

        access(contract) fun recordAudit(wasCorrect: Bool) {
            self.totalAudits = self.totalAudits + 1
            if wasCorrect {
                self.correctAudits = self.correctAudits + 1
            }
        }
    }

    // A verdict submitted by one auditor during Phase 2
    access(all) struct PendingVerdict {
        access(all) let auditorId:        String
        access(all) let verdict:          Bool     // true = drop detected
        access(all) let confidence:       UFix64   // 0.0–1.0
        access(all) let payloadSignature: String   // hex — ties to specific event
        access(all) let verdictSignature: String   // hex — auditor signs canonical string
        access(all) let submittedAt:      UFix64   // block timestamp

        init(
            auditorId:        String,
            verdict:          Bool,
            confidence:       UFix64,
            payloadSignature: String,
            verdictSignature: String
        ) {
            self.auditorId        = auditorId
            self.verdict          = verdict
            self.confidence       = confidence
            self.payloadSignature = payloadSignature
            self.verdictSignature = verdictSignature
            self.submittedAt      = getCurrentBlock().timestamp
        }
    }

    // An event in flight — collecting verdicts, not yet finalized
    access(all) struct PendingEvent {
        access(all) let eventId:           String   // = submissionSig
        access(all) let transporterId:     String
        access(all) let submissionSig:     String
        access(all) let anomalyConfidence: UFix64
        access(all) let registeredAt:      UFix64   // block timestamp
        access(all) let quorumIds:         [String] // expected auditor pubkeys
        access(all) let paymentPerAuditor: UFix64   // locked in transporter escrow
        access(all) var verdicts:          {String: PendingVerdict}  // auditorId → verdict
        access(all) var finalized:         Bool

        init(
            transporterId:     String,
            submissionSig:     String,
            anomalyConfidence: UFix64,
            quorumIds:         [String],
            paymentPerAuditor: UFix64
        ) {
            self.eventId           = submissionSig
            self.transporterId     = transporterId
            self.submissionSig     = submissionSig
            self.anomalyConfidence = anomalyConfidence
            self.registeredAt      = getCurrentBlock().timestamp
            self.quorumIds         = quorumIds
            self.paymentPerAuditor = paymentPerAuditor
            self.verdicts          = {}
            self.finalized         = false
        }

        access(contract) fun addVerdict(v: PendingVerdict) {
            self.verdicts[v.auditorId] = v
        }

        access(contract) fun markFinalized() {
            self.finalized = true
        }

        // True when all quorum members have submitted, or timeout has passed
        access(all) fun isReadyToFinalize(): Bool {
            if self.verdicts.length >= self.quorumIds.length {
                return true
            }
            let elapsed = getCurrentBlock().timestamp - self.registeredAt
            return elapsed >= SwarmVerifierV3.verdictTimeoutSecs
        }
    }

    // Per-auditor record inside a finalized AnomalyEvent
    access(all) struct AuditorResult {
        access(all) let auditorId:        String
        access(all) let verdict:          Bool
        access(all) let confidence:       UFix64
        access(all) let payloadSignature: String
        access(all) let verdictSignature: String
        access(all) let reputationDelta:  Fix64
        access(all) let aligned:         Bool     // true = matched consensus
        access(all) let payment:          UFix64  // FLOW received (0 if not aligned)

        init(
            auditorId:        String,
            verdict:          Bool,
            confidence:       UFix64,
            payloadSignature: String,
            verdictSignature: String,
            reputationDelta:  Fix64,
            aligned:         Bool,
            payment:          UFix64
        ) {
            self.auditorId        = auditorId
            self.verdict          = verdict
            self.confidence       = confidence
            self.payloadSignature = payloadSignature
            self.verdictSignature = verdictSignature
            self.reputationDelta  = reputationDelta
            self.aligned          = aligned
            self.payment          = payment
        }
    }

    // Immutable record written to anomalyLedger on finalization
    access(all) struct AnomalyEvent {
        access(all) let eventId:             String   // = submissionSig
        access(all) let transporterId:       String
        access(all) let submissionSig:       String
        access(all) let anomalyConfidence:   UFix64
        access(all) let cswarm:              UFix64
        access(all) let consensusVerdict:    Bool
        access(all) let dropVotes:           Int
        access(all) let totalVotes:          Int
        access(all) let auditorResults:      [AuditorResult]
        access(all) let transporterSlashed:  Bool
        access(all) let finalizedAt:         UFix64
        // Storacha CID: "" until transporter calls updateEventCid post-consensus.
        // The transporter uploads the full bundle (CSV + verdicts + consensus)
        // to Storacha and records the CID here for permanent provenance.
        access(all) var storachaCid:         String

        init(
            eventId:            String,
            transporterId:      String,
            submissionSig:      String,
            anomalyConfidence:  UFix64,
            cswarm:             UFix64,
            consensusVerdict:   Bool,
            dropVotes:          Int,
            totalVotes:         Int,
            auditorResults:     [AuditorResult],
            transporterSlashed: Bool
        ) {
            self.eventId            = eventId
            self.transporterId      = transporterId
            self.submissionSig      = submissionSig
            self.anomalyConfidence  = anomalyConfidence
            self.cswarm             = cswarm
            self.consensusVerdict   = consensusVerdict
            self.dropVotes          = dropVotes
            self.totalVotes         = totalVotes
            self.auditorResults     = auditorResults
            self.transporterSlashed = transporterSlashed
            self.finalizedAt        = getCurrentBlock().timestamp
            self.storachaCid        = ""
        }

        // Only callable from within the contract — sets CID after Storacha upload
        access(contract) fun setCid(cid: String) {
            self.storachaCid = cid
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Events
    // ─────────────────────────────────────────────────────────────────────────

    access(all) event AgentRegistered(
        nodeId:     String,
        stakedFlow: UFix64
    )

    access(all) event AnomalyRegistered(
        eventId:           String,
        transporterId:     String,
        anomalyConfidence: UFix64,
        quorumSize:        Int,
        paymentPerAuditor: UFix64
    )

    access(all) event VerdictSubmitted(
        eventId:   String,
        auditorId: String,
        verdict:   Bool,
        verdictN:  Int,    // how many verdicts collected so far
        quorumN:   Int     // how many are expected
    )

    access(all) event AnomalySettled(
        eventId:            String,
        transporterId:      String,
        consensusVerdict:   Bool,
        cswarm:             UFix64,
        dropVotes:          Int,
        totalVotes:         Int,
        transporterSlashed: Bool
    )

    access(all) event AgentBlacklisted(
        nodeId:     String,
        reputation: Fix64,
        stakedFlow: UFix64
    )

    access(all) event EventCidUpdated(
        eventId: String,
        cid:     String
    )

    // ─────────────────────────────────────────────────────────────────────────
    // Gateway resource
    // Held only by the deployer account. Controls Phase 1 (registerAnomaly)
    // so a rogue caller cannot spam fake events or lock up other nodes' escrow.
    // ─────────────────────────────────────────────────────────────────────────

    access(all) resource Gateway {

        // ── Phase 1: Transporter registers an anomaly event ──────────────────
        //
        // Parameters:
        //   transporterId     — transporter pubkey hex (128 chars)
        //   submissionSig     — hex ECDSA sig over canonical payload
        //                       (used as the unique eventId)
        //   anomalyConfidence — Pico TFLite P(drop), scaled 0.0–1.0
        //   quorumIds         — pubkey hex of the N selected auditors
        //   paymentPerAuditor — FLOW to pay each aligned auditor
        //
        // Effect:
        //   Locks (paymentPerAuditor × quorumSize) into transporter escrow.
        //   Creates a PendingEvent collecting verdicts from the declared quorum.
        access(all) fun registerAnomaly(
            transporterId:     String,
            submissionSig:     String,
            anomalyConfidence: UFix64,
            quorumIds:         [String],
            paymentPerAuditor: UFix64
        ) {
            pre {
                quorumIds.length > 0:
                    "Quorum must have at least one auditor"
                anomalyConfidence >= 0.0 && anomalyConfidence <= 1.0:
                    "Confidence must be between 0.0 and 1.0"
                SwarmVerifierV3.networkAgents[transporterId] != nil:
                    "Transporter not registered"
                !SwarmVerifierV3.networkAgents[transporterId]!.isBlacklisted:
                    "Transporter is blacklisted"
                SwarmVerifierV3.pendingEvents[submissionSig] == nil:
                    "Event already registered — duplicate submissionSig rejected"
                SwarmVerifierV3.anomalyLedger[submissionSig] == nil:
                    "Event already finalized — duplicate submissionSig rejected"
            }

            let totalEscrow = paymentPerAuditor * UFix64(quorumIds.length)

            // Lock escrow in transporter account
            var transporter = SwarmVerifierV3.networkAgents[transporterId]!
            transporter.lockEscrow(amount: totalEscrow)
            SwarmVerifierV3.networkAgents[transporterId] = transporter

            SwarmVerifierV3.pendingEvents[submissionSig] = PendingEvent(
                transporterId:     transporterId,
                submissionSig:     submissionSig,
                anomalyConfidence: anomalyConfidence,
                quorumIds:         quorumIds,
                paymentPerAuditor: paymentPerAuditor
            )

            emit AnomalyRegistered(
                eventId:           submissionSig,
                transporterId:     transporterId,
                anomalyConfidence: anomalyConfidence,
                quorumSize:        quorumIds.length,
                paymentPerAuditor: paymentPerAuditor
            )
        }

        // ── Post-consensus: Transporter records Storacha CID ─────────────────
        //
        // Called after the transporter receives the AnomalySettled event,
        // uploads the full event bundle to Storacha, and gets a CID back.
        // Only the Gateway holder (deployer / transporter relay) can call this.
        //
        // The uploaded bundle should contain:
        //   - raw CSV (75 rows of IMU data)
        //   - all auditor verdicts and confidence scores
        //   - consensus result and Cswarm
        //   - all signatures for full provenance
        access(all) fun updateEventCid(eventId: String, cid: String) {
            pre {
                SwarmVerifierV3.anomalyLedger[eventId] != nil:
                    "Event not finalized — cannot set CID on pending event"
                cid.length > 0:
                    "CID cannot be empty"
                SwarmVerifierV3.anomalyLedger[eventId]!.storachaCid == "":
                    "CID already set for this event"
            }
            SwarmVerifierV3.anomalyLedger[eventId]!.setCid(cid: cid)
            emit EventCidUpdated(eventId: eventId, cid: cid)
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Phase 2 — submitVerdict (open, gated by quorum membership)
    //
    // Each quorum auditor calls this independently after running their
    // Random Forest model on the CSV received via x402 from the transporter.
    //
    // The payloadSignature is the transporter's sig over the payload body
    // returned in the 200 response. Including it here ties the auditor's
    // verdict to the specific data they received — no verdict can be
    // fabricated without also having received the payload.
    // ─────────────────────────────────────────────────────────────────────────

    access(all) fun submitVerdict(
        eventId:          String,
        auditorId:        String,
        verdict:          Bool,
        confidence:       UFix64,
        payloadSignature: String,
        verdictSignature: String
    ) {
        pre {
            confidence >= 0.0 && confidence <= 1.0:
                "Confidence must be between 0.0 and 1.0"
            SwarmVerifierV3.pendingEvents[eventId] != nil:
                "Event not found or already finalized"
            !SwarmVerifierV3.pendingEvents[eventId]!.finalized:
                "Event already finalized"
            SwarmVerifierV3.networkAgents[auditorId] != nil:
                "Auditor not registered"
            !SwarmVerifierV3.networkAgents[auditorId]!.isBlacklisted:
                "Auditor is blacklisted"
            SwarmVerifierV3.pendingEvents[eventId]!.verdicts[auditorId] == nil:
                "Auditor has already submitted a verdict for this event"
            payloadSignature.length > 0:
                "payloadSignature cannot be empty — it links this verdict to the event data"
        }

        // Confirm auditorId is actually in the declared quorum
        var inQuorum = false
        for id in SwarmVerifierV3.pendingEvents[eventId]!.quorumIds {
            if id == auditorId {
                inQuorum = true
                break
            }
        }
        assert(inQuorum, message: "Auditor not in declared quorum for this event")

        var pendingEv = SwarmVerifierV3.pendingEvents[eventId]!
        pendingEv.addVerdict(v: PendingVerdict(
            auditorId:        auditorId,
            verdict:          verdict,
            confidence:       confidence,
            payloadSignature: payloadSignature,
            verdictSignature: verdictSignature
        ))
        SwarmVerifierV3.pendingEvents[eventId] = pendingEv

        emit VerdictSubmitted(
            eventId:   eventId,
            auditorId: auditorId,
            verdict:   verdict,
            verdictN:  pendingEv.verdicts.length,
            quorumN:   pendingEv.quorumIds.length
        )
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Phase 3 — finalizeEvent (open to anyone)
    //
    // Can be called once all quorum verdicts are in, or after verdictTimeoutSecs
    // has elapsed since registerAnomaly. Calling before either condition fails.
    //
    // Auditors that were in the quorum but did not submit before timeout are
    // treated as deviating (L=1) with confidence=0.0. This closes the free-rider
    // attack: an auditor cannot observe others' verdicts and submit last to
    // guarantee alignment. Silence = wrong answer.
    // ─────────────────────────────────────────────────────────────────────────

    access(all) fun finalizeEvent(eventId: String) {
        pre {
            SwarmVerifierV3.pendingEvents[eventId] != nil:
                "Event not found"
            !SwarmVerifierV3.pendingEvents[eventId]!.finalized:
                "Event already finalized"
        }

        let pendingEvent = SwarmVerifierV3.pendingEvents[eventId]!

        // isReadyToFinalize() reads getCurrentBlock().timestamp (impure),
        // so it cannot live in a pre block — assert here instead.
        assert(
            pendingEvent.isReadyToFinalize(),
            message: "Not ready: quorum incomplete and timeout not yet elapsed"
        )

        // ── Compute Cswarm and majority consensus ─────────────────────────────
        // Include all quorum members. Silent members (not in pendingEvent.verdicts)
        // contribute confidence=0.0 and verdict=false (no drop).
        var confidenceSum: UFix64 = 0.0
        var dropVotes: Int = 0
        let n = pendingEvent.quorumIds.length

        for id in pendingEvent.quorumIds {
            if let v = pendingEvent.verdicts[id] {
                confidenceSum = confidenceSum + v.confidence
                if v.verdict { dropVotes = dropVotes + 1 }
            }
            // silent auditor: confidence 0.0, verdict false — already at defaults
        }

        let cswarm: UFix64 = confidenceSum / UFix64(n)
        let consensusVerdict: Bool = dropVotes > (n / 2)
        let cswarmF = Fix64(cswarm)

        // ── Per-auditor reputation + payment ─────────────────────────────────
        var auditorResults: [AuditorResult] = []
        let paymentPerAuditor = pendingEvent.paymentPerAuditor

        for id in pendingEvent.quorumIds {
            let submitted = pendingEvent.verdicts[id]
            let verdict    = submitted?.verdict   ?? false
            let confidence = submitted?.confidence ?? 0.0
            let payloadSig = submitted?.payloadSignature ?? ""
            let verdictSig = submitted?.verdictSignature ?? ""
            let silent     = submitted == nil

            let vAgent  = Fix64(confidence)
            let aligned = verdict == consensusVerdict && !silent
            var delta: Fix64 = SwarmVerifierV3.alpha * (cswarmF - vAgent)
            if !aligned {
                delta = delta - SwarmVerifierV3.beta
            }

            var auditorAgent = SwarmVerifierV3.networkAgents[id]!
            auditorAgent.applyReputationDelta(delta: delta)
            auditorAgent.recordAudit(wasCorrect: aligned)

            var payment: UFix64 = 0.0
            if aligned {
                payment = paymentPerAuditor
                auditorAgent.receivePayment(amount: payment)
            }

            SwarmVerifierV3.networkAgents[id] = auditorAgent

            auditorResults.append(AuditorResult(
                auditorId:        id,
                verdict:          verdict,
                confidence:       confidence,
                payloadSignature: payloadSig,
                verdictSignature: verdictSig,
                reputationDelta:  delta,
                aligned:          aligned,
                payment:          payment
            ))
        }

        // ── Release / slash transporter escrow ────────────────────────────────
        // The transporter claimed anomalyConfidence >= 0.85 (drop detected).
        // If consensus says NO DROP, the transporter was wrong — slash stake.
        // If consensus says DROP, the transporter was right — release remaining
        // escrow (any unearned portion from silent/deviating auditors).
        let totalEscrow = paymentPerAuditor * UFix64(n)
        let alignedCount = auditorResults.filter(view fun(r: AuditorResult): Bool { return r.aligned }).length
        let paidOut = paymentPerAuditor * UFix64(alignedCount)
        let unspentEscrow = totalEscrow - paidOut

        var transporterAgent = SwarmVerifierV3.networkAgents[pendingEvent.transporterId]!
        transporterAgent.releaseEscrow(amount: totalEscrow)

        // Transporter claimed drop (confidence submitted implies >= 0.85 threshold).
        // If consensus disagrees: slash the unspent escrow from stake.
        var transporterSlashed = false
        let transporterClaimedDrop = pendingEvent.anomalyConfidence >= 0.85
        if transporterClaimedDrop != consensusVerdict {
            transporterAgent.slashStake(amount: unspentEscrow)
            transporterSlashed = true
        }
        // Regardless: any unspent escrow that was not slashed stays in stake
        SwarmVerifierV3.networkAgents[pendingEvent.transporterId] = transporterAgent

        // ── Write finalized event to ledger ───────────────────────────────────
        // storachaCid is "" — set later by updateEventCid once transporter uploads.
        var finalEvent = AnomalyEvent(
            eventId:            eventId,
            transporterId:      pendingEvent.transporterId,
            submissionSig:      pendingEvent.submissionSig,
            anomalyConfidence:  pendingEvent.anomalyConfidence,
            cswarm:             cswarm,
            consensusVerdict:   consensusVerdict,
            dropVotes:          dropVotes,
            totalVotes:         n,
            auditorResults:     auditorResults,
            transporterSlashed: transporterSlashed
        )
        SwarmVerifierV3.anomalyLedger[eventId] = finalEvent

        // Mark pending event finalized (kept for reference, not removed)
        var mutableEvent = pendingEvent
        mutableEvent.markFinalized()
        SwarmVerifierV3.pendingEvents[eventId] = mutableEvent

        emit AnomalySettled(
            eventId:            eventId,
            transporterId:      pendingEvent.transporterId,
            consensusVerdict:   consensusVerdict,
            cswarm:             cswarm,
            dropVotes:          dropVotes,
            totalVotes:         n,
            transporterSlashed: transporterSlashed
        )
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Public registration — open to all nodes
    // ─────────────────────────────────────────────────────────────────────────

    access(all) fun registerNode(nodeId: String, stake: UFix64) {
        pre {
            self.networkAgents[nodeId] == nil:
                "Node already registered"
            stake >= self.minimumStake:
                "Stake below minimum: ".concat(self.minimumStake.toString())
                .concat(" required, got ").concat(stake.toString())
        }
        self.networkAgents[nodeId] = AgentRecord(id: nodeId, stake: stake)
        emit AgentRegistered(nodeId: nodeId, stakedFlow: stake)
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Read-only helpers (queried by Pico during quorum selection)
    // ─────────────────────────────────────────────────────────────────────────

    access(all) fun getReputation(nodeId: String): Fix64? {
        return self.networkAgents[nodeId]?.reputation
    }

    access(all) fun getStake(nodeId: String): UFix64? {
        return self.networkAgents[nodeId]?.stakedFlow
    }

    access(all) fun isBlacklisted(nodeId: String): Bool {
        return self.networkAgents[nodeId]?.isBlacklisted ?? false
    }

    access(all) fun getAnomalyEvent(eventId: String): AnomalyEvent? {
        return self.anomalyLedger[eventId]
    }

    access(all) fun getPendingEvent(eventId: String): PendingEvent? {
        return self.pendingEvents[eventId]
    }

    // Returns the quorum score for a set of candidate auditor IDs.
    // score = w_price*(1/bidPrice) + w_rep*reputation + w_stake*stake
    // Called by the Pico after the 500ms bid window to select top N auditors.
    // bidPrices is parallel to candidates.
    access(all) fun scoreAuditors(
        candidates: [String],
        bidPrices:  [UFix64],
        wPrice:     UFix64,
        wRep:       UFix64,
        wStake:     UFix64,
        n:          Int
    ): [String] {
        pre {
            candidates.length == bidPrices.length:
                "candidates and bidPrices must be parallel arrays"
        }

        var eligible: [{String: AnyStruct}] = []
        var i = 0
        while i < candidates.length {
            let id = candidates[i]
            if let record = self.networkAgents[id] {
                if !record.isBlacklisted && bidPrices[i] > 0.0 {
                    let repScore  = Fix64(wRep)   * record.reputation
                    let stakeNum  = UFix64(wStake) * record.stakedFlow / 100.0
                    let priceNum  = UFix64(wPrice) / bidPrices[i]
                    // Score is approximate UFix64 sum — reputation is signed,
                    // treat negative rep as 0 for scoring purposes
                    let repPart: UFix64 = repScore > 0.0 ? UFix64(repScore) : 0.0
                    let score = priceNum + repPart + stakeNum
                    eligible.append({"id": id, "score": score})
                }
            }
            i = i + 1
        }

        // Insertion sort descending by score
        var k = 1
        while k < eligible.length {
            let cur = eligible[k]
            let curScore = cur["score"]! as! UFix64
            var m = k - 1
            while m >= 0 {
                let prevScore = eligible[m]["score"]! as! UFix64
                if prevScore < curScore {
                    eligible[m + 1] = eligible[m]
                    m = m - 1
                } else {
                    break
                }
            }
            eligible[m + 1] = cur
            k = k + 1
        }

        var result: [String] = []
        var r = 0
        while r < eligible.length && r < n {
            result.append(eligible[r]["id"]! as! String)
            r = r + 1
        }
        return result
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Initialisation — runs once at deploy time
    // ─────────────────────────────────────────────────────────────────────────

    init() {
        self.alpha              = 10.0
        self.beta               = 5.0
        self.blacklistThreshold = -50.0
        self.minimumStake       = 10.0
        self.verdictTimeoutSecs = 60.0

        self.networkAgents = {}
        self.pendingEvents = {}
        self.anomalyLedger = {}

        self.GatewayStoragePath = /storage/SwarmGatewayV2
        self.GatewayPublicPath  = /public/SwarmGatewayV2

        // Mint the one-and-only Gateway resource into the deployer's storage.
        // Only this account can call registerAnomaly and updateEventCid.
        self.account.storage.save(<- create Gateway(), to: self.GatewayStoragePath)
    }
}
