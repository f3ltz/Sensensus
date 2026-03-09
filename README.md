<<<<<<< HEAD
Phase 1: The Secure Local Swarm & TinyML (March 6 - March 8)

The focus here is getting the hardware and simulated nodes talking, but now every single packet must be cryptographically signed to prevent Sybil attacks.

Ranjit's Tasks (The Transporter - C++/Pico 2 W):

    Hardware & TinyML: Wire the BNO085 IMU. Write the C++ script to log acceleration data. Flash the converted TensorFlow Lite Micro 1D CNN model to detect drops.

    Cryptographic Identity: Integrate a lightweight C library like micro-ecc or mbedtls. Generate an ECDSA public/private key pair on boot.

    Secure Networking: Set up the lwip UDP Multicast listener. Only accept UDP beacons from Auditors if their ECDSA signature matches their public key. Drop all unsigned or invalid packets immediately.

    x402 Server: Spin up the local HTTP server to handle the 402 Payment Required logic and serve the 1.5-second CSV buffer upon valid payment simulation.

Asrith's Tasks (The Auditors - Python):

    Model Training & Identity: Train Model A (CNN for Pico) and Model B (Random Forest for Python). Add the Python ecdsa library to generate key pairs for each simulated Auditor node.cv

    Signed UDP Beacons: Write the script to broadcast UDP beacons every 5 seconds. The payload must include the node's public key and a cryptographic signature.

    x402 Purchasing: Listen for the Transporter's anomaly broadcast. Send a signed UDP bid. Execute the HTTP GET request, catch the 402, sign the dummy invoice, and retrieve the data to run through Model B.

Phase 2: Staking & The Web3 Bridge (March 9 - March 11)

The local swarm is securing itself mathematically. Now, we bridge it to Flow and Storacha to enforce the economic staking and reputation slashing.

Asrith's Tasks (Flow & Storacha):

    Smart Contract Staking: Write the SwarmVerifier.cdc Cadence contract. Implement a registry where new public keys must lock up testnet FLOW tokens to participate. Initialize all new nodes with a reputation score of exactly 0.

    Slashing Logic: Code the mathematical consensus check into the contract:
    Rt+1​=Rt​+α(Cswarm​−Vagent​)−β(L)

    Ensure that if Vagent​ deviates from the swarm consensus, the smart contract automatically slashes their staked tokens and broadcasts a blacklist event. Deploy this to the Flow Testnet.

    Edge Gateway Script: Write the Python bridge. Upload the encrypted CSV buffer and ML logs to Storacha to get the CID. Submit the CID, the nodes' public keys, and the consensus result to the deployed Flow contract.

Ranjit's Tasks (Payload Polish):

    Immutable Structuring: Ensure the final JSON payload leaving the Pico 2 W contains the exact ECDSA signatures, the winning Auditor's public key, and the confidence score so the Gateway can cryptographically prove the interaction on-chain.

Phase 3: Integration & The Sybil Dashboard (March 12 - March 14)

The judges need to see the network actively defending itself.

Joint Tasks:

    End-to-End Testing: Run the full pipeline. Trigger a drop, verify the signature, process the x402 payment, upload to Storacha, and watch the Flow smart contract settle the reputation score.

    The "Zero-Trust" Dashboard: Build the React or Python Streamlit interface.

        Live IMU View: Visualize the 3D orientation of the hardware.

        Network Graph: Show nodes popping in via UDP. Crucially, add a visual indicator for "Signature Verified" vs. "Rejected" to prove the Sybil resistance is working.

        Staking Ledger: Display the live FLOW testnet balances and the R scores of the participating nodes.

        The Receipt: Show the final Storacha CID and the Flow block explorer link.

Phase 4: Buffer & Polish (March 15 - March 16)

    Code Freeze: No new features.

    Attack Simulation: Manually spin up a malicious Python node that outputs garbage data or bad signatures and record the network rejecting/slashing it. This is your core pitch demonstration.

    Documentation & Pitch: Finalize the GitHub README and record the demo video showing the physical drop and the resulting on-chain slash/reward.
=======
# Sensensus
>>>>>>> 6da3c403f5121db6f5ed9c22a800d1cfe9376a72
