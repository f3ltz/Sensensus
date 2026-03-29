# Sensensus
Zero-Trust IoT Swarms Secured by TinyML, Cryptography, and Web3 Staking.

## The Problem 
In industries like supply chain logistics, insurance, and remote monitoring, IoT data is treated as the ground truth. But spoofing an IoT sensor is trivial. If a bad actor physically compromises a sensor or injects fake network packets, they can trigger fraudulent insurance claims or hide equipment damage. Traditional networks blindly trust the data source.

## The Solution: Sensensus
Sensensus is complete end to end system built to reduce blind trust on IoT devices. We combine <B> Edge AI (TinyML), Cryptographic Identity</B>, and <B>Web3 Economic Slashing </B> to create a self-policing network of devices (a "swarm").

When a node detects a physical anomaly, it must mathematically prove its claim to a decentralized quorum of peer nodes. If the node is lying, the smart contract automatically slashes its staked funds.

## The system architecture
Our network is divided into two roles: **The Transporter** and **The Auditor**.

1. **Hardware Detection (TinyML)**  
    - The Transporter (Raspberry Pi Pico 2 W) samples a BNO085 IMU at 50Hz.
    - An onboard TensorFlow Lite Micro 1D CNN model runs inference at 1Hz.
    - If a physical drop is detected (Confidence >= 0.85), the node shifts from `STATE_IDLE` to `STATE_ANOMALY`.

2. **Cryptographic Beacons & x402 Bidding**
    - The Transporter generates an ECDSA (secp256r1) signature of the event.
    - It broadcasts a UDP beacon. Python Auditor nodes receive this beacon and verify the public key signature to prevent Sybil attacks.
    - Auditors submit bids to verify the data. The Transporter selects a quorum based on the Auditors' Flow token stake and their respective reputation scores.

3. **Verification & The Web3 Bridge**
    - Auditors pay a dummy **HTTP 402 Payment Required** toll to fetch a 1.5-second CSV buffer of the drop data from the Transporter.
    - Auditors run the CSV through a secondary Random Forest ML model (or any model of their choosing, in our implementation our auditor uses Random Forest) to cross-check the hardware's claim.
    - The encrypted data and ML logs are uploaded to **Storacha** for immutable storage, generating a verifiable CID.

4. **Smart Contract Settlement (Flow Blockchain)**
    - The `SwarmVerifier.cdc` Cadence smart contract calculates the mathematical consensus (`cswarm`).
    - **Aligned Auditors:** Rewarded with their deposit back plus the bid price and a reputation boost.
    - **Deviated/Malicious Nodes:** Penalized via stake slashing and a reputation drop. If reputation drops below -50.0, the node is permanently blacklisted.

## Tech Stack
- **Hardware:** Raspberry Pi Pico 2W, BNO085 IMU
- **Edge ML:** TensorFlow Lite Micro (C++), scikit-learn (Python)
- **Blockchain:** Flow Testnet, Cadence (`SwarmVerifierV4`)
- **Decentralized Storage:** Storacha (IPFS CID generation)
- **Frontend:** React + Vite "Zero-Trust Dashboard"
- **Networking:** lwIP UDP Multicast, HTTP Server 
    
## Getting Started
1. Flash the Hardware

Navigate to the `PICOPART` directory. Make sure to define your Wi-Fi credentials in the conffig file and flash the firmware using PlatformIO.
```
cd PICOPART
pio run --target upload
```
2. Deploy Flow Smart Contract
Deploy the staking and consensus logic to the Flow testnet:

```
flow project deploy --network testnet
```
3. Spin up the Dashboard
```
cd dashboard
npm install
npm run dev
```
4. Run the Python Auditors & Trigger an Event

Start your auditor nodes in separate terminal windows. Then, physically drop the hardware. Watch the React Dashboard visualize the network consensus, intercept the UDP packets, process the x402 payment, and trigger the Flow slashing event in real-time!