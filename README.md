
# SENSENSUS
**Zero-Trust IoT Swarms Secured by TinyML, Cryptography, and Web3 Staking.**

🌐 **Live Dashboard Demo:** [Launch Sensensus Mission Control](https://sensensus.vercel.app/)

![Flow](https://img.shields.io/badge/Blockchain-Flow_Testnet-16FF96?style=for-the-badge&logo=flow)
![TinyML](https://img.shields.io/badge/Edge_AI-TensorFlow_Lite-FF6F00?style=for-the-badge&logo=tensorflow)
![Hardware](https://img.shields.io/badge/Hardware-Pi_Pico_2W-C51A4A?style=for-the-badge&logo=raspberrypi)
![License](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)

## The Problem
In industries spanning supply chain logistics, high-value asset insurance, and remote equipment monitoring, IoT data is traditionally treated as the absolute ground truth. However, hardware sensors represent a massive vulnerability in both traditional systems and modern Web3 architectures. This is known as the "Oracle Problem."

Spoofing an IoT sensor is trivial. If a bad actor physically compromises a single sensor, alters its calibration, or injects fake network packets into the data stream, they can trigger fraudulent insurance claims, hide equipment damage, or disrupt global logistics. Traditional centralized networks blindly trust the data source, creating a massive single point of failure that cannot be solved by software alone.

## The Solution
Sensensus is a **zero-trust** cyber-physical system built to eliminate blind trust in edge devices. We solve the Oracle Problem by mathematically decoupling physical event detection from event verification. When an IoT node detects an anomaly, it cannot simply declare it as fact—it must prove the claim to a decentralized, staked swarm of peer verifier nodes.

If a node is caught lying, deviating, or hallucinating data, the smart contract:

* **Automatically slashes its funds**
* **Permanently damages its on-chain reputation**

This creates a cryptoeconomic truth layer for physical sensor events.

### Key Features
* **Zero-Trust Hardware:** Raw sensor data is locally inferred using a 1D Convolutional Neural Network before ever touching the internet.
* **Cryptographic Sybil Resistance:** Every node signs its data beacons using ECDSA (secp256r1) elliptic curves to prevent node spoofing and man-in-the-middle attacks.
* **HTTP x402 Data Tolls:** A unique implementation of the `402 Payment Required` protocol to prevent network spam and monetize hardware data buffering.
* **Immutable Settlement:** Flow blockchain smart contracts handle all consensus logic, economic slashing, and ledger settlements autonomously.

## Submission Details
- **Code Status:** Protocol Labs — **Fresh Code** (built entirely during the hackathon)

## Tracks Targeted

### AI & Robotics
- Swarm coordination frameworks
- Verifiable AI
- x402 agent-to-agent machine payment tolls

### Crypto
- DePIN sensor network
- Novel economic slashing and governance
- Contributor rewards for environmental or infrastructure data

### Neurotech
- Zero-trust verification for biometric and neurological edge sensors
- Prevention of spoofed human-computer interface inputs
- Swarm decision tools for real-time distributed consensus

### Infrastructure & Digital Rights
- Securing the physical data layer for a decentralized internet

## Sponsor Bounties Integrated
- **Flow:** Core consensus logic, escrow management, and economic slashing via the `SwarmVerifierV4.cdc` Cadence smart contract
- **Storacha:** Decentralized immutable IPFS storage for verified machine learning CSV payloads post-consensus
- **NEAR Protocol:** Integration for best new/continued project
---

## System Architecture & Event Lifecycle

Every detected anomaly undergoes a rigorous 4-stage "Race to Quorum" before being written to the immutable ledger. 

![Event Consensus Lifecycle](./Images/diagram_1_lifecycle.png)
> *Figure 1: The 4-phase lifecycle of an anomaly on the Flow blockchain.*

Our network is divided into two distinct roles: **The Transporter** (the physical asset being tracked) and **The Auditor Swarm** (the decentralized verification network).

### 1. Hardware Detection (Edge AI)
- The **Transporter** (a Raspberry Pi Pico 2 W) samples a high-precision BNO085 IMU (accelerometer and quaternions) at a constant 50Hz.
- An onboard TensorFlow Lite Micro 1D-CNN model continuously runs inference on the data buffer at 1Hz, looking for specific shock signatures.
- If a physical drop is detected with a confidence rating of `>= 0.85`, the node shifts from `STATE_IDLE` to `STATE_ANOMALY`.

### 2. Cryptographic Beacons & Network Topology
Once in an anomaly state, the Transporter must alert the network without relying on a centralized broker. It generates an ECDSA signature of the event timestamp and broadcasts a UDP multicast beacon to the local network. 

![Network Topology](./Images/diagram_2_topology.png)
> *Figure 2: Data flows from the Hardware Edge, through the Auditor Swarm, and settles On-Chain.*

- Python-based **Auditor nodes** intercept this beacon and verify the public key signature to ensure the Transporter is a registered, staked network participant.
- Auditors submit bids (in Flow tokens) to verify the data. The Transporter selects a quorum based on the Auditors' available stake and their historical reputation scores.

### 3. Verification & The Web3 Bridge
- Selected Auditors pay a dummy **HTTP 402 Payment Required** toll to unlock a 1.5-second CSV buffer of the raw drop data from the Transporter's memory allocation.
- Auditors run the CSV through a secondary, independent Machine Learning model (e.g., a Random Forest classifier via scikit-learn) to mathematically cross-check the hardware's claim.
- The raw data and ML verification logs are encrypted and uploaded to **Storacha** (Filecoin/IPFS) for immutable storage, generating a globally verifiable CID.

### 4. Smart Contract Settlement & Game Theory
Auditors submit their final ML verdict (Drop vs. Normal) to the Flow blockchain via a signed transaction. The `SwarmVerifierV4.cdc` Cadence smart contract waits for the quorum to finish, then executes the Incentive Matrix:

![Incentive Matrix](./Images/diagram_3_gametheory.png)
> *Figure 3: The Game Theory and economic incentive matrix governed by SwarmVerifier.cdc.*

- **Aligned Auditors:** If an auditor's verdict matches the Swarm Consensus (`cswarm`), they are rewarded with their deposit back, plus the bid price payout, and a reputation boost.
- **Deviated/Malicious Nodes:** If a node contradicts the mathematical consensus (either due to a faulty ML model or malicious intent), its stake is slashed and its reputation drops. If reputation drops below `-50.0`, the node is permanently blacklisted and evicted from the network.

---

## Security Model

Sensensus is designed to withstand several attack vectors common to IoT networks:

1. **Hardware Tampering / Spoofing:** If an attacker hits a sensor with a hammer to simulate a drop, the raw IMU data signature will differ from a true free-fall impact. The Auditor Swarm's independent ML models will flag the data as anomalous and slash the Transporter.
2. **Sybil Attacks:** An attacker cannot spin up thousands of fake Transporters or Auditors. Every node must be registered on the Flow blockchain with an active financial stake.
3. **Network Spam / DDoS:** Transporters protect their limited memory buffers by requiring an HTTP 402 payment before releasing data, making DDoS attacks financially unviable.

---

## Tech Stack

**Edge Hardware & Firmware**
* Raspberry Pi Pico 2W (RP2350)
* BNO085 9-DOF IMU (I2C/Serial)
* C++ / PlatformIO
* lwIP UDP Multicast & HTTP Server

**Machine Learning**
* TensorFlow Lite Micro (C++ execution on Edge)
* scikit-learn (Python execution on Auditor Nodes)
* 1D Convolutional Neural Networks & Random Forest Classifiers

**Blockchain & Storage**
* Flow Testnet
* Cadence Smart Contracts (`SwarmVerifierV4.cdc`)
* Storacha (IPFS CID generation for immutable data proofs)

**Frontend Dashboard**
* React.js + Vite
* Custom CSS (Zero-Trust Mission Control UI)
* Flow FCL (Flow Client Library)

---

## Getting Started  
To run the full end-to-end system, you will need to deploy the smart contract, flash the edge hardware, spin up the local auditor swarm, and launch the dashboard.
### Prerequisites
* PlatformIO installed via VSCode.
* Flow CLI installed on your host machine.
* Node.js v18+ and npm.
* Python 3.9+ with `scikit-learn` and `requests` installed.

#### Step 1: Flash the Hardware (The Transporter)
1. Wiring the BNO085 to the Pico 2W:
- `VIN` ➔ `3.3V (OUT)`
- `GND` ➔ `GND`
- `SDA` ➔ `GPIO 4`
- `SCL` ➔ `GPIO 5`
2. Open the `Transporter_Pico` directory in PlatformIO
3. Navigate to `platformio.ini` and update the following definitions
- `WIFI_SSID` and `WIFI_PASS` (must be on the same network as your laptop)
- `PICO_PRIV_KEY_HEX` (generate a random 64-character hex string for the Pico's identity)
4. Navigate to `src/config.h` and tweak the values as required.

Once the network is live, physically drop the hardware. Watch the React Dashboard visualize the network consensus, intercept the UDP packets, process the x402 payment, and trigger the Flow slashing event in real-time.
