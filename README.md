# FirewallX-Core

Smart Firewall and Intrusion Detection System (IDS) built from scratch using Python.
## 🔄 System Flow

FirewallX-Core follows a multi-stage pipeline:

```text
Packet Capture → Parsing → Detection → Threat Scoring → Enforcement → Logging → Summary
```
                        ┌───────────────────┐
                        │ Packet Arrives    │
                        │ (Scapy sniff)     │
                        └─────────┬─────────┘
                                  ↓
                        ┌───────────────────┐
                        │ IP Layer Check     │
                        │ haslayer(IP)?      │
                        └─────────┬─────────┘
                                  ↓
                        ┌────────────────────────┐
                        │ Extract Packet Data     │
                        │ src_ip, dst_ip, port   │
                        └─────────┬─────────────┘
                                  ↓
            ┌──────────────────────────────────────────┐
            │ Is src_ip == LOCAL_IP ?                  │
            └───────────┬───────────────────────┬──────┘
                        │ YES                   │ NO
                        ↓                       ↓
        ┌──────────────────────────┐        Skip Detection
        │     DETECTION ENGINE      │
        └──────────┬───────────────┘
                   ↓
        ┌────────────────────────────┐
        │ Rate Detection             │
        │ - Track timestamps         │
        │ - Detect burst traffic     │
        └──────────┬─────────────────┘
                   ↓
        ┌────────────────────────────┐
        │ Port Scan Detection        │
        │ - Track unique ports       │
        │ - Ignore safe ports        │
        └──────────┬─────────────────┘
                   ↓
        ┌────────────────────────────┐
        │ Host Sweep Detection       │
        │ - Track destination IPs    │
        │ - Detect recon behavior    │
        └──────────┬─────────────────┘
                   ↓
        ┌────────────────────────────┐
        │ Cooldown Control           │
        │ - Prevent alert spam       │
        └──────────┬─────────────────┘
                   ↓
        ┌────────────────────────────┐
        │ Trigger Alert              │
        │ - RATE ALERT               │
        │ - SCAN ALERT               │
        │ - HOST SWEEP ALERT         │
        └──────────┬─────────────────┘
                   ↓
        ┌────────────────────────────┐
        │ Threat Scoring Engine      │
        │ update_threat_score()      │
        └──────────┬─────────────────┘
                   ↓
        ┌────────────────────────────┐
        │ Calculate Threat Level     │
        │ LOW / MED / HIGH / CRIT    │
        └──────────┬─────────────────┘
                   ↓
        ┌────────────────────────────────┐
        │ Decision Engine (IPS Logic)    │
        │                                │
        │ LOW      → Log only            │
        │ MEDIUM   → Monitor             │
        │ HIGH     → Warning             │
        │ CRITICAL → Auto Block          │
        └──────────┬─────────────────────┘
                   ↓
        ┌────────────────────────────┐
        │ Auto Response (if needed)  │
        │ enforce_ip_block()         │
        └──────────┬─────────────────┘
                   ↓
        ┌────────────────────────────┐
        │ Firewall Rule Check        │
        │ - Block IP?                │
        │ - Block Port?              │
        └──────────┬─────────────────┘
                   ↓
        ┌────────────────────────────┐
        │ Output Layer               │
        │ - Print message            │
        │ - Write log                │
        └──────────┬─────────────────┘
                   ↓
        ┌────────────────────────────┐
        │ Session Summary            │
        │ - Threat scores            │
        │ - Tracking data            │
        └────────────────────────────┘

### 1. Packet Capture

* Uses Scapy to capture live network packets
* Each packet is processed in real-time

### 2. Packet Parsing

* Extracts:

  * Source IP
  * Destination IP
  * Protocol (TCP/UDP)
  * Port number

### 3. Monitoring Filter

* Focuses only on traffic originating from the local machine
* Reduces noise from external network traffic

### 4. Detection Layer (IDS)

Multiple anomaly detection techniques are applied:

* **Rate Detection**
  Detects burst traffic within a short time window

* **Host Sweep Detection**
  Detects communication with multiple destination IPs (possible reconnaissance)

* **Port Scan Detection**
  Detects access to multiple ports from a single source

* **Repeated Block Detection**
  Identifies repeated blocked traffic from the same source

### 5. Threat Scoring System

Each detected event contributes to a cumulative threat score:

* Repeated block → +2
* Rate alert → +3
* Host sweep → +3
* Port scan → +4

### 6. Threat Levels

Based on accumulated score:

* LOW (0–3)
* MEDIUM (4–6)
* HIGH (7–9)
* CRITICAL (10+)

### 7. Rule Engine

Applies firewall rules from configuration:

* Block specific IPs
* Block specific ports

### 8. Enforcement

* Automatically applies blocking rules using Windows Firewall (netsh)

### 9. Logging

* All events are logged for analysis
* Stored in `logs/firewall.log`

### 10. Session Summary

Displays:

* Blocked sources
* Scan tracking
* Destination tracking
* Rate tracking
* Threat scores

---

## 📅 Progress Log

### Day 1

* Setup Python, Scapy, Npcap
* Captured packets
* Extracted source/destination IPs and ports

### Day 2

* Added TCP filtering
* Implemented basic port-based blocking logic

### Day 3

* Added IP-based filtering
* Implemented rule checks for blocked IPs

### Day 4

* Combined modules into firewall_engine.py
* Built unified rule engine (IP + Port filtering)

### Day 5

* Added dynamic JSON rule configuration (rules.json)
* Refactored rule checks into functions
* Tested simulated enforcement behavior

### Day 6

* Added Windows Firewall enforcement using subprocess and netsh
* Connected rule engine decisions to automated response
* Added duplicate rule prevention

### Day 7

* Added logging system for firewall events
* Added threshold-based intrusion alert detection
* Generated alerts for repeated blocked traffic
* Reorganized legacy modules into archive/src

### Day 8

* Added basic port scan detection
* Added session summary output
* Added host sweep (reconnaissance) detection
* Improved anomaly detection logic

### Day 9

* Added time-based rate detection (burst traffic detection)
* Improved alert system by preventing duplicate alerts
* Enhanced multi-layer IDS detection pipeline

### Day 10

* Added threat scoring system to evaluate risk based on multiple alerts
* Introduced severity levels (LOW, MEDIUM, HIGH, CRITICAL)
* Integrated scoring across all detection mechanisms
* Replaced static IP checks with dynamic local IP detection
* Added flexible monitoring system for scalable network analysis
* Refactored code structure for better readability and maintainability

### Day 11

* Implemented auto-response system (IPS layer)
* Added threat-based decision logic (LOW → CRITICAL)
* Enabled automatic firewall blocking on CRITICAL threat level
* Prevented duplicate blocking using state tracking
* Improved detection logic to allow continuous scoring
* Introduced cooldown mechanism to avoid alert spam
* Achieved full IDS → IPS transition

