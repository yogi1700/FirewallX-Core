# FirewallX-Core

Smart Firewall and Intrusion Detection System (IDS) built from scratch using Python.
## 🔄 System Flow

FirewallX-Core follows a multi-stage pipeline:

```text
Packet Capture → Parsing → Detection → Threat Scoring → Enforcement → Logging → Summary
```

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

## 🚀 Overview

FirewallX-Core captures live network traffic, applies firewall rules, enforces blocking via Windows Firewall, and detects suspicious behavior using multiple anomaly detection techniques.

---

## 🎯 Features

* Packet capture using Scapy
* Firewall rule engine (IP & Port based)
* Windows Firewall enforcement (netsh integration)
* Logging system with timestamps
* Intrusion Detection System (IDS) with multi-layer detection

### 🔍 Detection Capabilities

* Repeated block detection
* Port scan detection
* Host sweep (reconnaissance) detection
* Time-based rate detection (burst traffic)

---

## 🛠️ Tech Stack

* Python
* Scapy
* Windows Firewall (netsh)
* Networking (TCP/IP)

---

## 🧠 Architecture

```text
Packet Capture → Rule Engine → Enforce → Log → Detect → Alert
```

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

---

## 📊 Example Alerts

```
[ALERT] Suspicious repeated blocks from 10.232.93.106
[RATE ALERT] High activity from 10.232.93.106 (5 events in 5s)
[HOST SWEEP ALERT] Possible recon from 10.232.93.106
[SCAN ALERT] Possible port scan from 10.232.93.106
```

---

## 📁 Project Structure

```
FirewallX-Core/
├── src/
│   ├── firewall_engine.py
│   ├── enforce_firewall.py
│   └── logger.py
│
├── archive/
│   └── src/   # legacy prototype modules
│
├── config/
├── logs/
└── README.md
```

---

## 🔮 Next Steps

* Threat scoring system (combine alerts into severity levels)
* Advanced anomaly detection
* Real-time dashboard / UI
* Cross-platform firewall support

---

## 💬 Summary

FirewallX-Core has evolved from a basic packet sniffer into a **multi-layer firewall + IDS prototype** with:

* Real-time traffic monitoring
* Automated enforcement
* Logging and alerting
* Behavior-based anomaly detection

---
