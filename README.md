# FirewallX-Core 🔐

Smart Firewall and Intrusion Detection System (IDS) built from scratch using Python.

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
