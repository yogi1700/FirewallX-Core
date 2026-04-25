# FirewallX-Core 🔐

Rule-based Smart Firewall and Intrusion Detection System (IDS) prototype built from scratch using Python and Scapy.

---

## 🚀 Overview

FirewallX-Core captures live network traffic, inspects packets, applies configurable rules, and simulates security decisions (allow / block).

---

## 🧱 Architecture

Packet Capture → Parse → Rule Engine → Decision

---

## 🎯 Current Features

* Packet capture using Scapy
* IP-based filtering
* Port-based filtering
* Dynamic JSON rule configuration
* Simulated firewall decision engine

---

## 🛠️ Tech Stack

* Python
* Scapy
* TCP/IP Networking

---

## 📌 Example Output

```text
[BLOCKED:PORT] TCP ... PORT:53
[BLOCKED:IP] 10.232.93.238 -> 10.232.93.106
[ALLOWED] TCP ... PORT:443
```

---

## 📅 Progress

* Day 1 — Packet capture + extraction
* Day 2 — TCP filtering
* Day 3 — IP filtering
* Day 4 — Firewall engine
* Day 5 — Dynamic JSON rules

---

## ⚠️ Current Limitation

Current implementation performs rule evaluation and simulated blocking.
Real packet enforcement is the next step.

---

## 🔜 Next Steps

* Windows Firewall enforcement
* Logging system
* Port scan detection (IDS)
