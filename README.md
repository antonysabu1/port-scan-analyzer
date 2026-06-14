<p align="center">
  <h1 align="center">🛡️ NEXUS — Port Scan Detection & Prevention Lab</h1>
  <p align="center">
    <strong>A Docker-based Intrusion Prevention System (IPS) with real-time threat monitoring, deception technology, and forensic packet capture.</strong>
  </p>
  <p align="center">
    <img src="https://img.shields.io/badge/Python-3.11-blue?logo=python&logoColor=white" alt="Python">
    <img src="https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white" alt="Docker">
    <img src="https://img.shields.io/badge/Scapy-Packet%20Analysis-green" alt="Scapy">
    <img src="https://img.shields.io/badge/License-MIT-yellow" alt="License">
    <img src="https://img.shields.io/badge/Status-Active-brightgreen" alt="Status">
  </p>
</p>

---

## 📋 Overview

NEXUS is a hands-on **Detection Engineering laboratory** built entirely from scratch. It simulates real-world network reconnaissance attacks and provides automated detection, prevention, and forensic analysis capabilities — all running inside an isolated Docker environment.

This project demonstrates practical skills in:
- **Network Security** — Packet sniffing, firewall manipulation, threat intelligence
- **Detection Engineering** — Custom rule creation, threshold-based alerting, deception technology
- **Incident Response** — Automated blocking, forensic evidence capture, real-time notification
- **Full-Stack Development** — Python backend, HTML/CSS/JS dashboard, Docker orchestration

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Docker Network: lab_net                   │
│                      (10.0.0.0/24)                          │
│                                                             │
│  ┌──────────────┐    Attack Traffic    ┌──────────────────┐ │
│  │   ATTACKER   │ ──────────────────►  │     VICTIM       │ │
│  │  10.0.0.10   │    Nmap Scans        │    10.0.0.5      │ │
│  │  (Nmap/Curl) │                      │  (Nginx/SSH)     │ │
│  └──────────────┘                      │                  │ │
│                                        │  ┌────────────┐  │ │
│                                        │  │  DETECTOR   │  │ │
│                                        │  │  (Scapy)    │  │ │
│                                        │  │  Shared NS  │  │ │
│                                        │  └─────┬──────┘  │ │
│                                        └────────┼─────────┘ │
│                                                 │           │
│              ┌──────────────────────────────────┘           │
│              │  Alerts (JSON + SQLite + PCAP)               │
│              ▼                                              │
│  ┌────────────────────┐                                     │
│  │     DASHBOARD      │◄──── http://localhost:8080          │
│  │    10.0.0.15       │                                     │
│  │  (Nginx + Chart.js)│                                     │
│  └────────────────────┘                                     │
└─────────────────────────────────────────────────────────────┘
```

---

## ✨ Features

### 🔍 Multi-Protocol Detection Engine
| Protocol | Detection Method | Description |
|----------|-----------------|-------------|
| **TCP** | SYN / FIN / NULL / XMAS | Detects all major Nmap TCP scan types |
| **UDP** | Threshold-based | Catches UDP port scans (`nmap -sU`) |
| **ICMP** | Ping Sweep | Detects host discovery sweeps (`nmap -sn`) |

### 🛑 Active Defense (Intrusion Prevention)
When a scan is detected, the system **automatically bans** the attacker's IP address at the Linux kernel level using `iptables`. The attacker is permanently locked out — subsequent scan attempts will silently fail.

### 🪤 Deception Technology (Honeyports)
Highly sensitive ports are deployed as invisible tripwires:
- **Port 21** — FTP
- **Port 23** — Telnet  
- **Port 3306** — MySQL
- **Port 3389** — RDP
- **Port 5900** — VNC

If **any** IP touches these ports even once, they are **instantly and permanently banned** — no threshold required.

### 🎭 Decoy Scan Detection (Anti-Spoofing)
Detects Nmap's `-D` (Decoy) evasion technique by correlating MAC addresses with source IPs. If multiple IPs originate from the same hardware MAC address, NEXUS identifies a single attacker spoofing their identity and bans them.

### 🛡️ IP Whitelisting
Trusted IPs (e.g., the victim itself, localhost) are permanently whitelisted so they are never accidentally banned by the IPS.

### 📁 PCAP Forensic Export
Every detected attack automatically generates a `.pcap` file containing the raw suspicious packets. These files can be opened in **Wireshark** for deep forensic analysis and can serve as legal evidence.

### 🌐 Threat Intelligence Integration
On detection, the system queries the `ip-api.com` API to retrieve the attacker's:
- **City and Country**
- **Internet Service Provider (ISP)**

### 📊 Real-Time Web Dashboard
A cyberpunk-themed monitoring interface at `http://localhost:8080` featuring:
- Live alert counter and threat IP display
- Interactive **Chart.js** timeline graph
- Scrolling alert feed with Location, ISP, and BAN status

### 📱 Telegram Push Notifications *(Optional)*
Configure a Telegram Bot to receive instant push notifications on your phone when an attack is detected.

---

## 🚀 Quick Start

### Prerequisites
- [Docker](https://docs.docker.com/get-docker/) and [Docker Compose](https://docs.docker.com/compose/install/)
- Git

### 1. Clone the Repository
```bash
git clone https://github.com/antonysabu1/port-scan-analyzer.git
cd port-scan-analyzer
```

### 2. Build and Launch the Lab
```bash
docker-compose up --build -d
```

### 3. Open the Dashboard
Navigate to **[http://localhost:8080](http://localhost:8080)** in your web browser.

### 4. Simulate an Attack
```bash
# TCP SYN Scan (Mass Port Scan)
docker-compose exec -T attacker nmap -sS -p 1-100 10.0.0.5

# Honeyport Tripwire (Instant Ban)
docker-compose exec -T attacker nmap -sS -p 3306 10.0.0.5

# UDP Scan
docker-compose exec -T attacker nmap -sU -p 1-50 10.0.0.5

# ICMP Ping Sweep
docker-compose exec -T attacker nmap -sn 10.0.0.0/24

# Stealth FIN Scan
docker-compose exec -T attacker nmap -sF -p 1-100 10.0.0.5
```

### 5. Verify the Ban
Run the same scan again — it will hang or show all ports as `filtered`:
```bash
docker-compose exec -T attacker nmap -sS -p 1-100 10.0.0.5
# Output: 100 filtered tcp ports (no-response)
```

---

## 📱 Telegram Notifications (Optional)

1. Message [@BotFather](https://t.me/BotFather) on Telegram → `/newbot`
2. Get your Chat ID from [@userinfobot](https://t.me/userinfobot)
3. Create a `.env` file in the project root:
```env
TELEGRAM_BOT_TOKEN="your-bot-token-here"
TELEGRAM_CHAT_ID="your-chat-id-here"
```
4. Add `env_file: .env` under the `detector` service in `docker-compose.yml`
5. Restart: `docker-compose restart detector`

---

## 🗂️ Project Structure

```
port-scan-analyzer/
├── docker-compose.yml          # Orchestration (4 containers + network)
├── README.md                   # Documentation
├── .gitignore                  # Prevents secrets from being committed
│
├── attacker/
│   └── Dockerfile              # Alpine + Nmap + curl
│
├── victim/
│   └── Dockerfile              # Alpine + Nginx + Dropbear SSH
│
├── detector/
│   ├── Dockerfile              # Python 3.11 + Scapy + iptables
│   └── detector.py             # Core IPS engine (~280 lines)
│
└── dashboard/
    ├── Dockerfile              # Nginx (serves static files)
    ├── index.html              # Dashboard layout
    ├── style.css               # Cyberpunk dark theme
    └── script.js               # Chart.js + live polling logic
```

---

## 🛠️ Tech Stack

| Component | Technology |
|-----------|-----------|
| Detection Engine | Python 3.11 + Scapy |
| Active Defense | iptables (Linux Kernel Firewall) |
| Packet Forensics | Scapy `wrpcap` → PCAP files |
| Threat Intel | ip-api.com REST API |
| Database | SQLite3 |
| Dashboard | HTML5 + CSS3 + Vanilla JS |
| Charting | Chart.js |
| Notifications | Telegram Bot API |
| Infrastructure | Docker + Docker Compose |
| Networking | Isolated Bridge Network (10.0.0.0/24) |

---

## 🔬 Detection Logic

```
Incoming Packet
      │
      ├── TCP? ──► Check Honeyports ──► INSTANT BAN
      │              │
      │              └── Check Decoy (MAC correlation)
      │              │
      │              └── Threshold Check (>15 ports/5s) ──► BAN + ALERT
      │
      ├── UDP? ──► Check Honeyports ──► INSTANT BAN
      │              │
      │              └── Threshold Check (>15 ports/5s) ──► BAN + ALERT
      │
      └── ICMP? ─► Ping Sweep Check (>10 pings/5s) ──► BAN + ALERT
```

---

## 📄 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

<p align="center">
  Built with 🔥 by <strong>Antony Sabu</strong> — Detection Engineering Lab
</p>
