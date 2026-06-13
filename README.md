# Port Scan Detection Engineering Lab

A hands-on, Dockerized sandbox environment for building custom detection logic to identify malicious network scanning (nmap, masscan) using Python and Scapy.

## Overview
This project simulates a small, isolated network to demonstrate how port scanning works and how security engineers detect it. It includes:
*   **Victim Node**: A vulnerable target running standard services (Nginx, SSH).
*   **Attacker Node**: A kali-like environment preloaded with network exploration tools (`nmap`).
*   **Detector Node**: A custom Python/Scapy engine that sniffs network traffic and alerts on rapid, sequential connection attempts across multiple ports.

## Architecture
The lab uses `docker-compose` to network three containers:
1.  `lab_victim` (IP: 10.0.0.5)
2.  `lab_attacker` (IP: 10.0.0.10)
3.  `lab_detector` (Shares the network namespace of the victim)

## Getting Started

### 1. Build and Start the Lab
```bash
docker-compose up --build -d
```

### 2. View Detector Logs
Open a terminal to watch the detection engine in real-time:
```bash
docker-compose logs -f detector
```

### 3. Launch an Attack
Open a second terminal and use the attacker container to scan the victim:
```bash
# Standard Noisy SYN Scan
docker-compose exec attacker nmap -sS -p 1-100 10.0.0.5

# Stealth FIN Scan
docker-compose exec attacker nmap -sF -p 1-100 10.0.0.5

# Decoy Scan (IP Spoofing)
docker-compose exec attacker nmap -D 10.0.0.99,ME -p 1-100 10.0.0.5
```

## Detection Logic (`detector.py`)
The Python script relies on the `scapy` library to inspect raw TCP packets. 
*   It monitors for packets with `SYN`, `FIN`, `NULL`, or `XMAS` flags.
*   It tracks the Source IP address.
*   If a single Source IP attempts to connect to more than 15 unique ports within a 5-second sliding window, it triggers a High-Priority Alert.

## Educational Purpose
This repository is strictly for educational purposes to understand network protocol manipulation and detection engineering fundamentals.
