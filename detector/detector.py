from scapy.all import sniff, wrpcap, TCP, UDP, ICMP, IP, Ether
from collections import defaultdict
import time
import json
import os
import sqlite3
import requests
from datetime import datetime

# =============================================
#  NEXUS IPS - Configuration
# =============================================

THRESHOLD = 15                              # Max unique ports before auto-ban
WINDOW = 5                                  # Sliding window (seconds)
HONEY_PORTS = [21, 23, 3389, 3306, 5900]    # FTP, Telnet, RDP, MySQL, VNC
WHITELIST = ["10.0.0.5", "127.0.0.1"]       # IPs that should NEVER be banned
PCAP_DIR = "/app/logs/pcaps"                # Forensic packet capture directory
LOG_FILE = "/app/logs/alerts.json"
DB_FILE = "/app/logs/database.sqlite"

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")

# =============================================
#  State Tracking
# =============================================

scans = defaultdict(lambda: defaultdict(float))    # TCP scan tracker
udp_scans = defaultdict(lambda: defaultdict(float)) # UDP scan tracker
blocked_ips = set()                                 # Banned IP list
mac_ip_map = defaultdict(set)                       # MAC -> set of IPs (decoy detection)
captured_packets = []                               # Buffer for PCAP forensic export
icmp_tracker = defaultdict(list)                    # ICMP ping sweep tracker

# =============================================
#  Database Layer (Long-Term Memory)
# =============================================

def init_db():
    """Create SQLite tables for persistent alert storage."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS alerts
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                  timestamp TEXT, src_ip TEXT, ports INTEGER, 
                  location TEXT, isp TEXT, status TEXT, type TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS blocked
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  timestamp TEXT, ip TEXT, reason TEXT)''')
    conn.commit()
    conn.close()

# =============================================
#  Threat Intelligence API
# =============================================

def get_threat_intel(ip):
    """Query external API to profile attacker geolocation and ISP."""
    if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172."):
        return "Local Network", "Internal Lab System"
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=2).json()
        if response.get("status") == "success":
            return f"{response.get('city')}, {response.get('country')}", response.get('isp')
    except:
        pass
    return "Unknown Location", "Unknown ISP"

# =============================================
#  Notification System (Telegram)
# =============================================

def send_telegram(message):
    """Push critical alerts to Telegram."""
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {"chat_id": TELEGRAM_CHAT_ID, "text": message, "parse_mode": "Markdown"}
    try:
        requests.post(url, json=payload, timeout=2)
    except:
        pass

# =============================================
#  Active Defense (Intrusion Prevention)
# =============================================

def block_ip(ip, reason="Port Scan"):
    """Ban an attacker at the kernel firewall level using iptables."""
    if ip in blocked_ips or ip in WHITELIST:
        return
    os.system(f"iptables -A INPUT -s {ip} -j DROP")
    blocked_ips.add(ip)
    print(f"[IPS] 🛑 IP {ip} has been BANNED! Reason: {reason}")
    
    # Log the block to the database
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("INSERT INTO blocked (timestamp, ip, reason) VALUES (?, ?, ?)",
                  (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), ip, reason))
        conn.commit()
        conn.close()
    except:
        pass

# =============================================
#  PCAP Forensic Export
# =============================================

def save_pcap(packet, src_ip, alert_type):
    """Save suspicious packets to .pcap files for Wireshark forensic analysis."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_ip = src_ip.replace(".", "-")
    filename = f"{PCAP_DIR}/{timestamp}_{safe_ip}_{alert_type.replace(' ', '_')}.pcap"
    
    captured_packets.append(packet)
    try:
        wrpcap(filename, captured_packets[-50:])  # Save last 50 packets
        print(f"[FORENSICS] 📁 Packet capture saved: {filename}")
    except Exception as e:
        print(f"[FORENSICS] Failed to save PCAP: {e}")

# =============================================
#  Alert Pipeline
# =============================================

def log_alert(src_ip, port_count, alert_type="Port Scan Detected", packet=None):
    """Central alert handler: bans, logs, notifies, and exports forensics."""
    location, isp = get_threat_intel(src_ip)
    status = "BANNED"
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # 1. Active Defense — Ban the attacker
    block_ip(src_ip, reason=alert_type)
    
    # 2. Database Logging
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("INSERT INTO alerts (timestamp, src_ip, ports, location, isp, status, type) VALUES (?, ?, ?, ?, ?, ?, ?)",
                  (timestamp, src_ip, port_count, location, isp, status, alert_type))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[DB] Error: {e}")

    # 3. Telegram Push Notification
    telegram_msg = (
        f"🚨 *{alert_type}* 🚨\n\n"
        f"*Threat IP:* `{src_ip}`\n"
        f"*Ports Scanned:* {port_count}\n"
        f"*Location:* {location}\n"
        f"*ISP:* {isp}\n\n"
        f"*Action:* 🛑 IP BANNED"
    )
    send_telegram(telegram_msg)

    # 4. PCAP Forensic Export
    if packet:
        save_pcap(packet, src_ip, alert_type)

    # 5. Dashboard JSON Update
    alert = {
        "id": str(time.time()),
        "timestamp": timestamp,
        "source_ip": src_ip,
        "ports_scanned": port_count,
        "type": alert_type,
        "location": location,
        "isp": isp,
        "status": status
    }
    
    alerts = []
    if os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE, "r") as f:
                alerts = json.load(f)
        except:
            pass
            
    alerts.insert(0, alert)
    alerts = alerts[:50]
    
    with open(LOG_FILE, "w") as f:
        json.dump(alerts, f, indent=4)

# =============================================
#  Detection Engine
# =============================================

def detect_decoy(src_ip, mac_addr):
    """
    DECOY DETECTION (Nmap -D):
    If multiple different source IPs share the same MAC address,
    it means a single attacker is spoofing their IP to frame others.
    """
    if not mac_addr or mac_addr == "ff:ff:ff:ff:ff:ff":
        return
    
    mac_ip_map[mac_addr].add(src_ip)
    
    if len(mac_ip_map[mac_addr]) >= 3:
        decoy_ips = ", ".join(mac_ip_map[mac_addr])
        print(f"[DECOY] 🎭 Decoy scan detected! MAC {mac_addr} is using IPs: {decoy_ips}")
        log_alert(src_ip, len(mac_ip_map[mac_addr]),
                  alert_type=f"Decoy Scan (MAC: {mac_addr[:8]}..)")
        mac_ip_map[mac_addr].clear()

def detect_icmp_sweep(packet):
    """
    ICMP PING SWEEP DETECTION:
    Detects when a host sends ICMP Echo Requests to many IPs rapidly,
    which indicates network host discovery.
    """
    if ICMP in packet and IP in packet:
        src_ip = packet[IP].src
        
        if src_ip in WHITELIST or src_ip in blocked_ips:
            return
        
        current_time = time.time()
        icmp_tracker[src_ip].append(current_time)
        
        # Clean old entries outside the window
        icmp_tracker[src_ip] = [t for t in icmp_tracker[src_ip] if current_time - t <= WINDOW]
        
        if len(icmp_tracker[src_ip]) > 10:
            print(f"[ALERT] 📡 ICMP Ping Sweep from {src_ip}!")
            log_alert(src_ip, len(icmp_tracker[src_ip]), "ICMP Ping Sweep", packet)
            icmp_tracker[src_ip].clear()

def detect_udp_scan(packet):
    """
    UDP SCAN DETECTION:
    Monitors for rapid UDP probes to multiple ports from a single source.
    """
    if UDP in packet and IP in packet:
        src_ip = packet[IP].src
        
        if src_ip in WHITELIST or src_ip in blocked_ips:
            return
        
        dst_port = packet[UDP].dport
        current_time = time.time()
        
        # Honeyport check for UDP services
        if dst_port in HONEY_PORTS:
            print(f"[TRIPWIRE] 🪤 UDP Honeyport {dst_port} touched by {src_ip}!")
            log_alert(src_ip, 1, f"UDP Honeyport Tripwire (Port {dst_port})", packet)
            return
        
        # Clean old entries
        old_ports = [p for p, ts in udp_scans[src_ip].items() if current_time - ts > WINDOW]
        for p in old_ports:
            del udp_scans[src_ip][p]
        
        udp_scans[src_ip][dst_port] = current_time
        
        if len(udp_scans[src_ip]) > THRESHOLD:
            print(f"[ALERT] 📡 UDP Port Scan from {src_ip} ({len(udp_scans[src_ip])} ports)")
            log_alert(src_ip, len(udp_scans[src_ip]), "UDP Port Scan", packet)
            udp_scans[src_ip].clear()

def detect_tcp_scan(packet):
    """
    TCP SCAN DETECTION:
    Handles SYN, FIN, NULL, and XMAS scan detection with Honeyport tripwires.
    """
    if TCP in packet and IP in packet:
        flags = str(packet[TCP].flags)
        if flags in ('S', 'F', '', 'FPU'):
            src_ip = packet[IP].src
            
            # Whitelist & already-banned check
            if src_ip in WHITELIST or src_ip in blocked_ips:
                return

            dst_port = packet[TCP].dport
            
            # --- DECOY DETECTION ---
            if Ether in packet:
                detect_decoy(src_ip, packet[Ether].src)

            # --- HONEYPORT TRIPWIRE ---
            if dst_port in HONEY_PORTS:
                print(f"[TRIPWIRE] 🪤 Honeyport {dst_port} touched by {src_ip}!")
                log_alert(src_ip, 1, f"Honeyport Tripwire (Port {dst_port})", packet)
                return

            # --- THRESHOLD-BASED DETECTION ---
            current_time = time.time()
            old_ports = [p for p, ts in scans[src_ip].items() if current_time - ts > WINDOW]
            for p in old_ports:
                del scans[src_ip][p]
            
            scans[src_ip][dst_port] = current_time
            
            if len(scans[src_ip]) > THRESHOLD:
                print(f"[ALERT] 🚨 TCP Port Scan from {src_ip} ({len(scans[src_ip])} ports)")
                log_alert(src_ip, len(scans[src_ip]), "Mass Port Scan", packet)
                scans[src_ip].clear()

# =============================================
#  Master Packet Handler
# =============================================

def process_packet(packet):
    """Route each captured packet to the correct detection engine."""
    if IP in packet:
        if TCP in packet:
            detect_tcp_scan(packet)
        elif UDP in packet:
            detect_udp_scan(packet)
        elif ICMP in packet:
            detect_icmp_sweep(packet)

# =============================================
#  Main Entry Point
# =============================================

if __name__ == "__main__":
    os.makedirs("/app/logs", exist_ok=True)
    os.makedirs(PCAP_DIR, exist_ok=True)
    
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w") as f:
            json.dump([], f)
    
    init_db()
            
    print("=" * 55)
    print("🛡️  NEXUS Intrusion Prevention System (IPS) v2.0  🛡️")
    print("=" * 55)
    print(f"  TCP Threshold  : >{THRESHOLD} ports in {WINDOW}s window")
    print(f"  Honeyports     : {HONEY_PORTS}")
    print(f"  Whitelisted    : {WHITELIST}")
    print(f"  PCAP Export    : {PCAP_DIR}")
    print(f"  Protocols      : TCP | UDP | ICMP")
    print(f"  Decoy Detection: ENABLED")
    print(f"  Telegram       : {'ENABLED' if TELEGRAM_BOT_TOKEN else 'DISABLED'}")
    print("=" * 55)
    print("  Listening for malicious traffic...")
    print("=" * 55)
    
    # Sniff ALL protocols (removed tcp-only filter)
    sniff(prn=process_packet, store=0)
