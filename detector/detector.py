from scapy.all import sniff, TCP, IP
from collections import defaultdict
import time
import json
import os
import sqlite3
import requests
from datetime import datetime

# --- Configuration ---
THRESHOLD = 15
WINDOW = 5
HONEY_PORTS = [21, 23, 3389, 3306] # FTP, Telnet, RDP, MySQL
LOG_FILE = "/app/logs/alerts.json"
DB_FILE = "/app/logs/database.sqlite"

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")

scans = defaultdict(lambda: defaultdict(float))
blocked_ips = set()

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS alerts
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                  timestamp TEXT, src_ip TEXT, ports INTEGER, 
                  location TEXT, isp TEXT, status TEXT, type TEXT)''')
    conn.commit()
    conn.close()

def get_threat_intel(ip):
    if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172."):
        return "Local Network", "Internal Lab System"
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=2).json()
        if response.get("status") == "success":
            return f"{response.get('city')}, {response.get('country')}", response.get('isp')
    except:
        pass
    return "Unknown Location", "Unknown ISP"

def send_telegram(message):
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {"chat_id": TELEGRAM_CHAT_ID, "text": message, "parse_mode": "Markdown"}
    try:
        requests.post(url, json=payload, timeout=2)
    except Exception as e:
        pass

def block_ip(ip):
    if ip in blocked_ips:
        return
    os.system(f"iptables -A INPUT -s {ip} -j DROP")
    blocked_ips.add(ip)
    print(f"[IPS] 🛑 IP {ip} has been automatically banned!")

def log_alert(src_ip, port_count, alert_type="Port Scan Detected"):
    location, isp = get_threat_intel(src_ip)
    status = "BANNED"
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Active Defense
    block_ip(src_ip)
    
    # DB Logging
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("INSERT INTO alerts (timestamp, src_ip, ports, location, isp, status, type) VALUES (?, ?, ?, ?, ?, ?, ?)",
              (timestamp, src_ip, port_count, location, isp, status, alert_type))
    conn.commit()
    conn.close()

    # Telegram
    telegram_msg = f"🚨 *{alert_type}* 🚨\n*IP:* `{src_ip}`\n*Location:* {location}\n*ISP:* {isp}\n*Status:* BANNED"
    send_telegram(telegram_msg)

    # Dashboard JSON
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

def detect_scan(packet):
    if IP in packet and TCP in packet:
        flags = str(packet[TCP].flags)
        if flags == 'S' or flags == 'F' or flags == '' or flags == 'FPU':
            src_ip = packet[IP].src
            if src_ip in blocked_ips:
                return

            dst_port = packet[TCP].dport
            
            # --- DECEPTION TECHNOLOGY: HONEYPORTS ---
            if dst_port in HONEY_PORTS:
                print(f"[TRIPWIRE] Threat {src_ip} touched Honeyport {dst_port}!")
                log_alert(src_ip, 1, alert_type=f"Honeyport Tripwire (Port {dst_port})")
                return

            # Normal Threshold Logic
            current_time = time.time()
            old_ports = [port for port, ts in scans[src_ip].items() if current_time - ts > WINDOW]
            for port in old_ports:
                del scans[src_ip][port]
            
            scans[src_ip][dst_port] = current_time
            
            if len(scans[src_ip]) > THRESHOLD:
                print(f"[ALERT] Threat {src_ip} scanned {len(scans[src_ip])} ports!")
                log_alert(src_ip, len(scans[src_ip]), "Mass Port Scan")
                scans[src_ip].clear()

if __name__ == "__main__":
    os.makedirs("/app/logs", exist_ok=True)
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w") as f:
            json.dump([], f)
    
    init_db()
            
    print("========================================")
    print("🛡️  Nexus Intrusion Prevention System (IPS) 🛡️")
    print(f"Rules: Auto-Ban if >{THRESHOLD} ports hit OR if Honeyports {HONEY_PORTS} are touched")
    print("Active Defenses: ON | Deception Tech: ON | DB Logging: ON")
    print("Listening for traffic...")
    print("========================================")
    sniff(filter="tcp", prn=detect_scan, store=0)
