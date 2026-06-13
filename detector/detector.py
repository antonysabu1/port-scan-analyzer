from scapy.all import sniff, TCP, IP
from collections import defaultdict
import time

# --- Configuration ---
THRESHOLD = 15        # Number of unique ports to trigger alert
WINDOW = 5            # Time window in seconds

# Data structure: dictionary mapping source IP to a dictionary of {port: timestamp}
# Example: {'10.0.0.10': {80: 1715874000.0, 22: 1715874000.1}}
scans = defaultdict(lambda: defaultdict(float))

def detect_scan(packet):
    """
    Callback function that runs for every captured TCP packet.
    """
    # We are looking for TCP packets with the SYN flag set 
    # (SYN is the first packet sent when establishing a connection or running a stealth scan)
    if IP in packet and TCP in packet:
        # Check for multiple types of scan flags (SYN, FIN, XMAS, NULL)
        flags = str(packet[TCP].flags)
        if flags == 'S' or flags == 'F' or flags == '' or flags == 'FPU':
            src_ip = packet[IP].src
            dst_port = packet[TCP].dport
            current_time = time.time()
            
            # 1. Clean up old entries for this IP that are outside our time window
            old_ports = [port for port, ts in scans[src_ip].items() if current_time - ts > WINDOW]
            for port in old_ports:
                del scans[src_ip][port]
            
            # 2. Record the new port access
            scans[src_ip][dst_port] = current_time
            
            # 3. Check if threshold is exceeded (too many unique ports in the window)
            if len(scans[src_ip]) > THRESHOLD:
                print(f"[ALERT] Port Scan Detected from {src_ip}! ({len(scans[src_ip])} unique ports within {WINDOW} seconds)")
                # Clear the tracker for this IP so we don't spam the console continuously for the same scan
                scans[src_ip].clear()

if __name__ == "__main__":
    print("========================================")
    print("🛡️  Port Scan Detector Started  🛡️")
    print(f"Alert Rule: >{THRESHOLD} unique ports hit within {WINDOW} seconds")
    print("Listening for traffic...")
    print("========================================")

    # Start sniffing traffic. 
    # filter="tcp" ensures we only process TCP packets, improving performance.
    # store=0 prevents Scapy from keeping all packets in memory (prevents crashes).
    sniff(filter="tcp", prn=detect_scan, store=0)
