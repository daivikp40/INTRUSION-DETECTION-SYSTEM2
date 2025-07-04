# live_detection.py
from scapy.all import sniff, TCP, IP
from collections import defaultdict, deque
from datetime import datetime, timedelta
from database import init_db, insert_alert

BRUTE_FORCE_THRESHOLD = 2
PORT_SCAN_THRESHOLD = 2
BRUTE_FORCE_WINDOW = timedelta(minutes=2)
PORT_SCAN_WINDOW = timedelta(minutes=1)

failed_logins = defaultdict(deque)  # {ip: deque([timestamps])}
port_scans = defaultdict(deque)     # {ip: deque([(timestamp, port)])}
alerted_bruteforce = set()
alerted_portscan = set()

def detect_brute_force(ip):
    times = failed_logins[ip]
    while times and (datetime.now() - times[0]) > BRUTE_FORCE_WINDOW:
        times.popleft()
    if len(times) >= BRUTE_FORCE_THRESHOLD and ip not in alerted_bruteforce:
        insert_alert(
            times[-1].strftime("%Y-%m-%d %H:%M:%S"),
            ip,
            "Brute Force (Live)",
            f"{BRUTE_FORCE_THRESHOLD}+ SSH SYNs in {BRUTE_FORCE_WINDOW}."
        )
        alerted_bruteforce.add(ip)

def detect_port_scan(ip):
    attempts = port_scans[ip]
    while attempts and (datetime.now() - attempts[0][0]) > PORT_SCAN_WINDOW:
        attempts.popleft()
    ports = set(port for _, port in attempts)
    if len(ports) >= PORT_SCAN_THRESHOLD and ip not in alerted_portscan:
        insert_alert(
            attempts[-1][0].strftime("%Y-%m-%d %H:%M:%S"),
            ip,
            "Port Scan (Live)",
            f"Port scan: {len(ports)} ports in {PORT_SCAN_WINDOW}."
        )
        alerted_portscan.add(ip)

# For SYN detection (works for both string and int flags)
def is_syn(flags):
    # Handles both string and int representations
    return (flags == 'S') or (flags == 0x02) or (str(flags) == 'S') or (int(flags) & 0x02)

def process_packet(pkt):
    if pkt.haslayer(IP) and pkt.haslayer(TCP):
        src_ip = pkt[IP].src
        dst_port = pkt[TCP].dport
        flags = pkt[TCP].flags
        timestamp = datetime.now()
        print(f"Packet: src={src_ip}, dst_port={dst_port}, flags={flags}")

        # Brute force: SSH SYN packets (port 22)
        if dst_port == 22 and is_syn(flags):
            failed_logins[src_ip].append(timestamp)
            detect_brute_force(src_ip)

        # Port scan: SYN packets to many ports
        if is_syn(flags):
            port_scans[src_ip].append((timestamp, dst_port))
            detect_port_scan(src_ip)

def main():
    init_db()
    print("Starting live network scan. Press Ctrl+C to stop.")
    sniff(filter="tcp", prn=process_packet, store=0)

if __name__ == "__main__":
    main()