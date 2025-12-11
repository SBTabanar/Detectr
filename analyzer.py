from scapy.all import IP, TCP, UDP, ICMP
from collections import defaultdict
import time

class PacketAnalyzer:
    """
    Analyzes network packets to detect suspicious activity.
    Implements rules for DoS detection and Port Scanning.
    """
    def __init__(self, log_callback):
        """
        Initialize the analyzer with a callback for logging alerts.
        
        Args:
            log_callback (func): Function to call with alert messages.
        """
        self.log_callback = log_callback
        self.start_time = time.time()
        
        # Tracking structures
        self.ip_request_count = defaultdict(int)
        self.port_scan_tracker = defaultdict(set)
        self.flagged_ips = set()

    def process_packet(self, packet):
        """
        Callback function triggered for every captured packet.
        Analyzes the packet against defined intrusion detection rules.
        
        Args:
            packet (scapy.Packet): The captured packet.
        """
        if not packet.haslayer(IP):
            return

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # --- Rule 1: High Volume Traffic (Potential DoS) ---
        self.ip_request_count[src_ip] += 1
        # If an IP sends > 100 packets in a short session (simplified logic)
        if self.ip_request_count[src_ip] > 500:
            if src_ip not in self.flagged_ips:
                self.log_callback(f"[ALERT] High traffic volume detected from {src_ip}")
                self.flagged_ips.add(src_ip)

        # --- Rule 2: TCP Port Scanning (SYN Scan) ---
        if packet.haslayer(TCP):
            # Check for SYN flag (0x02) without ACK
            if packet[TCP].flags == 0x02:
                dst_port = packet[TCP].dport
                self.port_scan_tracker[src_ip].add(dst_port)
                
                # If one IP hits > 15 different ports
                if len(self.port_scan_tracker[src_ip]) > 15:
                    if src_ip not in self.flagged_ips:
                        self.log_callback(f"[CRITICAL] Port Scan detected from {src_ip} targeting {dst_ip}")
                        self.flagged_ips.add(src_ip)

        # --- Rule 3: ICMP Flood (Ping of Death simulation) ---
        if packet.haslayer(ICMP):
            # Logic for specific ICMP types or sizes could go here
            pass