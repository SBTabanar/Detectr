from scapy.all import IP, TCP, UDP, ICMP, ARP, Ether
from collections import defaultdict
import time

class PacketAnalyzer:
    """
    Analyzes network packets to detect suspicious activity.
    Implements rules for DoS detection, Port Scanning, and ARP Spoofing.
    """
    def __init__(self, log_callback, dos_threshold=100, scan_threshold=15):
        """
        Initialize the analyzer with a callback for logging alerts.
        
        Args:
            log_callback (func): Function to call with alert messages.
            dos_threshold (int): Max packets per second allowed from an IP.
            scan_threshold (int): Max unique ports targeted by an IP.
        """
        self.log_callback = log_callback
        self.dos_threshold = int(dos_threshold)
        self.scan_threshold = int(scan_threshold)
        
        # Tracking structures
        self.ip_request_count = defaultdict(int)
        self.ip_last_reset = defaultdict(float) # For time-based rate limiting
        self.port_scan_tracker = defaultdict(set)
        self.arp_table = {} # IP -> MAC mapping
        self.flagged_ips = set()
        
        # Statistics
        self.stats = {
            "total": 0,
            "tcp": 0,
            "udp": 0,
            "icmp": 0,
            "arp": 0,
            "other": 0,
            "alerts": 0
        }

    def get_stats(self):
        """Return current statistics dictionary."""
        return self.stats

    def process_packet(self, packet):
        """
        Callback function triggered for every captured packet.
        Analyzes the packet against defined intrusion detection rules.
        
        Args:
            packet (scapy.Packet): The captured packet.
        """
        self.stats["total"] += 1
        current_time = time.time()

        # --- Protocol Stats & Layer Checks ---
        if packet.haslayer(TCP): self.stats["tcp"] += 1
        elif packet.haslayer(UDP): self.stats["udp"] += 1
        elif packet.haslayer(ICMP): self.stats["icmp"] += 1
        elif packet.haslayer(ARP): self.stats["arp"] += 1
        else: self.stats["other"] += 1

        # --- Rule 0: ARP Spoofing Detection ---
        if packet.haslayer(ARP) and packet[ARP].op == 2: # ARP Reply
            src_ip = packet[ARP].psrc
            src_mac = packet[ARP].hwsrc
            
            if src_ip in self.arp_table:
                if self.arp_table[src_ip] != src_mac:
                    msg = f"[CRITICAL] ARP Spoofing Detected! IP {src_ip} changed MAC from {self.arp_table[src_ip]} to {src_mac}"
                    self._alert(src_ip, msg)
            self.arp_table[src_ip] = src_mac

        if not packet.haslayer(IP):
            return

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # --- Rule 1: High Volume Traffic (DoS - Rate Based) ---
        # Reset count if > 1 second has passed since last check for this IP
        if current_time - self.ip_last_reset[src_ip] > 1.0:
            self.ip_request_count[src_ip] = 0
            self.ip_last_reset[src_ip] = current_time
            
        self.ip_request_count[src_ip] += 1
        
        if self.ip_request_count[src_ip] > self.dos_threshold:
            self._alert(src_ip, f"[ALERT] High traffic rate ({self.ip_request_count[src_ip]} pps) from {src_ip}")

        # --- Rule 2: TCP Port Scanning (SYN Scan) ---
        if packet.haslayer(TCP):
            # Check for SYN flag (0x02) without ACK
            if packet[TCP].flags == 0x02:
                dst_port = packet[TCP].dport
                self.port_scan_tracker[src_ip].add(dst_port)
                
                if len(self.port_scan_tracker[src_ip]) > self.scan_threshold:
                    self._alert(src_ip, f"[CRITICAL] Port Scan detected from {src_ip} ({len(self.port_scan_tracker[src_ip])} ports)")

    def _alert(self, src_ip, message):
        """Internal helper to log and count alerts, avoiding spam for same IP."""
        # Simple deduplication: don't span console for same IP in short burst?
        # For now, we allow repeated alerts but could throttle here.
        # Check if we already alerted recently? (Skipped for simplicity, relying on logic above)
        
        # Note: DoS logic resets every second, so alerts can re-occur every second.
        # Port scan logic is cumulative.
        
        if message not in self.flagged_ips: # Using flagged_ips as a rough history for some rules
             # For DoS we might want to allow re-alerting, but for now lets just log everything
             pass
        
        self.log_callback(message)
        self.stats["alerts"] += 1