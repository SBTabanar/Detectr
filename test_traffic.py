import unittest
from unittest.mock import MagicMock
from scapy.all import IP, TCP
from analyzer import PacketAnalyzer

class TestPacketAnalyzer(unittest.TestCase):
    def setUp(self):
        self.mock_log = MagicMock()
        self.analyzer = PacketAnalyzer(self.mock_log)

    def test_high_volume_traffic(self):
        # Simulate > 500 packets from same IP
        src_ip = "192.168.1.100"
        dst_ip = "192.168.1.1"
        packet = IP(src=src_ip, dst=dst_ip)
        
        for _ in range(501):
            self.analyzer.process_packet(packet)
            
        # Check if the log was called with the specific alert
        self.mock_log.assert_called_with(f"[ALERT] High traffic volume detected from {src_ip}")

    def test_port_scan(self):
        # Simulate SYN packets to > 15 different ports
        src_ip = "192.168.1.101"
        dst_ip = "192.168.1.1"
        
        for port in range(20, 40):
            # TCP flags 0x02 is SYN
            packet = IP(src=src_ip, dst=dst_ip)/TCP(dport=port, flags=0x02)
            self.analyzer.process_packet(packet)
            
        # Check if the log was called with the specific critical alert
        self.mock_log.assert_called_with(f"[CRITICAL] Port Scan detected from {src_ip} targeting {dst_ip}")

if __name__ == '__main__':
    unittest.main()
