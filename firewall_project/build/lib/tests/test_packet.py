
import unittest
from firewall.packet import Packet

class TestPacket(unittest.TestCase):
    def test_packet_initialization(self):
        packet = Packet("192.168.1.1", "10.0.0.1", 1234, 80, "TCP", "payload")
        self.assertEqual(packet.src_ip, "192.168.1.1")
        self.assertEqual(packet.dst_ip, "10.0.0.1")
        self.assertEqual(packet.src_port, 1234)
        self.assertEqual(packet.dst_port, 80)
        self.assertEqual(packet.protocol, "TCP")
        self.assertEqual(packet.payload, "payload")

if __name__ == "__main__":
    unittest.main()
