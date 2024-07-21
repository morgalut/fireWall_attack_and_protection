
import unittest
from firewall.firewall import Firewall
from firewall.packet import Packet
from firewall.rule import RuleType
from firewall.enums import Action

class TestFirewall(unittest.TestCase):
    def setUp(self):
        self.firewall = Firewall()
        self.firewall.add_rule(RuleType.IP, "192.168.1.1", Action.DENY)
        self.firewall.add_rule(RuleType.PORT, 80, Action.LOG)
        self.firewall.add_rule(RuleType.PROTOCOL, "TCP", Action.ALLOW)

    def test_packet_allow(self):
        packet = Packet("192.168.1.2", "10.0.0.1", 8080, 80, "TCP", "test")
        result = self.firewall.process_packet(packet)
        self.assertEqual(result, "Packet from 192.168.1.2 to 10.0.0.1 is ALLOWED")

    def test_packet_deny(self):
        packet = Packet("192.168.1.1", "10.0.0.1", 8080, 80, "TCP", "test")
        result = self.firewall.process_packet(packet)
        self.assertEqual(result, "Packet from 192.168.1.1 to 10.0.0.1 is DENIED")

    def test_packet_log(self):
        packet = Packet("192.168.1.2", "10.0.0.1", 80, 80, "TCP", "test")
        result = self.firewall.process_packet(packet)
        self.assertEqual(result, "Packet from 192.168.1.2 to 10.0.0.1 is LOGGED")

if __name__ == "__main__":
    unittest.main()
