
import unittest
from firewall.rule import RuleType
from firewall.enums import Action

class TestRule(unittest.TestCase):
    def test_rule_type(self):
        self.assertEqual(RuleType.IP.value, 1)
        self.assertEqual(RuleType.PORT.value, 2)
        self.assertEqual(RuleType.PROTOCOL.value, 3)

    def test_action(self):
        self.assertEqual(Action.ALLOW.value, 1)
        self.assertEqual(Action.DENY.value, 2)
        self.assertEqual(Action.LOG.value, 3)

if __name__ == "__main__":
    unittest.main()
