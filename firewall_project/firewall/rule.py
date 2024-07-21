from enum import Enum

class RuleType(Enum):
    IP = 1
    PORT = 2
    PROTOCOL = 3

class Rule:
    def __init__(self, rule_type: RuleType, value, action):
        self.rule_type = rule_type
        self.value = value
        self.action = action

    def matches(self, packet) -> bool:
        if self.rule_type == RuleType.IP:
            return packet.src_ip == self.value or packet.dst_ip == self.value
        elif self.rule_type == RuleType.PORT:
            return packet.src_port == self.value or packet.dst_port == self.value
        elif self.rule_type == RuleType.PROTOCOL:
            return packet.protocol == self.value
        return False
