
from .packet import Packet
from .rule import Rule, RuleType
from .enums import Action

class Firewall:
    def __init__(self):
        self.rules = []

    def add_rule(self, rule_type: RuleType, value, action: Action):
        self.rules.append((rule_type, value, action))

    def process_packet(self, packet: Packet) -> str:
        for rule_type, value, action in self.rules:
            if rule_type == RuleType.IP:
                if packet.src_ip == value or packet.dst_ip == value:
                    return self.handle_action(action, packet)
            elif rule_type == RuleType.PORT:
                if packet.src_port == value or packet.dst_port == value:
                    return self.handle_action(action, packet)
            elif rule_type == RuleType.PROTOCOL:
                if packet.protocol == value:
                    return self.handle_action(action, packet)
        return "Packet is ALLOWED by default"

    def handle_action(self, action: Action, packet: Packet) -> str:
        if action == Action.DENY:
            return f"Packet from {packet.src_ip} to {packet.dst_ip} is DENIED"
        elif action == Action.ALLOW:
            return f"Packet from {packet.src_ip} to {packet.dst_ip} is ALLOWED"
        elif action == Action.LOG:
            return f"Packet from {packet.src_ip} to {packet.dst_ip} is LOGGED"
