# rule.py

from enum import Enum

class RuleType(Enum):
    IP = 1
    PORT = 2
    PROTOCOL = 3

class Rule:
    def __init__(self, rule_type: RuleType, value):
        self.rule_type = rule_type
        self.value = value
