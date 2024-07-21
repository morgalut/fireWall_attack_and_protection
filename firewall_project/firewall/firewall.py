import logging
from .packet import Packet
from .rule import Rule, RuleType
from .enums import Action
from sklearn.ensemble import RandomForestClassifier
import numpy as np

# Configure logging
logging.basicConfig(filename='C:/Users/Mor/Desktop/OpenFlowFirewall/firewall_project/logs/firewall.log',
                    level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

class Firewall:
    def __init__(self):
        self.rules = []
        self.model = None
        self.train_model()

    def add_rule(self, rule_type: RuleType, value, action: Action):
        self.rules.append((rule_type, value, action))

    def process_packet(self, packet: Packet) -> str:
        for rule_type, value, action in self.rules:
            if rule_type == RuleType.IP:
                if packet.src_ip == value or packet.dst_ip == value:
                    log_msg = self.handle_action(action, packet)
                    logging.info(log_msg)
                    return log_msg
            elif rule_type == RuleType.PORT:
                if packet.src_port == value or packet.dst_port == value:
                    log_msg = self.handle_action(action, packet)
                    logging.info(log_msg)
                    return log_msg
            elif rule_type == RuleType.PROTOCOL:
                if packet.protocol == value:
                    log_msg = self.handle_action(action, packet)
                    logging.info(log_msg)
                    return log_msg
        
        # Use machine learning model for decision making
        features = self.extract_features(packet)
        prediction = self.model.predict([features])
        log_msg = self.handle_action(Action.ALLOW if prediction[0] == 1 else Action.DENY, packet)
        logging.info(log_msg)
        return log_msg

    def handle_action(self, action: Action, packet: Packet) -> str:
        if action == Action.DENY:
            return f"Packet from {packet.src_ip} to {packet.dst_ip} is DENIED"
        elif action == Action.ALLOW:
            return f"Packet from {packet.src_ip} to {packet.dst_ip} is ALLOWED"
        elif action == Action.LOG:
            return f"Packet from {packet.src_ip} to {packet.dst_ip} is LOGGED"

    def extract_features(self, packet: Packet) -> np.array:
        # Extract features for machine learning model
        return np.array([
            self.ip_to_int(packet.src_ip),
            self.ip_to_int(packet.dst_ip),
            packet.src_port if packet.src_port else 0,
            packet.dst_port if packet.dst_port else 0,
            self.protocol_to_int(packet.protocol)
        ])

    def ip_to_int(self, ip: str) -> int:
        # Convert IP address to an integer
        return int(ip.split('.')[0]) * 256**3 + int(ip.split('.')[1]) * 256**2 + int(ip.split('.')[2]) * 256 + int(ip.split('.')[3])

    def protocol_to_int(self, protocol: str) -> int:
        # Convert protocol to an integer
        return 1 if protocol == 'TCP' else 2

    def train_model(self):
        # Training data: [src_ip_int, dst_ip_int, src_port, dst_port, protocol_int]
        X = np.array([
            [3232235776, 3232236032, 1234, 80, 1],  # Example data
            [3232235776, 3232236032, 5678, 80, 2],  # Example data
            # Add more training data here
        ])
        y = np.array([1, 0])  # Labels: 1 = ALLOW, 0 = DENY

        # Train the model
        self.model = RandomForestClassifier(n_estimators=100)
        self.model.fit(X, y)

        logging.info("Machine learning model trained.")

