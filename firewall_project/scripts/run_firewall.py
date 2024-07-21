import sys
import os
import logging
from firewall.firewall import Firewall
from firewall.packet import Packet
from firewall.rule import RuleType
from firewall.enums import Action

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Configure logging
logging.basicConfig(filename='C:\\Users\\Mor\\Desktop\\OpenFlowFirewall\\firewall_project\\logs\\firewall.log',
                    level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

def main():
    firewall = Firewall()
    firewall.add_rule(RuleType.IP, "192.168.1.1", Action.DENY)
    firewall.add_rule(RuleType.PORT, 80, Action.LOG)
    firewall.add_rule(RuleType.PROTOCOL, "TCP", Action.ALLOW)

    packet = Packet("192.168.1.2", "10.0.0.1", 8080, 80, "TCP", "test")
    result = firewall.process_packet(packet)
    
    # Print real-time packet details
    print(f"Processed packet from {packet.src_ip} to {packet.dst_ip}")
    print(f"Result: {result}")
    
    # Log the result
    logging.info(f"Processed packet from {packet.src_ip} to {packet.dst_ip}: {result}")

if __name__ == "__main__":
    main()
