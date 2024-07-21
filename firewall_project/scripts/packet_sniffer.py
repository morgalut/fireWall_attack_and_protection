import logging
import sys
import os
from scapy.all import IP, TCP, sniff
from firewall.firewall import Firewall
from firewall.packet import Packet
from firewall.rule import RuleType
from firewall.enums import Action

def packet_callback(packet):
    if packet.haslayer(IP):
        scapy_pkt = packet[IP]
        packet_obj = Packet(
            scapy_pkt.src,
            scapy_pkt.dst,
            packet[TCP].sport if packet.haslayer(TCP) else None,
            packet[TCP].dport if packet.haslayer(TCP) else None,
            "TCP" if packet.haslayer(TCP) else "UNKNOWN",
            packet.load
        )
        result = firewall.process_packet(packet_obj)
        log_msg = f"Packet from {packet_obj.src_ip} to {packet_obj.dst_ip}: {result}"
        print(log_msg)
        logging.info(log_msg)

firewall = Firewall()
firewall.add_rule(RuleType.IP, "192.168.1.1", Action.DENY)
firewall.add_rule(RuleType.PORT, 80, Action.LOG)
firewall.add_rule(RuleType.PROTOCOL, "TCP", Action.ALLOW)

sniff(prn=packet_callback, filter="ip", store=0)
