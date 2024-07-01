from scapy.layers.l2 import ARP
from scapy.layers.dns import IP
import scapy
from scapy.all import sniff
import scapy.packet
import warnings
from typing import Dict, List
import multiprocessing as mp
from scapy.layers.l2 import getmacbyip, Ether, ARP, srp
from scapy.layers.dns import DNS, DNSQR, DNSRR, IP, sr1, UDP
from scapy.all import send
import scapy.all as scapy
import time

STATIC_ARP_DICT = {
    "10.0.2.43": "12:34:56:12:34:56",
    "8.8.8.8": "52:54:00:12:35:00"
}


class SpoofDetector(object):
    def __init__(self, static_arp_dict) -> None:
        self.static_arp_dict = static_arp_dict
    
    def suspicious(self, pkt: scapy.packet.Packet) -> bool:
        ip_list = list(self.static_arp_dict.keys())
        if ARP in pkt and pkt[ARP].op == 2: #if it is an arp response packet
            ip = pkt[IP].src
            mac = pkt[ARP].hwsrc
            return ip in ip_list and mac != self.static_arp_dict[ip]
    
    def attacker_ip(self, pkt: scapy.packet.Packet) -> str:
        return pkt[IP].src
    
    def resolve_packet(self, pkt: scapy.packet.Packet) -> None:
        if self.suspicious(pkt):
            attacker_ip = self.attacker_ip(pkt)
            warnings.warn(f"detecetd arp poisening from ip address {attacker_ip}")
        return


    def run(self) -> None:
        try:
            scapy.sniff(filter=ARP, prn=self.resolve_packet)
        except:
            import traceback
            traceback.print_exc()

    def start(self) -> None:
        for i in range(1):
            self.run()


if __name__ == "__main__":
    spoof_detector = SpoofDetector(STATIC_ARP_DICT)
    spoof_detector.start()