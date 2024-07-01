from scapy.all import sniff, ARP
import warnings
import scapy.packet
from typing import Dict, List

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
            ip = pkt[ARP].psrc
            mac = pkt[ARP].hwsrc
            return ip in ip_list and self.static_arp_dict[ip] != mac
        return False
    
    def attacker_ip(self, pkt: scapy.packet.Packet) -> str:
        return pkt[ARP].psrc
    
    def resolve_packet(self, pkt: scapy.packet.Packet) -> None:
        sus = self.suspicious(pkt)
        if sus:
            attacker_ip = self.attacker_ip(pkt)
            print('suspected arp poisening from ip address:', attacker_ip)
        return


    def run(self) -> None:
        try:
            sniff(filter="arp", prn=self.resolve_packet, store=0)
        except:
            import traceback
            traceback.print_exc()

    def start(self) -> None:
        while True:
            self.run()


if __name__ == "__main__":
    spoof_detector = SpoofDetector(STATIC_ARP_DICT)
    spoof_detector.start()