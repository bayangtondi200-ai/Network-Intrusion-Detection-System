from scapy.all import sniff, IP, TCP
from detection.syn_flood import detect_syn_flood
from detection.port_scan import detect_port_scan
from colorama import Fore
import logging

logging.basicConfig(
    filename='logs/alerts.log',
    level=logging.INFO
)

def analyze_packet(packet):

    if packet.haslayer(IP) and packet.haslayer(TCP):

        src_ip = packet[IP].src
        dst_port = packet[TCP].dport

        if packet[TCP].flags == "S":

            if detect_syn_flood(src_ip):
                alert = f"SYN Flood détecté depuis {src_ip}"
                print(Fore.RED + alert)
                logging.info(alert)

            if detect_port_scan(src_ip, dst_port):
                alert = f"Port Scan détecté depuis {src_ip}"
                print(Fore.YELLOW + alert)
                logging.info(alert)

print("[+] IDS démarré...")

sniff(
    filter="tcp",
    prn=analyze_packet,
    store=0
)
