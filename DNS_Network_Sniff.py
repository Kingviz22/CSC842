#! /usr/bin/env python
import requests
from urllib.parse import urlparse
from scapy.all import DNS, DNSQR, IP, sniff

def load_malicious_domains(filename):
    with open(filename, "r") as file:
        return file.read().splitlines()

def process_packet(packet):
    # If the packet has a DNS Request Layer (DNSQR)
    if packet.haslayer(DNSQR):
        query_name = packet[DNSQR].qname.decode().rstrip('.\x00')  # The domain being requested
        print('DNS Query: ', query_name)  
        for domain in malicious_domains:
            if domain in query_name:
                print('[*] Detected Possible Malicious DNS Query: ', query_name)
                break
#grab list of malicious domains from urlhaus
url = 'https://urlhaus.abuse.ch/downloads/text_online/' 
listofurls = requests.get(url, allow_redirects=True)

#store the list into a .txt file
open('C:\\Users\\ipvizina\\downloads\\new.txt', 'wb').write(listofurls.content)
#load list into a variable to use to compare

malicious_domains = load_malicious_domains(r"C:\\Users\\ipvizina\downloads\\new2.txt")

# Sniff the network for packets
sniff(filter="port 53", prn=process_packet, store=0)
