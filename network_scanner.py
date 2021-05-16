#!/usr/bin/env python

from re import VERBOSE
import scapy.all as scapy


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    # arp_request.show()
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    # broadcast.show()
    arp_request_broadcast = broadcast/arp_request
    # arp_request_broadcast.show()
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    
    print('IP\t\t\tMAC Adress\n---------------------------------------------')
    for answer in answered_list:
        print(answer[1].psrc + "\t\t" + answer[1].hwsrc)
        

    print('---------------------------------------------')
    
scan("10.0.2.1/24")