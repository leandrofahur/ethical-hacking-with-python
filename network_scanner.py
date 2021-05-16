#!/usr/bin/env python
import scapy.all as scapy
import optparse

def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option('-t', '--target', dest='target', help='IP range target')

    (options, arguments) = parser.parse_args()

    if(not options.target):
        parser.error('[-] Please specify a target, use --help for more info.')

    return options.target

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    
    clients_list = []
    for answer in answered_list:
        clients_list.append({ "ip": answer[1].psrc, "mac": answer[1].hwsrc})
        
    return clients_list

def print_result(results_list):
    print('IP\t\t\tMAC Address\n---------------------------------------------')
    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"])


ip = get_arguments()
scan_result = scan(ip)
print_result(scan_result)