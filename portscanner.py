#!/usr/bin/env python3
from scapy.all import IP, TCP, sr1, send
import logging
import argparse
import signal
import sys

logging.basicConfig(level=logging.INFO, format="%(message)s")

parser = argparse.ArgumentParser(description="Port Scanner")
parser.add_argument("-t", required=True, metavar="{Target IP}", help="Target IP Address")
parser.add_argument("-sS", action="store_true", help="Simple Scan")
parser.add_argument("-sV", action="store_true", help="Verbose Scan")
args = parser.parse_args()

verbose = args.sV
simple = args.sS
target = args.t

if verbose:
    chosen_ports = range(1, 65536)

else:
    chosen_ports = [21, 22, 23, 25, 53, 80, 110, 443, 8080]

signal.signal(signal.SIGINT, lambda x, y: sys.exit(0))

def scan_ports(target, port):
    syn_packet = IP(dst=target)/TCP(dport=port, flags="S")
    response = sr1(syn_packet, timeout=1, verbose=0)

    if response:
        if response.haslayer("TCP"):
            flags = response.getlayer("TCP").flags
            if flags == 0x12:
                logging.info(f"Port {port} is open")
                end_connection =  IP(dst=target)/TCP(dport=port, flags="R")
                send(end_connection, verbose=0)

            elif flags == 0x14:
                logging.info(f"Port {port} is closed")

    else:
        logging.info(f"Port {port} is filtered or there was no response")

if __name__ == "__main__":
    for port in chosen_ports:
        scan_ports(target, port)
    logging.info("Port scan complete")