#!/usr/bin/env python2
# -*- coding: utf-8 -*-

import json
import threading
import argparse

from scapy.all import *
from netaddr import IPAddress, IPNetwork

from oui_lookup import oui_lookup


def scanner(opts):
    for ip in IPNetwork(opts.network):

        ip = "%s" % ip

        try:
            resp = srp1(
                    Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip),
                    timeout=opts.timeout,
                    verbose=False
                    )

            if resp:
                oui = oui_lookup(resp[ARP].hwsrc) or "unknown"

                print("%s %s[%s]" % (ip, resp[ARP].hwsrc, oui))

        except:
            print(ip)
            break

    print("Complete")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
            description="ARP scan",
            usage="$ arp_scan 192.168.0.0/24")

    parser.add_argument("network", help="Network address")
    parser.add_argument("-t", "--timeout", type=int, default=1)

    args = parser.parse_args()

    scanner_thread = threading.Thread(target=scanner, args=(args,))
    scanner_thread.setDaemon(True)
    scanner_thread.start()

    try:
        while True:
            pass
    except KeyboardInterrupt:
        print("")
