#!/usr/bin/env python2
# -*- coding: utf-8 -*-

import argparse

from scapy.all import *

from oui_lookup import oui_lookup


def main(opt):
    resp = srp1(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=opt.dst))

    if resp:
        print(oui_lookup(resp[ARP].hwsrc) or "unknown")

        print(resp.summary())


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="send arp")

    parser.add_argument("dst", help="Destination IP address")

    args = parser.parse_args()

    main(args)
