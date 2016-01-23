#!/usr/bin/env python2
# -*- coding: utf-8 -*-

from scapy.all import *

from oui_lookup import oui_lookup


colors = {
        "reset": "\x1b[39m"
        }

for i, c in enumerate((
    "black", "red", "green", "yellow", "blue", "magenta", "cyan", "white"
    )):
    colors[c] = "\x1b[%dm" % (30 + i,)


def callback(pkt):
    global colors

    arp = pkt[ARP]
    ether = pkt[Ether]

    def print_header():
        print("|  0x%x 0x%x %d %d" % (
            arp.hwtype,
            arp.ptype,
            arp.hwlen,
            arp.plen
            ))


    print("")
    print(".%s" % ("-" * 50))

    print("| Ether")
    print("|   %s[%s] -> %s[%s]" % (
        ether.src,
        oui_lookup(ether.src) or "unknown",
        ether.dst,
        oui_lookup(ether.dst) or "unknown"
        ))

    if arp.op is 1:
        print("| %s %s >> %s ?" % (
            colors["green"] + "Request" + colors["reset"],
            arp.psrc,
            arp.pdst,
            ))
        print("|   %s[%s] -> %s[%s]" % (
            arp.hwsrc,
            oui_lookup(arp.hwsrc) or "unknown",
            arp.hwdst,
            oui_lookup(arp.hwdst) or "unknown"
            ))
        print_header()

    elif arp.op is 2:
        print("| %s %s -> %s" % (
            colors["blue"] + "Reply" + colors["reset"],
            arp.psrc,
            arp.pdst
            ))
        print("|   %s[%s] -> %s[%s]" % (
            arp.hwsrc,
            oui_lookup(arp.hwsrc) or "unknown",
            arp.hwdst,
            oui_lookup(arp.hwdst) or "unknown"
            ))
        print_header()

    else:
        print("| %s %s -> %s" % (
            colors["cyan"] + ("%d" % (arp.op,)) + colors["reset"],
            arp.psrc,
            arp.pdst
            ))
        print_header()
        print(pkt.summary())

    print("`%s" % ("-" * 50))



sniff(filter="arp", prn=callback)
