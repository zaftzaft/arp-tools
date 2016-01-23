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
        header_str = {
                "hwtype": "0x%x" % (arp.hwtype,),
                "ptype":  "0x%x" % (arp.ptype,),
                "hwlen":  "%d" % (arp.hwlen,),
                "plen":   "%d" % (arp.plen,),
                }

        default = {
                "hwtype": 0x1,
                "ptype":  0x800,
                "hwlen":  6,      # MAC Addr len
                "plen":   4       # IPv4 Addr len
                }

        for k, v in default.items():
            if getattr(arp, k) != v:
                header_str[k] = colors["red"] + header_str[k] + colors["reset"]

        print("|   hw:%s p:%s hwl:%s pl:%s" % (
            header_str["hwtype"],
            header_str["ptype"],
            header_str["hwlen"],
            header_str["plen"]
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
