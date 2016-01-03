#!/usr/bin/env python2
# -*- coding: utf-8 -*-

from scapy.all import *

from oui_lookup import oui_lookup


def callback(pkt):
    #print(pkt.summary())

    arp = pkt[ARP]

    if arp.op is 1:
        print("\x1b[32mRequest\x1b[39m %s[%s] %s >> %s" % (
            arp.hwsrc,
            oui_lookup(arp.hwsrc) or "unknown",
            arp.psrc,
            arp.pdst)
            )

    elif arp.op is 2:
        print("\x1b[34mReply\x1b[39m %s[%s] %s -> %s[%s] %s" % (
            arp.hwsrc,
            oui_lookup(arp.hwsrc) or "unknown",
            arp.psrc,
            arp.hwdst,
            oui_lookup(arp.hwdst) or "unknown",
            arp.pdst)
            )
    else:
        print(pkt)



sniff(filter="arp", prn=callback)
