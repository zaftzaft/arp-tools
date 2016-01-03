#!/usr/bin/env python2
# -*- coding: utf-8 -*-

import sys
import json


with open("oui.json", "r") as f:
    oui_map = json.load(f)

with open("iab.json", "r") as f:
    iab_map = json.load(f)


def oui_lookup(mac_addr):
    oui = mac_addr.replace(":", "").replace("-", "")[:6].upper()
    iab = mac_addr.replace(":", "").replace("-", "")[:9].upper()

    if oui in oui_map:
        return oui_map[oui]
    elif iab in iab_map:
        return iab_map[iab]

    return None


if __name__ == "__main__":
    print(oui_lookup(sys.argv[1]) or "Unknown")
