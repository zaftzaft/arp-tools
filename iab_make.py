#!/usr/bin/env python2
# -*- coding: utf-8 -*-

import re
import json


iab_map = {}

with open("iab.txt", "r") as f:
    while True:
        data = f.readline()

        if len(data) is 0:
            break

        head = re.search(r"([A-F0-9\-]{8})\s*\(hex\)\s*(.+)", data)
        if head:
            nextline = f.readline(3)
            iab = "%s%s" % (head.group(1).replace("-", ""), nextline)
            iab_map[iab] = head.group(2).strip()


with open("iab.json", "w") as w:
    json.dump(iab_map, w)
