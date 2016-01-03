#!/usr/bin/env python2
# -*- coding: utf-8 -*-

import re
import json


oui_map = {}

with open("oui.txt", "r") as f:

    while True:
        data = f.readline()

        if len(data) is 0:
            break

        m = re.search(r"([A-F0-9]{6})\s*\(base 16\)\s*(.+)", data)
        if m:
            #print("%s %s" % (m.group(1), m.group(2)))
            oui_map[m.group(1)] = m.group(2).strip()


with open("oui.json", "w") as w:
    json.dump(oui_map, w)
