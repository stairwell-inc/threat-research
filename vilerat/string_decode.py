#!/usr/bin/env python3
# Author: Silas Cutler (silas@Stairwell.com)

import sys

def decode(indata):
    res = ""
    data_offset = indata[0] + 5
    key = indata[1:data_offset-2]

    for index, data in enumerate(indata[data_offset:]):
        if data == 0:
            break
        r = (data ^ key[index % len(key)]) & 0xFF
        res += chr(r)

    print(res)

if __name__ == "__main__":
    import base64
    indata = base64.b64decode('GdMhue0p3M7PzXkPvSwB9cIHTEWiCOZvNMYYAAAApCHa7V3cnc+PeVi9dgHbwnNMKKJ45m80AAAA')
    decode(indata)

