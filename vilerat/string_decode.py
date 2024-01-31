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











# v3 = int.from_bytes(fdata[:4], "little") // Size != v3?

# EAX == start of payload
# EDX == 19 (byte from start)


# AL - path

# iv3 = fdata[0] #movzx edx, byte ptr ds:[eax]
# ebx_offset = iv3 + 5  

# v3 = fdata[ebx_offset]

# res = ""
# pchar = ""
# for index, data in enumerate(fdata[ebx_offset:]):
#     v3 = fdata[index + 1]
#     if data == 0 and pchar == 0:
#         break
#     r = (data ^ v3) & 0xFF
#     # print(f"{hex(data)} ^ {hex(v3)} = {hex(r)} | {chr(r)}") # 19 ^ d3 - first run


#     res += chr(r)
#     pchar = r
#     # v3 = r + 1
#     # #print(v3)


#     # break
# print(res)
