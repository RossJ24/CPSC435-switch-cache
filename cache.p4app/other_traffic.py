#!/usr/bin/env python

import sys
import socket
import struct

OTHER_UDP_PORT = 10
other_data = struct.Struct('!B I I I I I I I')

if len(sys.argv) != 2:
    print("Usage: %s HOST" % sys.argv[0])
    sys.exit(1)

host = sys.argv[1]

addr = (host, OTHER_UDP_PORT)

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(2)

req = other_data.pack(97,int(1),int(2),int(3),int(4),int(5),int(6),int(7))
s.sendto(req, addr)
try:
    res, addr2 = s.recvfrom(1024)
except socket.timeout as e:
    print("Timeout: not in forwarding table")