#!/usr/bin/env python3

import fcntl
import struct
import os
import time
from scapy.all import *

TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_TAP   = 0x0002
IFF_NO_PI = 0x1000


# Create the tun interface
tun = os.open("/dev/net/tun", os.O_RDWR)
ifr = struct.pack('16sH', b'hazman_client%d', IFF_TUN | IFF_NO_PI)
ifname_bytes  = fcntl.ioctl(tun, TUNSETIFF, ifr)

# Get the interface name
ifname = ifname_bytes.decode('UTF-8')[:16].strip("\x00")
print("Interface Name: {}".format(ifname))

#incldue configuration
os.system("ip addr add 192.168.53.99/24 dev {}".format(ifname))
os.system("ip link set dev {} up".format(ifname))
#ip route
os.system("ip route add 192.168.60.0/24 dev {} via 10.9.0.11 onlink".format(ifname))

# Create UDP Socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

while True:
    #Get a packet from the tun interface (Task 3)
    packet = os.read(tun,2048)
    if packet:
      print(packet)
      #Send the packet via the tunnel
      sock.sendto(packet, ('10.9.0.11', 9090))