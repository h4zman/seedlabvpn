#!/usr/bin/env python3

import fcntl
import struct
import os
import time
from scapy.all import *

TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_TAP = 0x0002
IFF_NO_PI = 0x1000
IP_A = "0.0.0.0"
PORT = 9090

# Create the tun interface
tun = os.open("/dev/net/tun", os.O_RDWR)
ifr = struct.pack('16sH', b'tun%d', IFF_TUN | IFF_NO_PI)
ifname_bytes = fcntl.ioctl(tun, TUNSETIFF, ifr)

# Get the interface name
ifname = ifname_bytes.decode('UTF-8')[:16].strip("\x00")
print("Interface Name: {}".format(ifname))

# Configuration to Assign IP address to the interface and bring it up (Gateway)
os.system("ifconfig {} 192.168.53.20/24 up".format(ifname))
# Configuration for IP route
os.system("ip route add 192.168.50.0/24 dev {} via 10.9.0.12 onlink".format(ifname))

# Create UDP Socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((IP_A,PORT))

while True:
    # This will block until at least one interface is ready (Task 5)
    ready, _, _ = select.select([sock, tun], [], [])
    for fd in ready:
     if fd is sock:
      data, (ip, port) = sock.recvfrom(2048)
      pkt = IP(data)
      print("From socket_client <==: {} --> {}".format(pkt.src, pkt.dst))
      os.write(tun, bytes(pkt))

    if fd is tun:
      packet = os.read(tun, 2048)
      pkt = IP(packet)
      print("From tun_client ==>: {} --> {}".format(pkt.src, pkt.dst))
      sock.sendto(packet,('10.9.0.12',9090))
