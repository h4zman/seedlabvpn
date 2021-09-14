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
IP_A = '0.0.0.0'
PORT = 9090

# Create the tun interface
tun = os.open("/dev/net/tun", os.O_RDWR)
ifr = struct.pack('16sH', b'hazman_server%d', IFF_TUN | IFF_NO_PI)
ifname_bytes = fcntl.ioctl(tun, TUNSETIFF, ifr)

# Get the interface name
ifname = ifname_bytes.decode('UTF-8')[:16].strip("\x00")
print("Interface Name: {}".format(ifname))

#incldue configuration
os.system("ifconfig {} 192.168.53.98/24 up".format(ifname))
os.system("ip link set dev {} up". format(ifname) )

# Create UDP Socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((IP_A,PORT))

while True:
     #Task 4
     data, (ip, port) = sock.recvfrom(2048)
     packet = IP(data)
     if packet:
          os.write(tun,bytes(packet))
          sock.sendto(data,(packet.dst,port))
          print("{}:{} --> {}:{}".format(ip, port, IP_A, PORT))
          print(" Inside: {} --> {}".format(packet.src, packet.dst))
