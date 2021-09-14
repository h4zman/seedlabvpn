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

tap = os.open("/dev/net/tun", os.O_RDWR)
ifr = struct.pack('16sH', b'tap%d', IFF_TAP | IFF_NO_PI)
ifname_bytes = fcntl.ioctl(tap, TUNSETIFF, ifr)
ifname = ifname_bytes.decode('UTF-8')[:16].strip("\x00")

# Get the interface name
ifname = ifname_bytes.decode('UTF-8')[:16].strip("\x00")
print("Interface Name: {}".format(ifname))

# Configuration to Assign IP address to the interface and bring it up
os.system("ifconfig {} 192.168.53.10/24 up".format(ifname))

# Create socket interface
IP_A = "0.0.0.0"
PORT = 9090
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((IP_A, PORT))

while True:
	packet = os.read(tap, 2048)
	if packet:
		print("--------------------------------")
		ether = Ether(packet)
		print(ether.summary())
		# Send a spoofed ARP response
		FAKE_MAC   = "aa:bb:cc:dd:ee:ff"
		if ARP in ether and ether[ARP].op == 1 :
			arp       = ether[ARP]
			newether  = Ether(dst=ether.src, src=FAKE_MAC)
			newarp    = ARP(psrc=arp.pdst, hwsrc=FAKE_MAC,pdst=arp.psrc, hwdst=ether.src, op=2)
			newpkt     = newether/newarp

			print("*****Fake response: {}".format(newpkt.summary()))
			os.write(tap, bytes(newpkt))
