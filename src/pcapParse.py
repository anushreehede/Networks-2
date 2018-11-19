#### Script to read the pcap files into text files ####

import sys
import os
import socket
from datetime import datetime

import dpkt # For general packet information
from scapy.all import * # For reading the hex byte for transition point 1 message
import pyshark # For reading the info field of a packet

# Directory where pcap files are present
directory = sys.argv[1]
# Directory where pcap data will be stored
dest_directory = sys.argv[2]

# For every pcap file 
for filename in os.listdir(directory):
	# Get its path
	filepath = os.path.join(directory, filename)
	print('\n'+filename)

	# Open the text file which will store the current flow information
	newfile = dest_directory+"/"+filename+".txt"
	packets = open(newfile, "w")
	
	pcapReader = dpkt.pcap.Reader(open(filepath, "rb"))
	
	### 1. Find the packet which marks transition point 1
	pcap = rdpcap(filepath)
	j = 0 # counter for packets
	pkt_no = 0 # stores the packet number of transition point 1

	# Iterate through the packets 
	for pkt in pcap:
		j+=1 # increment packet counter

		# If the packet contains raw data
		if Raw in pkt: 
			# Iterate through the data until we get a byte with value 21 or 0x15
			for b in pkt[Raw]:
				if len(b.load) >= 6 and b.load[5] == 21:
	        		# Store the packet number 
					pkt_no = j
					break
		if pkt_no !=0:
			break

	### 2. Find the number of times a login has been attempted
	login_list = []
	j = 0
	cap = pyshark.FileCapture(filepath, only_summaries=True)
	for packet in cap:
		j+=1
		if 'Client: Encrypted packet' in packet.info:
			login_list.append(j)



	### 3. Begin parsing the pcap file properly 	
	i=0
	for ts, data in pcapReader:
		i+=1
		if i == pkt_no:
			tp = 1 # Found transition point 1 packet
		else:
			tp = 0 # Not transition point 1

		if i in login_list:
			login = 1 # Found an encrypted packet
		else:
			login = 0 # Otherwise
		# Get the link layer info
		ether = dpkt.ethernet.Ethernet(data)
		if ether.type != dpkt.ethernet.ETH_TYPE_IP: raise

		# Get the network layer info
		ip = ether.data
		src = socket.inet_ntoa(ip.src)
		dst = socket.inet_ntoa(ip.dst)
		
		# Get the transport layer info
		if ip.p in (dpkt.ip.IP_PROTO_TCP, dpkt.ip.IP_PROTO_UDP):
			tcp = ip.data
			s_port = tcp.sport
			d_port = tcp.dport

			if len(tcp.data) > 0: 

				# Store all the obtained info in the text file
				if d_port == 22:
					incoming=True
					# print("Packet: %d, Incoming: %r\nSource IP: %s, Destination IP: %s\nSource port no: %d, Destination port: %d\nTimestamp: %s, Size: %d, Trans point: %d, Login: %d\n" % (i,incoming, src, dst, s_port, d_port, str(datetime.utcfromtimestamp(ts)), len(data), tp, login))
					packets.write("%d,%r,%s,%s,%d,%d,%s,%d,%d,%d\n" % (i,incoming, src, dst, s_port, d_port, str(datetime.utcfromtimestamp(ts)), len(data), tp, login))
				elif s_port == 22:
					incoming=False
					# print("Packet: %d, Incoming: %r\nSource IP: %s, Destination IP: %s\nSource port no: %d, Destination port: %d\nTimestamp: %s, Size: %d, Trans point: %d, Login: %d\n" % (i,incoming, src, dst, s_port, d_port, str(datetime.utcfromtimestamp(ts)), len(data), tp, login))
					packets.write("%d,%r,%s,%s,%d,%d,%s,%d,%d,%d\n" % (i,incoming, src, dst, s_port, d_port, str(datetime.utcfromtimestamp(ts)), len(data), tp, login))
	
	# Close the text file
	packets.close()


