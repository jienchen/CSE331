import sys
import os
from scapy.all import *
import datetime
import threading

helpMesssage = """arpwatch.py [-i interface] 
				-i  Live capture from the network device <interface> (e.g., eth0). If not
			    specified, interface automatically defaults to eth0"""

interface = "eth0" # Default interface
conf.verb = 0 # Set verbosity of scapy to 0 to declutter console
arpTable = [] # List of IP and MAC addresses 

if (len(sys.argv) != 1 and len(sys.argv) != 3): # Argument length should be 1 or 3
	print helpMesssage
	sys.exit()

if len(sys.argv) == 3:
	if sys.argv[1] == "-i":
		interface = sys.argv[2]
	else:
		print helpMesssage
		sys.exit()

def updateARP():
	try:
		thread = threading.Timer(120.0,updateARP) #update the ARP Table every 2 mins
		thread.daemon = True
		thread.start()
		print "-" * 40
		print "ARP Table created at " + str(datetime.datetime.now())
		print '{:20s} {:20s}'.format("IP Address", "MAC Address")
		lines = os.popen('arp -n -i ' + interface) # -n option used to get IP's
		for line in lines:
			if interface in line:
				if line.split()[0] not in arpTable: # If IP is not in table
					arpTable.append(line.split()[0]) # IP Address
					arpTable.append(line.split()[2]) # MAC Address
				print '{:20s} {:20s}'.format(line.split()[0],line.split()[2])
		print "-" * 40
	except KeyboardInterrupt:
		print "\n\nProgram Interrupted"
		print "Exiting..."
		sys.exit(1)

def checkARP(packet):
	if ARP in packet and packet[ARP].op in (1,2): # who-has or is-at
		if packet[ARP].psrc in arpTable: # If IP is in table
			if(arpTable[arpTable.index(packet[ARP].psrc)+1] != packet[ARP].hwsrc): # Check MAC
				# Let user know if MAC address has changed
				print packet.sprintf("%ARP.psrc% changed from " +
				arpTable[arpTable.index(packet[ARP].psrc)+1] + " to %ARP.hwsrc%")

updateARP()
sniff(iface=interface, filter="arp", prn=checkARP)