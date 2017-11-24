import sys
from scapy.all import *
import socket

ports = [] 	# Array of ports to scan
openPorts = [] # Array of open ports 
target = "" # Target IP address
maskBits = 32 # Subnet (one IP by default)
# Generate table of TCP port and corresponding services
TCP_TABLE = dict((TCP_SERVICES[k], k) for k in TCP_SERVICES.keys()) 
helpMesssage = """Useage: synprobe.py [-p port_range] target
	-p          Allows for port range specification
				Most commly used port numbers will be used if unspecified
	port_range  The range of ports to be scanned
	<target>    A single IP address or a whole subnet (e.g., 192.168.0.0/24)."""
conf.verb = 0 # Set verbosity of scapy to 0 to declutter console

if (len(sys.argv )!= 2 and len(sys.argv) != 4): # Argument length should be 2 or 4
	print helpMesssage
	sys.exit()

if sys.argv[1] == "-p": # Check if -p flag was entered
	if '-' in sys.argv[2]: # If there is a range
		portString = sys.argv[2].split('-') # Delimit the string around -
		try:
			# Makes sure the first number is smaller than second number 
			if int(portString[0]) > int(portString[1]): 
				print "Enter a valid port number or range"
				sys.exit()
			# Creates array ranging from the two numbers entered
			ports = range(int(portString[0]),int(portString[1])+1)
		except ValueError:
			print "Enter a valid port number or range"
			sys.exit()
	else: # If there isn't a range
		ports.append(int(sys.argv[2])) # Simply add the number to ports
	target = sys.argv[3] 
else: # If -p flag was not entered
	target = sys.argv[1]
	ports = [7,9,13,20,21,22,23,25,50,51,53,80,110,119,123,135,143,161,443,8008] # Common ports

if '/' in target: # Subnet is speficied
	maskBits = int(target.split('/')[1])
	target = target.split('/')[0]

def pingTarget(): # Checks if target is available 
	try:
		ping = sr1(IP(dst=target)/TCP(dport=80,flags="S"),timeout=2.0) # Ping the target with SYN flag
		if not (ping is None):
			return True
		else: # ping has time out
			print "Ping to " + target + " timed out"
			return False
	except Exception: # If ping fails
		print "\nTCP Ping to " + target + " failed"
		return False

def portScan(port): # Scans a given port to determine if it is listening for TCP connections	
	srcport = RandShort() # Generate port number
	# Send SYN packet
	ans = sr1(IP(dst = target)/TCP(sport = srcport, dport = port, flags = "S")) 
	flags = ans.getlayer(TCP).flags # Extract flags of received packet
	# Check if flags are set to SYNACK or SYN (SYN is 0x02 ACK is 0x10, SYNACK is 0x12)
	if flags == 0x12 or flags == 0x02: 
		service = ""
		if port in TCP_TABLE: # Check to see if there is a service entry for port number
			service = TCP_TABLE[port]
		print '{:6s} {:6s} {:12s}'.format(str(port), "Open", service)
		return True
	else:
		return False # Port is closed

btarget = "" # Target IP in binary
for i in target.split('.'): # Delimit on comma
		btarget += str(format(int(i),"0b")) # Convert each part to binary and add together
# Mask in string of 1's and 0's (maskBits * 1's + 32-maskBits * 0's)
mask = str(format(long(2**(maskBits)-1),"0b").ljust(32,'0')) 
targetRange = int(int(mask,2) & int(btarget,2)) # AND the mask and the targetIP

# 32 bit address to converted to a.b.c.d
a = int(bin(targetRange>>24),2) # Uses the 1st byte to form an int
b = int(bin(targetRange>>16 & 0b000000011111111),2) # Uses the 2nd byte to form an int
c = int(bin(targetRange>>8 & 0b0000000000000011111111),2) # Uses the 3rd byte to form an int
d = int(bin(targetRange & 0b00000000000000000000011111111),2) # Uses the 4th byte to form an int
networkAdd = str(a)+"."+str(b)+"."+str(c)+"."+str(d)

target = networkAdd # Start with network address

try:
	for i in range(2**(32-maskBits)): # And then go through enitre subnet
		if pingTarget():
			print "\n---- Scanning " + target + " on " + str(len(ports)) + " port(s) ----"
			print '{:6s} {:6s} {:12s}'.format("Port", "State", "Service")
			for port in ports:
				if portScan(port): # Scan each port and if the port is open
					openPorts.append(port)
			openLength = len(openPorts)
			print "\n" + str(openLength) + " open port(s) and " + str(len(ports)-openLength) +" closed port(s)"

			for port in openPorts: # Go through open ports
				print "\n---- Establishing connection to "+target+" on port "+str(port)+"  ----"
					
				try:
					reply = ""
					if(port in TCP_TABLE and TCP_TABLE[port] == "domain"): # If port is for dns
						# Send dns query
						reply=sr1(IP(dst=target)/UDP(dport=port)/DNS(rd=1,qd=DNSQR(qname='www.cs.stonybrook.edu')))
					else:
						s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
						s.connect((target,port))
						s.settimeout(5.0)	
						if(port in TCP_TABLE and TCP_TABLE[port] == "http"): # If port is for http
							# Send http request
							s.send(b"GET / HTTP/1.1\n" + "Host: "+"\n\n")
						reply = s.recv(1024)
					if len(reply) > 0:
						print hexdump(reply)
					else:
						s.send("dummy request")
						reply = s.recv(1024)
						if len(reply) > 0:
							print reply
						else:
							print "No reply\n"
				except socket.timeout:
					print "Connection to " + target +" on port " + str(port) + " timed out..." 
				
		# CIDR addition
		if d < 255:
			d += 1
		elif c < 255:
			c += 1
			d = 0
		elif b < 255:
			b += 1
			c = 0
			d = 0
		else:
			a += 1
			b = 0
			c = 0
			d = 0
		target = str(a)+"."+str(b)+"."+str(c)+"."+str(d) # set target to next IP in subnet
		openPorts = [] # reset array of open ports

except Exception:
	print "Something went wrong..."
except KeyboardInterrupt: # In case the user needs to quit
	print "\n\nProgram Interrupted"
	print "Exiting..."
	sys.exit(1)