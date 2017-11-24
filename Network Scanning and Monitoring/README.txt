CSE 331 HW 3 
Ji En Chen
ID#: 109896249

---------------------synprobe.py---------------------
synprobe.py mainly consists of two helper functions, pingTarget()
and portScan(port). pingTarget() performs a TCP ping to see if 
the target IP is available. portScan() then scans all specificed
ports on available IP(s). To handle subnets, the base IP is 
converted to binary and masked with the corresponding number of 
mask bits. The default is set to 32 (which would map to the base
IP). The resulting network IP is used and incremented until all 
IP's of the subnet are checked. 7,9,13,20,21,22,23,25,50,51,53,
80,110,119,123,135,143,161,443,8008 is my list of 20 most common 
ports. Open ports were then printed along with corresponding 
entries in the TCP servces dictionary. Lastly, a connection was
attempted with each port. Special cases for http and dns were
created.

IP of metasploit VM: 192.168.243.131

Example outputs: 

root@kali:~/Desktop# python synprobe.py 192.168.243.131

---- Scanning 192.168.243.131 on 20 port(s) ----
Port   State  Service
21     Open   ftp
22     Open   ssh
23     Open   telnet
25     Open   smtp 
53     Open   domain 
80     Open   http 

6 open port(s) and 14 closed port(s)

---- Establishing connection to 192.168.243.131 on port 21  ----
0000   32 32 30 20 28 76 73 46  54 50 64 20 32 2E 33 2E   220 (vsFTPd 2.3.
0010   34 29 0D 0A                                        4)..
None

---- Establishing connection to 192.168.243.131 on port 22  ----
0000   53 53 48 2D 32 2E 30 2D  4F 70 65 6E 53 53 48 5F   SSH-2.0-OpenSSH_
0010   34 2E 37 70 31 20 44 65  62 69 61 6E 2D 38 75 62   4.7p1 Debian-8ub
0020   75 6E 74 75 31 0A                                  untu1.
None

---- Establishing connection to 192.168.243.131 on port 23  ----
0000   FF FD 18 FF FD 20 FF FD  23 FF FD 27               ..... ..#..'
None

---- Establishing connection to 192.168.243.131 on port 25  ----
0000   32 32 30 20 6D 65 74 61  73 70 6C 6F 69 74 61 62   220 metasploitab
0010   6C 65 2E 6C 6F 63 61 6C  64 6F 6D 61 69 6E 20 45   le.localdomain E
0020   53 4D 54 50 20 50 6F 73  74 66 69 78 20 28 55 62   SMTP Postfix (Ub
0030   75 6E 74 75 29 0D 0A                               untu)..
None

---- Establishing connection to 192.168.243.131 on port 53  ----
0000   45 00 00 CF 00 00 40 00  40 11 D1 C2 C0 A8 F3 83   E.....@.@.......
0010   C0 A8 F3 86 00 35 00 35  00 BB 6A D0 00 00 81 80   .....5.5..j.....
0020   00 01 00 02 00 04 00 00  03 77 77 77 02 63 73 0A   .........www.cs.
0030   73 74 6F 6E 79 62 72 6F  6F 6B 03 65 64 75 00 00   stonybrook.edu..
0040   01 00 01 C0 0C 00 05 00  01 00 00 03 84 00 2C 12   ..............,.
0050   65 63 32 2D 31 30 37 2D  32 32 2D 31 37 38 2D 31   ec2-107-22-178-1
0060   35 37 09 63 6F 6D 70 75  74 65 2D 31 09 61 6D 61   57.compute-1.ama
0070   7A 6F 6E 61 77 73 03 63  6F 6D 00 C0 33 00 01 00   zonaws.com..3...
0080   01 00 09 16 F6 00 04 6B  16 B2 9D C0 50 00 02 00   .......k....P...
0090   01 00 02 7F 76 00 05 02  75 31 C0 50 C0 50 00 02   ....v...u1.P.P..
00a0   00 01 00 02 7F 76 00 05  02 72 31 C0 50 C0 50 00   .....v...r1.P.P.
00b0   02 00 01 00 02 7F 76 00  05 02 72 32 C0 50 C0 50   ......v...r2.P.P
00c0   00 02 00 01 00 02 7F 76  00 05 02 75 32 C0 50      .......v...u2.P
None

---- Establishing connection to 192.168.243.131 on port 80  ----
0000   48 54 54 50 2F 31 2E 31  20 32 30 30 20 4F 4B 0D   HTTP/1.1 200 OK.
0010   0A 44 61 74 65 3A 20 53  61 74 2C 20 31 31 20 4E   .Date: Sat, 11 N
0020   6F 76 20 32 30 31 37 20  30 33 3A 35 33 3A 32 34   ov 2017 03:53:24
0030   20 47 4D 54 0D 0A 53 65  72 76 65 72 3A 20 41 70    GMT..Server: Ap
0040   61 63 68 65 2F 32 2E 32  2E 38 20 28 55 62 75 6E   ache/2.2.8 (Ubun
0050   74 75 29 20 44 41 56 2F  32 0D 0A 58 2D 50 6F 77   tu) DAV/2..X-Pow
0060   65 72 65 64 2D 42 79 3A  20 50 48 50 2F 35 2E 32   ered-By: PHP/5.2
0070   2E 34 2D 32 75 62 75 6E  74 75 35 2E 31 30 0D 0A   .4-2ubuntu5.10..
0080   54 72 61 6E 73 66 65 72  2D 45 6E 63 6F 64 69 6E   Transfer-Encodin
0090   67 3A 20 63 68 75 6E 6B  65 64 0D 0A 43 6F 6E 74   g: chunked..Cont
00a0   65 6E 74 2D 54 79 70 65  3A 20 74 65 78 74 2F 68   ent-Type: text/h
00b0   74 6D 6C 0D 0A 0D 0A 31  39 37 0D 0A 3C 68 74 6D   tml....197..<htm
00c0   6C 3E 3C 68 65 61 64 3E  3C 74 69 74 6C 65 3E 4D   l><head><title>M
00d0   65 74 61 73 70 6C 6F 69  74 61 62 6C 65 32 20 2D   etasploitable2 -
00e0   20 4C 69 6E 75 78 3C 2F  74 69 74 6C 65 3E 3C 2F    Linux</title></
00f0   68 65 61 64 3E 3C 62 6F  64 79 3E 0A 3C 70 72 65   head><body>.<pre
0100   3E 0A 0A 20 20 20 20 20  20 20 20 20 20 20 20 20   >..             
0110   20 20 20 5F 20 20 20 20  20 20 20 20 20 20 20 20      _            
0120   20 20 20 20 20 20 5F 20  20 20 20 20 20 20 5F 20         _       _ 
0130   5F 20 20 20 20 20 20 20  20 5F 20 20 20 20 20 5F   _        _     _
0140   20 20 20 20 20 20 5F 5F  5F 5F 20 20 0A 20 5F 20         ____  . _ 
0150   5F 5F 20 5F 5F 5F 20 20  20 5F 5F 5F 7C 20 7C 5F   __ ___   ___| |_
0160   20 5F 5F 20 5F 20 5F 5F  5F 20 5F 20 5F 5F 20 7C    __ _ ___ _ __ |
0170   20 7C 20 5F 5F 5F 20 28  5F 29 20 7C 5F 20 5F 5F    | ___ (_) |_ __
0180   20 5F 7C 20 7C 5F 5F 20  7C 20 7C 20 5F 5F 5F 7C    _| |__ | | ___|
0190   5F 5F 5F 20 5C 20 0A 7C  20 27 5F 20 60 20 5F 20   ___ \ .| '_ ` _ 
01a0   5C 20 2F 20 5F 20 5C 20  5F 5F 2F 20 5F 60 20 2F   \ / _ \ __/ _` /
01b0   20 5F 5F 7C 20 27 5F 20  5C 7C 20 7C 2F 20 5F 20    __| '_ \| |/ _ 
01c0   5C 7C 20 7C 20 5F 5F 2F  20 5F 60 20 7C 20 27 5F   \| | __/ _` | '_
01d0   20 5C 7C 20 7C 2F 20 5F  20 5C 20 5F 5F 29 20 7C    \| |/ _ \ __) |
01e0   0A 7C 20 7C 20 7C 20 7C  20 7C 20 7C 20 20 5F 5F   .| | | | | |  __
01f0   2F 20 7C 7C 20 28 5F 7C  20 5C 5F 5F 20 5C 20 7C   / || (_| \__ \ |
0200   5F 29 20 7C 20 7C 20 28  5F 29 20 7C 20 7C 20 7C   _) | | (_) | | |
0210   7C 20 28 5F 7C 20 7C 20  7C 5F 29 20 7C 20 7C 20   | (_| | |_) | | 
0220   20 5F 5F 2F 2F 20 5F 5F  2F 20 0A 7C 5F 7C 20 7C    __// __/ .|_| |
0230   5F 7C 20 7C 5F 7C 5C 5F  5F 5F 7C 5C 5F 5F 5C 5F   _| |_|\___|\__\_
0240   5F 2C 5F 7C 5F 5F 5F 2F  20 2E 5F 5F 2F 7C 5F 7C   _,_|___/ .__/|_|
0250   5C 5F 5F 0D 0A                                     \__..
None



root@kali:~/Desktop# python synprobe.py -p 53 192.168.243.131/24
Ping to 192.168.243.0 timed out
Ping to 192.168.243.1 timed out

---- Scanning 192.168.243.2 on 1 port(s) ----
Port   State  Service

0 open port(s) and 1 closed port(s)
Ping to 192.168.243.3 timed out
Ping to 192.168.243.4 timed out
Ping to 192.168.243.5 timed out
(repeats until 192.168.243.130)
---- Scanning 192.168.243.131 on 1 port(s) ----
Port   State  Service 
53     Open   domain

1 open port(s) and 0 closed port(s)

---- Establishing connection to 192.168.243.131 on port 53  ----
0000   45 00 00 CF 00 00 40 00  40 11 D1 C2 C0 A8 F3 83   E.....@.@.......
0010   C0 A8 F3 86 00 35 00 35  00 BB 6A D0 00 00 81 80   .....5.5..j.....
0020   00 01 00 02 00 04 00 00  03 77 77 77 02 63 73 0A   .........www.cs.
0030   73 74 6F 6E 79 62 72 6F  6F 6B 03 65 64 75 00 00   stonybrook.edu..
0040   01 00 01 C0 0C 00 05 00  01 00 00 03 84 00 2C 12   ..............,.
0050   65 63 32 2D 31 30 37 2D  32 32 2D 31 37 38 2D 31   ec2-107-22-178-1
0060   35 37 09 63 6F 6D 70 75  74 65 2D 31 09 61 6D 61   57.compute-1.ama
0070   7A 6F 6E 61 77 73 03 63  6F 6D 00 C0 33 00 01 00   zonaws.com..3...
0080   01 00 09 16 F6 00 04 6B  16 B2 9D C0 50 00 02 00   .......k....P...
0090   01 00 02 7F 76 00 05 02  75 31 C0 50 C0 50 00 02   ....v...u1.P.P..
00a0   00 01 00 02 7F 76 00 05  02 72 31 C0 50 C0 50 00   .....v...r1.P.P.
00b0   02 00 01 00 02 7F 76 00  05 02 72 32 C0 50 C0 50   ......v...r2.P.P
00c0   00 02 00 01 00 02 7F 76  00 05 02 75 32 C0 50      .......v...u2.P
None
Ping to 192.168.243.132 timed out
(repeats until 192.168.243.255)


root@kali:~/Desktop# python synprobe.py -p 90-120 192.168.243.131

---- Scanning 192.168.243.131 on 31 port(s) ----
Port   State  Service
111    Open   sunrpc
^C

Program Interrupted
Exiting...

root@kali:~/Desktop# python synprobe.py -p 90-120 192.168.243.131

---- Scanning 192.168.243.131 on 31 port(s) ----
Port   State  Service
111    Open   sunrpc

1 open port(s) and 30 closed port(s)

---- Establishing connection to 192.168.243.131 on port 111  ----
Connection to 192.168.243.131 on port 111 timed out...

---------------------arpwatch.py---------------------
arpwatch.py uses two functions, ARPUpdate() (every 2 minutes) and
checkARP(), along with scapy's sniff(). ARPUpdate() builds a table 
of MAC-IP bindings, sniff() detects all ARP packets on the 
specified interface, and checkARP() takes packets and checks them 
against the previously built table. Any differences are printed to
console.

In this example, I first ran arpwatch.py to build the ARP table. 
Then I ran a ARP spoofing attack to change the MAC address of the 
metasploit VM.

def spoof(routerIP, victimIP):
    victimMAC = MAC(victimIP)
    routerMAC = MAC(routerIP)
    send(ARP(op =2, pdst = victimIP, psrc = routerIP, hwdst = victimMAC))
    send(ARP(op = 2, pdst = routerIP, psrc = victimIP, hwdst = routerMAC))


IP of kali:          192.168.243.134
MAC of kali:         00:0c:29:8f:ed:23
IP of metasploit VM: 192.168.243.131

root@kali:~/Desktop# python arpwatch.py
----------------------------------------
ARP Table created at 2017-11-10 22:27:23.859032
IP Address           MAC Address
192.168.243.131      00:50:56:33:9e:4c
192.168.243.254      00:50:56:e4:8e:6b
192.168.243.1        00:50:56:c0:00:08
192.168.243.2        00:50:56:e4:72:9c
----------------------------------------
192.168.243.131 changed from 00:50:56:33:9e:4c to 00:0c:29:8f:ed:23

root@kali:~/Desktop# python arpwatch.py -i eth0
----------------------------------------
ARP Table created at 2017-11-10 22:45:51.079585
IP Address           MAC Address
192.168.243.131      00:50:56:33:9e:4c
192.168.243.254      00:50:56:e4:8e:6b
192.168.243.1        00:50:56:c0:00:08
192.168.243.2        00:50:56:e4:72:9c
----------------------------------------
192.168.243.131 changed from 00:50:56:33:9e:4c to 00:0c:29:8f:ed:23

