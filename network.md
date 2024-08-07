## day 1
FG - https://net.cybbh.io/public/networking/latest/index.html
VTA Logon - networking-ctfd-1.server.vta:8000 (http://10.50.20.180:8000/)
Miro - https://miro.com/app/board/o9J_klSqCSY=/?share_link_id=16133753693
IP - ssh student@10.50.40.228 -X 
password


Protocol Data Unit (PDU)
  Session-Application -> Data
  Transport -> Segment/Datagram
  Network -> Packet
  Data Link -> Frame
  Physical -> Bit


Internet Standards (Organizations)
  IETF = RFC
  IANA - Internet Numbers
    > # The ones that control who owns a set of IP's
  IEEE - LAN/WAN electrical standards
    > # Responsible for maintaining standards for protocols


============================= Layer 1 (Physical) ==================================
  # There are bits at this level
  # binary, decimal, hex, base64
  word = 32 bits
  half word = 16 bits
  byte = 8
  nibbles = 4
Topologies
> Bus
  > # Half-Duplex
  > # Straight line
> Star
  > # Switch is at the center of the star
> Ring
  > # Key that is shared with the devices in the ring
> Mesh
  > # Some are connected to each other, or all are connected to each other
> Wireless
  > # Wireless devices are connected to a modem
> Hierarchial 
  > # More aligned with an enterprise level company topology
  > # Firewalls, Different layers
Devices
> Hubs
  > # Everyone gets everything (Doesnt check frames that are sent)
  > # it broadcasts to all ports (Packet Collision)
> Repeaters
  > # Like hub, but amplifies signal so its stronger
> Switches
> Routers
  > # Based off of IP
Ethernet Timing (Bit-Time) ???????? <- (Research Later)
Speed        Bit-Time
10Mbps       100ns
100Mbps      10ns
1 Gps        1ns
10 Gbps     .1ns
100 Gbps    .01ns


============================= Layer 2 (Data-Link) ========================================
MAC (Medium Access Control)
  > # Transpose Layer 2 - 3 (Goes UP the OSI Model)
LLC (Logical Link Control
  > # Transpose to MAC Address (Goes DOWN the OSI Model)


Switch Operation
  # build MAC Address (CAM) Table
    > # Learns by reading source MAC Addresses
  # Forwarding Frames
    > # Decision based on destination MAC Address


> Switching Modes
  > Cut through
    > # Default Method
    > # Only check Destination MAC
  > Fragment-Free
    > # Stores first 64 bytes of the frame (Ethernet portion) before forwarding
  > Store-and-Forward
    > # Information is kept and sent at a later time to the destination
> Cam Table Overflow Attack  ?????????????/ <- (Research Later)
  > # Send frames with bogus source MAC Address to switch
  > # Cause switch to fill table with bogus addresses
  > # Switch will not be able to learn new (valid) MAC Addresses


MAC Addressing
> Length:  48-bit | 6 byte | 12 Hex
> Types
  > Unicast: One to One
    > # 8TH bit is off
  > Multicast: One to Many
    > # 8TH bit is off
  > Broadcast: One to All
    > # All bits on


Ethernet Header and Frame
> Mac Header/Trailer: 14 Bytes
> Data: 46-1500 Bytes
> EtherType
  > 0x0800 - IPv4
  > 0x0806 - ARP
  > 0x86DD - IPv6
  > 0x8100 - VLAN !!!!!!!!!!!
  > 0x88a8 - not a duble taging vlan attcat 


VLAN
# Splitting up a switch into virtual ports
> Trunk Link
  > # Joining two switches together with VLAN Ports as if they were physically connected with ethernet
> Types
  > # Default: VLAN 1
  > # Data - User Traffic
  > # Voice - VOIP Traffic
  > # Management - Switch and router managment
  > # Native - Untagged switch and router traffic
> Headers
  > # Header length is: 32 bits
  > # 802.1Q
  > # 802.1AD
> VLAN Hopping Attack
  > # Switch Spoofing (DTP)
  > # Single Tagging
  > # Double Tagging


ARP
> Types
  > ARP (OP 1 and 2)
    > # Requests info. Example: knows ip asks for mac (Location)
  > RARP (OP 3 and 4)
    > # The client requesting an IP Address from the server's gateway
  > Proxy ARP (OP 2)
    > # The host answering the ARP Request from whatever asked where they were
  > Gratuitous ARP (OP 2)
    > # The host broadcasts their location without the request
> ARP Cache
    > # A tables that has translations in it
    > # Collection of Address Resolution Protocol Entries


Man-In-The-Middle With ARP
  > # Causes victim machines to populate their ARP Cache with the MAC Address of the attacker's machine instead of the local router's MAC Address


VLAN Trunking Protocol (VTP)
  > # Dynamically add/remove/modify VLANs
> Cisco Proprietary
> Modes
  > Server
  > Client
  > Transparent
> Vulnerablities
  > Spoofing Attacks

Dynamic Trunking Protocol (DTP)
> # Used to dynamically create trunk links
> Vulnerabilities
  > # Can send crafted messages to form a VLAN trunk link
  > # On By Default
  > # Recomment to:
    > # Disable and manually access trunk link

CDP (Cisco Discovery Protocol)
  # Network Discovery tool or admins that identifies the neighbors
FDP (Foundry Discovery Protocol)
  # Proprietary data link layer protocol
LLDP (Link Layer Discovery Protocol)
  # Neighbors are able to find each other on the local network (principally wired Ethernet)


Spanning Tree Protocol (STP)
  # Layer 2 network protocol used to prevent looping within a network topology 
  # Always forward traffic in specific patterns
  # packets stuck in a loop is a broadcast storm
	  > # STP is a method to prevent this as it disables temporarily any link that is not the best route out. Redundancy can still be in place as a backup
> Types
  > # 802.1D STP
  > # Per VLAN Spanning Tree + (PVST+)
  > # 802.1w - Rapid Spanning Tree Protocol (RSTP)
  > # Rapid per VLAN Spanning Tree + (RPVST+)
  > # 802.1s (Multiple Spanning Tree)
> route bridge selection route out of the network
> spanning tree attack
	# can craft a bdu to deny service with a false/erroneous/spoofed bridge
> Port Security
	> # Restrict – block without shutting down
	> # protect- lets through but logs the mac
	> # shutdown – is shutdown
> Vulnerabilities
  > # Dependent on MAC Addresses
  > # MAC Spoofing
> Mitigiation techniques Layer 1
  > # Shutdown unused ports
  > # Enable Port Security
  > # IP Source Guard
  > # Manually assign STP Root
  > # BPDU Guard
  > # DHCP Snooping
> Mitigation Techniques Layer 2
  > # 802.1x
  > # Dynamic ARP inspection (DAI)
  > # Static CAM Entries
  > # Static ARP Entries


============================== Layer 3 (Network) ============================
IPv4 (0x0800)
> Classful subnetting
  > Class A (0-127)
  > Class B (128-191)
  > Class C (192-223)
  > Class D (224-239)
  > Class E (240-255)
> Classless subnetting (CIDR)
> NAT
> TTL
  > Linux (64)
  > Windows (128)
  > Network Devices
> Types
  > Unicast
  > Multicast
  > Broadcast
> Scopes
  > Public
  > Private (RFC 1918)
  > Loopback (127.0.0.1)
  > Link-Local (APIPA)
  > Multicast (class D)
> Fragmentation
  # Breaking up packets from higher MTU to lower MTU (Maximum Transmission Unit) network
  # Performed by routers
  # MF Flag is on from 1st until 2nd to last
  # offset is on from 2nd until the last
  # offset = (MTU - (IHL x 4)) / 8
> Auto Config
  > APIPA
  > DHCP
    > DORA
> Vulnerability 
  > Rogue DHCP
  > Evil Twin
  > DHCP Starvation 
    # Denial of service
IPv6 (Standardized 2017)
> Fragmentation
  > # Does not support fragmentation within its header
  > # Routers do not fragment IPv6 packets !!!!!!!!!!!!!1
  > # Source adjusts MTU to avoid Fragmentation
  > # Source can use IPv6 fragmentation extension header
> Addressing
  > # 128 bit addressing
> Subnetting
  > # Organizations assigned a 48-bit Prefix by IANA
> Types
  > Unicast
  > Multicast
  > Anycast
ICMPv4
  # IPv4 Protocol
> OS Fingerprinting
  > Linux
    > # Default Size: 64 Bytes
    > # Payload Message: nfo/./.345/.,0u98fgoij
  > Windows:
    > # Default Size: 40 Bytes
    > # Payload Message: abcdefghijklmnopqrstuvwxyz
> Traceroute
  > # Identifies Hops between the source and the destination
  > # Uses incrimenting ttls
  > # Uses ICMP (windows default), UDP (linux default), TCP
> Attacks
  > # Firewalking (Traceroute)
  > # Oversized ICMP Messages
  > # ICMP Redirects
  > # SMURF Attack
  > # Map Network w/ IP unreachables
  > # ICMP Covert Channels

(Classful)
  > # Do not Carry subnet mask information within the routing updates
  > # Exchange routing updaates at the regular time intervals
(Classless)
  > # Opposite of both

Routing Protocol
> # Used Between Layer 3 devices to learn and advertise routes and maintain routing tables
> # Routes a routed protocol for learning and maintaining routing table
Routed Protocol
> # Used between Routers to direct use traffic. It is also called network protocols
> # Routed by routing protocols


IGP and EGP
> IGP (Interior Gateway Protocols)
  > # Routing protocols that are used within an Autonomous System (AS).
  > # Referred to as intra-AS routing.
  > # Organizations and service providers IGPs on their internal networks.
  > # IGPs include RIP, EIGRP, OSPF, and IS-IS.
> EGP (Exterior Gateway Protocols)
  > # Used primarily for routing between autonomous systems.
  > # Referred to as inter-AS routing.
  > # Service providers and large companies will interconnect their AS using an EGP.
  > # The Border Gateway Protocol (BGP) is the only currently viable EGP and is the official routing protocol used by the Internet.
> OSPF
> RIPv2
> EIGRP
> ISIS

Distance Vector Routing Protocols
> # They share entire routing tables with their directly connected neighbors and from these shared tables they determine:
  > Distance
    > # How far away the destination network is from the outer and is based on a metric such as the hop count, cost, bandwidth, delay
  > Vector
    > # Specifies direction to the remote network
Link State Routing Protocols
>  Each router receives an LSA (Link State Adverstisement) and begins to build a map of the entire network


Routing Protocol Vulnerabilities
> DDOS
> Packet Mistreating Attacks (PMA)
> Routing Table Poisoning (RTP)
> Hit and Run DDOS (HAR)
> Persistence Attacks (PA)


BGP
> # Roadmap of the internet
> # Routes traffic between AS Number
> # Advertises IP CIDR address blocks
> # Establishes Peer relationships
> # Complicated Configuration
> # Complicated and slow path selection
> BGP Hijacking
  > # This works by illegitimate advertising of addresses, and takes over the CIDR address blocks corrupting the internet routing tables by falsifying the advertising addresses


Static Routing
> # Manually Configured routes
> # They dont advertise over the network
> # They dont use bandwidth


Dynamic Routing
> # Discover new remote networks
> # Maintaining current routing information
> # Choose the best path to remote networks
> # Recalculate a new path to a remote network should the primary fail


=========================== Layer 4 (Transport) ============================
Well-Know Ports: 0-1023
Registered : 1024-49151
Dynamic: 49152-65535


TCP Flags:
> CWR - 128
> ECE - 64
> URG - 32
> ACK - 16
> PSH - 8
> RST - 4
> SYN - 2
> FYN - 1


========================== Layer 5 (Session) ==================================
VPN
> # Encasulate a private IP through public IPs
> Types
  > # Remote Access VPN
  > # Site-to-Site VPN
  > # Client-to-Site VPN


L2TCP
> # Tunneling Protocol Cisco uses


IPSEC
> # Suite of protocols used to secure IP Communications by providing 3 triad of security at layer 3
> Transport Mode
  > # Only encrypts the payload of the original IP packet leaving the original IP header intact
> Tunnel Mode
  > # IP gets encapsulated and gets a new ip packet by adding an additional ip header
  > # Creates a secure VPN


Proxy
> # Functions as a messenger (An intermediary)
> # EXAMPLE: We want to give Bob a secret santa gift (He wont know it was us who have it to him), instead we use a messenger to give the present to Bob.



Socks
> # TCP ONLY!
> # Forwards TCP Traffic (Proxychains)


Netbios (Examine Network Basic Input Output System)
> # Name Resolution
> # TCP 139, UDP 137/138


SMB
> # TCP 139/445 and DUP 137/138
> # Acilitate the sharing of files, printers, serial ports, and various communications among network nodes


RPC (Examine Remote Procedure Call)
> # allows a program to request a service from another program located on the same system or on remote computer


API
> # Framework of rules and protocols for software components to interact
> # Methods, parameters, and data formats for requests and responses


======================= Layer 6 (Presentation) =====================
Responsibilities
> Translation
> Formating
> Encoding
> Encryption (Symmetric and asymmetric)
> Compression


======================== Layer 5 (Application) ===============================
Telnet
> Port 23
> Remote Login
> Authentication


SSH
> Port 22
> Remote Login
> Encrypted
> Asymmetric or PKI for key exchange
> User authentication
> Architecture
  > # User Key - Aymmetric public key used to identify the user to the server
  > # Host Key - Asymmetric Public key created to identify a server to a user
  > # Session Key - Symmetric Key created by the client and the server that protects the communication for a particular session
> First Connect
  > # RSA Key is saved to /home/<user>/.ssh/known_hosts file !!! Probably Important !!!
> Reconnect
  > # Wont prompt because the host is saved in the known_hosts file
> # If SSH gives an error that the rsa key is changed use this command:
  /> ssh-keygen -f "/home/student/.ssh/known_hosts" -R "172.16.82.106"
> View/change the ssh port, cat the known_hosts file and grep for port to check, and use vi to edit the file and change the port


HTTP(S) (TCP 80/443)
> User Request Methods
  > # GET / HEAD / POST / PUT
> User response codes
  > # 100,200,300,400,500
> Vulnerabilities
  > Flooding
  > Amplicification
  > Low and slow
  > Drive-by Downloads
  > BeEF Framework


DNS
> UDP 53 (Handles Queries/Responses)
> TCP 53 (Zone Transfer)
  > # When the server shares the domain information


FTP
> Port 21
  > # command and control
> Port 20
  > # Data
> Modes
  > # Active (Initiated on Port 21) <- Default
  > # Passive (Uses both ports)


TFTP (Port 69)
> # Clear-Text
> # Reliability provided at the application layer


SMTP (Port 25)
> # Internet standard used for sending electronic mail


POP (Port 110)
> # Used to retrieve electronic mail from a server


IMAP (Port 143)
> # Download electronic mail from a server


DHCP (UDP Port 67/68)
> # Assigns IP Address parameters across an enterprise


NTP (UDP Port 123)
> # Allows for clock sync between computers over packet-switched data networks


TACACS (Port 49)
> # Used for centralized authentication, authorization, and accounting.
> # Cisco


RADIUS (UDP 1645/1646 AND 1812/1813)
> # Open source networking protocol used for centralized autentication, authorization and accounting


SNMP (UDP Port 161/162)
> # Collects and organizes information about managed devices on IP networks


RTP
> # Streaming in real-time media over IP networks, designed for transmitting audio and video when speed is of essense


RDP (Port 3389)
> # Remote Desktop


Kerberos (UDP Port 88)
> # Network authentication protocol that ensures secure authentication for client-server applications.


LDAP (Port 389 and 636)
> # Accessing and managing distributed directory information services
[LECTURE]
Traffic Filtering Concepts
> Protocols Operation
> Header Analysis
> Network Recon
> Tunnel Analysis
> IOA and IOC
> Malware Analysis


Defense in Depth
> Perimeter Security
> Network Security
> Endpoint Security
> Application and OS Security
> Data Security

Default Policies
> Explicit (precisely and clearly expressed)
> Implicit (implied or understood)


Block-Listing vs Allow listing
> Block-listing
  > # Implicit ACCEPT
  > # Explicit DENY
> Allow-Listing (Formerly White-List)
  > # Implicit DENY
  > # Explicit ACCEPT


Firewall Filtering Methods
> Stateless (Packet) Filtering (L3+4)
> Stateful Inspection (L4)
> Circuit-Level (L5)
> Application Layer (L7)
> Next Generation (NGFW) (L7)


Software vs Hardware vs Cloud Firewalls
> Software (typically host-based)
> Hardware (typically network-based)
> Cloud (provided as a service)


Traffic Directions
> A-to-B
  > # Traffic originating from the localhost to the remote-host
    > # You (the client) are the client sending traffic to the server
  > # Return traffic from that remote-host back to the localhost
    > # The server is responding back to you (the client)
> B-to-A
  > # Traffic originating from the remote-host to the localhost
    > # A client is trying to connect to you (the server)
  > # Return traffic from the localhost back to the remote-host
    > # You (the server) are responding back to the client



Netfilter Framework
> Packet Filtering
> Stateless/Stateful Firewalls
> Network address and port translation (NAT and PAT)
> Other packet manupulation



Netfilter Hooks -> Chain
> NF_IP_PRE_ROUTING → PREROUTING
> NF_IP_LOCAL_IN → INPUT
> NF_IP_FORWARD → FORWARD
> NF_IP_LOCAL_OUT → OUTPUT
> NF_IP_POST_ROUTING → POSTROUTING



Netfilter Paradigm
> Tables (contain chains)
> Chains (contain rules)
> Rules (dictate what to match and what actions to perform on packets when packet match a rule)



Separate Applications
> Iptables (IPv4 packet administration)
> Ip6tables (Ipv6 packet adminstration)
> ebtables (Ethernet Bridge frame table administration)
> arptables (Arp packet administration)

============================= IPtables ====================================

Tables of IPtables
> Filter (default table. provides packet filtering)
> NAT (used to translate private <--> public address and ports)
> Mangle (provides special packet alteration. can modify various fields header fields)
> RAW (used to configure exemptions from connection tracking)
> Security (used for Mandatory Access Control (MAC) networking rules)



Chains of IPtables
> PREROUTING (packets entering NIC before routing)
> INPUT (packets to localhost after routing)
> FORWARD (packets routed from on NIC to another (needs to be enabled))
> OUTPUT (packets from localhost to be routed)
> POSTROUTING (packets leaving the system after routing)



Chains Assigned to Each Table
> Filter (INPUT, FORWARD, and OUTPUT)
> NAT (PREROUTING, POSTROUTING, INPUT, and OUTPUT)
> Mangle (All chains)
> Raw (PREROUTING and OUTPUT)
> Security (INPUT, FORWARD, and OUTPUT)



Common IPtable Options
/> -t
  > # Specifies the table. (Default is filter)
/> -A
  > # Appends a rule to the end of the list or below specified rule
/> -I
  > # Inserts the rule at the top of the list or above specified rule
/> -R
  > # Replaces a rule at the specified rule number
/> -D
  > # Deletes a rule at the specified rule number
/> -F
  > # Flushes the rules in the selected chain
/> -L
  > # Lists the rules in the selected chain using standard formatting
/> -S
  > # Lists the rules in the selected chain without standard formatting
/> -P
  > # Sets the default policy for the selected chain
/> -n
  > # Disables inverse lookups when listing rules
/> --line-numbers
  > # Prints the rule number when listing rules
/> -p
  > # Specifies the protocol
/> -i
  > # Specifies the input interface
/> -o
  > # Specifies the output interface
/> --sport
  > # Specifies the source port
/> --dport
  > # Specifies the destination port
/> -s
  > # Specifies the source IP
/> -d
  > # Specifies the destination IP
/> -j
  > # Specifies the jump target action


IPtables Syntax
/> iptables -t [table] -A [chain] [rules] -j [action]
  > # Table: filter*, nat, mangle
  > # Chain: INPUT, OUTPUT, PREROUTING, POSTROUTING, FORWARD



IPtables Rules Syntax
/> -i [ iface ] input
/> -o [ iface ] output
/> -s [ ip.add | network/CIDR ]
/> -d [ ip.add | network/CIDR ]
/> -p icmp [ --icmp-type type# { /code# } ]
/> -p tcp [ --sport | --dport { port1 |  port1:port2 } ]
/> -p tcp [ --tcp-flags SYN,ACK,PSH,RST,FIN,URG,ALL,NONE ]
/> -p udp [ --sport | --dport { port1 | port1:port2 } ]
> # -m to enable iptables extensions:
  /> -m state --state NEW,ESTABLISHED,RELATED,UNTRACKED,INVALID
  /> -m mac [ --mac-source | --mac-destination ] [mac]
  /> -p [tcp|udp] -m multiport [ --dports | --sports | --ports { port1 | port1:port15 } ]    <---- Multiple Ports
  /> -m bpf --bytecode [ 'bytecode' ]
  /> -m iprange [ --src-range | --dst-range { ip1-ip2 } ]
  iptables -t nat -A POSTROUTING -o eth0 -j SNAT --to 172.16.82.106



IPtables action Syntax
> ACCEPT (Allow the packet)
> REJECT (Deny the packet (send an ICMP reponse))
> DROP (Deny the packet (send no response))
/> -j [ ACCEPT | REJECT | DROP ]



Modify IPtables
> Flush table
  /> iptables -t [table] -F
> Change default policy
  /> iptables -t [table] -P [chain] [action]
> Lists rules with rule numbers
  /> iptables -t [table] -L --line-numbers
> Lists rules as commands interpreted by the system
  /> iptables -t [table] -S
> Inserts rule before Rule number
  /> iptables -t [table] -I [chain] [rule num] [rules] -j [action]
> Replaces rule at number
  /> iptables -t [table] -R [chain] [rule num] [rules] -j [action]
> Deletes rule at number
  /> iptables -t [table] -D [chain] [rule num]

================================ NFtables ===================================
NFtable Enhancements
> One table command to replace:
  > iptables
  > ip6tables
  > arptables
  > ebstables
> Simpler, Cleaner syntax
> Less code duplication resulting in faster execution
> simulateous configuration of IPv4 and IPv6


NFtables Families
> ip (IPv4 packets)
> ip6 (IPv6 packets)
> inet (IPv4 and IPv6 packets)
> arp (layer 2)
> bridge (processing traffic/packets traversing bridges.)
> netdev (allows for user classification of packets - nftables passes up to the networking stack (no counterpart in iptables))


NFTables Hooks
> Ingress (netdev only)
> prerouting
> input
> forward
> output
> postrouting


NFtables Chain-Types
> # There are three chain types
> Filter
  > # to filter packets - can be used with arp, bridge, ip, ip6, and inet families
> Route
  > # to reroute packets - can be used with ip and ipv6 families only
> NAT
  > # used for Network Address Translation - used with ip and ip6 table families only


NFtables Syntax
> Create the Table
  /> nft add table [family] [table]
  > [family] = ip*, ip6, inet, arp, bridge and netdev.
  > [table] = user provided name for the table.


> Create the Base Chain
/> nft add chain [family] [table] [chain] { type [type] hook [hook] priority [priority] \; policy [policy] \;}
  > [chain] = User defined name for the chain.
  > [type] =  can be filter, route or nat.
  > [hook] = prerouting, ingress, input, forward, output or postrouting.
  > [priority] = user provided integer. Lower number = higher priority. default = 0. Use "--" before negative numbers.
  > ; [policy] ; = set policy for the chain. Can be accept (default) or drop.
  > # Use "\" to escape the ";" in bash
> Create a Rule in the Chain
/> nft {add|insert} rule [family] [table] [chain] [matches (matches)] [statement]
  > [matches] = typically protocol headers(i.e. ip, ip6, tcp, udp, icmp, ether, etc)
  > (matches) = these are specific to the [matches] field.
  > [statement] = action performed when packet is matched. Some examples are: log, accept, drop, reject, counter, nat (dnat, snat, masquerade)


> Rule Match Options
/> ip [ saddr | daddr { ip | ip1-ip2 | ip/CIDR | ip1, ip2, ip3 } ]
/> tcp flags { syn, ack, psh, rst, fin }
/> tcp [ sport | dport { port1 | port1-port2 | port1, port2, port3 } ]
/> udp [ sport| dport { port1 | port1-port2 | port1, port2, port3 } ]
/> icmp [ type | code { type# | code# } ]
/> ct state { new, established, related, invalid, untracked }
/> iif [iface]
/> oif [iface]


Modify Ntables
/> nft { list | flush } ruleset
/> nft { delete | list | flush } table [family] [table]
/> nft { delete | list | flush } chain [family] [table] [chain]

> List table with handle numbers
/> nft list table [family] [table] [-a]
> Adds after position
/> nft add rule [family] [table] [chain] [position <position>] [matches] [statement]
> Inserts before position
/> nft insert rule [family] [table] [chain] [position <position>] [matches] [statement]
> Replaces rule at handle
/> nft replace rule [family] [table] [chain] [handle <handle>] [matches] [statement]
> Deletes rule at handle
/> nft delete rule [family] [table] [chain] [handle <handle>]
> To change the current policy
/> nft add chain [family] [table] [chain] { \; policy [policy] \;}

======================= NAT Rules ==============================
Configure IPtables NAT Rules
> Source NAT
  /> iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
    /> [EXAMPLE] iptables -t nat -A POSTROUTING -p tcp -o eth0 -s 192.168.0.1 -j SNAT --to 1.1.1.1:900
> Destination NAT
  /> iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 22 -j DNAT --to 10.0.0.1:22
  /> iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 -j DNAT --to 10.0.0.2:80
  /> iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 443 -j DNAT --to 10.0.0.3:443
  /> iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 -j REDIRECT --to-port 8080


Creating NAT Tables and Chains
> Create the NAT table
  /> nft add table ip NAT
> Create the NAT chains
  /> nft add chain ip NAT PREROUTING { type nat hook prerouting priority 0 \; }
  /> nft add chain ip NAT POSTROUTING { type nat hook postrouting priority 0 \; }
> Source NAT
  /> nft add rule ip NAT POSTROUTING ip saddr 10.10.0.40 oif eth0 snat 144.15.60.11
  /> nft add rule ip NAT POSTROUTING oif eth0 masquerade
> Destination NAT
  /> nft add rule ip NAT PREROUTING iif eth0 ip daddr 144.15.60.11 dnat 10.10.0.40
  /> nft add rule ip NAT PREROUTING iif eth0 tcp dport { 80, 443 } dnat 10.1.0.3
  /> nft add rule ip NAT PREROUTING iif eth0 tcp dport 80 redirect to 8080

================== Mangle Rules =========================
Configure IPtables mangle rules
> Mangle examples with IPtables
  /> iptables -t mangle -A POSTROUTING -o eth0 -j TTL --ttl-set 128
  /> iptables -t mangle -A POSTROUTING -o eth0 -j DSCP --set-dscp 26


Configure NFtables mangle rules
> Mangle examples with nftables
  /> nft add table ip MANGLE
  /> nft add chain ip MANGLE INPUT {type filter hook input priority 0 \; policy accept \;}
  /> nft add chain ip MANGLE OUTPUT {type filter hook output priority 0 \; policy accept \;}
  /> nft add rule ip MANGLE OUTPUT oif eth0 ip ttl set 128
  /> nft add rule ip MANGLE OUTPUT oif eth0 ip dscp set 26


============================= Firewalls ================================

Describe Firewall Type
> # Zone-Based Policy Firewall (Zone-Policy Firewall, ZBF or ZFW)
> # Host based firewalls
> # Network based firewalls


Positioning of Filtering Devices on a network
> Determine network segments
> Conduct audit
> filtering devices we need
> Device placement


Typical locations for filtering devices
> IPS
> Firewalls
> Routers
> Switches



Cisco Access Control List ## not on the test
> Standard numbered ACL syntax
  /> router(config)# access-list {1-99 | 1300-1999}  {permit|deny}  {source IP add} {source wildcard mask}
  /> router(config)#  access-list 10 permit host 10.0.0.1
  /> router(config)#  access-list 10 deny 10.0.0.0 0.255.255.255
  /> router(config)#  access-list 10 permit any


Standard named ACL syntax (place as far way from the host as posssible)
  /> router(config)# ip access-list standard [name]
  /> router(config-std-nacl)# {permit | deny}  {source ip add}  {source wildcard mask}
  /> router(config)#  ip access-list standard CCTC-STD
  /> router(config-std-nacl)#  permit host 10.0.0.1
  /> router(config-std-nacl)#  deny 10.0.0.0 0.255.255.255
  /> router(config-std-nacl)#  permit any



Signature vs Behavior based detection
> Signature Based
  > # Looks for known Intrusion stuff
> Behavior Based
  > # Looks at the behavior and identifies intrusion based on the way it acts



Extended numbered ACL Syntax (as close to the source as possible)
/> router(config)# access-list {100-199 | 2000-2699} {permit | deny} {protocol} {source IP add & wildcard} {operand: eq|lt|gt|neq} 
   {port# |protocol} {dest IP add & wildcard} {operand: eq|lt|gt|neq} {port# |protocol}
/> router(config)# access-list 144 permit tcp host 10.0.0.1 any eq 22
/> router(config)# access-list 144 deny tcp 10.0.0.0 0.255.255.255 any eq telnet
/> router(config)# access-list 144 permit icmp 10.0.0.0 0.255.255.255 192.168.0.0 0.0.255.255 echo
/> router(config)# access-list 144 deny icmp 10.0.0.0 0.255.255.255 192.168.0.0 0.0.255.255 echo-reply
/> router(config)# access-list 144 permit ip any any

/> router(config)# ip access-list extended  [name]
/> router(config-ext-nacl)# [sequence number] {permit | deny} {protocol} {source IP add & wildcard} 
   {operand: eq|lt|gt|neq} {port# |protocol} {dest IP add & wildcard} {operand:eq|lt|gt|neq} {port# |protocol}
/> router(config)# ip access-list extended CCTC-EXT
/> router(config-ext-nacl)# permit tcp host 10.0.0.1 any eq 22
/> router(config-ext-nacl)# deny tcp 10.0.0.0 0.255.255.255 any eq telnet
/> router(config-ext-nacl)# permit icmp 10.0.0.0 0.255.255.255 192.168.0.0 0.0.255.255 echo
/> router(config-ext-nacl)# deny icmp 10.0.0.0 0.255.255.255 192.168.0.0 0.0.255.255 echo-reply
/> router(config-ext-nacl)# permit ip any any


Apply An ACL to an Interface or Line
/> router(config)#  interface {type} {mod/slot/port}
/> router(config)#  ip access-group {ACL# | name} {in | out}
/> router(config)#  interface s0/0/0
/> router(config-if)#  ip access-group 10 out
/> router(config)#  interface g0/1/1
/> router(config-if)#  ip access-group CCTC-EXT in
/> router(config)#  line vty 0 15
/> router(config)#  access-class CCTC-STD in



Snort Rules
> Installation Directory
  > /etc/snort
> Config file
  > /etc/snort/snort/conf
> Rules Directory
  > /etc/snort/rules
> Advanced IDS (snort) Rules
  > Rule naming
    > [name].rules
  > Default Log Directory
    > /var/log/snort
  > Common line switches
    /> -D
      > # to run snort as a daemon
    /> -c
      > # to specify a config file when running snort
    /> -l
      > # specify a log directory
    /> -r
      > # to have snort read a pcap file
  > To run snort as a Daemon
    /> sudo snort -D -c /etc/snort/snort.conf -l /var/log/snort
  > To run snort against a PCAP
    /> sudo snort -c /etc/snort/rules/file.rules -r file.pcap
  > Check version
    /> snort --version
  > To check for what the log file for the running daemon is
    /> ps -elf | grep snort
  > SYNTAX
    /> alert [tcp,udp,icmp] [SIP] [SPORT] [<-,->,<->] [DIP] [DPORT] (msg:<message>; sid:<ID>; rev:<rev number>;)
  > To see binary log file in plain text along with hex
    /> tcpdump -r <log file> -XX -vn
      > # -vn just shows more information like TTL
  > To run snort
    /> snort -D -l /var/log/snort/ -c /etc/snort/snort.conf


Snort IDS/IPS Rule Header
/> [action] [protocol] [s.ip] [s.port] [direction] [d.ip] [d.port] ( match conditions ;)
  > Action - alert, log, pass, drop, or reject
  > Protocol - TCP, UDP, ICMP, or IP
  > Source IP address - one IP, network, [IP range], or any
  > Source Port - one, [multiple], any, or [range of ports]
  > Direction - source to destination or both
  > Destination IP address - one IP, network, [IP range], or any
  > Destination port - one, [multiple], any, or [range of ports]



Snort IDS/IPS General Rule options:
/> alert [tcp,udp,icmp] [SIP] [SPORT] [<-,->,<->] [DIP] [DPORT] (msg:<message>; sid:<ID>; rev:<rev number>;)
> msg:"text" - specifies the human-readable alert message
> reference: - links to external source of the rule
> sid: - used to uniquely identify Snort rules (required)
> rev: - uniquely identify revisions of Snort rules
> classtype: - used to describe what a successful attack would do
> priority: - level of concern (1 - really bad, 2 - badish, 3 - informational)
> metadata: - allows a rule writer to embed additional information about the rule



Snort IDS/IPS Payload Detection Options:
> content:"text" - looks for a string of text.
> content:"|binary data|" - to look for a string of binary HEX
> nocase - modified content, makes it case insensitive
> depth: - specify how many bytes into a packet Snort should search for the specified pattern
> offset: - skips a certain number of bytes before searching (i.e. offset: 12)
> distance: - how far into a packet Snort should ignore before starting to search for the specified pattern relative to the end of the previous pattern match
> within: - modifier that makes sure that at most N bytes are between pattern matches using the content keyword



Snort IDS/IPS Non-Payload Detection options:
> flow: - direction (to/from client and server) and state of connection (established, stateless, stream/no stream)
> ttl: - The ttl keyword is used to check the IP time-to-live value.
> tos: - The tos keyword is used to check the IP TOS field for a specific value.
> ipopts: - The ipopts keyword is used to check if a specific IP option is present
> fragbits: - Check for R|D|M ip flags.
> dsize: - Test the packet payload size
> seq: - Check for a specific TCP sequence number
> ack: - Check for a specific TCP acknowledge number.
> flags: - Check for E|C|U|A|P|R|S|F|0 TCP flags.
> itype: - The itype keyword is used to check for a specific ICMP type value.
> icode: - The icode keyword is used to check for a specific ICMP code value.



Snort IDS/IPS Post Detection options:
> logto: - The logto keyword tells Snort to log all packets that trigger this rule to a special output log file.
> session: - The session keyword is built to extract user data from TCP Sessions.
> react: - This keyword implements an ability for users to react to traffic that matches a Snort rule by closing connection and sending a notice.
> tag: - The tag keyword allow rules to log more than just the single packet that triggered the rule.
> detection_filter - defines a rate which must be exceeded by a source or destination host before a rule can generate an event.



Snort IDS/IPS Thresholding and Suppression options:
/> threshold: type [limit | threshold | both], track [by_src | by_dst], count [#], seconds [seconds]
  > limit - alerts on the 1st event during defined period then ignores the rest.
  > threshold - alerts every [x] times during defined period.
  > both - alerts once per time internal after seeing [x] amount of occurrences of event. It then ignores all other events during period.
  > track - rate is tracked either by source IP address, or destination IP address
  > count - number of rule matching in [s] seconds that will cause event_filter limit to be exceeded
  > seconds - time period over which count is accrued. [s] must be nonzero value



Snort rule Example
> Look for anonymous ftp traffic:
  /> alert tcp any any -> any 21 (msg:"Anonymous FTP Login"; content: "anonymous"; sid:2121; )
> This will cause the pattern matcher to start looking at byte 6 in the payload)
  /> alert tcp any any -> any 21 (msg:"Anonymous FTP Login"; content: "anonymous"; offset:5; sid:2121; )
> This will search the first 14 bytes of the packet looking for the word "anonymous"
  /> alert tcp any any -> any 21 (msg:"Anonymous FTP Login"; content: "anonymous"; depth:14; sid:2121; )
> Deactivates the case sensitivity of a text search
  /> alert tcp any any -> any 21 (msg:"Anonymous FTP Login"; content: "anonymous"; nocase; sid:2121; )
> ICMP ping sweep
  /> alert icmp any any -> 10.10.0.40 any (msg: "NMAP ping sweep Scan"; dsize:0; itype:8; icode:0; sid:10000004; rev: 1; )
> Look for a specific set of Hex bits (NoOP sled)
  /> alert tcp any any -> any any (msg:"NoOp sled"; content: "|9090 9090 9090|"; sid:9090; rev: 1; )
> Telnet brute force login attempt
  /> alert tcp any 23 -> any any (msg:"TELNET login incorrect";
     content:"Login incorrect"; nocase; flow:established, from_server;
     threshold: type both, track by_src, count 3, seconds 30;
     classtype: bad-unknown; sid:2323; rev:6; )


Technical attacks on IDS/IPS
> # Packet sequence manipulation
> # Fragmentation payload
> # Overlapping fragments with different reassembly by devices
> # Manipulating TCP headers
> # Manipulating IP options
> # Sending data during the TCP connection setup


Non-Technical Attacks against IDS/IPS
> # Attacking during periods of low manning
  > # Example - Ramadan 2012 Saudi Aramco attack
> # Attacking during a surge in activity
  > # Example - Target Corp. Point of sale machines during  the thanksgiving-christmas 2013 shopping season






alert icmp any any -> any any (msg:"Cows"; content:"|DEADBEEF|"; sid:1000001;)
>>>DEADBEEF in hex
alert icmp any any -> 10.3.0.0/24 any (msg:"DMZ Ping";itype:8;icode:0;sid:1000002;)
alert udp any any -> 10.0.0.0/8 [137,138] (sid:1000007;)
alert tcp any any -> 10.0.0.0/8 [137,139,445] (sid:1000008;)
alert ip any 3389 -> 192.168.65.20 any (sid:1000004;)
alert tcp any any -> any 22 (msg:"Oh no ";threshold:type both,track by_src,count 3,seconds 10;sid:1000005;)
