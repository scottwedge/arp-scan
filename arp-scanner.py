#!/usr/bin/python

import sys
from datetime import datetime


def banner():
        print("\t\t\033[93m                 __                 \033[1;m")
        print("\t\t\033[97m   _  _______\033[1;m   \033[93m/ /\033[1;m  \033[97m________  _____\033[1;m")
        print("\t\t\033[97m  | |/_/ ___/\033[1;m  \033[93m/ /\033[1;m  \033[97m/ ___/ _ \/ ___/\033[1;m")
        print("\t\t\033[97m _>  <(__  )\033[1;m  \033[93m/ /\033[1;m  \033[97m(__  )  __/ /__  \033[1;m")
        print("\t\t\033[97m/_/|_/____/\033[1;m  \033[93m/ /\033[1;m  \033[97m/____/\___/\___/\033[1;m")
        print("\t\t\033[93m            /_/\033[1;m")
        print("\n\t\t\033[97m       D.H.L \033[1;m\033[1;31m|\033[1;31m\033[97m xssec.id\033[1;m")

banner()


print "\n"
try:
        interface = raw_input("[*] Enter Desired Interface: ") # Get interface to scan
        ips = raw_input("[*] Enter Range of IPs to Scan for: ") # Get IP or IP range to scan
except KeyboardInterrupt:
        print "\n[*] User Requested Shutdown"
        print "[*] Quitting..."
        sys.exit(1)


print "\n[*] Scanning..." # Initiate scanning
start_time = datetime.now()

try:
        from scapy.all import srp, Ether, ARP, conf # Immport needed modules from scapy
except ImportError:
        print "[!] Scapy Installation Not Found"
        sys.exit(1)

conf.verb = 0  # Actually start scanning

try:
        ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst = ips), timeout = 2, iface=interface,inter=0.1)
except Exeption:
        print "[!] Failed to Resolve Mac-Address"
        sys.exit(1)
print "+-----------------------------------+"
print "|       MAC       -    IP           |" # Set up for result display
print "+-----------------------------------+"
for snd, rcv in ans:
        print rcv.sprintf(r"%Ether.src% - %ARP.psrc%") # Display results
stop_time = datetime.now() #Stp clock for total duration
total_time = stop_time - start_time # Find total time
print "\n[*] Scan Complete!" # Confirm scan completion
print ("[*] Scan Duration: %s" %(total_time)) #Display scan duration

# end of arp-scanner.py
