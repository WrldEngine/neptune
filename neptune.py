from threading import Thread, Lock
from queue import Queue
from colorama import init, Fore, Back, Style
import socket
import time
import argparse
import requests
import os
import subprocess
import sys
import threading

init()
RESET     = Fore.RESET
MAGENTA   = Fore.MAGENTA
YELLOW    = Fore.YELLOW
RED       = Fore.RED
BLACK     = Fore.BLACK
GREEN     = Fore.GREEN

bg_reset  = Back.RESET
bg_red    = Back.RED
bg_yellow = Back.YELLOW
bg_white  = Back.WHITE
bg_mag    = Back.MAGENTA

bnnr = f"""{MAGENTA}
 _   _            _                    
| \ | |          | |                   
|  \| | ___ _ __ | |_ _   _ _ __   ___ 
| . ` |/ _ \ '_ \| __| | | | '_ \ / _ \\
| |\  |  __/ |_) | |_| |_| | | | |  __/
|_| \_|\___| .__/ \__|\__,_|_| |_|\___|
           | |                         
           |_| {RESET}
{bg_yellow}{BLACK}Pulatov Kamran Development (c), 2022 | inst: @callistodev1 | Author: Pulatov Kamran{bg_reset}{RESET}
"""

n_thread = 200
q = Queue()
print_lock = Lock()
name = os.name

parser = argparse.ArgumentParser()
subparsers = parser.add_subparsers(help="commands")

net_scan = subparsers.add_parser('net', help='End point of range IP addresses')
net_scan.add_argument("-i", dest="tar", help="IP address")
net_scan.add_argument("-e", default="255", dest="end", help="End point of range IP addresses")

port_scan = subparsers.add_parser('ports', help='Scanning open ports of domain')
port_scan.add_argument("-i", dest="ip", help="Scanning open ports of domain")
port_scan.add_argument("-p", default="65535", dest="range", help="End point of range ports")

sender = subparsers.add_parser('comm', help='Connecting and sending requests to device')
sender.add_argument("-i", dest="host", help="IP address of domain/device")
sender.add_argument("-c", dest="port", help="Domain's/devise's port")

open_port = subparsers.add_parser('op', help='Checking port of address')
open_port.add_argument("-i", dest="addr", help="IP address")
open_port.add_argument("-p", dest="endport", help="Port")

args = parser.parse_args()

try:
    vars(args)["action"] = sys.argv[1]
except IndexError as e:
    parser.print_help()
    sys.exit()

def scan_port_of_domain(ip, port):
    s = socket.socket()
    try:
        s.connect((ip, int(port)))
    except socket.error:
        print(f"{RED}[-] {YELLOW}{ip}:{port}{RESET}{RED} - {YELLOW}CLOSED{RESET}")
    else:
        s.close()
        print(f"{GREEN}[+] {YELLOW}{ip}:{port}{RESET}{GREEN} - {YELLOW}OPEN{RESET}")

def scan_Ip(ip):
    param = '-n' if name=='nt' else '-c'
    command = ['ping', param, '1', ip]
    result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    if result.returncode == 0 and b'ttl=' in result.stdout.lower():
        print(f"{YELLOW}[+] - {ip:13} - ON{RESET}")

def mainf(host, ports):
    global q
    for t in range(n_thread):
        t = Thread(target=scan_thread)
        t.daemon = True
        t.start()
    for worker in ports:
        q.put(worker)
    q.join()

def scan_thread():
    global q
    while True:
        worker = q.get()
        port_scan(worker)
        q.task_done()

def port_scan(port):
    global ip_org
    host = ip_org
    try:
        s = socket.socket()
        s.connect((host, port))
    except:
        with print_lock:
            pass
    else:
        with print_lock:
            print(f"{YELLOW}[+] {host:15} | {port:5} | OPEN {RESET}")
    finally:
        s.close()

if args.action == 'ports':
    ip = args.ip
    port = args.range
    ip_org = socket.gethostbyname(ip)
    name = socket.getfqdn(ip_org)
    ports = [p for p in range(1, int(port))]
    
    print(bnnr)
    print(f"{RED}IP: {YELLOW}{ip_org}{RESET}{RED}, HOST:{YELLOW}{name}{RESET}")
    print(f"{RED}RANGE: 1 --> {port}{RESET}")

    start = time.time()
    
    print("")
    mainf(ip_org, ports)
    print("")

    total = time.time() - start
    print(f"{RED}Scanning time: %s sec{RESET}" % (round(total),))

elif args.action == 'net':
    print(bnnr)

    my_local_ip = socket.gethostbyname(socket.gethostname())
    net = str(args.tar)
    start_ip = net.split('.')

    point = '.'
    start_ip_lst = start_ip[0] + point + start_ip[1] + point + start_ip[2] + point
    end_point = args.end
    lst_ip = [start_ip_lst + str(i) for i in range(int(end_point) - int(start_ip[3]))]
    lst_ip.remove(my_local_ip) 

    print(f"{RED}Started range {YELLOW}{net}{RESET}{RED} --> {YELLOW}{start_ip_lst+f'{end_point}'}{RESET}\n")
    start = time.time()

    if my_local_ip != '127.0.0.1':
        for host in lst_ip:
            flood = threading.Thread(target=scan_Ip, args=[host]).start()
    else:
        print("Please check your network connection")

    total = time.time() - start
    print(f"\n{RED}Scanning time: %s sec{RESET}" % (round(total),))

elif args.action == 'comm':
    print(bnnr)
    host = args.host 
    port = args.port

    print(f"{YELLOW}Connection to {host}:{port} ---{RESET}\n")

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, int(port)))
    
    echo = s.recv(4096).decode()
    print( echo if len(echo)!=0 else '')
    try:
        while True:
            n = input()
            s.sendall(n.encode())

            data = s.recv(4096)
            try:
                print(data.decode())
            except:
                print(data)
    except ConnectionAbortedError as e:
        print(f"\n{RED}Connection aborted{RESET}")
    s.close()

elif args.action == 'op':
    print(bnnr)
    target = args.addr
    port = args.endport

    ip = socket.gethostbyname(target)
    host = socket.getfqdn(ip)

    print(f"{RED}IP: {YELLOW}{ip}{RESET}{RED}, HOST:{YELLOW}{host}{RESET}\n")
    start = time.time()

    scan_port_of_domain(ip, port)
    
    total = time.time() - start
    print(f"\n{RED}Scanning time: %s sec{RESET}" % (round(total),))
