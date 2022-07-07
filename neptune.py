import socket
import time
from threading import Thread, Lock
from queue import Queue
import argparse
import requests
import os
import subprocess
import sys
import threading
from colorama import init, Fore, Back, Style

init()
RESET = Fore.RESET
MAGENTA = Fore.MAGENTA
YELLOW = Fore.YELLOW
RED = Fore.RED
BLACK = Fore.BLACK

bg_reset = Back.RESET
bg_red = Back.RED
bg_yellow = Back.YELLOW
bg_white = Back.WHITE
bg_mag = Back.MAGENTA

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

port_scan = subparsers.add_parser('port', help='Scanning open ports of domain')
port_scan.add_argument("-i", dest="ip", help="Scanning open ports of domain")
port_scan.add_argument("-p", default="65535", dest="range", help="End point of range ports")

sender = subparsers.add_parser('comm', help='Connecting and sending requests to device')
sender.add_argument("-i", dest="host", help="IP address of domain/device")
sender.add_argument("-c", dest="port", help="Domain's/devise's port")

args = parser.parse_args()

try:
    vars(args)["action"] = sys.argv[1]
except IndexError as e:
    parser.print_help()
    sys.exit()
    
def scan_Ip(ip):
    addr = net + str(ip)
    param = '-n' if name=='nt' else '-c'
    command = ['ping', param, '1', addr]
    result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, creationflags=0x08000000)
    if result.returncode == 0 and b'TTL=' in result.stdout:
        print(f"{YELLOW}[+] - {addr:13} - ON{RESET}")

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

if args.action == 'port':
    ip = args.ip
    port = args.range
    ip_org = socket.gethostbyname(ip)
    name = socket.getfqdn(ip_org)
    ports = [p for p in range(1, int(port))]
    
    print(bnnr)
    print(f"{RED}IP: {YELLOW}{ip_org}{RESET}{RED}, HOST:{YELLOW}{name}{RESET}")
    print(f"{RED}RANGE: 1 --> {port}{RESET}")

    start = time.time()
    z = len(mainf(ip_org, ports))
    print(f"{YELLOW}-{RESET}" * z)
    mainf(ip_org, ports)
    print(f"{YELLOW}---------------{RESET}")

    total = time.time() - start
    print(f"{RED}Scanning time: %s sec{RESET}" % (round(total),))

elif args.action == 'net':
    print(bnnr)
    net = str(args.tar)
    net_split = net.split('.')
    a = '.'
    net = net_split[0] + a + net_split[1] + a + net_split[2] + a
    start_point = net_split[3]
    end_point = args.end

    print(f"{RED}Started range {YELLOW}{net+f'{start_point}'}{RESET}{RED} --> {YELLOW}{net+f'{end_point}'}{RESET}\n")
    start = time.time()
    for ip in range(int(start_point), int(end_point)):
        if ip == int(net_split[3]):
           continue
        potoc = threading.Thread(target=scan_Ip, args=[ip])
        potoc.start()

    potoc.join()
    total = time.time() - start
    print(f"\n{RED}Scanning time: %s sec{RESET}" % (round(total),))

elif args.action == 'comm':
    print(bnnr)
    host = args.host 
    port = args.port

    print(f"{YELLOW}Connection to {host}:{port} ---{RESET}")

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, int(port)))
    data = s.recv(4096)
    print(data)
    while len(data) != 0:
        n = input()
        s.sendall(n.encode())
    s.close()
