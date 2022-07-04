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

bnnr = """
 _   _            _                    
| \ | |          | |                   
|  \| | ___ _ __ | |_ _   _ _ __   ___ 
| . ` |/ _ \ '_ \| __| | | | '_ \ / _ \\
| |\  |  __/ |_) | |_| |_| | | | |  __/
|_| \_|\___| .__/ \__|\__,_|_| |_|\___|
           | |                         
           |_| By Pulatov Kamran
Pulatov Kamran Development, 2022 | inst: @callistodev1
"""

n_thread = 200
q = Queue()
print_lock = Lock()
name = os.name

parser = argparse.ArgumentParser()
subparsers = parser.add_subparsers(help="commands")

net_scan = subparsers.add_parser('net', help='End point of range IP addresses')
net_scan.add_argument("-t", dest="tar", help="IP address")
net_scan.add_argument("-e", default="255", dest="end", help="End point of range IP addresses")

port_scan = subparsers.add_parser('port', help='Scanning open ports of domain')
port_scan.add_argument("-i", dest="ip", help="Scanning open ports of domain")
port_scan.add_argument("-r", default="65535", dest="range", help="End point of range ports")
args = parser.parse_args()
try:
    vars(args)["action"] = sys.argv[1]
except:
    print("Error ! Invalid command")

def scan_Ip(ip):
    addr = net + str(ip)
    param = '-n' if name=='nt' else '-c'
    command = ['ping', param, '1', addr]
    result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, creationflags=0x08000000)
    if result.returncode == 0 and b'TTL=' in result.stdout:
        print(f"[+] - {addr:13} - ON")

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
            print(f"[+] {host:15} | {port:5} | OPEN")
    finally:
        s.close()

if args.action == 'port':
    ip = args.ip
    port = args.range
    ip_org = socket.gethostbyname(ip)
    name = socket.getfqdn(ip_org)
    ports = [p for p in range(1, int(port))]
    
    print(bnnr)
    print(f"IP: {ip_org}, HOST: {name}")
    print(f"RANGE: 1 --> {port}")

    start = time.time()
    print("---------------")
    mainf(ip_org, ports)
    print("---------------")

    total = time.time() - start
    print(f"Scanning time: %s sec" % (round(total),))

elif args.action == 'net':
    print(bnnr)
    net = str(args.tar)
    net_split = net.split('.')
    a = '.'
    net = net_split[0] + a + net_split[1] + a + net_split[2] + a
    start_point = net_split[3]
    end_point = args.end

    print(f"Started range {net+f'{start_point}'} --> {net+f'{end_point}'}")
    start = time.time()
    for ip in range(int(start_point), int(end_point)):
        if ip == int(net_split[3]):
           continue
        potoc = threading.Thread(target=scan_Ip, args=[ip])
        potoc.start()

    potoc.join()
    total = time.time() - start
    print(f"Scanning time: %s sec" % (round(total),))