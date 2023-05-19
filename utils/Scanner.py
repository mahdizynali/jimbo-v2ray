# import sys
# import nmap
# up_hosts = []
# def findUpHosts(ip_range):
#     try:
#         nmp = nmap.PortScanner()
#         nmp.scan(hosts=ip_range, arguments='-n -sn', timeout=3)
#         hosts_list = [(x, nmp[x]['status']['state']) for x in nmp.all_hosts()]
#         hosts_list = sorted(hosts_list, key=lambda x: [int(i) for i in x[0].split('.')])
#         for host, status in hosts_list:
#             if status == "up" :
#                 up_hosts.append(host)
#     except KeyboardInterrupt:
#         print("IP scan: Interrupted !!")
#         sys.exit(0)

import socket
import time
import requests
from config import payload

def ip_scanner(ip_address) -> bool :
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket.setdefaulttimeout(1)
    res = sock.connect_ex((ip_address, payload["port"]))
    if res == 0:
        return True
    
def upload (ip) -> None :
    session_up = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket.setdefaulttimeout(1)
    packet = b"a" * 100000 # 0.1 MB of data
    try :
        session_up.connect((ip, payload["port"]))
        t0 = time.time()
        session_up.send(packet)
        session_up.close()
        print("upload time : ",time.time() - t0)
    except :
        print(ip, " upload failed")    

    
def download_speed_test(n_bytes: int,timeout: int, ips):
    
    start_time = time.perf_counter()
    r = requests.get(
        url=f"http://{ips}/__down",
        params={"bytes": n_bytes},
        timeout=timeout,
        headers={"Host": "speed.cloudflare.com"}
    )
    total_time = time.perf_counter() - start_time
    cf_time = float(r.headers.get("Server-Timing").split("=")[1]) / 1000
    latency = r.elapsed.total_seconds() - cf_time
    download_time = total_time - latency

    mb = n_bytes * 8 / (10 ** 6)
    download_speed = mb / download_time

    print("download speed : ",download_speed, "   latency : ",latency)