import socket
import time
from utils.config import *
from utils.Scanner import findUpHosts


import time
from typing import Tuple

import requests

# range_ip = payload["range_ips"]
range_ip = "203.28.8.0/24"
final_range = range_ip.replace(range_ip[-4::1],"")
live_ip = []

def upload (ip) -> None :
    session_up = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket.setdefaulttimeout(1)
    packet = b"a" * 100000 # 0.1 MB of data
    try :
        session_up.connect((ip, payload["port"]))
        t0 = time.time()
        session_up.send(packet)
        session_up.close()
        print(time.time() - t0)
    except :
        print(ip, " out")

# def download (ip) -> None :
#     session_down = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     try :
#         session_down.bind(("https://"+ip+"/__down" , 443))
#         print("here")
#         session_down.listen(5)
#         conn, addr = session_down.accept()
#         data = 0
#         t0 = time.time()
#         while True:
#             data = conn.recv(256*1024)
#             data += len(data)
#             if not data: 
#                 break
#         print(time.time() - t0)
#     except :
#         print(ip, " download fault")
        

def ip_scanner(ip_address) -> bool :
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket.setdefaulttimeout(1)
    res = sock.connect_ex((ip_address, payload["port"]))
    if res == 0:
        return True
    
def download_speed_test(
    n_bytes: int,
    timeout: int,
    ips
) -> Tuple[float, float]:
    
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

    return download_speed, latency


# for ip in range(payload["end_point"] + 1):
for ip in range(10):
    ip_address = final_range + str(ip)
    # if (ip_scanner(ip_address)):
    live_ip.append(ip_address)
    print(ip_address)
    d,l = download_speed_test(1000000,timeout=3,ips=ip_address)
    # upload(ip_address)
    # download("203.28.8.5")
    print(d, "    ", l)
    print("="*20)



