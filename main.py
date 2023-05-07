import socket
import time
from utils.config import *

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

def download (ip) -> None :
    session_down = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try :
        session_down.bind((ip, 34425))
        print("here")
        session_down.listen(5)
        conn, addr = session_down.accept()
        data = 0
        t0 = time.time()
        while True:
            data = conn.recv(256*1024)
            data += len(data)
            if not data: 
                break
        print(time.time() - t0)
    except :
        print(ip, " download fault")
        

def ip_scanner(ip_address) -> bool :
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket.setdefaulttimeout(1)
    res = sock.connect_ex((ip_address, payload["port"]))
    if res == 0:
        return True
    
# for ip in range(payload["end_point"] + 1):
for ip in range(10):
    ip_address = final_range + str(ip)
    # if (ip_scanner(ip_address)):
    live_ip.append(ip_address)
    print(ip_address)
    upload(ip_address)
    # download(ip_address)
    print("="*20)

# import socketserver
# def get_free_port() -> int:
#     """returns a free port

#     Returns:
#         int: free port
#     """
#     with socketserver.TCPServer(("203.28.8.0", 0), None) as s:
#         free_port = s.server_address[1]
#     return free_port

# print(get_free_port())
test something
