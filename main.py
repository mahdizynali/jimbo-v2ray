import socket
import time
from utils.config import *

# range_ip = payload["range_ips"]
range_ip = "104.17.240.0/20"
final_range = range_ip.replace(range_ip[-4::1],"")

def ip_scanner(ip_address):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket.setdefaulttimeout(1)
    result = sock.connect_ex((ip_address, payload["port"]))
    if result == 0:
        return 1
    else:
        return 0
live_ip = []


# for ip in range(payload["end_point"] + 1):
for ip in range(5):
    ip_address = final_range + str(ip)
    
    if (ip_scanner(ip_address)):
           live_ip.append(ip_address)
           print(ip_address, "is live")

print("done")



# def upload (ip):
#     s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     a = b"a" * 100_000_0  # 100 MB of data
#     s.connect((ip, 443))
#     t0 = time.time()
#     s.send(a)
#     s.close()
#     print(time.time() - t0)


# def download (ip):
#     s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#     s.bind((ip, 443))
#     s.listen()
#     conn, addr = s.accept()
#     s = 0
#     t0 = time.time()
#     while True:
#         data = conn.recv(256*1024)
#         s += len(data)
#         if s == 100_000_000:
#             break
#     print(time.time() - t0)

# download("104.17.240.2")