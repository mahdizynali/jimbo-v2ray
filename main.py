import socket
import time
from datetime import datetime
from utils.config import *

ip_address = "104.17.240.0/20"
splitted = ip_address.split('.')
print(splitted)


starting_number = payload["start"]
ending_number = payload["end"]
ending_number = ending_number + 1
start_time = datetime.now()

def ip_scanner(ip_address):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket.setdefaulttimeout(2)
    result = sock.connect_ex((ip_address, 443))
    if result == 0:
        return 1
    else:
        return 0
live_ip = []

def execute():
    for ip in range(starting_number, ending_number):
        ip_address = splitted[0]+"."+splitted[1]+"."+splitted[2]+"." + str(ip)
        if (ip_scanner(ip_address)):
            live_ip.append(ip_address)
            print(ip_address, "is live")

execute()
end_time = datetime.now()
total_time = end_time - start_time

print("Scanning completed in: ", total_time)



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