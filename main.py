import socket
import time
from utils.config import *

# range_ip = payload["range_ips"]
range_ip = "104.17.240.0/20"
final_range = range_ip.replace(range_ip[-4::1],"")
live_ip = []

def upload (ip):
    session_up = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    packet = b"a" * 1000000 # 0.1 MB of data
    session_up.connect((ip, payload["port"]))
    t0 = time.time()
    session_up.send(packet)
    session_up.close()
    print(time.time() - t0)


def download (ip):
    session_down = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try :
        session_down.bind((ip, payload["port"]))
        session_down.listen()
        conn, addr = session_down.accept()
        session_down = 0
        t0 = time.time()
        while True:
            data = conn.recv(256*1024)
            session_down += len(data)
            if session_down == 1000000:
                break
        print(time.time() - t0)
    except :
        print(ip, " fault")
        

def ip_scanner(ip_address):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket.setdefaulttimeout(1)
    res = sock.connect_ex((ip_address, payload["port"]))
    if res == 0:
        return True
    
# for ip in range(payload["end_point"] + 1):
for ip in range(3):
    ip_address = final_range + str(ip)
    if (ip_scanner(ip_address)):
           live_ip.append(ip_address)
           print(ip_address, "is live")
           upload(ip_address)
           download(ip_address)
           print("="*20)

print("done")