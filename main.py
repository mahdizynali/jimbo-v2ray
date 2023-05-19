from utils.config import *
from utils.Scanner import *

# range_ip = payload["range_ips"]
range_ip = "203.28.8.0/24"
final_range = range_ip.replace(range_ip[-4::1],"")
aliveIp = []

# for ip in range(payload["end_point"] + 1):
for ip in range(10):
    ip_address = final_range + str(ip)
    if (ip_scanner(ip_address)):
        aliveIp.append(ip_address)
        print(ip_address)
        upload(ip_address)
        download_speed_test(1000000,timeout=3,ips=ip_address)
    print("="*20)



