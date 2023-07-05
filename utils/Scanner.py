import socket
import time
import requests
from termcolor import colored, cprint

class scanner :
    '''test aliveness , upload speed, download speed'''
    def __init__(self, rangeIP, port, epoch) -> None:
        self.rangeIP = rangeIP
        self.port = port
        self.epoch = epoch
        self.handler()

    def ip_scanner(self, ip) -> bool :
        ''' check whether is an ip alive or not '''
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(1)
        res = sock.connect_ex((ip, 443))
        if res == 0:
            return True
        
    def upload_speed (self, ip) -> None :
        ''' send packet into ip ip address in order to check upload speed time '''
        
        session_up = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(1)
        packet = b"a" * 100000 # 0.1 MB of data
        try :
            session_up.connect((ip, 443))
            t0 = time.time()
            session_up.send(packet)
            session_up.close()
            cprint("upload time : " + time.time() - t0, "green")
        except :
            cprint("upload faild !", "yellow")    

        
    def download_speed(self, n_bytes: int,timeout: int, ips) -> None:
        ''' download initial mount of bytes from specific address to check download speed time '''
        
        try :
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

            cprint("download speed : "+ download_speed, "green")
            cprint("latency : "+ latency, "green")
        except :
            cprint("download faild !", 'yellow')

    def handler(self) -> None :
        ''' pass elements into processor functions and printout results'''
        
        for ip in range(self.epoch):
            ip_address = self.rangeIP + str(ip)
            if (self.ip_scanner(ip_address)):
                print("ip : " + ip_address)
                self.upload_speed(ip_address)
                self.download_speed(1000000, timeout=2, ips=ip_address)
            else:
                text = ip_address + " down !"
                cprint(text, 'red')
            print("="*20)
