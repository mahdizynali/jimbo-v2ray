import socket
import time
import requests
from termcolor import colored, cprint
from multiprocessing import Pool

class scanner :
    '''test aliveness , upload speed, download speed'''
    def __init__(self, rangeIP, port, epoch, num_processes) -> None:
        self.rangeIP = rangeIP
        self.port = port
        self.epoch = epoch
        self.num_processes = num_processes
        self.ip_address = []
        self.generate_ip()
        with Pool(processes=num_processes) as pool:
            pool.map(self.handler, self.ip_address)
        
    def generate_ip(self):
        for ip in range(self.epoch) :
            self.ip_address.append(self.rangeIP + str(ip))
            
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
            return (time.time() - t0)
        except :
            return False 

        
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
            # cprint("latency : "+ latency, "green")
            return download_speed
        except :
            return False

    def handler(self, ip_address) -> None :
        ''' pass elements into processor functions and printout results'''
        if (self.ip_scanner(ip_address)):
            up_spead = self.upload_speed(ip_address)
            down_spead = self.download_speed(1000000, timeout=2, ips=ip_address)
            if (up_spead != False and down_spead != False) :
                cprint("alive ip : " + ip_address, "green")
                print("upload speed : "+ up_spead , "green")
                print("download speed : "+ down_spead , "green")
            else:
                cprint(ip_address + " down !", 'red')
            print("="*20)
        else:   
            cprint(ip_address + " down !", 'red')
            print("="*20)