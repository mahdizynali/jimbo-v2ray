import sys
import nmap

up_hosts = []

def findUpHosts(ip_range):
    try:
        nmp = nmap.PortScanner()
        nmp.scan(hosts=ip_range, arguments='-n -sn', timeout=3)
        hosts_list = [(x, nmp[x]['status']['state']) for x in nmp.all_hosts()]
        hosts_list = sorted(hosts_list, key=lambda x: [int(i) for i in x[0].split('.')])
        for host, status in hosts_list:
            if status == "up" :
                up_hosts.append(host)
    except KeyboardInterrupt:
        print("IP scan: Interrupted !!")
        sys.exit(0)