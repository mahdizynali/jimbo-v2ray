import os

directory = os.path.dirname(os.path.realpath(__file__)) 

with open (directory + "/ipv4.txt", "r") as file:
    ips = [line.strip() for line in file.readlines()]
    file.close()


payload = {
    'range_ips' : ips,
    'port' : 443,
    'end_point' : 255
}
