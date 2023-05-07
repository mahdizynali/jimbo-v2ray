import socket
import os
import time
from datetime import datetime

directory = os.path.dirname(os.path.realpath(__file__)) 

with open (directory + "/ipv4.txt", "r") as file:
    range_ips = [line.strip() for line in file.readlines()]
    file.close()
