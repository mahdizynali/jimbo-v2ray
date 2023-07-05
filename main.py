# Authored By Mahdi Zeinali - 2023
# github : github.com/mahdizynali

from utils.Scanner import scanner

range_ip = "203.28.8.0/24"
final_range = range_ip.replace(range_ip[-4::1],"")

scan = scanner(final_range, port=443, epoch=10)