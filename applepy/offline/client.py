import requests
import re

SERVER_ADDRESS = "http://127.0.0.1:5000"

if __name__ == '__main__':
    address_input = input("Enter server IP address (default http://127.0.0.1:5000): ")
    if address_input is not "":
        SERVER_ADDRESS = address_input
    while True:
        option = input("Welcome\n[1] Show alerts\n[0] Leave\n >")
        ips_to_block = []
        if option == "1":
            response = requests.get(SERVER_ADDRESS).json()
            for line in response[1]:
                print(line)
                ips = re.findall("\d{0,3}\.\d{0,3}\.\d{0,3}\.\d{0,3}", line)
                for ip in ips:
                    if ip not in ips_to_block:
                        ips_to_block.append(ip)
            if response[0] is True:
                print("=======================\n ADD RULE TO FIREWALL!\n=======================")
                for ip in ips_to_block:
                    print("BLOCK IP '{0}'\n".format(ip))
        if option == "0":
            break
