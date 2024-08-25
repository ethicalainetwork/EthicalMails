import socket
import os
import subprocess

def check_port_open(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    result = sock.connect_ex((ip,port))
    if result == 0:
       print(f"Port {port} is open on {ip}")
    else:
       print(f"Port {port} is not open on {ip}")
    sock.close()

def check_dns(domain):
    try:
        resolved_ip = socket.gethostbyname(domain)
        print(f"{domain} resolved to {resolved_ip}")
    except Exception as e:
        print(f"Could not resolve {domain}. Error: {str(e)}")

def check_firewall(port):
    # This is only working on systems with "firewall-cmd" command like CentOS
    try:
        output = subprocess.check_output(f"firewall-cmd --query-port={port}/tcp", shell=True)
        if "yes" in output.decode():
           print(f"Port {port} is open in firewall.")
        else:
           print(f"Port {port} is closed in firewall.")
    except Exception as e:
        print(f"Could not check firewall. Error: {str(e)}")

if __name__ == "__main__":
    ip = "localhost"
    port = 465
    domain = "example.com"

    check_port_open(ip, port)
    check_dns(domain)
    check_firewall(port)