import subprocess

def check_firewall(port):
    try:
        output = subprocess.check_output(f"sudo ss -ltn 'sport = :{port}'", shell=True)
        if str(port) in output.decode():
            print(f"Port {port} is open in firewall.")
        else:
            print(f"Port {port} is closed in firewall.")
    except Exception as e:
        print(f"Could not check firewall. Error: {str(e)}")

if __name__ == "__main__":
    port = 465
    check_firewall(port)