import socket
import ssl

target_host = "mail.datas.world"
target_port = 465

# Create a socket object
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(10)

# Wrap the socket with SSL
wrappedSocket = ssl.wrap_socket(sock)

try:
    # Try to connect
    wrappedSocket.connect((target_host, target_port))
    print('Connection Success!')
except Exception as e:
    print('Connection Error:', e)
finally:
    wrappedSocket.close()