import sys
sys.path.insert(0,'E:\study\cowrie prototype\miner prototype')
import socket
import json
import chat1

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)         # Create a socket object
host = chat1.addr[0]    #private ip address of machine running fedora
port = 8800

data = "Success"
slen = 10
s.connect((host, port))


s.sendall(data.encode())
