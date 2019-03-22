from socket import socket, gethostbyname, AF_INET, SOCK_DGRAM,SOCK_STREAM
import json
import sys
PORT_NUMBER = 8800
SIZE = 2048

hostName = "192.168.1.13"

mySocket = socket( AF_INET, SOCK_STREAM )
mySocket.bind( (hostName, PORT_NUMBER) )
mySocket.listen()
conn,addr=mySocket.accept()
print ("Test server listening on port {0}\n".format(PORT_NUMBER))
print(addr)
if True:
    try:
        data= int(conn.recv(10).decode())
    except:
        raise RuntimeError("Connection closed by the remote host")  # do away with the invalid literal for int
else:
    print("*")
print(data)
Success="Success"
chunks = []
bytes_recd = 0

while bytes_recd < data:

    if True:
        chunk = conn.recv(min(data - bytes_recd, 2048))

        if not chunk:
            pass
        if chunk:
            chunks.append(chunk)
            import api
            print(chunks)

        bytes_recd = bytes_recd + len(chunk)
    else:
         raise RuntimeError("Socket timeout")

segments = b''.join(chunks).decode("utf-8")
#print("Received segments: {}".format(segments))

print(json.loads(segments))

sys.exit()