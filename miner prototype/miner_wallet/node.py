from urllib.parse import urlparse
from socks import *
from peerhandlers import  *



def convert_ip_port(ip):
    if ':' in ip:
        ip, some_port = ip.split(':')
    return ip, int(some_port)
def set_port():
    s= socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    host = socket.gethostbyname(socket.gethostname())
    s.bind((str(host), 8802))
    s.listen()
    conn,addr = s.accept()
    return conn , s,addr





