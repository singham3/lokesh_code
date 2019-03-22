from urllib.parse import urlparse
from socks import *
from peerhandlers import  *

nodes = set()
node_address1 = {"a891f1f7039adab56c3c5204632baabbab0f78c4e52c3d48eee42605":'192.168.1.7:8877',"c891f1f7039adab56c3c5204632baabbab0f78c4e52c3d48eee42605":'192.168.1.13:2628',"d891f1f7039adab56c3c5204632baabbab0f78c4e52c3d48eee42605":'192.168.1.29:2628'}

def convert_ip_port(ip):
    if ':' in ip:
        ip, some_port = ip.split(':')
    return ip, int(some_port)
def set_port():
    s= socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    host = socket.gethostbyname(socket.gethostname())
    s.bind((str(host),8802))
    s.listen()
    conn,addr = s.accept()
    return conn , s

def add_node(address):
    recipient_ip = node_address1[address]
    ip,port=convert_ip_port(recipient_ip)
    s = socksocket()
    if s.connect((ip,port)):
        nodes.add(ip)
        response = {'message': 'All the nodes are now connected. The Hadcoin Blockchain now contains the following nodes:',
                    'total_nodes': list(nodes)}
        print(response)
        s.close()
    else:
        response = "node is not connect to {}:{}".format(ip,port)
        print(response)