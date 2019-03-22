import socket
import json
import threading

peersync_lock = threading.Lock()
accept_peers = True

def send_success(addr,data):
    if not peersync_lock.locked() and accept_peers:
        peersync_lock.acquire()
        try:
            s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            s.connect((str(addr[0]),int(8802)))
            s.sendall(str(len(str(json.dumps(data)))).encode("utf-8").zfill(10) + str(json.dumps(data)).encode("utf-8"))
            return "Done"
        except:
            return "Error"
        finally:
            peersync_lock.release()