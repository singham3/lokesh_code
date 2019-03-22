import connections
import threading
import mining_heavy
from mempool import *
import chat1
import sqlite3
import json
import sys

while True:
    recive_data, soc,addr = connections.receive()
    soc.close()
    print(recive_data)
    if recive_data == "mpinsert":
        recive_mp, sock, addr = connections.receive()
        sock.close()
        mining_heavy.mempool_recive(recive_mp,addr)
        continue
    elif recive_data == "statusget":
        recive_addr, s, addr = connections.receive()
        s.close()
        print(recive_addr,addr)
        mining_heavy.send_status(recive_addr,addr)
        continue
    elif not recive_data:
        continue






