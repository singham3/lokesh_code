import os



import connections
import mining_heavy
import websockets
import super_node
import socket
import asyncio
import sqlite3
import threading

def data_recv():
    recive_data,addr = connections.receive()
    print(recive_data)
    if recive_data == "mpinsert":
        recive_mp, addr = connections.receive()
        mining_heavy.mempool_recive(recive_mp,addr)

    elif recive_data == "statusget":
        recive_addr, addr = connections.receive()
        mining_heavy.send_status(recive_addr,addr)

    elif recive_data == "addmoney":
        recive_req, addr = connections.receive()
        super_node.requestmoney(recive_req,addr)

    elif recive_data == "register":
        recive_register, addr = connections.receive()
        super_node.register(recive_register,addr)
    elif recive_data == "miner register":
        recive_miner_register, addr = connections.receive()
        super_node.miner_register(recive_miner_register,addr)
    elif recive_data == "check block":
        recive_ckeck_block, addr = connections.receive()
        mining_heavy.Check_block(recive_ckeck_block, addr)
    elif not recive_data:
        pass



while True:
    data_recv()