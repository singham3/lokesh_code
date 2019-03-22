

from mining_heavy import miner_address_validate

import websockets
import asyncio
import sqlite3
import time
import super_node
import mempool
import socket

MemPools = mempool.Mempools()

async def hello(websocket, path):



    while True:
        try:
            data = await websocket.recv()

            if data == "send mempool last id":
                mp_last_id = MemPools.Fetchone(file="mempool.db",sql="SELECT transaction_id FROM transactions ORDER BY transaction_id DESC LIMIT 1",write=True)


                if not mp_last_id:
                    mp_last_id = (0,)
                await websocket.send(str(mp_last_id))
                continue

            elif data == "send node last id":
                last_id = super_node.node_fetchone("SELECT ID FROM Nodes ORDER BY ID DESC LIMIT 1")

                if  not last_id:
                    last_id = (0,)
                await websocket.send(str(last_id))
                continue


            elif data == "DONE":
                print(f"> {data}")
                break
            elif data == "node data send":
                print(f"> {data}")
                continue
            elif data ==  "mempool data send":
                print(f"> {data}")
                continue
            elif data == "ledger data send":
                continue
            a = eval(data)

            if miner_address_validate(str(a[0])):
                print("address in format")
                user_exist = super_node.All_Cowrie("SELECT * FROM Nodes WHERE address = %s ", a[0])
                if user_exist:
                    if a[1] == "send ledger last id":
                        print("sending node last id")
                        ledger_last_id = MemPools.Fetchone(file="static/ledger.db",sql="SELECT block_height FROM transactions ORDER BY block_height DESC LIMIT 1",write=True)
                        if not ledger_last_id:
                            ledger_last_id = (0,)
                        await websocket.send(str(ledger_last_id))
                        continue
                    else:
                        print(a,a[1])
                else:
                    await websocket.send(str("user not register"))


            elif len(a) == 5:
                super_node.Insert_Nodes("SELECT * FROM Nodes WHERE address = %s",(a[1],a[2],a[3],a[4]))
                await websocket.send("node received")
                continue

            elif len(a) == 11:
                mp_verify = MemPools.Fetchall(file="mempool.db",sql="SELECT * FROM transactions WHERE txn_id = ?",param=(a[2],),write=True)
                if mp_verify:
                    print("data already in mempool")
                else:
                    mp_insert = MemPools.execute(file="mempool.db",sql="INSERT INTO transactions (timestamp,txn_id, myaddress, recipient, amount, signature,public_key_hashed,operation, openfield, fee) VALUES (?,?,?,?,?,?,?,?,?,?)",param=(a[1], a[2], a[3], a[4], float(a[5]), a[6], a[7], a[8], a[9], float(a[10])),write=True)
                    if mp_insert:
                        await websocket.send("mempool received")

                    else:
                        print("can not insert in mempool database")
                        continue
            elif len(a)==13 or len(a[0]) == 13:

                if str(a[2]).isdigit() and miner_address_validate(str(a[-1])):
                    print("transactions table data")
                    create_ledger = MemPools.execute(file='static/ledger.db',
                                                     sql="CREATE TABLE  IF NOT EXISTS transactions (block_height INTEGER PRIMARY KEY AUTOINCREMENT, timestamp,Nones, address, recipient, amount, block_hash, fee, reward, operation, openfield,Previous_hash, Miner_address)",
                                                     write=True)

                    if create_ledger:
                        mp_verify = MemPools.Fetchall(file="static/ledger.db",sql="SELECT * FROM transactions WHERE block_hash = ?",param=(a[6],), write=True)
                        if mp_verify:
                            print("data already in ledger`s transactions table")
                            continue
                        else:
                            transactions_insert = MemPools.execute(file="static/ledger.db",sql="INSERT INTO transactions(timestamp,Nones, address, recipient, amount, block_hash, fee, reward, operation, openfield,Previous_hash, Miner_address) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",param=(a[1],a[2],a[3],a[4],a[5],a[6],a[7],a[8],a[9],a[10],a[11],a[12]),write=True)
                            if transactions_insert:
                                await websocket.send("ledger transactions received")
                                continue
                            else:
                                print("can not insert in ledger`s transactions database")

                elif str(a[0][2]).isascii() and float(a[0][-1]):
                    print("transfered table data")
                    transfered_insert = False
                    delete_mempool = False
                    create_ledger_t = MemPools.execute(file='static/ledger.db',sql="CREATE TABLE IF NOT EXISTS transfered (block_height , timestamp,txn_id,Nones, sender, recipient, amount , signature, public_key, block_hash, operation, openfield,fee )",write=True)
                    if create_ledger_t:
                        for i in range(len(a)):
                            mp_verify = MemPools.Fetchall(file="static/ledger.db", sql="SELECT * FROM transfered WHERE txn_id = ?",
                                                          param=(a[i][2],), write=True)
                            if mp_verify:
                                print("data already in ledger`s transfered table")
                            else:
                                transfered_insert = MemPools.execute(file="static/ledger.db",sql="INSERT INTO transfered VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",param=(a[i][0],a[i][1],a[i][2],a[i][3],a[i][4],a[i][5],a[i][6],a[i][7],a[i][8],a[i][9],a[i][10],a[i][11],a[i][12]),write=True)
                                print(transfered_insert,delete_mempool)
                                if transfered_insert:
                                    delete_mempool = MemPools.execute(file="mempool.db",sql="DELETE  FROM transactions WHERE signature = ?",param=(a[i][7],),write=True)
                    print(transfered_insert, delete_mempool)
                    if transfered_insert and delete_mempool:
                        await websocket.send("ledger transfered received")
                    else:
                        print("can not insert in ledger`s transfered database")
                else:
                    print("data is not fit in parameter")
                continue




            else:
                print("data not receive")
        except :
            continue

hostname = socket.gethostname()
host = socket.gethostbyname(hostname)
start_server = websockets.serve(hello, host, 8765)
asyncio.get_event_loop().run_until_complete(start_server)
asyncio.get_event_loop().run_forever()


