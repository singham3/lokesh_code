
import websockets
import asyncio
import sqlite3
import time

import  mempool
import newwallet
import sys
import peerhandlers
peer_connection = peerhandlers.Peers()
Mempools = mempool.Mempools()

async def Ledger_sync():
    Signature_enc, address, public_key = newwallet.Signature()
    peer_dict = peer_connection.peers_get()
    for host, port in peer_dict.items():
        async with websockets.connect('ws://{}:{}'.format(host,8765)) as websocket:
            await websocket.send(str((newwallet.address,"send ledger last id")))
            time.sleep(2)
            last_id = await websocket.recv()

            if last_id == "user not register":
                print("user not register")

            last_id = eval(last_id)
            print(last_id)
            while True:
                try:
                    data = Mempools.Fetchone(file="static/ledger.db",sql="SELECT * FROM transactions WHERE block_height > ?",param=last_id,write=True)
                    transfered = Mempools.Fetchall(file="static/ledger.db",sql="SELECT * FROM transfered WHERE block_hash = ?",param=(data[6],),write=True)

                    if data :
                        await websocket.send(str(data))

                        time.sleep(2)
                        if transfered:
                            await websocket.send(str(transfered))
                            time.sleep(3)
                        await websocket.send("ledger data send")

                        greeting = await websocket.recv()
                        print(f"< {greeting}")

                        l_id2 = list(last_id)

                        l_id2[0] = int(l_id2[0]) + 1

                        last_id = tuple(l_id2)


                    elif data == None and transfered == None:
                        await websocket.send("DONE")
                        break
                    else:
                        print("database not connect")
                        continue
                except:
                    print("database connection failed")
                    break
            print("thread terminating...")



asyncio.get_event_loop().run_until_complete(Ledger_sync())





