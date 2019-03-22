import websockets
import asyncio
import sqlite3
import time
import super_node
import  mempool
import sys
import peerhandlers
peer_connection = peerhandlers.Peers()

async def mempool_sync():

    entry=0
    peer_dict = peer_connection.peers_get()

    for host, port in peer_dict.items():
        async with websockets.connect('ws://{}:{}'.format(host, 8765)) as websocket:
            await websocket.send("send mempool last id")
            last_id = await websocket.recv()
            last_id = eval(last_id)
            print(last_id)
            while True:
                try:
                    conn = sqlite3.connect('mempool.db')
                    cursor = conn.cursor()
                    cursor.execute(mempool.SQL_CREATE)
                    cursor.execute('SELECT * FROM transactions WHERE transaction_id > ?',last_id)
                    data = cursor.fetchone()
                    try:
                        last_entry = data[0]
                    except:
                        last_entry = 0

                    print(data)
                    if last_entry > entry:
                        entry = last_entry

                        time.sleep(2)
                        await websocket.send(str(data))
                        print(f"> {data}")
                        time.sleep(1)
                        await websocket.send("mempool data send")
                        greeting = await websocket.recv()
                        print(f"< {greeting}")

                        l_id2 = list(last_id)

                        l_id2[0] = int(l_id2[0]) + 1

                        last_id = tuple(l_id2)
                    elif last_entry == 0:
                        await websocket.send("DONE")
                        break
                except:
                    print("database connection failed")
                    break
            print("thread terminating...")





asyncio.get_event_loop().run_until_complete(mempool_sync())




