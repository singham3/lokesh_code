import websockets
import asyncio
import sqlite3
import time
import super_node
import  mempool
import sys

import peerhandlers
peer_connection = peerhandlers.Peers()
async def node_sync():
    peer_dict = peer_connection.peers_get()
    for host, port in peer_dict.items():
        async with websockets.connect('ws://{}:{}'.format(host, 8765)) as websocket:
            await websocket.send("send node last id")
            time.sleep(2)
            last_id = await websocket.recv()
            last_id = eval(last_id)
            print(last_id)
            while True:
                try:
                    nodes = super_node.node_fetchone("SELECT * FROM nodes WHERE ID > %s",last_id)

                    if nodes:
                        time.sleep(2)
                        await websocket.send(str(nodes))

                        time.sleep(1)
                        await websocket.send("node data send")
                        greeting = await websocket.recv()
                        print(f"< {greeting}")

                        l_id2 = list(last_id)

                        l_id2[0] = int(l_id2[0]) + 1

                        last_id = tuple(l_id2)

                    else:
                        await websocket.send("DONE")
                        break
                except :

                    print("Database connection failed")
                    break


            print("thread terminating...")



asyncio.get_event_loop().run_until_complete(node_sync())




