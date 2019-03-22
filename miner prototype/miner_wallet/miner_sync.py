import asyncio
import websockets
import time
import sqlite3
import mempool


mempools = mempool.Mempools()

async def hello():
    entry=0
    block_entry = 0
    flag = 0
    flag1 = 0
    while True:
        while True:
            async with websockets.connect('ws://192.168.1.21:8764') as websocket:
                print("connected")

                data = mempools.Fetchone('mempool.db','SELECT * FROM transactions ORDER BY transaction_id DESC LIMIT 1',write=True)
                data2 = mempools.Fetchone('static/ledger.db','SELECT * FROM transactions ORDER BY block_height DESC LIMIT 1',write=True)
                print(type(data[0]),type(data2[0]))
                last_entry = data[0]
                last_block_entry = data2[0]
                if last_entry > entry :
                    entry= last_entry
                    mempool_data = data + ("mempool data",)
                    time.sleep(2)
                    await websocket.send(str(mempool_data))

                    print(f"> {mempool_data}")
                    flag = 1


                if last_block_entry>block_entry:
                    block_entry = last_block_entry


                    block_data = data2 + ("block data",)
                    time.sleep(2)
                    await websocket.send(str(block_data))

                    print("block data-->", block_data)

                    flag1 = 1
                if flag == 1 and flag1 == 1:
                    print("DONE")
                    await websocket.send("DONE")
                    greeting = await websocket.recv()
                    print(f"< {greeting}")
                    break
                else:
                    print("data sending error")
                if last_entry == None or last_block_entry == None:
                    print("DONE")
                    await websocket.send("DONE")
                    greeting = await websocket.recv()
                    print(f"< {greeting}")
                    break
                else:
                    await websocket.send("Waiting For New Entry!!!!")
                    time.sleep(5)

        if flag == 1 and flag1 == 1:
            print("data send successfully")
            print("thread terminating...")
            break
        else:
            continue


asyncio.get_event_loop().run_until_complete(hello())
asyncio.get_event_loop().run_forever()