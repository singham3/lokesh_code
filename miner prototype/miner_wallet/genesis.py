import hashlib
import socket
import re
import sqlite3
import os
import sys
import time
import base64
import json
import chat1
import connections
from Cryptodome.Hash import SHA224
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import PKCS1_v1_5
from  mempool import Mempools
import peerhandlers
from Cryptodome import Random
import asyncio
import subprocess

peer_connect = peerhandlers.Peers()

if os.path.isfile("privkey.der"):
    print("privkey.der found")
elif os.path.isfile("privkey_encrypted.der"):
    print("privkey_encrypted.der found")

else:
    # generate key pair and an address
    key = RSA.generate(4096)
    public_key = key.publickey()

    private_key_readable = key.exportKey()
    public_key_readable = key.publickey().exportKey()
    address = hashlib.sha224(public_key_readable).hexdigest()  # hashed public key
    # generate key pair and an address
    with open("privkey.der", "a") as f:
        f.write(private_key_readable.decode())

    with open("pubkey.der", "a") as f:
        f.write(public_key_readable.decode())

    with open("address.txt", "a") as f:
        f.write("{}\n".format(address))



# import keys
c = open('privkey.der').read()

key = RSA.importKey(c.encode())

public_key = key.publickey()
private_key_readable = key.exportKey()
public_key_readable = key.publickey().exportKey()
address = hashlib.sha224(public_key_readable).hexdigest()


public_key_hashed = base64.b64encode(public_key_readable)

mempoolss = Mempools()



from mining_heavy import *

def Mining():

    query = "SELECT * FROM transactions WHERE address = ?"

    c = mempoolss.Fetchone(file="static/ledger.db", sql=query, param= ("genesis",),write=True)

    print(c)
    if not c:

        timestamp = str(time.time())

        transaction = (timestamp, "genesis", address, str(float(15000000000)), "genesis")
        h = SHA224.new(str(transaction).encode())
        signer = PKCS1_v1_5.new(key)
        signature = signer.sign(h)
        signature_enc = base64.b64encode(signature)

        proof, block_hash, mine_time = proof_of_work(0, transaction)
        # block_hash = hashlib.sha224(str((timestamp, transaction)).encode("utf-8")).hexdigest()  # first hash is simplified

        cursor = None
        mem_cur = None
        try:
            conn = sqlite3.connect('static/ledger.db')
            cursor = conn.cursor()
            cursor.execute(
                "CREATE TABLE transactions (block_height INTEGER PRIMARY KEY AUTOINCREMENT, timestamp,Nones, address, recipient, amount, block_hash, fee, reward, operation, openfield,Previous_hash, Miner_address)")
            cursor.execute(
                "INSERT INTO transactions(timestamp,Nones, address, recipient, amount, block_hash, fee, reward, operation, openfield,Previous_hash, Miner_address) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (timestamp, proof, 'genesis', address, '0', block_hash, 0, 0, 1, 'genesis', 0,
                 address))  # Insert a row of data
            conn.commit()  # Save (commit) the changes

            # mempool = sqlite3.connect('mempool.db')
            # mem_cur = mempool.cursor()
            # mem_cur.execute("CREATE TABLE transactions (timestamp, address, recipient, amount, signature, public_key, operation, openfield)")
            # mempool.commit()
            # mempool.close()

            print("Genesis created, don't forget to change genesis address in the config file")


        except sqlite3.Error as e:
            print("Error %s:" % e.args[0])
            sys.exit(1)
        finally:
            if cursor is not None:
                cursor.close()
            if mem_cur is not None:
                mem_cur.close()

    else:
        print("False")
        timestamp = str(time.time())

        transaction, amount, fee = get_txn()
        mine_sign = []
        for i in range(len(transaction)):
            mine_sign.append(transaction[i][2])

        h = SHA224.new(str(transaction).encode())
        signer = PKCS1_v1_5.new(key)
        signature = signer.sign(h)
        signature_enc = base64.b64encode(signature)

        Previous_hash, block_height = previous_hash()

        proof, block_hash, mine_time = proof_of_work(Previous_hash, transaction)
        check_block_send = (mine_time, proof, block_hash, mine_sign, address)

        peer_connect.peers_send("check block")
        time.sleep(2)
        peer_connect.peers_send(check_block_send)

        counter = 1
        declied = 0
        peer_ips = peer_connect.peers_get()
        for i in range(len(peer_ips)):
            status_block = connections.receive()
            if status_block == "block verified":
                counter += 1
            elif status_block == "block not verified":
                declied += 1
                print("Block declied ")
            else:
                continue

        if counter > declied:

            if not os.path.isfile("static/ledger.db"):
                print("please download leger.db file")
            else:
                # transaction processing
                cursor = None
                mem_cur = None
                try:
                    conn = sqlite3.connect('static/ledger.db')
                    cursor = conn.cursor()

                    cursor.execute(
                        "CREATE TABLE  IF NOT EXISTS transactions (block_height INTEGER PRIMARY KEY AUTOINCREMENT, timestamp,Nones, address, recipient, amount, block_hash, fee, reward, operation, openfield,Previous_hash, Miner_address)")
                    cursor.execute(
                        "INSERT INTO transactions(timestamp,Nones, address, recipient, amount, block_hash, fee, reward, operation, openfield,Previous_hash, Miner_address) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                        (timestamp, proof, address, address, amount, block_hash, fee, 12, 10, 'Mining', Previous_hash,
                         address))  # Insert a row of data

                    conn.commit()  # Save (commit) the changes
                    conn.close()

                    transfered(transaction, block_height + 1, proof, block_hash)

                    fee_sum = mempoolss.Fetchone('static/ledger.db',
                                                 'SELECT SUM(fee) FROM transfered WHERE block_height = ?',
                                                 param=(block_height + 1,), write=True)

                    miner_db = (block_height + 1, time.time(), address, fee_sum[0], 15, proof, block_hash,signature_enc.decode(),"miner fee add", "transfer: miner fee")
                    miner_fee(miner_db)
                    conn.close()
                    for i in range(len(transaction)):
                        ex = (transaction[i][6],)
                        conn = sqlite3.connect('mempool.db')
                        cursor = conn.cursor()
                        cursor.execute("DELETE  FROM transactions WHERE signature= ?", ex)
                        conn.commit()
                        conn.close()

                    print("Congrats!!! You just mined a block...")
                    ledger_sync_file = "python ledger_sync.py"
                    try:
                          # specify your cmd command
                        process = subprocess.Popen(ledger_sync_file.split(), stdout=subprocess.PIPE)
                        output, error = process.communicate()
                    except:
                        print("can not able to sync ledger data")
                    return
                except sqlite3.Error as e:
                    print("Error %s:" % e.args[0])
                    sys.exit(1)
                finally:

                    if mem_cur is not None:
                        mem_cur.close()

        else:
            print("finaly block has deined")


        return
