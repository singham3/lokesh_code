import sqlite3
import sys
import hashlib
import json
import time
import genesis
from mempool import *
import chat1


MemPools = Mempools()

def proof_of_work( previous_proof,txn):
    new_proof = 1
    check_proof = False
    hash_operation = None
    t = time.time()

    txn_enc = hashlib.sha256(str(txn).encode()).hexdigest()
    while check_proof is False:
        hash_operation = hashlib.sha256(str (txn_enc +str(new_proof)).encode()).hexdigest()
        if hash_operation[:4]=="0000":
            check_proof = True
        else:
            new_proof += 1

    g = time.time()
    print(g-t)

    return new_proof,hash_operation

def mempool_recive(recive_data,addr):
    print(recive_data,addr)
    try:
        db = sqlite3.connect('mempool.db')
        cursor = db.cursor()
        cursor.execute(SQL_CREATE)
        cursor.execute("INSERT INTO transactions (timestamp, myaddress, recipient, amount, signature,public_key_hashed,operation, openfield, fee) VALUES (?,?,?,?,?,?,?,?,?)",(recive_data[0], recive_data[1], recive_data[2], float(recive_data[3]), recive_data[4],recive_data[5], recive_data[6], recive_data[7], float(recive_data[8])))
        db.commit()
        done = chat1.send_success(addr, "Success")
        if done == "Done":
            print("OK", "Transaction accepted to mempool")
        elif done == "Error":
            print("Error")
    except:
        print("Error", "There was a problem with transaction processing. Full message")


def send_status(recive_addr,addr):
    print(recive_addr,addr)
    p_addr = MemPools.Fetchall('static/ledger.db',"SELECT * FROM transfered WHERE recipient = ? OR sender = ?",(recive_addr[0],recive_addr[0]),True)
    p_addr_block = MemPools.Fetchall('static/ledger.db', "SELECT * FROM transactions WHERE block_height > ?", (recive_addr[1],),True)
    done = chat1.send_success(addr, p_addr_block)
    time.sleep(2)
    done2 = chat1.send_success(addr, p_addr)
    if  done == "Done" and done2 == "Done":
        print("All Transaction Has been sent to {}".format(recive_addr))
    elif  done == "Error" and done2 == "Error":
        print("Error")

def hash(self, block):
    encoded_block = json.dumps(block, sort_keys=True).encode()
    return hashlib.sha256(encoded_block).hexdigest()

def previous_hash():
    db = sqlite3.connect('static/ledger.db')
    cursor = db.cursor()
    cursor.execute("SELECT * FROM transactions ORDER BY block_height DESC LIMIT 1")
    all = cursor.fetchall()
    db.commit()
    return all[0][7],all[0][0]
def transfered(txn,block_height,proof,block_hash):
    print(txn,block_height,proof,block_hash)
    timestamp = time.time()
    conn = sqlite3.connect('static/ledger.db')
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS transfered (block_height INTEGER, timestamp,Nones, sender, recipient, amount, signature, public_key, block_hash, operation, openfield,fee)")
    for i in range(len(txn)):
        amount = txn[i][4] + txn[i][9]
        cursor.execute("INSERT INTO transfered VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", (block_height, timestamp, proof, txn[i][2], txn[i][3], amount, txn[i][5], txn[i][6], block_hash, txn[i][7], txn[i][8], txn[i][9]))  # Insert a row of data
        conn.commit()

def get_txn():
    db = sqlite3.connect('mempool.db')
    cursor = db.cursor()
    cursor.execute("SELECT * FROM transactions  ORDER BY fee DESC limit 10")
    all = cursor.fetchall()
    db.commit()
    amount=0
    fee=0
    print(all[1][4])
    for i in range(len(all)):
        amount = amount+all[i][4]
        fee=fee+all[i][-1]
    return all,amount,fee


