
import sqlite3
import sys
import hashlib
import json
# import test
import time
import genesis
from mempool import *
import chat1
import super_node
import re
import subprocess
MemPools = Mempools()

Checkblock_file  = "python Checkblock.py"
ledger_sync_file = "python ledger_sync.py"

def proof_of_work( Previous_hash,txn):
    new_proof = 1
    check_proof = False
    hash_operation = None
    t = time.time()


    txn_enc = hashlib.sha224(str(txn).encode()).hexdigest()
    while check_proof is False:

        hash_operation = hashlib.sha224(str (txn_enc +str(new_proof)+str(Previous_hash)).encode()).hexdigest()
        if hash_operation[:4]=="0000":
            check_proof = True
        else:
            new_proof += 1

    g = time.time()
    print(g-t)

    return new_proof,hash_operation,g

def mempool_recive(recive_data,addr):
    print((recive_data[3]))
    user_exist = super_node.All_Cowrie("SELECT * FROM Nodes WHERE address = %s ", recive_data[3])
    user_exist1 = super_node.All_Cowrie("SELECT * FROM Nodes WHERE address = %s ", recive_data[2])
    if user_exist and user_exist1:
        try:

            db = sqlite3.connect('mempool.db')
            cursor = db.cursor()
            cursor.execute(SQL_CREATE)
            cursor.execute("INSERT INTO transactions (timestamp,txn_id, myaddress, recipient, amount, signature,public_key_hashed,operation, openfield, fee) VALUES (?,?,?,?,?,?,?,?,?,?)",(recive_data[0],recive_data[1], recive_data[2], recive_data[3], float(recive_data[4]), recive_data[5],recive_data[6], recive_data[7], recive_data[8], float(recive_data[9])))
            db.commit()
            done = chat1.send_success(addr, "Success")
            if done == "Error":
                print("Error")
            elif done == "Done":
                print("OK", "Transaction accepted to mempool")
                try:
                    mpinsert = MemPools.Fetchone('mempool.db',"SELECT * FROM transactions WHERE txn_id = ?",(recive_data[1],),True)
                    if mpinsert:
                        try:
                            process = subprocess.Popen(Checkblock_file.split(), stdout=subprocess.PIPE)
                            output, error = process.communicate()
                        except:
                            print("can not eble to sync mempool data")
                    else:
                        print("Transaction Can Not insert into mempool")
                    mptxn = MemPools.Fetchone('mempool.db', "SELECT COUNT(transaction_id) FROM transactions ", write=True)
                    print(mptxn[0])
                    if mptxn[0] >= 10:
                        print("start mining")
                        genesis.Mining()
                        print("mining done")
                        try:
                            process = subprocess.Popen(ledger_sync_file.split(), stdout=subprocess.PIPE)
                            output, error = process.communicate()
                        except:
                            print("can not able to sync ledger data")
                    else:
                        print("Waiting, There is less then 10 trasiction for mining")
                    return
                except:
                    print("Error, for mining processing.")
        except:
            print("Error", "There was a problem with transaction processing. Full message")
    else:
        done = chat1.send_success(addr, "User Not Register")
        if done == "Done":
            print("User Not Register", "Transaction not accepted to mempool")
        elif done == "Error":
            print("Error")
    return


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
    return hashlib.sha224(encoded_block).hexdigest()

def previous_hash():
    try:
        db = sqlite3.connect('static/ledger.db')
        cursor = db.cursor()
        cursor.execute("SELECT * FROM transactions ORDER BY block_height DESC LIMIT 1")
        all = cursor.fetchall()
        db.commit()
        return all[0][6],all[0][0]
    except:
        return 0,0

def transfered(txn,block_height,proof,block_hash):
    print(txn)
    timestamp = time.time()
    conn = sqlite3.connect('static/ledger.db')
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS transfered (block_height , timestamp,txn_id,Nones, sender, recipient, amount , signature, public_key, block_hash, operation, openfield,fee )")
    for i in range(len(txn)):
        amount = txn[i][5] - txn[i][10]
        cursor.execute("INSERT INTO transfered VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", (block_height, timestamp,txn[i][2], proof, txn[i][3], txn[i][4], amount, txn[i][6], txn[i][7], block_hash, txn[i][8], txn[i][9], txn[i][10]))  # Insert a row of data
        conn.commit()
    print("successfull inserted in transfered table")

def get_txn():
    db = sqlite3.connect('mempool.db')
    cursor = db.cursor()
    cursor.execute("SELECT * FROM transactions  ORDER BY fee DESC limit 10")
    all = cursor.fetchall()
    db.commit()
    amount=0
    fee=0

    for i in range(len(all)):
        amount = amount+all[i][5]
        fee=fee+all[i][-1]
    return all,amount,fee


def miner_fee(miner_db):
    db = MemPools.commit('miner_wallet.db','CREATE TABLE IF NOT EXISTS wallet (transaction_id INTEGER PRIMARY KEY AUTOINCREMENT, block_height VARCHAR ,timestamp TEXT, MinerAddress TEXT,fee_amount VARCHAR,reward VARCHAR,Nones VARCHAR, block_hash TEXT,Signature TEXT , operation TEXT,openfild TEXT)',True)
    if db:
        print('wallet db insert')
        insert_fee = Mempools.execute(file = 'miner_wallet.db',sql = 'INSERT INTO wallet (block_height,timestamp, MinerAddress,fee_amount,reward,Nones, block_hash,Signature,operation,openfild) VALUES (?,?,?,?,?,?,?,?,?,?)',param = (miner_db[0], miner_db[1], miner_db[2], miner_db[3],miner_db[4], miner_db[5],miner_db[6], miner_db[7], miner_db[8], miner_db[9]), write=True)
        if insert_fee :
            print("inserted")
        else:
            print("error in miner wallet")

    else:
        conn = sqlite3.connect('miner_wallet.db')
        cursor = conn.cursor()
        cursor.execute('CREATE TABLE IF NOT EXISTS wallet (transaction_id INTEGER PRIMARY KEY AUTOINCREMENT, block_height VARCHAR ,timestamp VARCHAR, MinerAddress TEXT,fee_amount INTEGER,reward INTEGER,Nones VARCHAR, block_hash TEXT,Signature TEXT , operation TEXT,openfild TEXT )')
        conn.commit()
        conn.close()
        insert_fee = Mempools.execute(file='miner_wallet.db',sql='INSERT INTO wallet (block_height,timestamp, MinerAddress,fee_amount,reward,Nones, block_hash,Signature,operation,openfild) VALUES (?,?,?,?,?,?,?,?,?,?)',param=(miner_db[0], miner_db[1], miner_db[2], float(miner_db[3]), float(miner_db[4]), miner_db[5],miner_db[6], miner_db[7], miner_db[8], miner_db[9]), write=True)
        if insert_fee :
            print("inserted")
        else:
            print("error in miner wallet")

def Check_block(data,addr):

    mempool_data = []
    for i in range(len(data[3])):

        mp_data = Mempools.Fetchall(None,file='mempool.db',sql="SELECT * FROM transactions WHERE txn_id = ?",param=(data[3][i],),write=True)
        mempool_data.append(mp_data)


    ledger_create = MemPools.execute(file= "static/ledger.db" , sql = "CREATE TABLE IF NOT EXISTS transactions (block_height INTEGER PRIMARY KEY AUTOINCREMENT, timestamp,Nones, address, recipient, amount, block_hash, fee, reward, operation, openfield,Previous_hash, Miner_address)",write= True)
    Previous_hash ,block_height = previous_hash()
    txn_enc = hashlib.sha224(str(mempool_data).encode()).hexdigest()
    hash_operation = hashlib.sha224(str(txn_enc + str(data[1]) + str(Previous_hash)).encode()).hexdigest()

    if hash_operation == data[2]:
        conform_block = chat1.send_success(addr, "block verified")
        if conform_block == "Done":
            print("block verified")
        elif conform_block == "Error":
            print("can`t able to send block verified")
    else:
        conform_block = chat1.send_success(addr, "block not verified")
        if conform_block == "Done":
            print("block verified")
        elif conform_block == "Error":
            print("can`t able to send block verified")


def miner_address_validate(address):
    if re.match('[abcdef0123456789]{56}', address):
        return True
    else:
        return False