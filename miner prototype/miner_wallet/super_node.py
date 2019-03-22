import os
import pymysql
import  chat1
import essentials
import time
import connections
import base64
from Cryptodome.Signature import PKCS1_v1_5
from Cryptodome.Hash import SHA224
from decimal import *
from  peerhandlers import  *
import subprocess
from newwallet import *
test1_file = "python test1.py"
ledger_sync_file = "python ledger_sync.py"

peers_connect = Peers()


def Cowrium_database():
    try:
        connection = pymysql.connect(host='localhost', user='root', password='')
        cursor = connection.cursor()
        database_query = "CREATE DATABASE IF NOT EXISTS Cowrium"
        cursor.execute(database_query)
        connection.commit()
        connection.close()


        connection2 = pymysql.connect(host='localhost', user='root', password='',db='cowrium')
        cursor2 = connection2.cursor()
        sql = "CREATE TABLE IF NOT EXISTS Cowrie (coin_id INTEGER PRIMARY KEY auto_increment,timestamp VARCHAR(45) NOT NULL,Coin VARCHAR(50) NOT NULL,amount VARCHAR(200) NOT NULL,address VARCHAR(64) NOT NULL,recipient VARCHAR(64) NOT NULL,public_key TEXT(5000) NOT NULL,signature TEXT(4500) NOT NULL,fee VARCHAR(200) NOT NULL,operation VARCHAR(200) NOT NULL);"
        sql2 = "CREATE TABLE IF NOT EXISTS Nodes (ID INTEGER PRIMARY KEY auto_increment,timestamp VARCHAR(45) NOT NULL,address VARCHAR(64) NOT NULL,public_key TEXT(5000) NOT NULL,signature TEXT(5000) NOT NULL);"
        cursor2.execute(sql)
        cursor2.execute(sql2)
        connection2.commit()
        connection2.close()
    except:
        print("cannot connect to database")


def Insert_Cowrie(param):
    try:
        connection = pymysql.connect(host='localhost', user='root', password='', db='cowrium')
        cursor = connection.cursor()
        sql = "INSERT INTO cowrie (timestamp,Coin,amount,address,recipient,public_key,signature,fee,operation) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)"
        cursor.execute(sql,param)
        connection.commit()
        connection.close()
    except:
        Cowrium_database()
        connection = pymysql.connect(host='localhost', user='root', password='', db='cowrium')
        cursor = connection.cursor()
        sql = "INSERT INTO cowrie (timestamp,Coin,amount,address,recipient,public_key,signature,fee,operation) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)"
        cursor.execute(sql, param)
        connection.commit()
        connection.close()



def All_Cowrie(sql,param=None):
    try:
        connection = pymysql.connect(host='localhost', user='root', password='', db='cowrium')
        cursor = connection.cursor()
        if param:
            cursor.execute(sql,param)
        else:
            cursor.execute(sql)
        result = cursor.fetchall()
        connection.close()
        if result:
            return result
        else:
            return False
    except:
        Cowrium_database()
        connection = pymysql.connect(host='localhost', user='root', password='', db='cowrium')
        cursor = connection.cursor()
        if param:
            cursor.execute(sql, param)
        else:
            cursor.execute(sql)
        result = cursor.fetchall()
        connection.close()
        if result:
            return result
        else:
            return False

def check_node(sql,addr):
    try:
        connection = pymysql.connect(host='localhost', user='root', password='', db='cowrium')
        cursor = connection.cursor()
        cursor.execute(sql, addr)
        result = cursor.fetchone()
        connection.close()
        if result:
            return False
        else:
            return True
    except:
        Cowrium_database()
        connection = pymysql.connect(host='localhost', user='root', password='', db='cowrium')
        cursor = connection.cursor()
        cursor.execute(sql, addr)
        result = cursor.fetchone()
        connection.close()
        if result:
            return False
        else:
            return True

def node_fetchone(sql,param = None):
    try:
        connection = pymysql.connect(host='localhost', user='root', password='', db='cowrium')
        cursor = connection.cursor()
        if param:
            cursor.execute(sql,param)
        else:
            cursor.execute(sql)
        result = cursor.fetchone()
        connection.close()
        if result:
            return result
        else:
            return False
    except:
        Cowrium_database()
        connection = pymysql.connect(host='localhost', user='root', password='', db='cowrium')
        cursor = connection.cursor()
        if param:
            cursor.execute(sql, param)
        else:
            cursor.execute(sql)
        result = cursor.fetchone()
        connection.close()
        if result:
            return result
        else:
            return False


def Insert_Nodes(sql,param):
    check = check_node(sql,param[1])
    if check:
        try:
            connection = pymysql.connect(host='localhost', user='root', password='', db='cowrium')
            cursor = connection.cursor()
            sql2 = "INSERT INTO Nodes (timestamp,address,public_key,signature) VALUES (%s,%s,%s,%s)"
            cursor.execute(sql2,param)
            connection.commit()
            connection.close()
        except:
            Cowrium_database()
            connection = pymysql.connect(host='localhost', user='root', password='', db='cowrium')
            cursor = connection.cursor()
            sql2 = "INSERT INTO Nodes (timestamp,address,public_key,signature) VALUES (%s,%s,%s,%s)"
            cursor.execute(sql2, param)
            connection.commit()
            connection.close()
    else:
        pass




def requestmoney(recive_req,addr):

    d = All_Cowrie("SELECT * FROM cowrie ORDER BY Coin ASC limit 1")
    fee = essentials.fee_calculate(operation=recive_req[5])


    if d:
        verifi = All_Cowrie("SELECT * FROM Nodes WHERE address = %s",recive_req[1])
        if verifi:
            data = (recive_req[0],str(Decimal(d[0][2])-Decimal(recive_req[2])),recive_req[2],str(address),recive_req[1],recive_req[4],recive_req[3],fee,recive_req[5])
            Insert_Cowrie(data)

            txn_id = signature_enc[:57]
            data_miner = (time.time(),txn_id,str(address),recive_req[1],recive_req[2],signature_enc,public_key_readable.decode(),recive_req[5],"add money",float(fee))
            try:
                done = chat1.send_success(addr, "Success")
                if done == "Done":
                    print("OK", "Transaction accepted to mempool")
                elif done == "Error":
                    print("Error")
                peers_connect.peers_send("mpinsert")

                time.sleep(2)
                peers_connect.peers_send(data_miner)
                reply,addr2 = connections.receive()
                print(reply)
                if reply == "Success":
                    print("OK", "Transaction accepted to mempool")
                else:
                    print("Error","There was a problem with transaction processing. Full message: {}".format(reply))


            except:
                print("data can not send")

        else:
            done = chat1.send_success(addr, "Address is not register")
            if done == "Done":
                print("OK", "Transaction accepted to mempool")
            elif done == "Error":
                print("Error comming")
    else:

        data = (time.time(),str(30000000000),'0',str(address),str(address),str(public_key_hashed),str(signature_enc),'0',"First Coin")
        Insert_Cowrie(data)
    # done = chat1.send_success(addr, "Success")
    # if done == "Done":
    #     print("OK", "Transaction accepted to mempool")
    # elif done == "Error":
    #     print("Error")


def register(recive_register,addr):
    user_exist = All_Cowrie("SELECT * FROM Nodes WHERE address = %s ", recive_register[1])
    if user_exist:
        done = chat1.send_success(addr, "User Already Registered")
        if done == "Done":
            print("User Already Register")
        elif done == "Error":
            print("Error")
        return
    else:
        try:
            param = (str(recive_register[0]),str(recive_register[1]),str(recive_register[2]),str(recive_register[3]))
            Insert_Nodes("SELECT * FROM Nodes WHERE address = %s",param)
            try:
                process = subprocess.Popen(test1_file.split(), stdout=subprocess.PIPE)
                output, error = process.communicate()


            except:
                print("can not eble to sync user node data")
            done = chat1.send_success(addr, "Success")
            if done == "Done":
                print("OK", "user has been registered")
            elif done == "Error":
                print("Error")
            return

        except:
            Cowrium_database()
            param = (str(recive_register[0]), str(recive_register[1]), str(recive_register[2]), str(recive_register[3]))
            Insert_Nodes("SELECT * FROM Nodes WHERE address = %s",param)
            try:
                process = subprocess.Popen(test1_file.split(), stdout=subprocess.PIPE)
                output, error = process.communicate()
            except:
                print("can not able to sync user node data")
            done = chat1.send_success(addr, "Success")
            if done == "Done":
                print("OK", "user has been registered")
            elif done == "Error":
                print("Error")
            return


def miner_register(recive_miner_register,addr):
    user_exist = All_Cowrie("SELECT * FROM Nodes WHERE address = %s ", recive_miner_register[1])
    if user_exist:
        done = chat1.send_success(addr, "miner Already Registered")
        if done == "Done":
            print("miner Already Register")
        elif done == "Error":
            print("Error")
        return
    else:
        try:
            param = (str(recive_miner_register[0]),str(recive_miner_register[1]),str(recive_miner_register[2]),str(recive_miner_register[3]))
            Insert_Nodes("SELECT * FROM Nodes WHERE address = %s",param)

            try:
                process = subprocess.Popen(test1_file.split(), stdout=subprocess.PIPE)
                output, error = process.communicate()
            except:
                print("can not able to sync user node data")
            time.sleep(2)
            try:
                process = subprocess.Popen(ledger_sync_file.split(), stdout=subprocess.PIPE)
                output, error = process.communicate()
            except:
                print("can not able to sync ledger data")
            done = chat1.send_success(addr, "Success")
            if done == "Done":
                print("OK", "miner has been registered")
            elif done == "Error":
                print("Error")
            return
        except:
            Cowrium_database()
            param = (str(recive_miner_register[0]), str(recive_miner_register[1]), str(recive_miner_register[2]), str(recive_miner_register[3]))
            Insert_Nodes("SELECT * FROM Nodes WHERE address = %s",param)
            try:
                process = subprocess.Popen(test1_file.split(), stdout=subprocess.PIPE)
                output, error = process.communicate()
            except:
                print("can not able to sync miner node data")
            time.sleep(2)
            try:
                process = subprocess.Popen(ledger_sync_file.split(), stdout=subprocess.PIPE)
                output, error = process.communicate()
            except:
                print("can not able to sync ledger data")
            done = chat1.send_success(addr, "Success")
            if done == "Done":
                print("OK", "miner has been registered")
            elif done == "Error":
                print("Error")
            return