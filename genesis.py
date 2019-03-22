import hashlib
import socket
import re
import sqlite3
import os
import sys
import time
import base64

from Cryptodome.Hash import SHA256, SHA224
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import PKCS1_v1_5
import peerhandlers
import essentials


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

timestamp = str(time.time())

transaction = (timestamp, "genesis", address, str(float(100000000)), "genesis")
h = SHA224.new(str(transaction).encode())
signer = PKCS1_v1_5.new(key)
signature = signer.sign(h)
signature_enc = base64.b64encode(signature)

block_hash = hashlib.sha224(str((timestamp, transaction)).encode("utf-8")).hexdigest()  # first hash is simplified

Peers_connection=peerhandlers.Peers()
if os.path.isfile("static/ledger.db"):
    print("You are beyond genesis")
else:
    # transaction processing
    cursor = None
    mem_cur = None
    try:
        conn = sqlite3.connect('static/ledger.db')
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE IF NOT EXISTS transactions (block_height INTEGER , timestamp,Nones, address, recipient, amount INTEGER, signature, public_key, block_hash, fee INTEGER, reward, operation, openfield)") # Save (commit) the changes
        conn.commit()

        print("Genesis created, don't forget to change genesis address in the config file")


    except sqlite3.Error as e:
        print("Error %s:" % e.args[0])
        sys.exit(1)
    finally:
        if cursor is not None:
            cursor.close()
        if mem_cur is not None:
            mem_cur.close()
