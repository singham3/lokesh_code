"""
Common helpers for Bismuth
"""

import os, hashlib, base64

# from Crypto import Random
from Cryptodome.PublicKey import RSA
import getpass
import re
import time
import json
from decimal import *
from quantizer import *

__version__ = "0.0.3"



def fee_calculate(openfield='', operation='', block=0):
    # block var will be removed after HF
    fee = Decimal("0.01") + (Decimal(len(openfield)) / Decimal("100000"))  # 0.01 dust
    if operation == "token:issue":
        fee = Decimal(fee) + Decimal("10")
    if openfield.startswith("alias="):
        fee = Decimal(fee) + Decimal("1")
    return quantize_eight(fee)


def keys_load(privkey="privkey.der", pubkey="pubkey.der"):
    keyfile = "wallet.der"
    if os.path.exists("wallet.der"):
        print("Using modern wallet method")
        return keys_load_new ("wallet.der")

    else:
        # print ("loaded",privkey, pubkey)
        # import keys
        try:  # unencrypted

            key = RSA.importKey(open(privkey).read())
            private_key_readable = key.exportKey().decode ("utf-8")
            # public_key = key.publickey()
            encrypted = False
            unlocked = True

        except:  # encrypted
            encrypted = True
            unlocked = False
            key = None
            private_key_readable = open(privkey).read()

        # public_key_readable = str(key.publickey().exportKey())
        public_key_readable = open(pubkey.encode('utf-8')).read()

        if (len(public_key_readable)) != 271 and (len(public_key_readable)) != 799:
            raise ValueError("Invalid public key length: {}".format(len(public_key_readable)))

        public_key_hashed = base64.b64encode(public_key_readable.encode('utf-8'))
        address = hashlib.sha224(public_key_readable.encode('utf-8')).hexdigest()

        print("Upgrading wallet")
        keys_save (private_key_readable, public_key_readable, address, keyfile)

        return key, public_key_readable, private_key_readable, encrypted, unlocked, public_key_hashed, address, keyfile



def keys_check(app_log, keyfile):
    # key maintenance
    if os.path.isfile("privkey.der") is True:
        app_log.warning("privkey.der found")
    elif os.path.isfile("privkey_encrypted.der") is True:
        app_log.warning("privkey_encrypted.der found")
        os.rename("privkey_encrypted.der","privkey.der")

    elif os.path.isfile (keyfile) is True:
        app_log.warning ("{} found".format(keyfile))
    else:
        # generate key pair and an address
        key = RSA.generate(4096)
        #public_key = key.publickey()

        private_key_readable = key.exportKey().decode("utf-8")
        public_key_readable = key.publickey().exportKey().decode("utf-8")
        address = hashlib.sha224(public_key_readable.encode("utf-8")).hexdigest()  # hashed public key
        # generate key pair and an address

        app_log.info("Your address: {}".format(address))
        app_log.info("Your public key: {}".format(public_key_readable))

        # export to single file
        keys_save(private_key_readable, public_key_readable, address, keyfile)
        # export to single file


def keys_load_new(keyfile="wallet.der"):
    # import keys

    with open (keyfile,'r') as keyfile:
        wallet_dict = json.load (keyfile)


    private_key_readable = wallet_dict['Private Key']
    public_key_readable = wallet_dict['Public Key']
    address = wallet_dict['Address']

    try:

        key = RSA.importKey(private_key_readable)
        encrypted = False
        unlocked = True


    except:  # encrypted
        encrypted = True
        unlocked = False
        key = None

    # public_key_readable = str(key.publickey().exportKey())
    if (len(public_key_readable)) != 271 and (len(public_key_readable)) != 799:
        raise ValueError("Invalid public key length: {}".format(len(public_key_readable)))

    public_key_hashed = base64.b64encode(public_key_readable.encode('utf-8'))

    return key, public_key_readable, private_key_readable, encrypted, unlocked, public_key_hashed, address, keyfile




def keys_save(private_key_readable, public_key_readable, address, file):

    wallet_dict = {}
    wallet_dict['Private Key'] = private_key_readable
    wallet_dict['Public Key'] = public_key_readable
    wallet_dict['Address'] = address

    if not isinstance(file,str):
        file = file.name

    with open (file, 'w') as keyfile:
        json.dump (wallet_dict, keyfile)

