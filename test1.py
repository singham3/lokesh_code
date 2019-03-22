import essentials
import json
from Cryptodome.PublicKey import RSA
import genesis

key, public_key_readable, private_key_readable, encrypted, unlocked, public_key_hashed, address, keyfile=essentials.keys_load()
print ('key--',key)


keyfile2= "wallet.der"
with open(keyfile2, 'r') as keyfile2:
    wallet_dict = json.load(keyfile2)

private_key_readable2 = wallet_dict['Private Key']
public_key_readable2 = wallet_dict['Public Key']
address2 = wallet_dict['Address']

key2 = RSA.importKey(private_key_readable2)
print ('====',key2)


