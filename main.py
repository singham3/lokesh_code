from node import *
import json
import datetime
import hashlib
from uuid import uuid4
from urllib.parse import urlparse
import requests
import socks


class Blockchain:

    def __init__(self):
        self.chain = []
        self.transactions = []
        self.create_block(proof = 1,previous_hash = '0')
        self.nodes = set()

    def create_block(self,proof,previous_hash):
        block = {'index': len(self.chain) + 1,
                 'timestap': str(datetime.datetime.now()),
                 'proof':proof,
                 'transactions':self.transactions,
                 'previous_hash':previous_hash}
        self.transactions = []
        self.chain.append(block)
        return block
    def get_previous_block(self):
        return self.chain[-1]

    def proof_of_work(self,previous_proof):
        new_proof = 1
        check_proof = False
        while check_proof is False:
            hash_operation = hashlib.sha224(str(new_proof**2 - previous_proof**2).encode()).hexdigest()
            if hash_operation[:4]=='0000':
                check_proof = True
            else:
                new_proof += 1
        return new_proof

    def hash(self, block):
        encoded_block = json.dumps(block, sort_keys = True).encode()
        return hashlib.sha224(encoded_block).hexdigest()

    def is_chain_valid(self, chain):
        previous_block = chain[0]
        block_index = 1
        while block_index < len(chain):
            block = chain[block_index]
            if block['previous_hash'] != self.hash(previous_block):
                return False
            previous_proof = previous_block['proof']
            proof = block['proof']
            hash_operation = hashlib.sha256(str(proof**2 - previous_proof**2).encode()).hexdigest()
            if hash_operation[:4] != '0000':
                return False
            previous_block = block
            block_index += 1
        return True

    def add_transactions(self,sender,recipient,amount,  operation,openfield):
        self.transactions.append({'sender':sender,
                                  'recipient':recipient,
                                  'amount':amount,
                                  'operation':operation,
                                  'openfield':openfield})
        previous_block = self.get_previous_block()
        return previous_block['index'] + 1

    def add_node(self,address):
        print(address)
        parsed_url = urlparse(address)

        self.nodes.add(parsed_url.path)


    def replace_chain(self):
        network = self.nodes
        longest_chain = None
        max_length = len(self.chain)
        for node in network:
            response = requests.get(f'http://{node}/get_chain')
            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']
                if length > max_length and self.is_chain_valid(chain):
                    max_length = length
                    longest_chain = chain
        if longest_chain:
            self.chain = longest_chain
            return True
        return False

blockchain = Blockchain()

node_address = str(uuid4()).replace('-','')
def convert_ip_port(ip):
    if ':' in ip:
        ip, some_port = ip.split(':')
    return ip, int(some_port)
def Mine_Block(sender,recipient,amount,operation,openfield):
    previous_block = blockchain.get_previous_block()
    previous_proof = previous_block['proof']
    proof = blockchain.proof_of_work(previous_proof)
    previous_hash = blockchain.hash(previous_block)
    blockchain.add_transactions(sender= sender,recipient= recipient, amount=amount,operation=operation,openfield=openfield)
    block = blockchain.create_block(proof, previous_hash)
    response = {'message': 'Congratulations, you just mined a block!',
                'index': block['index'],
                'timestamp': block['timestap'],
                'proof': block['proof'],
                'transactions': block['transactions'],
                'previous_hash': block['previous_hash']
                }
    return response


def Get_Chain():
    response = {'chain': blockchain.chain,
                'length': len(blockchain.chain)}



def Is_Valid():
    is_valid = blockchain.is_chain_valid(blockchain.chain)
    if is_valid:
        response = {'message': 'All good. The Blockchain is valid.'}
    else:
        response = {'message': 'Houston, we have a problem. The Blockchain is not valid.'}


def Add_Transaction(sender,amount,recipient, operation,openfield):


    transaction_keys = [sender,recipient,amount, operation,openfield]
    if not all(key in transaction_keys for key in transaction_keys):
        response='Some elements of the transaction are missing'
        return response

    index = blockchain.add_transactions(sender,recipient,amount, operation,openfield)
    response = {'message': f'This transaction will be added to Block {index}'}
    return response


def Connect_Node(recipient):

    ip = node_address1[recipient]

    blockchain.add_node(ip)
    response = {'message': 'All the nodes are now connected. The Hadcoin Blockchain now contains the following nodes:',
                'total_nodes': list(blockchain.nodes)}
    return response


def Replace_Chain():
    is_chain_replaced = blockchain.replace_chain()
    if is_chain_replaced:
        response = {'message': 'The nodes had different chains so the chain was replaced by the longest one.',
                    'new_chain': blockchain.chain}
    else:
        response = {'message': 'All good. The chain is the largest one.',
                    'actual_chain': blockchain.chain}




