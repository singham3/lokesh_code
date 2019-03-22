import sys
sys.path.append('E:\study\cowrie prototype\miner prototype\miner_wallet\miner')
from mempool import *
from decimal import *





mempools = Mempools()


def balance(addr):
    send_amt=mempools.Fetchall('miner_wallet.db','SELECT SUM(amount) FROM miner_transfered WHERE sender=?',(addr,),True)
    fee_amt = mempools.Fetchall('miner_wallet.db', 'SELECT SUM(fee) FROM miner_transfered WHERE sender=?', (addr,), True)
    recv_amt = mempools.Fetchall('miner_wallet.db', 'SELECT SUM(amount) FROM miner_transfered WHERE recipient=?',(addr,), True)

    if not recv_amt  or not send_amt:

        if not recv_amt  and send_amt:
            if not  fee_amt :

                balance = Decimal(0) - Decimal(send_amt[0][0])
                return balance-0, 0, send_amt[0][0]
            else:
                balance = Decimal(0) - Decimal(send_amt[0][0])
                return balance - fee_amt[0][0], 0, send_amt[0][0]
        elif not send_amt and recv_amt:
            if not fee_amt:

                balance = Decimal(recv_amt[0][0]) - 0
                return balance-0, recv_amt[0][0], 0
            else:
                balance = Decimal(recv_amt[0][0]) - 0
                return balance-fee_amt[0][0], recv_amt[0][0], 0
        else:
            return 0,0,0
    elif not fee_amt:

        balance = Decimal(recv_amt[0][0]) - Decimal(send_amt[0][0])
        return balance-0, Decimal(recv_amt[0][0]),Decimal(send_amt[0][0])
    else:
        balance = Decimal(recv_amt[0][0]) - Decimal(send_amt[0][0])
        return balance - fee_amt[0][0], Decimal(recv_amt[0][0]), Decimal(send_amt[0][0])

def miner_fee_reward():
    total_fee = mempools.Fetchall('miner_wallet.db','SELECT SUM(fee_amount) FROM wallet ',write=True)
    total_reward = mempools.Fetchall('miner_wallet.db','SELECT SUM(reward) FROM wallet ',write=True)

    if not total_fee  or not total_reward :
        if not total_fee  and total_reward:
            total_reward_fee = 0 + Decimal(total_reward[0][0])
            return Decimal(total_reward_fee)
        elif total_fee and not total_reward :
            total_reward_fee = Decimal(total_fee[0][0]) + 0
            return Decimal(total_reward_fee)
        else:
            return 0
    else:
        total_reward_fee = Decimal(total_fee[0][0]) + Decimal(total_reward[0][0])
        return Decimal(total_reward_fee)

