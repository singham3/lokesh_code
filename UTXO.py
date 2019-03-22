from mempool import *





mempools = Mempools()


def balance(addr):
    send_amt=mempools.Fetchall('static/ledger.db','SELECT SUM(amount) FROM transfered WHERE sender=?',(addr,),True)
    recv_amt = mempools.Fetchall('static/ledger.db', 'SELECT SUM(amount) FROM transfered WHERE recipient=?',(addr,), True)
    print(recv_amt[0][0],send_amt[0][0])
    balance=Decimal(recv_amt[0][0])-Decimal(send_amt[0][0])
    return balance,recv_amt[0][0],send_amt[0][0]