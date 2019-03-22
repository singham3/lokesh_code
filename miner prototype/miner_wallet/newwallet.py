
import genesis
import ast
import csv
import glob
import re
import log
import os
import platform
import tarfile
import time
import datetime
import connections
import recovery
import webbrowser
from datetime import datetime
from decimal import *
# from main import *
from quantizer import *
from keys import *
from essentials import *
from tkinter import *
from tkinter import filedialog, messagebox, ttk
from cwrurl import  *

from mempool import *
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
from peerhandlers import  *
import socks
from simplecrypt import encrypt, decrypt
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.Hash import SHA256, SHA224
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
from Cryptodome.Signature import PKCS1_v1_5
import super_node
import UTXO

import essentials

class Keys:
    def __init__(self):
        self.key = None
        self.public_key_readable = None
        self.private_key_readable = None
        self.encrypted = None
        self.unlocked = None
        self.public_key_hashed = None
        self.myaddress = None
        self.keyfile = None

#global keys
s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
global statusget
global stats_timestamp


def click_on_tab_tokens(event):
    if str(nbtabs.index(nbtabs.select())) == "4":
        pass
def address_insert():
    gui_address_t.delete(0, END)
    gui_address_t.insert(0, root.clipboard_get())
def recipient_insert():
    recipient.delete(0, END)
    recipient.insert(0, root.clipboard_get())

def data_insert():
    openfield.delete('1.0', END)  # remove previous
    openfield.insert(INSERT, root.clipboard_get())


def data_insert_r():
    openfield_r.delete('1.0', END)  # remove previous
    openfield_r.insert(INSERT, root.clipboard_get())

def url_insert():
    url.delete(0, END)  # remove previous
    url.insert(0, root.clipboard_get())
def address_copy():
    root.clipboard_clear()
    root.clipboard_append(keyring.myaddress)


def url_copy():
    root.clipboard_clear()
    root.clipboard_append(url_r.get())


def recipient_copy():
    root.clipboard_clear()
    root.clipboard_append(recipient.get())
def recipient_insert():
    recipient.delete(0, END)
    recipient.insert(0, root.clipboard_get())
def watch():
    address = gui_address_t.get()
    # refresh(address, s)

def unwatch():
    gui_address_t.delete(0, END)
    gui_address_t.insert(INSERT, keyring.myaddress)
    # refresh(keyring.myaddress, s)
# data for charts
def create_url_clicked( command, recipient, amount, operation, openfield):
    """isolated function so no GUI leftovers are in bisurl.py"""

    result = create_url( command, recipient, amount, operation, openfield)
    url_r.delete(0, END)
    url_r.insert(0, result)

def all_spend_clear():
    all_spend_var.set(False)

    amount.delete(0, END)
    amount.insert(0, 0)

def data_insert_clear():
    openfield.delete('1.0', END)
    openfield_r.delete('1.0', END)


def read_url_clicked(url):
    """isolated function so no GUI leftovers are in bisurl.py"""
    result = (read_url(url))

    recipient.delete(0, END)
    amount.delete(0, END)
    operation.delete(0, END)
    openfield.delete("1.0", END)
    recipient.insert(0, result[1])  # amount
    amount.insert(0, result[2])  # recipient

    operation.insert(INSERT, result[3])  # operation
    openfield.insert(INSERT, result[4])  # openfield

def encryption_button_refresh():
    if keyring.unlocked: #it is a function of key and it is either true or false
        decrypt_b.configure(text="Unlocked", state=DISABLED)
    if not keyring.unlocked:
        decrypt_b.configure(text="Unlock", state=NORMAL)
        messagemenu.entryconfig("Sign Messages", state="disabled")  # messages
        walletmenu.entryconfig("Recovery", state="disabled")  # recover
    if not keyring.encrypted:
        encrypt_b.configure(text="Encrypt", state=NORMAL)
    if keyring.encrypted:
        encrypt_b.configure(text="Encrypted", state=DISABLED)
    lock_b.configure(text="Lock", state=DISABLED)


def aliases_list():
    top12 = Toplevel()
    top12.title("Your aliases")
    aliases_box = Text(top12, width=100)
    aliases_box.grid(row=0, pady=0)

    connections.send(s, "aliasget", 10)
    connections.send(s, keyring.myaddress, 10)

    aliases_self = connections.receive(s, 10)

    for x in aliases_self:
        aliases_box.insert(INSERT, replace_regex(x[0], "alias="))
        aliases_box.insert(INSERT, "\n")

    close = Button(top12, text="Close", command=top12.destroy)
    close.grid(row=3, column=0, sticky=W + E, padx=15, pady=(5, 5))


def replace_regex(string, replace):
    replaced_string = re.sub(r'^{}'.format(replace), "", string)
    return replaced_string


def alias_register(alias_desired):
    connections.send(s, "aliascheck", 10)
    connections.send(s, alias_desired, 10)

    result = connections.receive(s, 10)

    if result == "Alias free":
        send("0", keyring.myaddress, "", "alias=" + alias_desired)
        pass
    else:
        messagebox.showinfo("Conflict", "Name already registered")


def alias():
    alias_var = StringVar()

    # enter password
    top8 = Toplevel()
    top8.title("Enter Desired Name")

    alias_label = Label(top8, text="Input name")
    alias_label.grid(row=0, column=0, sticky=N + W, padx=15, pady=(5, 0))

    input_alias = Entry(top8, textvariable=alias_var)
    input_alias.grid(row=1, column=0, sticky=N + E, padx=15, pady=(0, 5))

    dismiss = Button(top8, text="Register", command=lambda: alias_register(alias_var.get().strip()))
    dismiss.grid(row=2, column=0, sticky=W + E, padx=15, pady=(15, 0))

    dismiss = Button(top8, text="Dismiss", command=top8.destroy)
    dismiss.grid(row=3, column=0, sticky=W + E, padx=15, pady=(5, 5))


def encrypt_get_password():
    if keyring.encrypted:
        messagebox.showwarning("Error", "Already encrypted")
        return

    # enter password
    top3 = Toplevel()
    top3.title("Enter Password")

    password_label = Label(top3, text="Input password")
    password_label.grid(row=0, column=0, sticky=N + W, padx=15, pady=(5, 0))

    password_var_enc.set("")
    input_password = Entry(top3, textvariable=password_var_enc, show='*')
    input_password.grid(row=1, column=0, sticky=N + E, padx=15, pady=(0, 5))

    confirm_label = Label(top3, text="Confirm password")
    confirm_label.grid(row=2, column=0, sticky=N + W, padx=15, pady=(5, 0))

    password_var_con.set("")
    input_password_con = Entry(top3, textvariable=password_var_con, show='*')
    input_password_con.grid(row=3, column=0, sticky=N + E, padx=15, pady=(0, 5))

    enter = Button(top3, text="Encrypt", command=lambda: encrypt_fn(top3))
    enter.grid(row=4, column=0, sticky=W + E, padx=15, pady=(5, 5))

    cancel = Button(top3, text="Cancel", command=top3.destroy)
    cancel.grid(row=5, column=0, sticky=W + E, padx=15, pady=(5, 5))
    # enter password
def Add_register():

    tx_timestamp = str(time.time())

    register = (tx_timestamp,keyring.public_key_readable, keyring.myaddress)
    h = SHA224.new(str(register).encode("utf-8"))

    signer = PKCS1_v1_5.new(keyring.key)

    signature = signer.sign(h)
    signature_enc = base64.b64encode(signature).decode()
    verifier = PKCS1_v1_5.new(keyring.key)
    if verifier.verify(h, signature):
        submit = str(tx_timestamp),str(keyring.myaddress),str(keyring.public_key_hashed.decode("utf-8")),str(signature_enc)
        while True:
            try:
                Peers_connection.peers_send("miner register")
                time.sleep(2)
                Peers_connection.peers_send(submit)
                reply,addr = connections.receive()
                print(reply)
                if reply == "Success":
                    messagebox.showinfo("Congratulation!!!","Welcome to Cowrium, You are now registered.")
                    count_id = super_node.node_fetchone("SELECT COUNT(ID) FROM Nodes")
                    if count_id[0] == 1:
                        last_id = super_node.node_fetchone("SELECT ID,address FROM Nodes WHERE ID = 1 AND address = %s LIMIT 1",keyring.myaddress)
                        if last_id[0] == 1 and last_id[1] == keyring.myaddress:
                            query = "SELECT * FROM transactions WHERE address = ?"
                            c = Mempool.Fetchone(file="static/ledger.db", sql=query, param=("genesis",), write=True)
                            if not c:
                                genesis.Mining()
                else:
                    messagebox.showerror("Error",
                                         "There was a problem with register process. Full message: {}".format(
                                             reply))


                break

            except:
                messagebox.showerror("Error", "There was a problem with transaction processing. Full message")
            break
    else:
        print("signature not varified")

def encrypt_fn(destroy_this):

    password = password_var_enc.get()
    password_conf = password_var_con.get()

    if password == password_conf:
        busy(destroy_this)
        try:

            ciphertext = encrypt(password, keyring.private_key_readable)
            ciphertext_export = base64.b64encode(ciphertext).decode()
            essentials.keys_save(ciphertext_export, keyring.public_key_readable, keyring.myaddress, keyring.keyfile)

            # encrypt_b.configure(text="Encrypted", state=DISABLED)
            Add_register()
            keyring.key, keyring.public_key_readable, keyring.private_key_readable, keyring.encrypted, keyring.unlocked, keyring.public_key_hashed, keyring.myaddress, keyring.keyfile = essentials.keys_load()

            encryption_button_refresh()
        finally:
            notbusy(destroy_this)
        destroy_this.destroy()
        # lock_b.configure(text="Lock", state=NORMAL)
    else:
        messagebox.showwarning("Mismatch", "Password Mismatch")


def decrypt_get_password():
    # enter password
    top4 = Toplevel()
    top4.title("Enter Password")

    input_password = Entry(top4, textvariable=password_var_dec, show='*')
    input_password.grid(row=0, column=0, sticky=N + E, padx=15, pady=(5, 5))

    enter = Button(top4, text="Unlock", command=lambda: decrypt_fn(top4))
    enter.grid(row=1, column=0, sticky=W + E, padx=15, pady=(5, 5))

    cancel = Button(top4, text="Cancel", command=top4.destroy)
    cancel.grid(row=2, column=0, sticky=W + E, padx=15, pady=(5, 5))
    # enter password


def decrypt_fn(destroy_this):
    busy(destroy_this)
    try:
        keyring.password = password_var_dec.get()

        keyring.decrypted_privkey = decrypt(keyring.password, base64.b64decode(keyring.private_key_readable))  # decrypt privkey

        keyring.key = RSA.importKey(keyring.decrypted_privkey)  # be able to sign

        notbusy(destroy_this)
        destroy_this.destroy()

        decrypt_b.configure(text="Unlocked", state=DISABLED)
        lock_b.configure(text="Lock", state=NORMAL)
        messagemenu.entryconfig("Sign Messages", state=NORMAL)  # messages
        walletmenu.entryconfig("Recovery", state=NORMAL)  # recover
    except:
        notbusy(destroy_this)
        messagebox.showwarning("Locked", "Wrong password")

    password_var_dec.set("")

def lock_fn(button):
    key = None
    decrypt_b.configure(text="Unlock", state=NORMAL)
    lock_b.configure(text="Locked", state=DISABLED)
    messagemenu.entryconfig("Sign Messages", state=DISABLED)  # messages
    walletmenu.entryconfig("Recovery", state=DISABLED)  # recover
    password_var_dec.set("")



def busy(an_item=None):
    an_item = an_item if an_item else root
    an_item.config(cursor="")


def notbusy(an_item=None):
    an_item = an_item if an_item else root
    an_item.config(cursor="")

def recover():
    result = recovery.recover(keyring.key)
    messagebox.showinfo("Recovery Result", result)


def address_validate(address):
    if re.match('[abcdef0123456789]{56}', address):
        return True
    else:
        return False



def send_confirm(sender,amount,recipient, operation,openfield):
    amount = quantize_eight(amount)

    # cryptopia check
    if recipient == "edf2d63cdf0b6275ead22c9e6d66aa8ea31dc0ccb367fad2e7c08a25" and len(openfield) not in [1, 20]:
        messagebox.showinfo("Cannot send", "Identification message is missing for Cryptopia, please include it")
        return
    # cryptopia check

    top10 = Toplevel()
    top10.title("Confirm")

    # if alias_cb_var.get():  # alias check
    #     connections.send(s, "addfromalias", 10)
    #     connections.send(s, recipient_input, 10)
    #     recipient_input = connections.receive(s, 10)
    #
    # # encr check
    # if encrypt_var.get():
    #     # get recipient's public key
    #
    #     connections.send(s, "pubkeyget", 10)
    #     connections.send(s, recipient_input, 10)
    #     target_public_key_hashed = connections.receive(s, 10)
    #
    #     recipient_key = RSA.importKey(base64.b64decode(target_public_key_hashed).decode("utf-8"))
    #
    #     # openfield_input = str(target_public_key.encrypt(openfield_input.encode("utf-8"), 32))
    #
    #     data = openfield_input.encode("utf-8")
    #     # print (open("pubkey.der").read())
    #     session_key = get_random_bytes(16)
    #     cipher_aes = AES.new(session_key, AES.MODE_EAX)
    #
    #     # Encrypt the session key with the public RSA key
    #     cipher_rsa = PKCS1_OAEP.new(recipient_key)
    #
    #     # Encrypt the data with the AES session key
    #     ciphertext, tag = cipher_aes.encrypt_and_digest(data)
    #     enc_session_key = (cipher_rsa.encrypt(session_key))
    #     openfield_input = str([x for x in (cipher_aes.nonce, tag, ciphertext, enc_session_key)])
    #
    # # encr check
    #
    # if encode_var.get() and not msg_var.get():
    #     openfield_input = base64.b64encode(openfield_input.encode("utf-8")).decode("utf-8")
    # if msg_var.get() and encode_var.get():
    #     openfield_input = "bmsg=" + base64.b64encode(openfield_input.encode("utf-8")).decode("utf-8")
    # if msg_var.get() and not encode_var.get():
    #     openfield_input = "msg=" + openfield_input
    # if encrypt_var.get():
    #     openfield_input = "enc=" + str(openfield_input)
    #
    fee = fee_calculate(openfield, operation)

    confirmation_dialog = Text(top10, width=100)
    confirmation_dialog.insert(INSERT, (
        "Amount: {}\nFee: {}\nTotal: {}\nTo: {}\nOperation: {}\nData: {}".format('{:.8f}'.format(amount),
        '{:.8f}'.format(fee), '{:.8f}'.format(Decimal(amount) + Decimal(fee)), recipient, operation, openfield)))
    confirmation_dialog.configure(state="disabled")
    confirmation_dialog.grid(row=0, pady=0)

    enter = Button(top10, text="Confirm",
                   command=lambda: send_confirmed(amount, recipient, operation, openfield, fee,
                                                  top10))
    enter.grid(row=1, column=0, sticky=W + E, padx=15, pady=(5, 5))

    done = Button(top10, text="Cancel", command=top10.destroy)
    done.grid(row=2, column=0, sticky=W + E, padx=15, pady=(5, 5))


def send_confirmed(amount, recipient, operation, openfield, fee, top10):
    send(amount, recipient, operation, openfield, fee)
    top10.destroy()


def send(amount, recipient, operation, openfield, fee):
    #all_spend_check()

    if keyring.key is None:
        messagebox.showerror("Locked", "Wallet is locked")

    print("Received tx command")

    try:
        Decimal(amount)
        try:
            if (amount>0.00000001):
                print ("amount checked")
        except:
            messagebox.showerror("Invalid Amount", "Amount must be greater then 0.00000001")
    except:
        messagebox.showerror("Invalid Amount", "Amount must be a number")

    if not address_validate(recipient):
        messagebox.showerror("Invalid Address", "Invalid address format")
    else:

        # print("Amount: {}".format(amount))
        # print("Recipient: {}".format(recipient))
        # print("Data: {}".format(openfield))


        tx_timestamp =str(time.time())  # randomize timestamp for unique signatures
        transaction = (str(tx_timestamp), str(keyring.myaddress), str(recipient), '%.8f' % float(amount),
                       str(operation), str(openfield))  # this is signed, float kept for compatibility

        h = SHA224.new(str(transaction).encode("utf-8"))
        signer = PKCS1_v1_5.new(keyring.key)
        signature = signer.sign(h)
        signature_enc = base64.b64encode(signature).decode()
        # print("Client: Encoded Signature: {}".format(signature_enc.decode("utf-8")))

        verifier = PKCS1_v1_5.new(keyring.key)

        if verifier.verify(h, signature):

            # print("Client: The signature is valid, proceeding to save transaction, signature, new txhash and the public key to mempool")

            #print(str(tx_timestamp), str(keyring.myaddress), str(recipient), '%.8f' % float(amount),str(signature_enc), str(operation), '%.8f' % float(fee), str(openfield))
            submit = str(tx_timestamp), str(keyring.myaddress), str(recipient), '%.8f' % float(
               amount), str(signature_enc), str(keyring.public_key_hashed.decode("utf-8")), str(
               operation), str(openfield),'%.8f' % float(fee) # float kept for compatibility

            print(sys.getsizeof(submit))
            print (sys.getsizeof(str(tx_timestamp)),sys.getsizeof( str(keyring.myaddress)),sys.getsizeof( str(recipient)), sys.getsizeof('%.8f' % float(
               amount)),sys.getsizeof( str(signature_enc)), sys.getsizeof(str(keyring.public_key_hashed.decode("utf-8"))), sys.getsizeof(str(
               operation)),sys.getsizeof( str(openfield)),sys.getsizeof('%.8f' % float(fee)))
            while True:
                # connections.send(s, "mpinsert", 10)
                # connections.send(s, tx_submit, 10)
                # reply = connections.receive(s, 10)
                # print(reply)
                # print("Client: {Client}".format(reply))
                try:
                    Peers_connection.peers_send("mpinsert")
                    time.sleep(2)
                    Peers_connection.peers_send(submit)
                    reply = connections.receive()
                    print(reply)
                    if reply == "Success":
                        messagebox.showinfo("OK", "Transaction accepted to mempool")
                    else:
                        messagebox.showerror("Error","There was a problem with transaction processing. Full message: {}".format(reply))
                    break


                # enter transaction end
                    # db = sqlite3.connect('mempool.db')
                    # cursor = db.cursor()
                    # cursor.execute(SQL_CREATE)
                    # print(signature_enc)
                    # cursor.execute("INSERT INTO transactions VALUES (?,?,?,?,?,?,?,?)",
                    #              (tx_timestamp, keyring.myaddress, recipient, float(amount), signature_enc, operation, openfield, float(fee)))
                    # db.commit()
                    # messagebox.showinfo("OK", "Transaction accepted to mempool")
                except:
                    messagebox.showerror("Error","There was a problem with transaction processing. Full message")
                break
        else:
            print("signature not varified")
    # f = Mempool.fetchall(SQL_SELECT_ALL_TXS)
    # Peers_connection.peers_send(f[-1])

        #refresh(gui_address_t.get(), s)
    # enter transaction end


def token_transfer(token, amount, window):
    operation.delete(0, END)
    operation.insert(0, "token:transfer")

    openfield.delete('1.0', END)  # remove previous
    openfield.insert(INSERT, "{}:{}".format(token, amount))
    window.destroy()

    send_confirm(0, recipient.get(), "token:transfer", "{}:{}".format(token, amount))


def token_issue(token, amount, window):
    operation.delete(0, END)
    operation.insert(0, "token:issue")

    openfield.delete('1.0', END)  # remove previous
    openfield.insert(INSERT, "{}:{}".format(token, amount))
    recipient.delete(0, END)
    recipient.insert(INSERT, keyring.myaddress)
    window.destroy()

    send_confirm(0, recipient.get(), "token:issue", "{}:{}".format(token, amount))


def tokens():
    tokens_main = Frame(tab_tokens, relief='ridge', borderwidth=0)
    tokens_main.grid(row=0, column=0, pady=5, padx=5, sticky=N + W + E + S)
    # tokens_main.title ("Tokens")

    token_box = Listbox(tokens_main, width=100)
    token_box.grid(row=0, pady=0)

    scrollbar_v = Scrollbar(tokens_main, command=token_box.yview)
    scrollbar_v.grid(row=0, column=1, sticky=N + S + E)

    Peers_connection.peers_send("tokensget")
    Peers_connection.peers_send(gui_address_t.get())
    tokens_results = connections.receive()
    print(tokens_results)

    for pair in tokens_results:
        try:
            token = pair[0]
            balance = pair[1]
            token_box.insert(END, (token, ":", balance))
        except:
            print("There was an issue fetching tokens")
            pass

    # callback
    def callback(event):
        token_select = (token_box.get(token_box.curselection()[0]))
        token_name_var.set(token_select[0])
        token_amount_var.set(token_select[2])

    token_box.bind('<Double-1>', callback)

    # callback

    token_name_var = StringVar()
    token_name = Entry(tokens_main, textvariable=token_name_var, width=80)
    token_name.grid(row=2, column=0, sticky=E, padx=15, pady=(5, 5))

    token_name_label_var = StringVar()
    token_name_label_var.set("Token Name:")
    token_name_label = Label(tokens_main, textvariable=token_name_label_var)
    token_name_label.grid(row=2, column=0, sticky=W, padx=15, pady=(0, 0))

    # balance_var = StringVar()
    # balance_msg_label = Label(frame_buttons, textvariable=balance_var)

    token_amount_var = StringVar()
    token_amount = Entry(tokens_main, textvariable=token_amount_var, width=80, )
    token_amount.grid(row=3, column=0, sticky=E, padx=15, pady=(5, 5))

    token_amount_label_var = StringVar()
    token_amount_label_var.set("Token Amount:")
    token_amount_label = Label(tokens_main, textvariable=token_amount_label_var)
    token_amount_label.grid(row=3, column=0, sticky=W, padx=15, pady=(0, 0))

    transfer = Button(tokens_main, text="Transfer", command=lambda: token_transfer(token_name_var.get(), token_amount_var.get(), tokens_main))
    transfer.grid(row=4, column=0, sticky=W + E, padx=5)

    issue = Button(tokens_main, text="Issue", command=lambda: token_issue(token_name_var.get(), token_amount_var.get(), tokens_main))
    issue.grid(row=5, column=0, sticky=W + E, padx=5)

    # cancel = Button (tokens_main, text="Cancel", command=tokens_main.destroy)
    # cancel.grid (row=6, column=0, sticky=W + E, padx=5)


def keys_untar(archive):
    with open(archive, "r") as archive_file:
        tar = tarfile.open(archive_file.name)
        name = tar.getnames()
        tar.extractall()
    print("{} file untarred successfully".format(name))
    return name


def keys_load_dialog():


    wallet_load = filedialog.askopenfilename(multiple=False, initialdir="", title="Select wallet")

    if wallet_load.endswith('.gz'):
        print(wallet_load)
        wallet_load = keys_untar(wallet_load)[0]

    keyring.key, keyring.public_key_readable, keyring.private_key_readable, keyring.encrypted, keyring.unlocked, keyring.public_key_hashed, keyring.myaddress, keyring.keyfile = essentials.keys_load_new(wallet_load)  # upgrade later, remove blanks

    encryption_button_refresh()

    gui_address_t.delete(0, END)
    gui_address_t.insert(INSERT, keyring.myaddress)

    recipient_address.config(state=NORMAL)
    recipient_address.delete(0, END)
    recipient_address.insert(INSERT, keyring.myaddress)
    recipient_address.config(state=DISABLED)

    sender_address.config(state=NORMAL)
    sender_address.delete(0, END)
    sender_address.insert(INSERT, keyring.myaddress)
    sender_address.config(state=DISABLED)

    #refresh(keyring.myaddress, s)


def keys_backup():
    root.filename = filedialog.asksaveasfilename(initialdir="", title="Select backup file")

    if not root.filename == "":
        if not root.filename.endswith(".tar.gz"):
            root.filename = root.filename + ".tar.gz"

        der_files = glob.glob("*.der")

        tar = tarfile.open(root.filename, "w:gz")
        for der_file in der_files:
            tar.add(der_file, arcname=der_file)
        tar.close()


def request_process(address, amount, Operation, top):
    request_process_confirmed(address, amount, Operation, top)


def request_process_confirmed(address, amount, Operation, top):
    top.destroy()
    Send_request_money(address, amount, Operation)


def Send_request_money(address, amount, Operation):
    if keyring.key is None:
        messagebox.showerror("Locked", "Wallet is locked")

    print("Received tx command")

    try:
        Decimal(amount)
    except:
        messagebox.showerror("Invalid Amount", "Amount must be a number")

    if not address_validate(address):
        messagebox.showerror("Invalid Address", "Invalid address format")
    else:
        tx_timestamp = str(time.time())
        transaction = (str(tx_timestamp), str(address), '%.8f' % float(amount), str(Operation))

        h = SHA224.new(str(transaction).encode("utf-8"))
        signer = PKCS1_v1_5.new(keyring.key)
        signature = signer.sign(h)
        signature_enc = base64.b64encode(signature).decode()
        verifier = PKCS1_v1_5.new(keyring.key)
        if verifier.verify(h, signature):

            # print("Client: The signature is valid, proceeding to save transaction, signature, new txhash and the public key to mempool")

            # print(str(tx_timestamp), str(keyring.myaddress), str(recipient), '%.8f' % float(amount),str(signature_enc), str(operation), '%.8f' % float(fee), str(openfield))
            submit = str(tx_timestamp), str(keyring.myaddress), '%.8f' % float(amount), str(signature_enc), str(
                keyring.public_key_hashed.decode("utf-8")), str(Operation)

            while True:
                try:
                    Peers_connection.peers_send("addmoney")
                    time.sleep(2)
                    Peers_connection.peers_send(submit)
                    reply = connections.receive()
                    print(reply)
                    if reply == "Success":
                        messagebox.showinfo("OK",
                                            "Money added succesfully. This process will take few time, please wait...")
                    else:
                        messagebox.showerror("Error",
                                             "There was a problem with transaction processing. Full message: {}".format(
                                                 reply))
                    break

                except:
                    messagebox.showerror("Error", "There was a problem with transaction processing. Full message")
                break
        else:
            print("signature not varified")


def Addmoney():
    top = Toplevel()
    top.title("Add Money")

    d = Frame(top, relief='ridge', borderwidth=0)
    d.grid(row=0, column=0, pady=5, padx=5, sticky=N + W + E + S)

    my_address = Entry(d, width=60, text="My Address")
    my_address.grid(row=0, column=1, sticky=W, pady=5, padx=5)
    my_address.insert(0, keyring.myaddress)
    my_address.configure(state=DISABLED)
    Label(d, text="My Address :").grid(row=0, column=0, sticky=W + N, pady=5, padx=5)

    g = Frame(top, relief='ridge', borderwidth=0)
    g.grid(row=1, column=0, pady=5, padx=5, sticky=N + W + E + S)
    amount = Entry(g, width=60, text="Amount")
    amount.grid(row=1, column=1, sticky=W, pady=5, padx=5)
    amount.insert(0, "0.00000000")
    Label(g, text="Amount :").grid(row=1, column=0, sticky=W + N, pady=5, padx=5)

    Operations = Frame(top, relief='ridge', borderwidth=0)
    Operations.grid(row=2, column=0, pady=5, padx=5, sticky=N + W + E + S)
    Operation = Entry(Operations, width=60, text="Operation")
    Operation.grid(row=2, column=1, sticky=W, pady=5, padx=5)
    Label(Operations, text="Operation :").grid(row=2, column=0, sticky=W + N, pady=5, padx=5)

    addbutton = Frame(top, relief='ridge', borderwidth=0)
    addbutton.grid(row=3, column=0, pady=5, padx=5, sticky=N + W + E + S)
    add_button = Button(addbutton, width=60, text="Add Money",
                        command=lambda: request_process(keyring.myaddress, str(amount.get()).strip(),
                                                        str(Operation.get()).strip(), top))
    add_button.grid(row=3, column=6, sticky=W, pady=5, padx=5)

    done = Button(addbutton, width=60, text="Cancel", command=top.destroy)
    done.grid(row=4, column=6, sticky=W, pady=5, padx=5)




def help():
    top13 = Toplevel()
    top13.title("Help")
    aliases_box = Text(top13, width=100)
    aliases_box.grid(row=0, pady=0)

    aliases_box.insert(INSERT, "Encrypt with PK:\n Encrypt the data with the recipient's private key. Only they will be able to view it.")
    aliases_box.insert(INSERT, "\n\n")
    aliases_box.insert(INSERT, "Mark as Message:\n Mark data as message. The recipient will be able to view it in the message section.")
    aliases_box.insert(INSERT, "\n\n")
    aliases_box.insert(INSERT, "Base64 Encoding:\n Encode the data with base64, it is a group of binary-to-text encoding scheme that representd binary data in an ASCII string format by translating it into a radix-64 representation.")
    aliases_box.insert(INSERT, "\n\n")
    aliases_box.insert(INSERT, "Operation:\n A static operation for blockchain programmability.")
    aliases_box.insert(INSERT, "\n\n")
    aliases_box.insert(INSERT, "Data:\n A variable operation for blockchain programmability.")
    aliases_box.insert(INSERT, "\n\n")
    aliases_box.insert(INSERT, "Alias Recipient:\n Use an alias of the recipient in the recipient field if they have one registered")
    aliases_box.insert(INSERT, "\n\n")
    aliases_box.insert(INSERT, "Resolve Aliases:\n Show aliases instead of addressess where applicable in the table below.")
    aliases_box.insert(INSERT, "\n\n")

    close = Button(top13, text="Close", command=top13.destroy)
    close.grid(row=3, column=0, sticky=W + E)



def refresh():
    if not keyring.encrypted:
        messagebox.showwarning("Error", "Encrypt your wallet first")
        return
    x = tx_tree.get_children()
    for item in x: tx_tree.delete(item)
    if os.path.isfile('static/ledger.db'):
        d = Mempool.Fetchall('static/ledger.db', "SELECT * FROM transactions  ORDER BY block_height DESC limit 1", '', True)
        if not d:
            statusget = (keyring.myaddress, 0)
            print(statusget)
        else:
            statusget = (keyring.myaddress, d[0][0])
            print(statusget)
    else:
        statusget = (keyring.myaddress, 0)
    # Peers_connection.peers_send("statusget")
    # time.sleep(2)
    # Peers_connection.peers_send(statusget)
    # transfered_txn = connections.receive()
    # transfered_txn1 = connections.receive()

    # for i in range(len(transfered_txn)):
    #     txn = (int(transfered_txn[i][0]),transfered_txn[i][1],transfered_txn[i][2],transfered_txn[i][3],transfered_txn[i][4],float(transfered_txn[i][5]),transfered_txn[i][6],transfered_txn[i][7],transfered_txn[i][8],float(transfered_txn[i][9]),transfered_txn[i][10],transfered_txn[i][11],transfered_txn[i][12],transfered_txn[i][6])
    #     mp = Mempool.execute('static/ledger.db',"INSERT INTO transactions(block_height,timestamp,Nones, address, recipient, amount, signature, public_key, block_hash, fee, reward, operation, openfield) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",txn,True)
    #
    # Mempool.commit('static/ledger.db',"CREATE TABLE IF NOT EXISTS transfered (ID INTEGER PRIMARY KEY AUTOINCREMENT,block_height INTEGER, timestamp,Nones, sender, recipient, amount INTEGER, signature, public_key, block_hash, operation, openfield,fee INTEGER)",write=True)
    transfered_txn1 = Mempool.Fetchall('miner/static/ledger.db', "SELECT * FROM transfered WHERE recipient = ? OR sender = ?",(keyring.myaddress, keyring.myaddress), True)


    for i in range(len(transfered_txn1)):
        txn = (int(transfered_txn1[i][0]), transfered_txn1[i][1], transfered_txn1[i][2], transfered_txn1[i][3],
               transfered_txn1[i][4], transfered_txn1[i][5],
               float(transfered_txn1[i][6]), transfered_txn1[i][7], transfered_txn1[i][8], transfered_txn1[i][9],
               transfered_txn1[i][10], transfered_txn1[i][11],float(transfered_txn1[i][12]))

        c = Mempool.Fetchall('miner_wallet.db', "SELECT * FROM transfered WHERE signature=?", (transfered_txn1[i][7],), True)
        if c:
            print("Transaction Has Already In History")
        else:
            Mempool.commit('miner_wallet.db',"CREATE TABLE IF NOT EXISTS miner_transfered (ID INTEGER PRIMARY KEY AUTOINCREMENT,block_height INTEGER, timestamp,txn_id,Nones, sender, recipient, amount INTEGER, signature, public_key, block_hash, operation, openfield,fee INTEGER)",write=True)

            mp1 = Mempool.execute('miner_wallet.db',"INSERT INTO miner_transfered(block_height, timestamp,txn_id,Nones, sender, recipient, amount, signature, public_key, block_hash, operation, openfield,fee) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",txn,True)
            if mp1:
                pass
            else:
                messagebox.showwarning("Error","Database can not connected")
                break

    view = Mempool.Fetchall('static/ledger.db',"SELECT * FROM transfered ORDER BY ID DESC limit ?",(10,),True)
    if view:
        for i in range(len(view)):
            row = (datetime.datetime.fromtimestamp(int(view[i][2])).strftime('%Y-%m-%d %H:%M:%S'),view[i][4],view[i][5],view[i][6],"None")
            tx_tree['show'] = 'headings'
            tx_tree.insert("",0,values=row)
        balance_miner, recv, send = UTXO.balance(keyring.myaddress)
        balance = balance_miner + UTXO.miner_fee_reward()
        balance_var.set("Balance: {:.8f} CWR".format(Decimal(balance)))
        balance_raw.set(balance)
        # address_var.set("Address: {}".format(address))
        debit_var.set("Sent Total: {:.8f} CWR".format(Decimal(send)))
        credit_var.set("Received Total: {:.8f} CWR".format(Decimal(recv)))
    else:
        balance_miner, recv, send = UTXO.balance(keyring.myaddress)
        balance = balance_miner + UTXO.miner_fee_reward()
        balance_var.set("Balance: {:.8f} CWR".format(Decimal(balance)))
        balance_raw.set(balance)
        # address_var.set("Address: {}".format(address))
        debit_var.set("Sent Total: {:.8f} CWR".format(Decimal(send)))
        credit_var.set("Received Total: {:.8f} CWR".format(Decimal(recv)))
        messagebox.showwarning("Error", "Database can not connected")
def Signature():
    if not keyring.encrypted:
        print("Error", "Encrypt your wallet first")
    elif keyring.key is None:
        print("Locked", "Wallet is locked")
    else:
        tx_timestamp = str(time.time())

        register = (tx_timestamp,keyring.public_key_readable, keyring.myaddress)
        h = SHA224.new(str(register).encode("utf-8"))

        signer = PKCS1_v1_5.new(keyring.key)

        signature = signer.sign(h)
        signature_enc = base64.b64encode(signature).decode()
        verifier = PKCS1_v1_5.new(keyring.key)
        if verifier.verify(h, signature):
            return signature_enc,keyring.myaddress,keyring.public_key_readable
        else:
            print("Can Not Verifi")


if __name__ == "__main__":
    keyring = Keys()
    Mempool = Mempools("Error")
    Peers_connection = Peers()
    #keyring.myaddress = "b891f1f7039adab56c3c5204632baabbab0f78c4e52c3d48eee42605"
    stats_nodes_count_list = []
    stats_thread_count_list = []
    stats_consensus_list = []
    stats_consensus_percentage_list = []
    stats_diff_list_0 = []
    stats_diff_list_1 = []
    stats_diff_list_2 = []
    stats_diff_list_3 = []
    stats_diff_list_4 = []
    stats_diff_list_5 = []
    stats_diff_list_6 = []

    debug_level = "WARNING"
    full_ledger = True
    port = 5658
    light_ip = "127.0.0.1"
    node_ip = "127.0.0.1"
    version = "testnet"
    terminal_output = False
    gui_scaling = "adapt"

    if os.path.exists("privkey.der"):
        private_key_load = "privkey.der"
    else:
        private_key_load = "privkey_encrypted.der"
    public_key_load = "pubkey.der"

    keyring.key, keyring.public_key_readable, keyring.private_key_readable, keyring.encrypted, keyring.unlocked, keyring.public_key_hashed, keyring.myaddress, keyring.keyfile = essentials.keys_load( private_key_load, public_key_load)
    print("Keyfile: {}".format(keyring.keyfile))

    if "testnet" in version:
        port = 2829
        light_ip = ["127.0.0.1"]

    #app_log = log.log("wallet.log", debug_level, terminal_output)  # debug_level = WARNING  & terminal_output = False

    # essentials.keys_check(app_log, "wallet.der")

    light_ip_conf = light_ip

    # light_ip = get_best_ipport_to_use(light_ip_conf)
    # light_ip.insert(0,node_ip)
    # light_ip = "127.0.0.1:8150"

    root = Tk()

    root.wm_title("Cowrie Light Wallet - v{}".format('0.8.2'))
    # root.geometry("1310x700") #You want the size of the app to be 500x500

    # root['bg']="black"


    """nuitka
    root.resizable(0, 0)  # Don't allow resizing in the x or y direction / resize #nuitka
    img_icon = PIL.Image.open("graphics/icon.jpg") #nuitka
    photo_icon = PIL.ImageTk.PhotoImage(img_icon) #nuitka
    root.tk.call('wm', 'iconphoto', root._w, photo_icon, ) #nuitka
    """

    if gui_scaling == "adapt":
        dpi_value = root.winfo_fpixels('1i')
        root.tk.call('tk', 'scaling', dpi_value / 72)

    elif gui_scaling != "default":
        root.tk.call("tk", "scaling", gui_scaling)

    password_var_enc = StringVar()
    password_var_con = StringVar()
    password_var_dec = StringVar()

    frame_bottom = Frame(root, relief='sunken', borderwidth=1)
    frame_bottom.grid(row=5, column=0, sticky='NESW', pady=5, padx=5)

    # notebook widget
    nbtabs = ttk.Notebook(root)
    nbtabs.grid(row=1, column=0, sticky='NESW', pady=5, padx=5)

    # tab_main Main
    tab_main = ttk.Frame(nbtabs)
    nbtabs.add(tab_main, text='Overview')

    canvas_main = Canvas(tab_main, highlightthickness=0)
    canvas_main.grid(row=0, column=0, sticky=W + E + N + S, columnspan=99, rowspan=99)

    frame_logo = Frame(tab_main, relief='ridge', borderwidth=4)
    frame_logo.grid(row=1, column=0, pady=5, padx=5, sticky=W)

    frame_coins = Frame(tab_main, relief='ridge', borderwidth=4)
    frame_coins.grid(row=0, column=0, sticky=W + E + N, pady=5, padx=5)

    frame_hyperlinks = Frame(tab_main, relief='ridge', borderwidth=4)
    frame_hyperlinks.grid(row=0, column=98, pady=5, padx=5, sticky=W + N)

    frame_support = Frame(tab_main, relief='ridge', borderwidth=4)
    frame_support.grid(row=98, column=98, pady=5, padx=5, sticky=W + N)

    # frame_mainstats = Frame(tab_main, relief = 'ridge', borderwidth = 4)
    # frame_mainstats.grid(row=5, column=1, sticky=W + E + N, pady=5, padx=5)


    # tab_transactions transactions
    tab_transactions = ttk.Frame(nbtabs)

    nbtabs.add(tab_transactions, text='History')

    frame_entries_t = Frame(tab_transactions, relief='ridge', borderwidth=0)
    frame_entries_t.grid(row=0, column=0, pady=5, padx=5)

    # frame_labels_t = Frame(tab_transactions,relief = 'ridge', borderwidth = 0)
    # frame_labels_t.grid(row=0, column=0, pady=5, padx=5, sticky=N+W+E+S)

    frame_table = Frame(tab_transactions, relief='ridge', borderwidth=0)
    frame_table.grid(row=1, column=0, sticky=W + E + N, pady=5, padx=5)

    tx_tree = ttk.Treeview(tab_transactions, selectmode="extended", columns=('time','sender', 'recipient', 'amount', 'type'), height=20)
    tx_tree.grid(row=1, column=0)

    # table
    tx_tree.heading("#1", text='time')
    tx_tree.column("#1", anchor='center', width=100)

    tx_tree.heading("#2", text='sender')
    tx_tree.column("#2", anchor='center', width=347)

    tx_tree.heading("#3", text='recipient')
    tx_tree.column("#3", anchor='center', width=347)

    tx_tree.heading("#4", text='amount')
    tx_tree.column("#4", anchor='center', width=35)

    tx_tree.heading("#5", text='type')
    tx_tree.column("#5", anchor='center', width=40)

    tx_tree.grid(sticky=N + S + W + E)
    tx_tree['show'] = 'headings'
    # refresh(myaddress, s)

    # tab_send sendcoin tab
    tab_send = ttk.Frame(nbtabs)
    nbtabs.add(tab_send, text='Send')

    frame_entries = Frame(tab_send)
    frame_entries.grid(row=0, column=0, pady=5, padx=5, sticky=N + W + E + S)

    frame_send = Frame(tab_send, relief='ridge', borderwidth=1)
    frame_send.grid(row=0, column=2, pady=5, padx=5, sticky=N)

    frame_tick = Frame(frame_send, relief='ridge', borderwidth=1)
    frame_tick.grid(row=4, column=0, pady=5, padx=5, sticky=S)

    # tab_receive receive
    tab_receive = ttk.Frame(nbtabs)
    nbtabs.add(tab_receive, text='Receive')

    frame_entries_r = Frame(tab_receive, relief='ridge', borderwidth=0)
    frame_entries_r.grid(row=0, column=0, pady=5, padx=5, sticky=N + W + E + S)

    recipient_address = Entry(frame_entries_r, width=60, text="myaddress")
    recipient_address.insert(0,keyring.myaddress)

    recipient_address.grid(row=0, column=1, sticky=W, pady=5, padx=5)
    recipient_address.configure(state=DISABLED)

    amount_r = Entry(frame_entries_r, width=60)
    amount_r.grid(row=2, column=1, sticky=W, pady=5, padx=5)
    amount_r.insert(0, "0.00000000")

    openfield_r = Text(frame_entries_r, width=60, height=5, font=("Tahoma", 8))
    openfield_r.grid(row=3, column=1, sticky=W, pady=5, padx=5)

    operation_r = Entry(frame_entries_r, width=60)
    operation_r.grid(row=4, column=1, sticky=W, pady=5, padx=5)

    url_r = Entry(frame_entries_r, width=60)
    url_r.grid(row=5, column=1, sticky=W, pady=5, padx=5)
    url_r.insert(0, "cwr://")

    # tab5 tokens
    tab_tokens = ttk.Frame(nbtabs)
    nbtabs.add(tab_tokens, text='Tokens')

    nbtabs.bind('<<NotebookTabChanged>>', click_on_tab_tokens)
    tokens_main = Frame(tab_tokens, relief='ridge', borderwidth=0)
    tokens_main.grid(row=0, column=0, pady=5, padx=5, sticky=N + W + E + S)
    # tokens_main.title ("Tokens")

    token_box = Listbox(tokens_main, width=100)
    token_box.grid(row=0, pady=0)

    scrollbar_v = Scrollbar(tokens_main, command=token_box.yview)
    scrollbar_v.grid(row=0, column=1, sticky=N + S + E)

    # connections.send(s, "tokensget", 10)
    # connections.send(s, gui_address_t.get(), 10)
    # tokens_results = connections.receive(s, 10)
    token_name_var = StringVar()
    token_name = Entry(tokens_main, textvariable=token_name_var, width=80)
    token_name.grid(row=2, column=0, sticky=E, padx=15, pady=(5, 5))

    token_name_label_var = StringVar()
    token_name_label_var.set("Token Name:")
    token_name_label = Label(tokens_main, textvariable=token_name_label_var)
    token_name_label.grid(row=2, column=0, sticky=W, padx=15, pady=(0, 0))

    # balance_var = StringVar()
    # balance_msg_label = Label(frame_buttons, textvariable=balance_var)

    token_amount_var = StringVar()
    token_amount = Entry(tokens_main, textvariable=token_amount_var, width=80, )
    token_amount.grid(row=3, column=0, sticky=E, padx=15, pady=(5, 5))

    token_amount_label_var = StringVar()
    token_amount_label_var.set("Token Amount:")
    token_amount_label = Label(tokens_main, textvariable=token_amount_label_var)
    token_amount_label.grid(row=3, column=0, sticky=W, padx=15, pady=(0, 0))

    transfer = Button(tokens_main, text="Transfer")
    transfer.grid(row=4, column=0, sticky=W + E, padx=5)

    issue = Button(tokens_main, text="Issue")
    issue.grid(row=5, column=0, sticky=W + E, padx=5)
    # frames
    # menu

    # canvas
    menubar = Menu(root)
    walletmenu = Menu(menubar, tearoff=0)
    menubar.add_cascade(label="Wallet", menu=walletmenu)
    walletmenu.add_command(label="Load Wallet...", command=keys_load_dialog)
    walletmenu.add_command(label="Backup Wallet...", command=keys_backup)
    walletmenu.add_command(label="Encrypt Wallet...", command=encrypt_get_password)
    walletmenu.add_separator()
    walletmenu.add_command(label="Recovery", command=recover)
    walletmenu.add_separator()
    # walletmenu.add_command(label="Spending URL QR", command=lambda: qr(url.get()))
    # walletmenu.add_command(label="Reception URL QR", command=lambda: qr(url_r.get()))
    walletmenu.add_command(label="Alias Registration...", command=alias)
    walletmenu.add_command(label="Show Alias", command=alias_register)
    walletmenu.add_command(label="Fingerprint...")
    walletmenu.add_separator()
    walletmenu.add_command(label="Exit", command=root.quit)

    messagemenu = Menu(menubar, tearoff=0)
    menubar.add_cascade(label="Message", menu=messagemenu)
    messagemenu.add_command(label="Show Messages")
    messagemenu.add_command(label="Sign Messages")

    if not os.path.exists("theme"):
        with open("theme", "w") as theme_file:
            theme_file.write("Barebone")

    theme_menu = Menu(menubar, tearoff=0)

    theme_list = []
    for theme_picture in glob.glob('themes/*.jpg'):
        theme_picture = os.path.basename(theme_picture).split('.jpg')[0]
        theme_list.append(theme_picture)
        theme_menu.add_command(label=theme_picture)

    theme_menu.add_command(label="Barebone")
    menubar.add_cascade(label="Themes", menu=theme_menu)

    miscmenu = Menu(menubar, tearoff=0)
    menubar.add_cascade(label="Misc", menu=miscmenu)
    miscmenu.add_command(label="Mempool")
    miscmenu.add_command(label="CSV Export...")
    miscmenu.add_command(label="Statistics")
    miscmenu.add_command(label="Help", command=help)

    connect_menu = Menu(menubar, tearoff=0)
    menubar.add_cascade(label="Connection", menu=connect_menu)
    connect_list = []

    for ip_once in light_ip:
        connect_list.append(ip_once)
        connect_menu.add_command(label=ip_once)

    # labels
    Label(frame_entries, text="My Address:").grid(row=0, sticky=W + N, pady=5, padx=5)
    Label(frame_entries, text="Recipient:").grid(row=1, sticky=W, pady=5, padx=5)
    Label(frame_entries, text="Amount:").grid(row=2, sticky=W, pady=5, padx=5)
    Label(frame_entries, text="Data:", height=4).grid(row=3, sticky=W, pady=5, padx=5)
    Label(frame_entries, text="Operation:", height=4).grid(row=4, sticky=W, pady=5, padx=5)
    Label(frame_entries, text="URL:").grid(row=5, sticky=W + S, pady=5, padx=5)
    Label(frame_entries, text="If you have a CWR URL, copy it, click paste-button\n"
                              "on URL field and then click 'read'."
                              "If you want to send Cowrie\n"
                              "to the shown recipient, click send and then\n"
                              "the confirmation dialog opens.", justify=LEFT).grid(row=6, column=1, sticky=W + S, pady=1,
                                                                                   padx=1, columnspan=2)

    Label(frame_entries_r, text="Recipient:").grid(row=0, sticky=W, pady=5, padx=5)
    Label(frame_entries_r, text="Amount:").grid(row=2, sticky=W, pady=5, padx=5)
    Label(frame_entries_r, text="Data:", height=4).grid(row=3, sticky=W, pady=5, padx=5)
    Label(frame_entries_r, text="Operation:", height=4).grid(row=4, sticky=W, pady=5, padx=5)
    Label(frame_entries_r, text="URL:").grid(row=5, sticky=W + S, pady=5, padx=5)

    Label(frame_entries_r, text="Enter amount and if wanted, a message in field Data.\n"
                                "Your address is automatically used. Click create and copy the url.", justify=LEFT).grid(
        row=6, column=1, sticky=W + S, pady=1, padx=1, columnspan=2)

    Label(frame_entries_t, text="Address:").grid(row=0, column=0, sticky=W + N, pady=5, padx=5)

    resolve_var = BooleanVar()
    resolve = Checkbutton(frame_entries_t, text="Aliases", variable=resolve_var, width=14, anchor=W)
    resolve.grid(row=0, column=5, sticky=W)

    # canvas


    # display the menu
    root.config(menu=menubar)
    # menu

    # buttons


    send_b = Button(frame_send, text="Send Cowrie",command = lambda: send_confirm(keyring.myaddress,str(amount.get()).strip(), recipient.get().strip(), operation.get().strip(), (openfield.get("1.0", END)).strip()), height=2,width=22, font=("Tahoma", 12))
    send_b.grid(row=0, column=0)

    frame_logo_buttons = Frame(frame_send)
    frame_logo_buttons.grid(row=5, column=0, padx=5, pady=5)

    encrypt_b = Button(frame_logo_buttons, text="Encrypt", command=encrypt_get_password,  height=1, width=8)
    encrypt_b.grid(row=0, column=0)
    decrypt_b = Button(frame_logo_buttons, text="Unlock", command=decrypt_get_password, height=1, width=8)
    decrypt_b.grid(row=0, column=1)
    lock_b = Button(frame_logo_buttons, text="Locked", command=lambda: lock_fn(lock_b), height=1, width=8, state=DISABLED)
    lock_b.grid(row=0, column=2)



    # encryption_button_refresh()
    # buttons

    # refreshables

    # update balance label
    balance_raw = StringVar()
    balance_var = StringVar()

    # address_var = StringVar()
    # address_var_label = Label(frame_coins, textvariable=address_var, font=("Tahoma", 8, "bold"))
    # address_var_label.grid(row=0, column=0, sticky=S, padx=15)

    balance_msg_label = Label(frame_coins, textvariable=balance_var, font=("Tahoma", 16, "bold"))
    balance_msg_label.grid(row=1, column=0, sticky=S, padx=15)

    balance_msg_label_sendtab = Label(frame_send, textvariable=balance_var, font=("Tahoma", 10))
    balance_msg_label_sendtab.grid(row=3, column=0, sticky=N + S)

    debit_var = StringVar()
    spent_msg_label = Label(frame_coins, textvariable=debit_var, font=("Tahoma", 12))
    spent_msg_label.grid(row=2, column=0, sticky=N + E, padx=15)

    credit_var = StringVar()
    received_msg_label = Label(frame_coins, textvariable=credit_var, font=("Tahoma", 12))
    received_msg_label.grid(row=3, column=0, sticky=N + E, padx=15)

    fees_var = StringVar()
    fees_paid_msg_label = Label(frame_coins, textvariable=fees_var, font=("Tahoma", 12))
    fees_paid_msg_label.grid(row=4, column=0, sticky=N + E, padx=15)

    rewards_var = StringVar()
    rewards_paid_msg_label = Label(frame_coins, textvariable=rewards_var, font=("Tahoma", 12))
    rewards_paid_msg_label.grid(row=5, column=0, sticky=N + E, padx=15)

    bl_height_var = StringVar()
    block_height_label = Label(frame_bottom, textvariable=bl_height_var)
    block_height_label.grid(row=0, column=7, sticky=S + E, padx=5)

    ip_connected_var = StringVar()
    ip_connected_label = Label(frame_bottom, textvariable=ip_connected_var)
    ip_connected_label.grid(row=0, column=8, sticky=S + E, padx=5)

    diff_msg_var = StringVar()
    diff_msg_label = Label(frame_bottom, textvariable=diff_msg_var)
    diff_msg_label.grid(row=0, column=5, sticky=S + E, padx=5)

    sync_msg_var = StringVar()
    sync_msg_label = Label(frame_bottom, textvariable=sync_msg_var)
    sync_msg_label.grid(row=0, column=0, sticky=N + E, padx=15)

    version_var = StringVar()
    version_var_label = Label(frame_bottom, textvariable=version_var)
    version_var_label.grid(row=0, column=2, sticky=N + E, padx=15)

    hash_var = StringVar()
    hash_var_label = Label(frame_bottom, textvariable=hash_var)
    hash_var_label.grid(row=0, column=4, sticky=S + E, padx=5)

    mempool_count_var = StringVar()
    mempool_count_var_label = Label(frame_bottom, textvariable=mempool_count_var)
    mempool_count_var_label.grid(row=0, column=3, sticky=S + E, padx=5)

    server_timestamp_var = StringVar()
    server_timestamp_label = Label(frame_bottom, textvariable=server_timestamp_var)
    server_timestamp_label.grid(row=0, column=9, sticky=S + E, padx=5)

    ann_var = StringVar()
    ann_var_text = Text(frame_logo, width=20, height=4, font=("Tahoma", 8))
    ann_var_text.grid(row=1, column=0, sticky=E + W, padx=5, pady=5)
    ann_var_text.config(wrap=WORD)
    ann_var_text.config(background="grey75")

    encode_var = BooleanVar()
    alias_cb_var = BooleanVar()
    msg_var = BooleanVar()
    encrypt_var = BooleanVar()
    all_spend_var = BooleanVar()

    # address and amount

    # gui_address.configure(state="readonly")

    gui_copy_address = Button(frame_entries, text="Copy",command=address_copy, font=("Tahoma", 7))
    gui_copy_address.grid(row=0, column=2, sticky=W)

    gui_copy_recipient = Button(frame_entries, text="Copy",command=recipient_copy, font=("Tahoma", 7))
    gui_copy_recipient.grid(row=1, column=2, sticky=W)

    gui_insert_recipient = Button(frame_entries, text="Paste",command=recipient_insert, font=("Tahoma", 7))
    gui_insert_recipient.grid(row=1, column=3, sticky=W)

    # gui_help = Button(frame_entries, text="Help", command=help, font=("Tahoma", 7))
    # gui_help.grid(row=4, column=2, sticky=W + E, padx=(5, 0))

    gui_all_spend = Checkbutton(frame_entries, text="All", variable=all_spend_var, font=("Tahoma", 7))
    gui_all_spend.grid(row=2, column=2, sticky=W)

    gui_all_spend_clear = Button(frame_entries, text="Clear",command=all_spend_clear, font=("Tahoma", 7))
    gui_all_spend_clear.grid(row=2, column=3, sticky=W)

    data_insert_clipboard = Button(frame_entries, text="Paste",command=data_insert, font=("Tahoma", 7))
    data_insert_clipboard.grid(row=3, column=2)

    data_insert_clear_s = Button(frame_entries, text="Clear",command=data_insert_clear, font=("Tahoma", 7))
    data_insert_clear_s.grid(row=3, column=3, sticky=W)

    url_insert_clipboard = Button(frame_entries, text="Paste",command=url_insert, font=("Tahoma", 7))
    url_insert_clipboard.grid(row=5, column=2, sticky=W)

    read_url_b = Button(frame_entries, text="Read",command=lambda: read_url_clicked(url.get()),font=("Tahoma", 7))
    read_url_b.grid(row=5, column=3, sticky=W)

    data_insert_clipboard = Button(frame_entries_r, text="Paste",command=data_insert_r, font=("Tahoma", 7))
    data_insert_clipboard.grid(row=3, column=2)

    data_insert_clear_r = Button(frame_entries_r, text="Clear",command=data_insert_clear, font=("Tahoma", 7))
    data_insert_clear_r.grid(row=3, column=3, sticky=W)

    gui_copy_address_r = Button(frame_entries_r, text="Copy",command=address_copy, font=("Tahoma", 7))
    gui_copy_address_r.grid(row=0, column=2, sticky=W)

    gui_copy_url_r = Button(frame_entries_r, text="Copy",command=url_copy, font=("Tahoma", 7))
    gui_copy_url_r.grid(row=5, column=3, sticky=W)

    create_url_b = Button(frame_entries_r, text="Create",command=lambda: create_url_clicked( "pay", gui_address_t.get(), amount_r.get(), operation_r.get(), openfield_r.get("1.0", END).strip()),font=("Tahoma", 7))
    create_url_b.grid(row=5, column=2, sticky=W)

    gui_paste_address = Button(frame_entries_t, text="Paste",command=address_insert, font=("Tahoma", 7))
    gui_paste_address.grid(row=0, column=2, sticky=W)

    gui_watch = Button(frame_entries_t, text="Watch", command=refresh, font=("Tahoma", 7))
    gui_watch.grid(row=0, column=3, sticky=W)

    gui_unwatch = Button(frame_entries_t, text="Reset",command=unwatch, font=("Tahoma", 7))
    gui_unwatch.grid(row=0, column=4, sticky=W, padx=(0, 5))

    # hyperlinks
    hyperlink_BISGit = Button(frame_hyperlinks, text="Cowrie@Github", font=("Tahoma", 7))
    hyperlink_BISGit.grid(row=0, column=0, sticky=N + E + S + W, padx=1, pady=1)

    hyperlink_BE = Button(frame_hyperlinks, text="Official Block Explorer", font=("Tahoma", 7))
    hyperlink_BE.grid(row=1, column=0, sticky=N + E + S + W, padx=1, pady=1)

    hyperlink_howto = Button(frame_hyperlinks, text="HowTos@Github", font=("Tahoma", 7))
    hyperlink_howto.grid(row=2, column=0, sticky=N + E + S + W, padx=1, pady=1)

    hyperlink_bct = Button(frame_hyperlinks, text="CWR@Bitcointalk", font=("Tahoma", 7))
    hyperlink_bct.grid(row=3, column=0, sticky=N + E + S + W, padx=1, pady=1)
    # hyperlinks

    # supportbutton
    dev_support = Button(frame_support, text="Add Money",command=Addmoney, font=("Tahoma", 7))
    dev_support.grid(row=98, column=98, sticky=N + E + S + W, padx=1, pady=1)
    # supportbutton

    gui_address_t = Entry(frame_entries_t, width=60)
    gui_address_t.grid(row=0, column=1, sticky=W, pady=5, padx=5)
    gui_address_t.insert(0,keyring.myaddress)

    sender_address = Entry(frame_entries, width=60)
    sender_address.insert(0,keyring.myaddress)
    sender_address.grid(row=0, column=1, sticky=W, pady=5, padx=5)
    sender_address.configure(state=DISABLED)

    recipient = Entry(frame_entries, width=60)
    recipient.grid(row=1, column=1, sticky=W, pady=5, padx=5)

    amount = Entry(frame_entries, width=60)
    amount.grid(row=2, column=1, sticky=W, pady=5, padx=5)
    amount.insert(0, "0.00000000")

    openfield = Text(frame_entries, width=60, height=5, font=("Tahoma", 8))
    openfield.grid(row=3, column=1, sticky=W, pady=5, padx=5)

    operation = Entry(frame_entries, width=60)
    operation.grid(row=4, column=1, sticky=W, pady=5, padx=5)

    url = Entry(frame_entries, width=60)
    url.grid(row=5, column=1, sticky=W, pady=5, padx=5)
    url.insert(0, "cwr://")



    encode = Checkbutton(frame_tick, text="Base64 Encoding", variable=encode_var, width=14,
                         anchor=W)
    encode.grid(row=0, column=0, sticky=W)

    msg = Checkbutton(frame_tick, text="Message", variable=msg_var, width=14, anchor=W)
    msg.grid(row=1, column=0, sticky=W)

    encr = Checkbutton(frame_tick, text="Encrypt with PK", variable=encrypt_var, width=14,
                       anchor=W)
    encr.grid(row=2, column=0, sticky=W)

    alias_cb = Checkbutton(frame_tick, text="Alias Recipient", variable=alias_cb_var, command=None, width=14, anchor=W)
    alias_cb.grid(row=4, column=0, sticky=W)

    balance_enumerator = Entry(frame_entries, width=5)
    # address and amount

    # logo

    # logo_hash_decoded = base64.b64decode(icons.logo_hash)
    # logo = PhotoImage(data="graphics/logo.png")

    """nuitka
    logo_img = PIL.Image.open("graphics/logo.png")
    logo = PIL.ImageTk.PhotoImage(logo_img)
    
    Label(frame_logo, image=logo).grid(column=0, row=0)
    # logo
    """
    # node_connect()
    # refresh_auto()

    # try:
    #     themes(open("theme", "r").read())  # load last selected theme
    # except:
    #     with open("theme", "w") as theme_file:
    #         theme_file.write("Barebone")

    root.mainloop()
