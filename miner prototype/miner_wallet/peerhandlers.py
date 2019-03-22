import json
import os
import re
import sys
import threading
import time

import socket

slen = 10

class Peers:
    def __init__(self,config=None, logstats=True):
        self.testnet= True
        self.tor_conf = True
        self.purge_conf = True
        self.config = config
        self.logstats = logstats
        self.peersync_lock = threading.Lock()
        self.consensus_lock = threading.Lock()
        self.startup_time = time.time()
        self.reset_time = self.startup_time
        self.warning_list = []
        self.stats = []
        self.connection_pool = []
        self.peer_opinion_dict = {}
        self.consensus_percentage = 0
        self.consensus = None
        self.tried = {}
        self.peer_dict = {}
        self.ip_to_mainnet = {}
        self.connection_pool = []
        # We store them apart from the initial config, could diverge somehow later on.
        self.banlist = "127.1.2.3"
        self.whitelist = "127.0.0.1"
        self.ban_threshold = 30
        self.accept_peers = True

        self.peerfile = "peers.txt"
        self.suggested_peerfile = "suggested_peers.txt"
        self.first_run = True

        # if self.is_testnet:  # overwrite for testnet
        #     self.peerfile = "peers_test.txt"
        #     self.suggested_peerfile = "suggested_peers_test.txt"

        # if self.is_regnet:  # regnet won't use any peer, won't connect. Kept for compatibility
        #     self.peerfile = regnet.REGNET_PEERS
        #     self.suggested_peerfile = regnet.REGNET_SUGGESTED_PEERS

        # self.load_and_convert_if_needed()

    def peers_get(self, peerfile='peers.txt'):
        """Returns a peerfile from disk as a dict {ip:port}"""
        peer_dict = {}
        if not peerfile:
            peerfile = self.peerfile
        if not os.path.exists(peerfile):
            with open(peerfile, "a"):
                print("Peer file created")
        else:
            with open(peerfile, "r") as peer_file:
                peer_dict = json.load(peer_file)
        return peer_dict

    def peers_send(self,data, peerfile='peers.txt'):
        """Tests all peers from a list."""
        # TODO: lengthy, no need to test everyone at once?
        if not self.peersync_lock.locked() and self.accept_peers:
            self.peersync_lock.acquire()
            try:
                peer_dict = self.peers_get(peerfile)
                peers_remove = {}

                for key, value in peer_dict.items():
                    host, port = key, int(value)
                    try:
                        s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                        # s.settimeout(0.6)
                        # if self.tor_conf == 1:
                        #     s.settimeout(5)
                        #     s.setproxy(socks.PROXY_TYPE_SOCKS5, "192.168.1.8", 5859)

                        s.connect((host, port))
                        print("connected to {}:{}".format(host,port))


                        s.sendall(str(len(str(json.dumps(data)))).encode("utf-8").zfill(slen) + str(json.dumps(data)).encode("utf-8"))

                        print(f"Send Data to {host} {port} successful, keeping the peer")
                        s.close()



                    except:
                        if self.purge_conf == 1:
                            # remove from peerfile if not connectible

                            peers_remove[key] = value
                        pass

                for key in peers_remove:
                    del peer_dict[key]
                    print(f"Removed formerly active peer {key}")

                # with open(peerfile, "w") as output:
                #     json.dump(peer_dict, output)
            finally:
                self.peersync_lock.release()