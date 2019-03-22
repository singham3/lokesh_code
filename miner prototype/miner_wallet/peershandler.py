import json
import os
import re
import sys
import threading
import time

import socks

class Peers:
    """The peers manager. A thread safe peers manager"""

    __slots__ = ('app_log','config','logstats','self.testnet','peersync_lock','startup_time','reset_time','warning_list','stats',
                 'connection_pool','peer_opinion_dict','consensus_percentage','consensus',
                 'tried','peer_dict','peerfile','suggested_peerfile','banlist','whitelist','ban_threshold',
                 'ip_to_mainnet', 'peers', 'consensus_lock', 'first_run', 'accept_peers')

    def __init__(self, config=None, logstats=True):

        self.config = config
        self.logstats = logstats

        self.testnet = False
        self.tor_conf = False
        self.purge_conf = True
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

    def peers_get(self, peerfile=''):
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
    def peers_test(self,peerfile):
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
                        s = socks.socksocket()
                        s.settimeout(0.6)
                        if self.tor_conf == 1:
                            s.settimeout(5)
                            s.setproxy(socks.PROXY_TYPE_SOCKS5, "127.0.0.1", 9050)
                        s.connect((host, port))
                        s.close()
                        print(f"Connection to {host} {port} successful, keeping the peer")
                    except:
                        if self.purge_conf == 1 :
                            # remove from peerfile if not connectible

                            peers_remove[key] = value
                        pass

                for key in peers_remove:
                    del peer_dict[key]
                    print(f"Removed formerly active peer {key}")

                with open(peerfile, "w") as output:
                    json.dump(peer_dict, output)
            finally:
                self.peersync_lock.release()