#!/bin/python3

from scapy.all import *
import requests
import json
import time
import sys
import os

import argparse
import logging

import urllib3
urllib3.disable_warnings()

from websocket_ha import WebSocketHa


class Tracker(object):

    MTU = 1500
    CACHE_INVALID_THRESHOLD = 5 # seconds

    def __init__(self, config, token):
        self.config = config
        self.token = token
        self.username = self.config['nodered']['username']
        self.password = self.config['nodered']['password']
        self.entities = self.config['entities']
        self.url = self.config['nodered']['url']
        self.filter = 'udp dst port 67 and udp[282:3] = 0x350101'
        self.cache = dict()

    def track(self):
        logging.info("Running...")
        sniff(filter=self.filter, prn=self.handle_packet)

    def cache_invalid(self, mac):
        return mac in self.cache and (time.time() - self.cache[mac]) >= Tracker.CACHE_INVALID_THRESHOLD

    def handle_packet(self, pkt):
        logging.info(pkt.summary())
        mac = pkt[Ether].src
        if self.cache_invalid(mac):
            self.notify(pkt[Ether].src)
            self.cache[mac] = time.time()

    def notify(self, mac):

        logging.info(f"Notifying {mac}")
        session = requests.Session()
        session.auth = (self.username, self.password)

        url = f'{self.url}'
        response = session.post(url, verify=False, data={'mac': mac})
        logging.info(response.text)

def load_config(config_path):

    config_file = open(config_path, 'rb')
    config = json.loads(config_file.read())
    config_file.close()
    return config

def setup_logging():
    logging.basicConfig(format='[%(asctime)s] - %(levelname)s - %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p')
    logging.getLogger().setLevel(logging.INFO)

def get_args():

    parser = argparse.ArgumentParser(description='Track devices in the network')
    parser.add_argument('--config', dest='config', action='store', help='path to config file')
    parser.add_argument('--token', dest='token', action='store', help='token used to communicate with Home Assistant')

    args = parser.parse_args()

    if args.config is None:
        parser.error("Must specify path to config file")

    return args

def main():

    args = get_args()

    # set logging level
    setup_logging()

    # parse config
    config = load_config(args.config)

    # run tracker
    logging.info(f"found token {args.token}")
    tracker = Tracker(config, args.token)
    tracker.track()


if __name__ == '__main__':
    main()
