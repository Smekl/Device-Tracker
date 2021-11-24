#!/bin/python3

from scapy.all import *
import requests
import json
import sys
import os

import argparse
import logging

class Tracker(object):

    MTU = 1500

    def __init__(self, config):
        self.config = config
        self.username = self.config['nodered']['username']
        self.password = self.config['nodered']['password']
        self.ip = self.config['nodered']['ip']
        self.port = self.config['nodered']['port']
        self.filter = 'udp dst port 67 and ip src 0.0.0.0'

    def track(self):
        logging.info("Running...")
        sniff(filter=self.filter, prn=self.handle_packet)

    def handle_packet(self, pkt):
        logging.info(pkt.summary())
        self.notify(pkt[Ether].src)

    def notify(self, mac):

        logging.info(f"Notifying {mac}")
        session = requests.Session()
        session.auth = (self.username, self.password)

        url = f'https://{self.ip}:{self.port}/endpoint/arrived'
        response = session.post(url, verify=False, data={'mac': mac})
        logging.info(response.text)

def load_config(config_path):

    config_file = open(config_path, 'rb')
    config = json.loads(config_file.read())
    config_file.close()
    return config

def get_args():

    parser = argparse.ArgumentParser(description='Track devices in the network')
    parser.add_argument('--config', dest='config', action='store', help='path to config file')

    args = parser.parse_args()

    if args.config is None:
        parser.error("Must specify path to config file")

    return args

def main():

    args = get_args()

    # set logging level
    logging.getLogger().setLevel(logging.INFO)

    # parse config
    config = load_config(args.config)

    # run tracker
    tracker = Tracker(config)
    tracker.track()


if __name__ == '__main__':
    main()
