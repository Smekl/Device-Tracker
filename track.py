#!/bin/python3

from scapy.all import AsyncSniffer, Ether
from threading import Lock, Event, Timer
import concurrent.futures
import requests
import asyncio
import json
import time
import sys
import os

import argparse
import logging

from websocket_ha import WebSocketHa

class Tracker(object):

    MTU = 1500

    def __init__(self, config, token):
        self.config = config
        self.token = token
        self.entities = self.config['entities']
        logging.info(f"got entities {self.entities}")

        logging.info("setting up websocket")
        self.ws = WebSocketHa(config['url']) if config.get('url') else WebSocketHa('ws://supervisor/core/websocket')
        self.ws.connect()
        self.ws.auth(self.token)

        self.cache_timeout = self.config['timeout']
        self.filter = 'udp dst port 67 and udp[248:1] = 0x35 and udp[249:1] = 0x1 and udp[250:1] = 0x3' # DHCP Request
        self.cache = dict()
        self.pkts = list()
        self.__lock = Lock()
        self.__event = Event()
        self.sniffer = AsyncSniffer(filter=self.filter, prn=lambda x: self.__insert_packet(x), store=0)

    def __insert_packet(self, pkt):
        self.__lock.acquire()
        self.pkts.append(pkt)
        self.__lock.release()
        self.__event.set()

    def track(self):
        logging.info("tracker started")
        self.sniffer.start()
        last_keepalive = 0
        interval = 5
        while True:

            # keep connection alive every 5 seconds
            cur_time = time.time()
            delta = cur_time - last_keepalive
            if delta > interval: 
                self.ws.ping()
                last_keepalive = cur_time
                delta = 0

            # check packets
            if len(self.pkts) > 0:
                self.__lock.acquire()
                pkts = self.pkts.copy()
                self.pkts.clear()
                self.__lock.release()
                for pkt in pkts:
                    self.handle_packet(pkt)

            Timer(interval - delta, lambda: self.__event.set()).start()
            self.__event.wait()
            self.__event.clear()

        self.sniffer.stop()

    def cache_invalid(self, mac):
        return mac not in self.cache or (time.time() - self.cache[mac]) >= self.cache_timeout

    def handle_packet(self, pkt):
        logging.info(pkt.summary())
        mac = pkt[Ether].src
        if self.cache_invalid(mac):
            self.notify(pkt[Ether].src)
            self.cache[mac] = time.time()

    def should_track_mac(self, mac):
        return self.get_entity_by_mac(mac) is not None

    def get_entity_by_mac(self, mac):
        for entity in self.entities:
            if entity['mac'] == mac:
                return entity

    def notify(self, mac):
        logging.info(f"notifying {mac}")
        if self.should_track_mac(mac):
            entity = self.get_entity_by_mac(mac)['entity']
            entity = entity.split('.')[1]

            # since we do not have absence detection, do this to trigger state change
            self.see(entity, mac, "not_home")
            self.see(entity, mac, "home")

    def see(self, entity, mac, location):
        try:
            result = self.ws.call_service('device_tracker', 'see', service_data={
                    "dev_id": entity,
                    "mac": mac,
                    "location_name": location
                })

            if not result:
                logging.debug(f"device_tracker.see({entity}, {mac}, {location}) failed")
        except:
            import traceback
            logging.error(traceback.format_exc())

def load_config(config_path):

    config_file = open(config_path, 'rb')
    config = json.loads(config_file.read())
    config_file.close()
    return config

def setup_logging(debug):
    logging.basicConfig(format='[%(asctime)s] - %(levelname)s - %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p')
    if debug:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)

def get_args():

    parser = argparse.ArgumentParser(description='Track devices in the network')
    parser.add_argument('--config', dest='config', action='store', help='path to config file')
    parser.add_argument('--token', dest='token', action='store', help='token used to communicate with Home Assistant')

    args = parser.parse_args()

    if args.config is None:
        parser.error("Must specify path to config file")

    if args.token is None:
        args.token = os.environ['SUPERVISOR_TOKEN']

    return args

def main():

    # parse args
    args = get_args()

    # parse config
    config = load_config(args.config)

    # set logging level
    setup_logging(config['debug'])

    # run tracker
    tracker = Tracker(config, args.token)
    tracker.track()


if __name__ == '__main__':
    main()
