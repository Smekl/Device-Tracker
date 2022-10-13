#!/bin/python3

from scapy.all import AsyncSniffer, Ether, UDP
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
        self.absence_timeout = self.config['absence_timeout']

        logging.info("setting up websocket")
        self.ws = WebSocketHa(config['url']) if config.get('url') else WebSocketHa('ws://supervisor/core/websocket')
        self.ws.connect()
        self.ws.auth(self.token)

        self.cache_timeout = self.config['timeout']
        #self.filter = '(udp dst port 67 and udp[248:1] = 0x35 and udp[249:1] = 0x1 and udp[250:1] = 0x3) ' # DHCP Request
        self.filter = ' '.join([f'or (ether src {entity["mac"]})' for entity in self.entities])
        now = time.time()
        self.cache = dict(map(lambda entity: (entity['mac'], now), self.entities))
        self.pkts = list()
        self.__lock = Lock()
        self.__event = Event()
        logging.debug(f"using filter -> {self.filter}")
        self.sniffer = AsyncSniffer(filter=self.filter, prn=lambda x: self.__insert_packet(x), store=0)

    def __insert_packet(self, pkt):
        self.__lock.acquire()
        self.pkts.append(pkt)
        self.__lock.release()
        self.__event.set()

    def check_absence(self):
        now = time.time()
        for entity in self.entities:
            mac = entity['mac']
            if mac in self.cache and now - self.cache[mac] > self.absence_timeout:
                logging.info(f"entity {entity['name']} left home")
                self.see(entity['entity'], entity['name'], mac, "not_home")
                self.cache.pop(entity['mac'])

    def track(self):
        logging.info("tracker started")
        self.sniffer.start()
        last_keepalive = 0
        interval = 5
        while True:

            # keep connection alive every 5 seconds
            # check absence of tracked devices every 5 seconds
            cur_time = time.time()
            delta = cur_time - last_keepalive
            if delta > interval: 
                self.ws.ping()
                self.check_absence()
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

            # start a timer for ping
            timer = Timer(interval - delta, lambda: self.__event.set())
            timer.start()

            # wait for either timer or a packet to come
            self.__event.wait()

            # make sure timer is stopped
            timer.cancel()

            # clear the event
            self.__event.clear()

        self.sniffer.stop()

    def cache_invalid(self, mac):
        return mac not in self.cache or (time.time() - self.cache[mac]) >= self.cache_timeout

    def handle_packet(self, pkt):
        logging.info(pkt.summary())
        mac = pkt[Ether].src
        if self.should_track_mac(mac):
            if mac not in self.cache:
                self.notify(mac)
            self.cache[mac] = time.time()

    def should_track_mac(self, mac):
        return self.get_entity_by_mac(mac) is not None

    def get_entity_by_mac(self, mac):
        for entity in self.entities:
            if entity['mac'] == mac:
                return entity

    def notify(self, mac):
        logging.info(f"notifying {mac}")
        entity = self.get_entity_by_mac(mac)
        dev_id = entity['entity'].split('.')[1]
        name = entity['name']
        self.see(dev_id, name, mac, "home")

    def see(self, dev_id, name, mac, location):
        try:
            result = self.ws.call_service('device_tracker', 'see', service_data={
                    "dev_id": dev_id,
                    "mac": mac,
                    "host_name": name,
                    "location_name": location
                })

            if not result:
                logging.debug(f"device_tracker.see({dev_id}, {name}, {mac}, {location}) failed")
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
