#!/bin/python3

import requests
from scapy.all import *
import subprocess

import os

NODERED_USERNAME = ''
NODERED_PASSWORD = ''
INTERFACE = 'enp2s0f0'
HOST = 'https://localhost:1880'

tracked_macs = {
}

def notify_home_assistant(mac):

    session = requests.Session()
    session.auth = (NODERED_USERNAME, NODERED_PASSWORD)

    name = tracked_macs[mac]
    url = f'{HOST}/endpoint/arrived'
    response = session.post(url, verify=False, data={'name': name})
    print(response.text)

def handle_packet(pkt):
    sender_mac = pkt[Ether].src
    if sender_mac in tracked_macs:
        notify_home_assistant(sender_mac)

def track():
    sniff(iface=INTERFACE, filter='udp port 68 and ip src 0.0.0.0', prn=handle_packet)


def main():
    track()


if __name__ == '__main__':
    main()
