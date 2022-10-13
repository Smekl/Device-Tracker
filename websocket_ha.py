
import sys
import time
import json
import logging
import websocket

class WebSocketTimedOut(Exception):
    pass

class AuthenticationFailed(Exception):
    pass

class BadProtocol(Exception):
    pass

class WebSocketHa(object):

    def __init__(self, url):
        self.url = url
        self.ws = None
        self._id = 1
        self._stop_keepalive = False

    def recv(self):
        data = self.ws.recv()
        if not data:
            logging.error("data is None")
            raise WebSocketTimedOut

        res = json.loads(data)
        logging.debug(res)
        return res

    def send(self, data: dict, with_id=True):
        if with_id:
            data['id'] = self._id
            self._id += 1

        logging.debug(data)
        self.ws.send(json.dumps(data))

    def connect(self):
        logging.info("Connecting")
        self.ws = websocket.create_connection(self.url)

    def close(self):
        self.ws.close()
        self._stop_keepalive = True

    def auth(self, token):
        logging.info("Authenticating")
        data = self.recv()
        if data['type'] != 'auth_required':
            raise BadProtocol('expected auth_required')

        self.send({
                'type': 'auth',
                'access_token': token
            }, with_id=False)

        data = self.recv()
        if data['type'] != 'auth_ok':
            raise AuthenticationFailed

        return True

    def call_service(self, domain: str, service: str, service_data=None, target=None):
        data = {
            'type': 'call_service',
            'domain': domain,
            'service': service,
            }

        if service_data is not None:
            data['service_data'] = service_data

        if target is not None:
            data['target'] = {
                'entity_id': target
            }

        self.send(data)

        result = self.recv()
        if result['id'] != data['id']:
            raise BadProtocol(f'expected id: {data["id"]} but got id: {result["id"]}')

        return result['success']

    def ping(self):
        self.send({
                'type': 'ping'
            })

        resp = self.recv()
        if resp is not None and resp['type'] == 'pong':
            return True

        return False

    def keepalive(self):
        while not self._stop_keepalive:
            if not self.ping():
                logging.error("connection timed out. need to reconnect.")
            else:
                logging.info("keepalive OK")

            time.sleep(5)


def test():
    logging.getLogger().setLevel(logging.DEBUG)
    ws = WebSocketHa('ws://supervisor/core/websocket')
    ws.connect()
    ws.auth("")    
    ws.keepalive()
    ws.close()

if __name__ == '__main__':
    test()