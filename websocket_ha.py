
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
    """
    this class is not thread safe
    """

    # arbitrary maximum value for ID.
    # reset connection if we reach that number
    ID_THRESHOLD = 65 * 1024

    def __init__(self, url):
        self.url = url
        self.ws = None
        self._id = 1
        self._token = None

    @classmethod
    def ensure(self, func):
        """
        in case supervisor goes offline, we want to ensure that the connection retries reconnecting the supervisor.
        """
        def wrapper(self, *args):
            max_retries = 30
            retry = 0
            while retry < max_retries:
                try:
                    return func(self, *args)
                except:
                    retry += 1
                    self.__resetup_connection()
                    time.sleep(5)

        return wrapper

    def __resetup_connection(self):
        self._id = 1
        self.close()
        self.connect()
        self.auth(self._token)

    @WebSocketHa.ensure
    def recv(self):
        data = self.ws.recv()
        if not data:
            logging.error("data is None")
            raise WebSocketTimedOut

        res = json.loads(data)
        logging.debug(res)
        return res

    @WebSocketHa.ensure
    def send(self, data: dict, with_id=True):
        if with_id:

            if self._id >= WebSocketHa.ID_THRESHOLD:
                logging.info(f"id reached threshold ({WebSocketHa.ID_THRESHOLD}). resetting.")
                self.__resetup_connection()

            data['id'] = self._id
            self._id += 1

        logging.debug(data)
        self.ws.send(json.dumps(data))

    def connect(self):
        logging.info("Connecting")
        self.ws = websocket.create_connection(self.url)

    def close(self):
        self.ws.close()

    def auth(self, token):
        logging.info("Authenticating")
        self._token = token
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


def test():
    logging.getLogger().setLevel(logging.DEBUG)
    ws = WebSocketHa('ws://supervisor/core/websocket')
    ws.connect()
    ws.auth("")    
    ws.keepalive()
    ws.close()

if __name__ == '__main__':
    test()