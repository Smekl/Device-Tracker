
import asyncio
import asyncws
import json
import sys

import logging

from threading import Thread

class WebSocketTimedOut(Exception):
    pass

class AuthenticationFailed(Exception):
    pass

class WebSocketHa(object):

    def __init__(self, url):
        self.url = url
        self.ws = None
        self._id = 1
        self._stop_keepalive = False

    async def recv(self):
        data = await self.ws.recv()
        if data is None:
            logging.error("data is None")
            raise WebSocketTimedOut

        res = json.loads(data)
        logging.debug(res)
        return res

    async def send(self, data: dict, with_id=True):
        if with_id:
            data['id'] = self._id
            self._id += 1

        logging.debug(data)
        await self.ws.send(json.dumps(data))

    async def connect(self):
        logging.info("Connecting")
        self.ws = await asyncws.connect(self.url)

    async def close(self):
        await self.ws.close()
        self._stop_keepalive = True

    async def auth(self, token):
        logging.info("Authenticating")
        data = await self.recv()
        assert data['type'] == 'auth_required'

        await self.send({
                'type': 'auth',
                'access_token': token
            }, with_id=False)

        data = await self.recv()
        if data['type'] != 'auth_ok':
            raise AuthenticationFailed

        return True

    async def call_service(self, domain: str, service: str, service_data=None, target=None):
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

        await self.send(data)

        result = await self.recv()
        assert result['id'] == data['id']
        return result['success']

    async def ping(self):
        await self.send({
                'type': 'ping'
            })

        resp = await self.recv()
        if resp is not None and resp['type'] == 'pong':
            return True

        return False

    async def keepalive(self):
        while not self._stop_keepalive:
            if not await self.ping():
                logging.error("connection timed out. need to reconnect.")
            else:
                logging.info("keepalive OK")

            await asyncio.sleep(5)


async def test():
    logging.getLogger().setLevel(logging.DEBUG)
    ws = WebSocketHa('ws://supervisor/core/websocket')
    await ws.connect()
    await ws.auth("")    
    ws.keepalive_forever()
    await asyncio.sleep(20)

if __name__ == '__main__':
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(test())