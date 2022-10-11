
import asyncio
import asyncws
import json
import sys

import logging

class WebSocketHa(object):

    def __init__(self, url):
        self.url = url
        self.ws = None
        self._id = 1

    async def recv(self):
        data = await self.ws.recv()
        res = json.loads(data)
        logging.debug(res)
        return res

    async def send(self, data: dict):
        logging.debug(data)
        await self.ws.send(json.dumps(data))

    async def connect(self):
        logging.info("Connecting..")
        self.ws = await asyncws.connect(self.url)
        logging.info("Connected")

    async def close(self):
        await self.ws.close()

    async def auth(self, token):
        logging.info("Authenticating")
        data = await self.recv()
        assert data['type'] == 'auth_required'

        await self.send({
                'type': 'auth',
                'access_token': token
            })

        data = await self.recv()
        assert data['type'] == 'auth_ok'
        return True

    async def call_service(self, domain: str, service: str, service_data=None, target=None):
        data = {
            'id': self._id,
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
        self._id += 1

        result = await self.recv()
        assert result['id'] == data['id']
        return result['success']


async def test():
    ws = WebSocketHa('ws://supervisor/core/websocket')
    await ws.connect()
    await ws.auth("")
    await ws.call_service('light', 'turn_on', target='light.living_room')
    await ws.close()

if __name__ == '__main__':
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(test())