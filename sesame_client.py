import asyncio
from typing import Optional
from Crypto.Cipher import AES
from Crypto.Hash import CMAC

from sesame_transport import SSMTransportHandler, CCMAgent
class SesameClient:
    def __init__(self, sesame_addr, priv_key):
        self.txrx = SSMTransportHandler(sesame_addr, priv_key, self.response_handler)
        self.response_listener: dict = {}
    async def connect(self):
        waiter = self.wait_for_response(14)
        await self.txrx.connect()
        initial, _ = await waiter
        await self._login(initial)

    async def _login(self, data):
        cobj = CMAC.new(self.txrx.priv_key, ciphermod=AES)
        print(f"Login data: {data[2:].hex()}, data length: {len(data)}")
        cobj.update(data[2:])
        cmac_result = cobj.digest()
        token = cmac_result[:16]
        self.txrx.ccm = CCMAgent(data[2:6], token=token)
        await self.send_and_wait(2, token[:4], encrypted=False)

    async def send_and_wait(self, item_code, data, encrypted: bool, response_code: Optional[int] = None):
        waiter = self.wait_for_response(response_code if response_code is not None else item_code)
        if encrypted:
            await self.txrx.send_encrypted(item_code, data)
        else:
            await self.txrx.send_plain(item_code, data)
        result, metadata = await waiter
        return result, metadata
    
    def wait_for_response(self, item_code: int):
        loop = asyncio.get_running_loop()
        f = loop.create_future()
        def callback(result, metadata):
            loop.call_soon_threadsafe(f.set_result, (result, metadata))
        self.add_listener(item_code, callback, oneoff=True)
        return f

    def add_listener(self, item_code, callback, oneoff=False):
        if item_code not in self.response_listener:
            self.response_listener[item_code] = []
        self.response_listener[item_code].append((callback, oneoff))
    
    def remove_listener(self, item_code, callback):
        if item_code in self.response_listener and callback in self.response_listener[item_code]:
            for entry in self.response_listener[item_code]:
                if entry[0] == callback:
                    self.response_listener[item_code].remove(entry)

    async def response_handler(self, data, is_encrypted=False):
        print(f"item_code: {data[1]}, data: {data[2:].hex()}")
        if data[1] in self.response_listener:
            for entry in self.response_listener[data[1]]:
                callback, is_oneoff = entry
                callback(data, metadata={is_encrypted: is_encrypted})
                if is_oneoff:
                    self.response_listener[data[1]].remove(entry)