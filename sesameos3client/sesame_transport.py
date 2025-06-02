from typing import Optional
from Crypto.Cipher import AES
from bleak import BleakClient
import logging

logger = logging.getLogger(__name__)

class CCMAgent:
    def __init__(self, random_code, token):
        self.random_code = random_code
        self.token = token
        self.recv_count = 0
        self.send_count = 0
        self.nouse = 0
    def create_iv(self, count):
        count_bytes = count.to_bytes(8, 'little')
        nouse_bytes = self.nouse.to_bytes(1, 'little')
        return count_bytes + nouse_bytes + self.random_code
    def encrypt(self, data, tag_length=4):
        iv = self.create_iv(self.send_count)
        self.send_count += 1
        cipher = AES.new(self.token, AES.MODE_CCM, nonce=iv, mac_len=tag_length)
        additional_data = b'\x00'
        cipher.update(additional_data)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return ciphertext + tag
    def decrypt(self, data, tag_length=4):
        iv = self.create_iv(self.recv_count)
        self.recv_count += 1
        cipher = AES.new(self.token, AES.MODE_CCM, nonce=iv, mac_len=tag_length)
        additional_data = b'\x00'
        cipher.update(additional_data)
        ciphertext = data[:-tag_length]
        tag = data[-tag_length:]
        return cipher.decrypt_and_verify(ciphertext, tag)
class SSMTransportHandler:
    addr: str
    ccm: Optional[CCMAgent]
    def __init__(self, addr, response_handler):
        self.addr = addr
        self.ccm = None
        self.buffer = b''
        self.response_handler = response_handler
    async def connect(self):
        self.client = BleakClient(self.addr, timeout = 30)
        await self.client.connect()
        logger.info(f"Connected to {self.addr}")
        await self.client.start_notify("16860003-a5ae-9856-b6d3-dbb4c676993e", self.notification_handler)
    async def disconnect(self):
        if self.client.is_connected:
            await self.client.stop_notify("16860003-a5ae-9856-b6d3-dbb4c676993e")
            await self.client.disconnect()
            logger.info(f"Disconnected from {self.addr}")
        else:
            logger.warning("Client is not connected")

    async def send(self, data: bytes, encrypted: bool):
        if encrypted:
            if self.ccm is None:
                raise RuntimeError("CCM agent is not initialized")
            data = self.ccm.encrypt(data)
        for i in range(0, len(data), 19):
            chunk = data[i:i + 19]
            if i != (len(data) - 1) // 19 * 19:
                parsing_type = 0
            else:
                if encrypted:
                    parsing_type = 2
                else:
                    parsing_type = 1
            SEG = parsing_type << 1
            SEG += 1 if i == 0 else 0
            await self.gatt_write(SEG.to_bytes(1) + chunk)

    async def gatt_write(self, data):
        logger.debug(f"Writing data: {data.hex()}")
        await self.client.write_gatt_char("16860002-a5ae-9856-b6d3-dbb4c676993e", data)
    async def data_handler(self, data, is_encrypted=False):
        if is_encrypted:
            if self.ccm is None:
                raise RuntimeError("CCM agent is not initialized")
            data = self.ccm.decrypt(data)
        elif self.ccm is not None:
            return
        await self.response_handler(data, is_encrypted)

    async def notification_handler(self, _sender, data):
        match data[0]:
            case 0:
                self.buffer += data[1:]
            case 1:
                if len(self.buffer) > 0:
                    logger.warning(f"Overwriting incomplete packet")
                self.buffer = data[1:]
            case 2:
                self.buffer += data[1:]
                await self.data_handler(self.buffer)
                self.buffer = b''
            case 3:
                await self.data_handler(data[1:])
            case 4:
                self.buffer += data[1:]
                await self.data_handler(self.buffer, is_encrypted=True)
                self.buffer = b''
            case 5:
                await self.data_handler(data[1:], is_encrypted=True)
            case _:
                logger.warning(f"Unhandled packet status: {data[0]}")
                logger.warning(f"Data: {data.hex()}")
