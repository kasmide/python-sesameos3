from Crypto.Cipher import AES
from Crypto.Hash import CMAC
from bleak import BleakClient

class SSMTransportHandler:
    def __init__(self, addr, priv_key, response_handler):
        self.addr = addr
        self.priv_key = priv_key
        self.ccm = None
        self.buffer = b''
        self.response_handler = response_handler
    async def connect(self):
        self.client = BleakClient(self.addr)
        await self.client.connect()
        print(f"Connected to {self.addr}")
        await self.client.start_notify("16860003-a5ae-9856-b6d3-dbb4c676993e", self.notification_handler)
    async def disconnect(self):
        if self.client.is_connected:
            await self.client.stop_notify("16860003-a5ae-9856-b6d3-dbb4c676993e")
            await self.client.disconnect()
            print(f"Disconnected from {self.addr}")
        else:
            print("Client is not connected")
    async def send_encrypted(self, item_code: int, payload: bytearray):
        print(f"Sending item code: {item_code}, payload: {payload.hex()}")
        encrypted_data = self.ccm.encrypt(item_code.to_bytes(1) + payload)
        if len(encrypted_data) < 20:
            SEG = 2
            SEG <<= 1
            SEG += 1
            await self.gatt_write(SEG.to_bytes(1, 'big') + encrypted_data)
        else:
            for i in range(0, len(encrypted_data), 19):
                chunk = encrypted_data[i:i + 19]
                SEG = 0 if i != (len(encrypted_data) - 1) // 19 * 19 else 2 # set parsing type https://raw.githubusercontent.com/CANDY-HOUSE/.github/main/profile/uml/uml_output/communication_layer.png
                SEG <<= 1
                SEG += 1 if i == 0 else 0 # is_start
                await self.gatt_write(SEG.to_bytes(1) + chunk)
    async def send_plain(self, item_code: int, payload: bytearray):
        print(f"Sending plain data: {item_code}, {payload.hex()}")
        data = item_code.to_bytes(1) + payload
        if len(data) < 20:
            SEG = 1
            SEG <<= 1
            SEG += 1
            await self.gatt_write(SEG.to_bytes(1) + data)
        else:
            for i in range(0, len(data), 19):
                chunk = data[i:i + 19]
                SEG = 0 if i != (len(data) - 1) // 19 * 19 else 1
                SEG <<= 1
                SEG += 1 if i == 0 else 0
                await self.gatt_write(SEG.to_bytes(1) + chunk)

    async def gatt_write(self, data):
        print(f"Writing data: {data.hex()}")
        await self.client.write_gatt_char("16860002-a5ae-9856-b6d3-dbb4c676993e", data)
    async def data_handler(self, data, is_encrypted=False):
        if is_encrypted:
            try:
                data = self.ccm.decrypt(data)
            except Exception as e:
                print(f"Decryption failed: {e}")
                return
        print(f"received packet: {data.hex()}")
        await self.response_handler(data, is_encrypted)

    async def notification_handler(self, _sender, data):
        print(f"recv: {data.hex()}")
        match data[0]:
            case 0:
                print("Received a middle of a split packet")
                self.buffer += data[1:]
            case 1:
                print("Received the head of a split packet")
                if len(self.buffer) > 0:
                    print(f"W: overwriting unmatured packet")
                self.buffer = data[1:]
            case 2:
                print("Received the end of a plain split packet")
                self.buffer += data[1:]
                await self.data_handler(self.buffer)
                self.buffer = b''
            case 3:
                print("Received a single plain packet")
                await self.data_handler(data[1:])
            case 4:
                print("Received the end of an encrypted split packet")
                self.buffer += data[1:]
                await self.data_handler(self.buffer, is_encrypted=True)
                self.buffer = b''
            case 5:
                print("Received a single encrypted packet")
                await self.data_handler(data[1:], is_encrypted=True)
            case _:
                print(f"Unhandled packet status: {data[0]}")
                print(f"Data: {data.hex()}")

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