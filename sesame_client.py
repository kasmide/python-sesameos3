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
        print(f"type: {data[0]}, item_code: {data[1]}, data: {data[2:].hex()}")
        if data[1] in self.response_listener:
            for entry in self.response_listener[data[1]]:
                callback, is_oneoff = entry
                callback(data, metadata={is_encrypted: is_encrypted})
                if is_oneoff:
                    self.response_listener[data[1]].remove(entry)
        match data[1]:
            case 2:
                print("login response")
                timestamp = data[3:7]
                print(f"Timestamp: {int.from_bytes(timestamp, "little")}")
            case 4:
                print("history response")
                if data[2] == 0:
                    id = int.from_bytes(data[3:7], "little")
                    type = data[7]
                    timestamp = int.from_bytes(data[8:12], "little")
                    mechstatus = data[12:19]
                    ss5_len = data[19]
                    ss5 = data[19:]
                    print(f"ID: {id}, Type: {type}, Timestamp: {timestamp}, "
                          f"MechStatus: {mechstatus.hex()}, SS5_Len: {ss5_len}, SS5: {ss5}, actual length: {len(data[19:])}")
                elif data[2] == 5:
                    print("history is empty")
            case 5:
                print("version details")
                version = data[3:15]
                print(f"Version: {version}")
            case 14:
                print("initial response")
                random_code = data[2:6]
                print(f"Random Code: {random_code.hex()}")
            case 80:
                print("mechsettings")
                if data[0] == 8:
                    lock = int.from_bytes(data[2:4], "little")
                    lock = lock if lock < 2 ** 15 else lock - 2 ** 16
                    unlock = int.from_bytes(data[4:6], "little")
                    unlock = unlock if unlock < 2 ** 15 else unlock - 2 ** 16
                    auto_lock_second = int.from_bytes(data[6:8], "little")
                    print(f"Lock: {lock}, Unlock: {unlock}, Auto Lock Seconds: {auto_lock_second}")
                else:
                    print(f"Unknown mechsettings data type but at least we received {data.hex()}")
            case 81:
                print("mechstatus")
                battery = int.from_bytes(data[2:4], "little")
                target = int.from_bytes(data[4:6], "little")
                target = target if target < 2 ** 15 else target - 2 ** 16
                position = int.from_bytes(data[6:8], "little")
                position = position if position < 2 ** 15 else position - 2 ** 16
                is_clutch_failed = (data[8] >> 0) & 1
                is_lock_range = (data[8] >> 1) & 1
                is_unlock_range = (data[8] >> 2) & 1
                is_critical = (data[8] >> 3) & 1
                is_stop = (data[8] >> 4) & 1
                is_low_battery = (data[8] >> 5) & 1
                is_clockwise = (data[8] >> 6) & 1
                print(f"Battery: {battery}mV, Target: {target}, Position: {position}, "
                      f"Clutch Failed: {is_clutch_failed}, Lock Range: {is_lock_range}, "
                      f"Unlock Range: {is_unlock_range}, Critical: {is_critical}, "
                      f"Stop: {is_stop}, Low Battery: {is_low_battery}, Clockwise: {is_clockwise}")
            case 82:
                print("lock response")
                if data[2] == 0:
                    print("Lock successful")
                else:
                    print(f"Unknown response: {data[2]}")
            case 83:
                print("unlock response")
                if data[2] == 0:
                    print("Unlock successful")
                else:
                    print(f"Unknown response: {data[2]}")
            case 92:
                print("OpenSensor autolock time")
                time = int.from_bytes(data[2:4], "little")
                print(f"Auto lock time: {time}")
            case _:
                print(f"Unhandled response item code: {data[1]}")
