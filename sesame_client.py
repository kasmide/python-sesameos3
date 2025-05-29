import asyncio
from typing import Optional
from Crypto.Cipher import AES
from Crypto.Hash import CMAC

from sesame_transport import SSMTransportHandler, CCMAgent
class SesameClient:
    class MechStatus:
        def __init__(self, battery, target, position, clutch_failed, lock_range,
                     unlock_range, critical, stop, low_battery, clockwise):
            self.battery = battery
            self.target = target
            self.position = position
            self.clutch_failed = clutch_failed
            self.lock_range = lock_range
            self.unlock_range = unlock_range
            self.critical = critical
            self.stop = stop
            self.low_battery = low_battery
            self.clockwise = clockwise
        @classmethod
        def from_bytes(cls, data: bytes):
            battery = int.from_bytes(data[0:2], "little")
            target = int.from_bytes(data[2:4], "little")
            target = target if target < 2 ** 15 else target - 2 ** 16
            position = int.from_bytes(data[4:6], "little")
            position = position if position < 2 ** 15 else position - 2 ** 16
            is_clutch_failed = (data[6] >> 0) & 1
            is_lock_range = (data[6] >> 1) & 1
            is_unlock_range = (data[6] >> 2) & 1
            is_critical = (data[6] >> 3) & 1
            is_stop = (data[6] >> 4) & 1
            is_low_battery = (data[6] >> 5) & 1
            is_clockwise = (data[6] >> 6) & 1
            print(f"Battery: {battery}, Target: {target}, Position: {position}, is_clutch_failed: {is_clutch_failed}, "
                  f"is_lock_range: {is_lock_range}, is_unlock_range: {is_unlock_range}, is_critical: {is_critical}, "
                  f"is_stop: {is_stop}, is_low_battery: {is_low_battery}, is_clockwise: {is_clockwise}")
            return cls(battery, target, position, is_clutch_failed, is_lock_range,
                       is_unlock_range, is_critical, is_stop, is_low_battery, is_clockwise)
    class MechSettings:
        def __init__(self, lock, unlock, auto_lock_seconds):
            self.lock = lock
            self.unlock = unlock
            self.auto_lock_seconds = auto_lock_seconds
        @classmethod
        def from_bytes(cls, data: bytes):
            lock = int.from_bytes(data[0:2], "little")
            lock = lock if lock < 2 ** 15 else lock - 2 ** 16
            unlock = int.from_bytes(data[2:4], "little")
            unlock = unlock if unlock < 2 ** 15 else unlock - 2 ** 16
            auto_lock_seconds = int.from_bytes(data[4:6], "little")
            print(f"Lock: {lock}, Unlock: {unlock}, Auto Lock Seconds: {auto_lock_seconds}")
            return cls(lock, unlock, auto_lock_seconds)

    def __init__(self, sesame_addr, priv_key):
        self.txrx = SSMTransportHandler(sesame_addr, self._response_handler)
        self.response_listener: dict = {}
        self.priv_key = priv_key
        self.mech_status = None
        self.mech_settings = None
    async def connect(self):
        waiter = self._wait_for_response(14)
        await self.txrx.connect()
        initial, _ = await waiter
        await self._login(initial)

    async def disconnect(self):
        await self.txrx.disconnect()

    async def _login(self, data):
        cobj = CMAC.new(self.priv_key, ciphermod=AES)
        cobj.update(data[2:])
        cmac_result = cobj.digest()
        token = cmac_result[:16]
        self.txrx.ccm = CCMAgent(data[2:6], token=token)
        await self._send_and_wait(2, token[:4], encrypted=False)

    async def lock(self, display_name: str):
        display_name = display_name.encode('utf-8')[:32]
        display_name_len = len(display_name).to_bytes(1, "little")
        try:
            await asyncio.wait_for(self._send_and_wait(82, display_name_len + display_name, encrypted=True), timeout=2)
        except asyncio.TimeoutError:
            raise TimeoutError("Lock command timed out.")

    async def unlock(self, display_name: str):
        display_name = display_name.encode('utf-8')[:32]
        display_name_len = len(display_name).to_bytes(1, "little")
        try:
            await asyncio.wait_for(self._send_and_wait(83, display_name_len + display_name, encrypted=True), timeout=2)
        except asyncio.TimeoutError:
            raise TimeoutError("Unlock command timed out.")

    async def _send(self, item_code, payload, encrypted: bool):
        data = item_code.to_bytes(1) + payload
        await self.txrx.send(data, encrypted=encrypted)

    async def _send_and_wait(self, item_code, data, encrypted: bool, response_code: Optional[int] = None):
        waiter = self._wait_for_response(response_code if response_code is not None else item_code)
        await self._send(item_code, data, encrypted=encrypted)
        result, metadata = await waiter
        return result, metadata

    def _wait_for_response(self, item_code: int):
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

    async def _response_handler(self, data, is_encrypted=False):
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
                    print(f"ID: {id}, Type: {type}, Timestamp: {timestamp}, "
                              f"MechStatus: {self.MechStatus.from_bytes(mechstatus)}")
                    if len(data) > 19:
                        ss5_len = data[19]
                        ss5 = data[20:20 + ss5_len]
                        print(f"SS5_Len: {ss5_len}, SS5: {ss5.decode("utf-8")}, Left: {data[20 + ss5_len:].hex()}")
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
                    self.mech_settings = self.MechSettings.from_bytes(data[2:])
                else:
                    print(f"Unknown mechsettings data type but at least we received {data.hex()}")
            case 81:
                print("mechstatus")
                self.mech_status = self.MechStatus.from_bytes(data[2:9])
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
