from abc import ABC, abstractmethod
import asyncio
import inspect
import logging
from datetime import datetime
from typing import Callable, Generic, Optional, Self, Type, TypeVar, Union, Awaitable
from uuid import UUID
from Crypto.Cipher import AES
from Crypto.Hash import CMAC

from .sesame_transport import SSMTransportHandler, CCMAgent

logger = logging.getLogger(__name__)

class EventData:
    class HistoryData:
        class HistoryType:
            NONE = 0
            BLE_LOCK = 1
            BLE_UNLOCK = 2
            TIME_CHANGED = 3
            AUTOLOCK_UPDATED = 4
            MECH_SETTING_UPDATED = 5
            AUTOLOCK = 6
            MANUAL_LOCKED = 7
            MANUAL_UNLOCKED = 8
            MANUAL_ELSE = 9
            DRIVE_LOCKED = 10
            DRIVE_UNLOCKED = 11
            DRIVE_FAILED = 12
            BLE_ADV_PARAM_UPDATED = 13
            WM2_LOCK = 14
            WM2_UNLOCK = 15
            WEB_LOCK = 16
            WEB_UNLOCK = 17
        id: int
        type: int
        timestamp: datetime
        mech_status: 'EventData.MechStatus'
        ss5: bytes
        def __init__(self, id, type, timestamp, mech_status, ss5):
            self.id = id
            self.type = type # 0 autolock, 2 bluetooth
            self.timestamp = timestamp
            self.mech_status = mech_status
            self.ss5 = ss5
        @classmethod
        def from_bytes(cls, data: bytes):
            id = int.from_bytes(data[1:5], "little")
            type = data[5]
            timestamp = datetime.fromtimestamp(int.from_bytes(data[6:10], "little"))
            mechstatus = EventData.MechStatus.from_bytes(data[10:17])
            ss5 = data[17:]
            return cls(id, type, timestamp, mechstatus, ss5)
    class MechStatus:
        battery: int
        target: int
        position: int
        clutch_failed: bool
        lock_range: bool
        unlock_range: bool
        critical: bool
        stop: bool
        low_battery: bool
        clockwise: bool
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
            is_clutch_failed = (data[6] >> 0) & 1 == 1
            is_lock_range = (data[6] >> 1) & 1 == 1
            is_unlock_range = (data[6] >> 2) & 1 == 1
            is_critical = (data[6] >> 3) & 1 == 1
            is_stop = (data[6] >> 4) & 1 == 1
            is_low_battery = (data[6] >> 5) & 1 == 1
            is_clockwise = (data[6] >> 6) & 1 == 1
            logger.debug(f"Battery: {battery}, Target: {target}, Position: {position}, is_clutch_failed: {is_clutch_failed}, "
                  f"is_lock_range: {is_lock_range}, is_unlock_range: {is_unlock_range}, is_critical: {is_critical}, "
                  f"is_stop: {is_stop}, is_low_battery: {is_low_battery}, is_clockwise: {is_clockwise}")
            return cls(battery, target, position, is_clutch_failed, is_lock_range,
                       is_unlock_range, is_critical, is_stop, is_low_battery, is_clockwise)
    class MechSettings:
        lock: int
        unlock: int
        auto_lock_seconds: int
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
            logger.debug(f"Lock: {lock}, Unlock: {unlock}, Auto Lock Seconds: {auto_lock_seconds}")
            return cls(lock, unlock, auto_lock_seconds)

        def to_bytes(self):
            lock_bytes = self.lock.to_bytes(2, "little", signed=True)
            unlock_bytes = self.unlock.to_bytes(2, "little", signed=True)
            auto_lock_seconds_bytes = self.auto_lock_seconds.to_bytes(2, "little")
            return lock_bytes + unlock_bytes + auto_lock_seconds_bytes


T = TypeVar("T")
EventTypeT = TypeVar("EventTypeT", bound="EventType")
class EventType(ABC, Generic[T]):
    response: T
    item_code: int
    @classmethod
    @abstractmethod
    def from_bytes(cls, data: bytes) -> Self:
        """Create an instance of the event type from raw bytes."""
        pass

class Event:
    class LoginEvent(EventType[datetime]):
        item_code = 2
        def __init__(self, timestamp: datetime):
            self.response = timestamp
        @classmethod
        def from_bytes(cls, data):
            unixtime = int.from_bytes(data[2:6], "little")
            return cls(datetime.fromtimestamp(unixtime))
    class HistoryEvent(EventType[Optional[EventData.HistoryData]]):
        item_code = 4
        def __init__(self, history_data: Optional[EventData.HistoryData]):
            self.response = history_data
        @classmethod
        def from_bytes(cls, data):
            if data[2] == 0:
                return cls(EventData.HistoryData.from_bytes(data[2:]))
            else:
                return cls(None)
    class InitializeEvent(EventType[bytes]):
        item_code = 14
        def __init__(self, random_data: bytes):
            self.response = random_data
        @classmethod
        def from_bytes(cls, data):
            return cls(data[2:6])
    class MechSettingsEvent(EventType[EventData.MechSettings]):
        item_code = 80
        def __init__(self, mech_settings: EventData.MechSettings):
            self.response = mech_settings
        @classmethod
        def from_bytes(cls, data):
            return cls(EventData.MechSettings.from_bytes(data[2:]))
    class MechStatusEvent(EventType[EventData.MechStatus]):
        item_code = 81
        def __init__(self, mech_status: EventData.MechStatus):
            self.response = mech_status
        @classmethod
        def from_bytes(cls, data):
            return cls(EventData.MechStatus.from_bytes(data[2:9]))
    class LockEvent(EventType[None]):
        item_code = 82
        def __init__(self):
            self.response = None
        @classmethod
        def from_bytes(cls, data):
            return cls()
    class UnlockEvent(EventType[None]):
        item_code = 83
        def __init__(self):
            self.response = None
        @classmethod
        def from_bytes(cls, data):
            return cls()
    class OpenSensorAutoLockTimeEvent(EventType[int]):
        item_code = 92
        def __init__(self, auto_lock_time: int):
            self.response = auto_lock_time
        @classmethod
        def from_bytes(cls, data):
            return cls(int.from_bytes(data[2:4], "little"))

class SesameClient:
    def __init__(self, sesame_addr, priv_key):
        self.txrx = SSMTransportHandler(sesame_addr, self._response_handler)
        self.response_listener: dict = {}
        self.priv_key = priv_key
        self.mech_status = None
        self.mech_settings = None

    def __del__(self):
        if self.txrx.client.is_connected:
            asyncio.run(self.txrx.disconnect())
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

    async def wait_for(self, event_type: Type[EventTypeT], timeout: int = 5) -> EventTypeT:
        item_code = event_type.item_code
        waiter = self._wait_for_response(item_code)
        result = await asyncio.wait_for(waiter, timeout)
        return event_type.from_bytes(result[0])

    async def lock(self, display_name: str):
        display_name_bytes = display_name.encode('utf-8')[:32]
        display_name_len = len(display_name_bytes).to_bytes(1, "little")
        try:
            await asyncio.wait_for(self._send_and_wait(82, display_name_len + display_name_bytes, encrypted=True), timeout=5)
        except asyncio.TimeoutError:
            raise TimeoutError("Lock command timed out.")

    async def unlock(self, display_name: str):
        display_name_bytes = display_name.encode('utf-8')[:32]
        display_name_len = len(display_name_bytes).to_bytes(1, "little")
        try:
            await asyncio.wait_for(self._send_and_wait(83, display_name_len + display_name_bytes, encrypted=True), timeout=5)
        except asyncio.TimeoutError:
            raise TimeoutError("Unlock command timed out.")

    async def set_autolock_time(self, seconds: int):
        data = seconds.to_bytes(2, "little")
        await asyncio.wait_for(self._send_and_wait(11, data, encrypted=True), timeout=5)

    async def set_mech_settings(self, config: EventData.MechSettings):
        await asyncio.wait_for(self._send_and_wait(80, config.to_bytes(), encrypted=True), timeout=5)

    async def get_version(self) -> str:
        result, metadata = await asyncio.wait_for(self._send_and_wait(5, b'', encrypted=True), timeout=5)
        return result[3:15].decode('utf-8')

    async def get_history_head(self) -> Event.HistoryEvent:
        result, metadata = await asyncio.wait_for(self._send_and_wait(4, b'\x01', encrypted=True), timeout=5)
        return Event.HistoryEvent.from_bytes(result)

    async def get_history_tail(self) -> Event.HistoryEvent:
        result, metadata = await asyncio.wait_for(self._send_and_wait(4, b'\x00', encrypted=True), timeout=5)
        return Event.HistoryEvent.from_bytes(result)

    async def delete_history(self, history_id: int):
        data = history_id.to_bytes(4, 'little')
        result, metadata = await asyncio.wait_for(self._send_and_wait(18, data, encrypted=True, response_code=18), timeout=5)
        if result[2] != 0:
            raise ValueError(f"Failed to delete history with ID {history_id}, response code: {result[2]}")
        logger.info(f"History with ID {history_id} deleted successfully.")

    def add_listener(self, event_type: Type[EventTypeT], callback: Union[Callable[[EventTypeT, dict], None], Callable[[EventTypeT, dict], Awaitable[None]]]):
        self._add_listener(event_type.item_code, callback, deserialize=event_type)

    def remove_listener(self, event_type: Type[EventTypeT], callback: Union[Callable[[EventTypeT, dict], None], Callable[[EventTypeT, dict], Awaitable[None]]]):
        self._remove_listener(event_type.item_code, callback)

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
        self._add_listener(item_code, callback, oneoff=True)
        return f

    def _add_listener(self, item_code, callback, oneoff=False, deserialize=None):
        if item_code not in self.response_listener:
            self.response_listener[item_code] = []
        self.response_listener[item_code].append((callback, oneoff, deserialize))
    
    def _remove_listener(self, item_code, callback):
        if item_code in self.response_listener and callback in self.response_listener[item_code]:
            for entry in self.response_listener[item_code]:
                if entry[0] == callback:
                    self.response_listener[item_code].remove(entry)

    async def _response_handler(self, data, is_encrypted=False):
        logger.debug(f"type: {data[0]}, item_code: {data[1]}, data: {data[2:].hex()}")
        if data[1] in self.response_listener:
            deserialize_result = None
            for entry in self.response_listener[data[1]]:
                callback, is_oneoff, deserialize = entry
                if deserialize is not None:
                    if deserialize_result is None:
                        deserialize_result = deserialize.from_bytes(data)
                    result = deserialize_result
                else:
                    result = data
                if inspect.iscoroutinefunction(callback):
                    await callback(result, metadata={'is_encrypted': is_encrypted})
                else:
                    callback(result, metadata={'is_encrypted': is_encrypted})
                    
                if is_oneoff:
                    self.response_listener[data[1]].remove(entry)
        match data[1]:
            case 2:
                logger.debug("login response")
                timestamp = data[3:7]
                logger.debug(f"Timestamp: {int.from_bytes(timestamp, 'little')}")
            case 4:
                logger.debug("history response")
                if data[2] == 0:
                    EventData.HistoryData.from_bytes(data[2:])
                elif data[2] == 5:
                    logger.debug("history is empty")
            case 5:
                logger.debug("version details")
                version = data[3:15]
                logger.debug(f"Version: {version}")
            case 14:
                logger.debug("initial response")
                random_code = data[2:6]
                logger.debug(f"Random Code: {random_code.hex()}")
            case 80:
                logger.debug("mechsettings")
                if data[0] == 8:
                    self.mech_settings = EventData.MechSettings.from_bytes(data[2:])
                elif data[0] == 7:
                    logger.info("mechsettings set successfully")
            case 81:
                logger.debug("mechstatus")
                self.mech_status = EventData.MechStatus.from_bytes(data[2:9])
            case 82:
                logger.debug("lock response")
                if data[2] == 0:
                    logger.info("Lock successful")
                else:
                    logger.warning(f"Unknown response: {data[2]}")
            case 83:
                logger.debug("unlock response")
                if data[2] == 0:
                    logger.info("Unlock successful")
                else:
                    logger.warning(f"Unknown response: {data[2]}")
            case 92:
                logger.debug("OpenSensor autolock time")
                time = int.from_bytes(data[2:4], "little")
                logger.debug(f"Auto lock time: {time}")
            case _:
                logger.warning(f"Unhandled response item code: {data[1]}")
