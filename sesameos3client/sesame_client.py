from abc import ABC, abstractmethod
import asyncio
import inspect
import logging
import struct
from dataclasses import dataclass
from datetime import datetime
from typing import Callable, ClassVar, Generic, Optional, Self, Type, TypeVar, Union, Awaitable
from Crypto.Cipher import AES
from Crypto.Hash import CMAC

from .sesame_transport import SSMTransportHandler, CCMAgent

logger = logging.getLogger(__name__)

class EventData:
    @dataclass
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
        
        @classmethod
        def from_bytes(cls, data: bytes):
            id, type, timestamp_int = struct.unpack('<xIBI', data[1:10])
            timestamp = datetime.fromtimestamp(timestamp_int)
            mechstatus = EventData.MechStatus.from_bytes(data[10:17])
            ss5 = data[17:]
            return cls(id, type, timestamp, mechstatus, ss5)
    @dataclass
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
        
        @classmethod
        def from_bytes(cls, data: bytes):
            battery, target, position, flags = struct.unpack('<HhhB', data[0:7])
            is_clutch_failed = (flags >> 0) & 1 == 1
            is_lock_range = (flags >> 1) & 1 == 1
            is_unlock_range = (flags >> 2) & 1 == 1
            is_critical = (flags >> 3) & 1 == 1
            is_stop = (flags >> 4) & 1 == 1
            is_low_battery = (flags >> 5) & 1 == 1
            is_clockwise = (flags >> 6) & 1 == 1
            logger.debug(f"Battery: {battery}, Target: {target}, Position: {position}, is_clutch_failed: {is_clutch_failed}, "
                  f"is_lock_range: {is_lock_range}, is_unlock_range: {is_unlock_range}, is_critical: {is_critical}, "
                  f"is_stop: {is_stop}, is_low_battery: {is_low_battery}, is_clockwise: {is_clockwise}")
            return cls(battery, target, position, is_clutch_failed, is_lock_range,
                       is_unlock_range, is_critical, is_stop, is_low_battery, is_clockwise)
    @dataclass
    class MechSettings:
        lock: int
        unlock: int
        auto_lock_seconds: int
        
        @classmethod
        def from_bytes(cls, data: bytes):
            lock, unlock, auto_lock_seconds = struct.unpack('<hhH', data[0:6])
            logger.debug(f"Lock: {lock}, Unlock: {unlock}, Auto Lock Seconds: {auto_lock_seconds}")
            return cls(lock, unlock, auto_lock_seconds)


T = TypeVar("T")
EventTypeT = TypeVar("EventTypeT", bound="EventType")

@dataclass
class EventType(ABC, Generic[T]):
    response: T
    item_code: ClassVar[int]
    
    @classmethod
    @abstractmethod
    def from_bytes(cls, data: bytes) -> Self:
        """Create an instance of the event type from raw bytes."""
        pass

class Event:
    class LoginEvent(EventType[datetime]):
        item_code = 2
        
        @classmethod
        def from_bytes(cls, data):
            unixtime = struct.unpack('<xxI', data[2:6])[0]
            return cls(datetime.fromtimestamp(unixtime))
    class HistoryEvent(EventType[Optional[EventData.HistoryData]]):
        item_code = 4
        
        @classmethod
        def from_bytes(cls, data):
            if data[2] == 0:
                return cls(EventData.HistoryData.from_bytes(data[2:]))
            else:
                return cls(None)
    class InitializeEvent(EventType[bytes]):
        item_code = 14
        
        @classmethod
        def from_bytes(cls, data):
            return cls(data[2:6])

    class MechSettingsEvent(EventType[EventData.MechSettings]):
        item_code = 80
        
        @classmethod
        def from_bytes(cls, data):
            return cls(EventData.MechSettings.from_bytes(data[2:]))

    class MechStatusEvent(EventType[EventData.MechStatus]):
        item_code = 81
        
        @classmethod
        def from_bytes(cls, data):
            return cls(EventData.MechStatus.from_bytes(data[2:9]))

    class LockEvent(EventType[None]):
        item_code = 82
        
        @classmethod
        def from_bytes(cls, data):
            return cls(None)

    class UnlockEvent(EventType[None]):
        item_code = 83
        
        @classmethod
        def from_bytes(cls, data):
            return cls(None)

    class OpenSensorAutoLockTimeEvent(EventType[int]):
        item_code = 92

        @classmethod
        def from_bytes(cls, data):
            return cls(struct.unpack('<xxH', data[2:4])[0])

class SesameClient:
    def __init__(self, sesame_addr, device_secret):
        self.txrx = SSMTransportHandler(sesame_addr, self._response_handler, self._handle_disconnect)
        self.response_listener: dict = {}
        self.device_secret = device_secret
        self.mech_status = None
        self.mech_settings = None
        self.is_connected: bool = False
        self._connected_callback: list[Callable[[], Union[Awaitable[None], None]]] = []
        self._disconnected_callback: list[Callable[[], Union[Awaitable[None], None]]] = []

    def __del__(self):
        if self.is_connected:
            asyncio.run(self.disconnect())
    async def connect(self):
        waiter = self._wait_for_response(14)
        await self.txrx.connect()
        self.is_connected = True
        for callback in self._connected_callback:
            if inspect.iscoroutinefunction(callback):
                await callback()
            else:
                callback()
        initial, _ = await waiter
        await self._login(initial)

    async def disconnect(self):
        await self.txrx.disconnect()
        self._handle_disconnect()

    def on_connected(self, callback: Callable[[], Union[Awaitable[None], None]]):
        self._connected_callback.append(callback)

    def on_disconnected(self, callback: Callable[[], Union[Awaitable[None], None]]):
        """Register a callback for disconnection events."""
        self._disconnected_callback.append(callback)

    def _handle_disconnect(self, _client=None):
        if not self.is_connected:
            return
        self.is_connected = False
        for callback in self._disconnected_callback:
            if inspect.iscoroutinefunction(callback):
                asyncio.create_task(callback())
            else:
                callback()

    async def _login(self, data):
        cobj = CMAC.new(self.device_secret, ciphermod=AES)
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
        payload = struct.pack('<B', len(display_name_bytes)) + display_name_bytes
        try:
            await asyncio.wait_for(self._send_and_wait(82, payload, encrypted=True), timeout=5)
        except asyncio.TimeoutError:
            raise TimeoutError("Lock command timed out.")

    async def unlock(self, display_name: str):
        display_name_bytes = display_name.encode('utf-8')[:32]
        payload = struct.pack('<B', len(display_name_bytes)) + display_name_bytes
        try:
            await asyncio.wait_for(self._send_and_wait(83, payload, encrypted=True), timeout=5)
        except asyncio.TimeoutError:
            raise TimeoutError("Unlock command timed out.")

    async def set_autolock_time(self, seconds: int):
        data = struct.pack('<H', seconds)
        await asyncio.wait_for(self._send_and_wait(11, data, encrypted=True), timeout=5)

    async def set_mech_settings(self, lock: int, unlock: int):
        payload = struct.pack('<hh', lock, unlock)
        await asyncio.wait_for(self._send_and_wait(80, payload, encrypted=True), timeout=5)

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
        data = struct.pack('<I', history_id)
        result, metadata = await asyncio.wait_for(self._send_and_wait(18, data, encrypted=True, response_code=18), timeout=5)
        if result[2] != 0:
            raise ValueError(f"Failed to delete history with ID {history_id}, response code: {result[2]}")
        logger.info(f"History with ID {history_id} deleted successfully.")

    def add_listener(self, event_type: Type[EventTypeT], callback: Union[Callable[[EventTypeT, dict], None], Callable[[EventTypeT, dict], Awaitable[None]]]):
        self._add_listener(event_type.item_code, callback, deserialize=event_type)

    def remove_listener(self, event_type: Type[EventTypeT], callback: Union[Callable[[EventTypeT, dict], None], Callable[[EventTypeT, dict], Awaitable[None]]]):
        self._remove_listener(event_type.item_code, callback)

    async def _send(self, item_code, payload, encrypted: bool):
        data = struct.pack('<B', item_code) + payload
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
                timestamp = struct.unpack('<I', data[3:7])[0]
                logger.debug(f"Timestamp: {timestamp}")
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
                time = struct.unpack('<H', data[2:4])[0]
                logger.debug(f"Auto lock time: {time}")
            case _:
                logger.warning(f"Unhandled response item code: {data[1]}")
