import asyncio
import base64
import json
import logging
import os
from aioconsole import ainput
from sesameos3client import EventData, SesameClient, Event

async def main():
    log_level = os.getenv('LOG_LEVEL', 'WARNING').upper()

    logging.basicConfig(
        level=getattr(logging, log_level, logging.WARNING),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    with open("config.json", "r") as f:
        config = json.load(f)
        SSM_ADDR = config["sesame_addr"]
        PRIV_KEY = base64.b64decode(config["sesame_key"])
    client = SesameClient(SSM_ADDR, PRIV_KEY)
    client.add_listener(Event.MechStatusEvent, lambda e, metadata: print(f"Mech status received: {vars(e.response).items()}"))
    await client.connect()
    print(f"Connected to {SSM_ADDR}")

    while True:
        match (await ainput("command? ")).strip().lower():
            case "unlock":
                await client.unlock(await ainput("display name? "))
            case "lock":
                await client.lock(await ainput("display name? "))
            case "custom":
                item_code = int(await ainput("item code? "))
                payload_str = await ainput("payload (hex)? ")
                payload = bytes.fromhex(payload_str)
                await client._send_and_wait(item_code, payload, encrypted=True)
            case "hist head":
                hist = await client.get_history_head()
                if hist.response is None:
                    print("No history available")
                else:
                    print(f"id: {hist.response.id}, type: {hist.response.type}, time: {hist.response.timestamp}, ss5: {hist.response.ss5.hex()}")
            case "hist tail":
                hist = await client.get_history_tail()
                assert hist.response is not None
                print(f"id: {hist.response.id}, type: {hist.response.type}, time: {hist.response.timestamp}, ss5: {hist.response.ss5.hex()}")
            case "hist delete":
                id = int(await ainput("id to delete? "))
                await client._send_and_wait(18, id.to_bytes(4, 'little'), encrypted=True)
            case "autolock":
                duration = int(await ainput("duration in seconds? "))
                await client.set_autolock_time(duration)
            case "version":
                version = await client.get_version()
                print(f"Version: {version}")
            case "mechsettings":
                settings = client.mech_settings
                assert settings is not None
                print(f"Lock: {settings.lock}, Unlock: {settings.unlock}, Auto Lock Seconds: {settings.auto_lock_seconds}")
                lock = int(await ainput("Lock pos? "))
                unlock = int(await ainput("Unlock pos? "))
                auto_lock_seconds = int(await ainput("Auto lock seconds? "))
                await client.set_mech_settings(EventData.MechSettings(
                    lock=lock,
                    unlock=unlock,
                    auto_lock_seconds=auto_lock_seconds
                ))

            case "q":
                await client.txrx.disconnect()
                break

asyncio.run(main())
