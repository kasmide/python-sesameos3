import asyncio
import base64
import json
from aioconsole import ainput
from sesameos3client import SesameClient, Event

async def main():
    with open("config.json", "r") as f:
        config = json.load(f)
        SSM_ADDR = config["sesame_addr"]
        PRIV_KEY = base64.b64decode(config["sesame_key"])
    client = SesameClient(SSM_ADDR, PRIV_KEY)
    await client.connect()
    client.add_listener(Event.MechStatusEvent, lambda e, metadata: print(f"Mech status received: battery {e.response.battery} mV, is_locked: {e.response.lock_range}, stop: {e.response.stop}"))

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
            case "q":
                await client.txrx.disconnect()
                break

asyncio.run(main())
