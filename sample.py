import asyncio
import base64
import json
from aioconsole import ainput
from sesameos3 import SesameClient, Event

async def main():
    with open("config.json", "r") as f:
        config = json.load(f)
        SSM_ADDR = config["sesame_addr"]
        PRIV_KEY = base64.b64decode(config["sesame_key"])
    client = SesameClient(SSM_ADDR, PRIV_KEY)
    await client.connect()
    client.add_listener(Event.MechStatusEvent, lambda e, _: print(f"Mech status received: battery {e.response.battery} mV, is_locked: {e.response.lock_range}, stop: {e.response.stop}"))

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
            case "hist peek":
                await client._send_and_wait(4, (1).to_bytes(1), encrypted=True)
            case "hist pop":
                await client._send_and_wait(4, (0).to_bytes(1), encrypted=True)
            case "q":
                await client.txrx.disconnect()
                break

asyncio.run(main())
