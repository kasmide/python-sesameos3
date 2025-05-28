import asyncio
import base64
import json
from sesame_transport import SSMTransportHandler
from sesame_client import SesameClient

async def main():
    with open("config.json", "r") as f:
        config = json.load(f)
        SSM_ADDR = config["sesame_addr"]
        PRIV_KEY = base64.b64decode(config["sesame_key"])
    client = SesameClient(SSM_ADDR, PRIV_KEY)
    await client.connect()
    while True:
        match input("command? ").strip().lower():
            case "unlock":
                await client.send_and_wait(83, "Python".encode('utf-8')[:6], encrypted=True)
            case "lock":
                await client.send_and_wait(82, "Python".encode('utf-8')[:6], encrypted=True)
            case "custom":
                item_code = int(input("item code? "))
                payload_str = input("payload (hex)? ")
                payload = bytes.fromhex(payload_str)
                await client.send_and_wait(item_code, payload, encrypted=True)
            case "peek_history":
                await client.send_and_wait(4, b'1', encrypted=True)
            case "q":
                await client.txrx.disconnect()
                break

asyncio.run(main())
