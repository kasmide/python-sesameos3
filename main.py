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
                str = input("display name? ").encode('utf-8')[:32]
                str_len = len(str).to_bytes(1, "little")
                await client.send_and_wait(83, str_len + str, encrypted=True)
            case "lock":
                str = input("display name? ").encode('utf-8')[:32]
                str_len = len(str).to_bytes(1, "little")
                await client.send_and_wait(82, str_len + str, encrypted=True)
            case "custom":
                item_code = int(input("item code? "))
                payload_str = input("payload (hex)? ")
                payload = bytes.fromhex(payload_str)
                await client.send_and_wait(item_code, payload, encrypted=True)
            case "hist peek":
                await client.send_and_wait(4, b'1', encrypted=True)
            case "q":
                await client.txrx.disconnect()
                break

asyncio.run(main())
