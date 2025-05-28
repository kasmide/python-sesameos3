import asyncio
import base64
import json
from sesame_transport import SSMTransportHandler

async def main():
    with open("config.json", "r") as f:
        config = json.load(f)
        SSM_ADDR = config["sesame_addr"]
        PRIV_KEY = base64.b64decode(config["sesame_key"])
    handler = SSMTransportHandler(SSM_ADDR, PRIV_KEY)
    await handler.connect()
    while True:
        match input("command? ").strip().lower():
            case "unlock":
                await handler.send_encrypted(83, "Python".encode('utf-8')[:6])
            case "lock":
                await handler.send_encrypted(82, "Python".encode('utf-8')[:6])
            case "q":
                await handler.disconnect()
                break

asyncio.run(main())
