import asyncio
from wireshark_mcp.server import main


def run():
    asyncio.run(main())


if __name__ == "__main__":
    run()