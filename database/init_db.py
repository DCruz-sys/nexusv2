import asyncio
import os

import asyncpg


async def main() -> None:
    conn = await asyncpg.connect(
        host=os.getenv("POSTGRES_HOST", "localhost"),
        port=int(os.getenv("POSTGRES_PORT", "5432")),
        database=os.getenv("POSTGRES_DB", "nexus_memory"),
        user=os.getenv("POSTGRES_USER", "nexus"),
        password=os.getenv("POSTGRES_PASSWORD", "nexus"),
    )
    schema = open(os.path.join(os.path.dirname(__file__), "schema.sql"), "r", encoding="utf-8").read()
    await conn.execute(schema)
    await conn.close()


if __name__ == "__main__":
    asyncio.run(main())
