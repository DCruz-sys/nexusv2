import asyncio
import os
import subprocess
import sys
from pathlib import Path


SCHEMA_PATH = Path(__file__).with_name("schema.sql")


async def _init_with_asyncpg() -> None:
    try:
        import asyncpg  # type: ignore
    except Exception as exc:  # pragma: no cover
        raise RuntimeError("asyncpg is not installed") from exc

    host = os.getenv("POSTGRES_HOST", "localhost")
    port = int(os.getenv("POSTGRES_PORT", "5432"))
    database = os.getenv("POSTGRES_DB", "nexus_memory")
    user = os.getenv("POSTGRES_USER", "nexus")
    password = os.getenv("POSTGRES_PASSWORD", "nexus")

    last_err: Exception | None = None
    for attempt in range(1, 16):
        try:
            conn = await asyncpg.connect(
                host=host,
                port=port,
                database=database,
                user=user,
                password=password,
            )
            await conn.execute(SCHEMA_PATH.read_text(encoding="utf-8"))
            await conn.close()
            print(f"[init_db] schema applied via asyncpg to {host}:{port}/{database}")
            return
        except Exception as exc:  # pragma: no cover
            last_err = exc
            await asyncio.sleep(1)

    raise RuntimeError(f"Unable to connect to PostgreSQL after retries: {last_err}")


def _compose_file() -> str:
    return str(Path(__file__).resolve().parents[1] / "docker" / "docker-compose.yml")


def _init_with_docker_compose() -> None:
    compose_file = _compose_file()
    cmd = [
        "docker",
        "compose",
        "-f",
        compose_file,
        "exec",
        "-T",
        "postgres",
        "psql",
        "-U",
        os.getenv("POSTGRES_USER", "nexus"),
        "-d",
        os.getenv("POSTGRES_DB", "nexus_memory"),
        "-v",
        "ON_ERROR_STOP=1",
        "-f",
        "/docker-entrypoint-initdb.d/schema.sql",
    ]
    result = subprocess.run(cmd, text=True, capture_output=True)
    if result.returncode != 0:
        raise RuntimeError(
            "Docker Compose fallback failed. "
            "Ensure docker compose is running and postgres service is healthy.\n"
            f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
        )
    print("[init_db] schema applied via docker compose exec")


async def main() -> None:
    try:
        await _init_with_asyncpg()
    except Exception as asyncpg_error:
        print(f"[init_db] asyncpg path unavailable: {asyncpg_error}")
        print("[init_db] trying docker compose fallback...")
        _init_with_docker_compose()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as exc:
        print(f"[init_db] failed: {exc}", file=sys.stderr)
        sys.exit(1)
