"""WebSocket event streaming for runs (v2).

The worker writes events to SQLite; the WS endpoint tails the DB so it works
across processes without an in-memory broker.
"""

from __future__ import annotations

import asyncio

from fastapi import WebSocket, WebSocketDisconnect

from nexus_v2.api.auth import authenticate_websocket
from nexus_v2.infra.repos.events import list_events
from nexus_v2.infra.repos.runs import get_run


async def stream_run_events(websocket: WebSocket, run_id: str) -> None:
    principal = await authenticate_websocket(websocket, required_role="viewer")
    if not principal:
        return
    await websocket.accept()

    try:
        run = await get_run(run_id)
        if run:
            await websocket.send_json({"type": "run_status", "run": run})

        since_seq = int(websocket.query_params.get("since_seq") or 0)
        while True:
            events = await list_events(run_id=run_id, since_seq=since_seq, limit=500)
            if events:
                for ev in events:
                    since_seq = max(since_seq, int(ev.get("seq") or since_seq))
                    await websocket.send_json({"type": "event", "event": ev})
            else:
                try:
                    await asyncio.wait_for(websocket.receive_text(), timeout=10)
                except asyncio.TimeoutError:
                    await websocket.send_json({"type": "ping"})
                except WebSocketDisconnect:
                    break
    except WebSocketDisconnect:
        return
    except Exception:
        try:
            await websocket.close(code=1011)
        except Exception:
            pass

