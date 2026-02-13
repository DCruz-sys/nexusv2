"""Shared swarm run event broadcaster."""
from fastapi import WebSocket


swarm_ws_connections: dict[str, list[WebSocket]] = {}


def register_swarm_ws(run_id: str, websocket: WebSocket):
    swarm_ws_connections.setdefault(run_id, []).append(websocket)


def unregister_swarm_ws(run_id: str, websocket: WebSocket):
    if run_id not in swarm_ws_connections:
        return
    try:
        swarm_ws_connections[run_id].remove(websocket)
    except ValueError:
        pass


async def broadcast_swarm_event(run_id: str, payload: dict):
    ws_list = swarm_ws_connections.get(run_id, [])
    for ws in ws_list[:]:
        try:
            await ws.send_json(payload)
        except Exception:
            unregister_swarm_ws(run_id, ws)
