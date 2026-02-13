"""Shared scan progress event broadcaster."""
from fastapi import WebSocket


scan_ws_connections: dict[str, list[WebSocket]] = {}


def register_scan_ws(scan_id: str, websocket: WebSocket):
    scan_ws_connections.setdefault(scan_id, []).append(websocket)


def unregister_scan_ws(scan_id: str, websocket: WebSocket):
    if scan_id not in scan_ws_connections:
        return
    try:
        scan_ws_connections[scan_id].remove(websocket)
    except ValueError:
        pass


async def broadcast_scan_event(scan_id: str, payload: dict):
    ws_list = scan_ws_connections.get(scan_id, [])
    for ws in ws_list[:]:
        try:
            await ws.send_json(payload)
        except Exception:
            unregister_scan_ws(scan_id, ws)
