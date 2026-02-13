"""Event broker (v2).

In the current v2 implementation, events are persisted to SQLite and the API
tails the DB to stream them over WebSockets. A broker abstraction is kept so we
can later swap to a real pub/sub mechanism if needed.
"""

from __future__ import annotations


class EventBroker:
    async def publish(self, *_args, **_kwargs) -> None:
        return None


event_broker = EventBroker()

