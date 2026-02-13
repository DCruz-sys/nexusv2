from pydantic import BaseModel
from typing import Any, Dict


class PentestTask(BaseModel):
    target: str
    scope: Dict[str, Any]
