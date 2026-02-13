from pydantic import BaseModel


class PentestReport(BaseModel):
    summary: str
