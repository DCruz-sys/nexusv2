from pydantic import BaseModel


class AgentResponse(BaseModel):
    agent: str
    success: bool
