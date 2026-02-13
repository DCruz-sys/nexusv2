from typing import Any, Dict, List

from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from agents.orchestrator import PentestOrchestrator

app = FastAPI(title="Nexus V2 - Agentic AI Pentest Platform", version="2.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
orchestrator: PentestOrchestrator | None = None


class PentestRequest(BaseModel):
    target: str
    scope: Dict[str, Any]
    scan_types: List[str] = ["recon", "vuln_scan"]
    require_approval: bool = True


class PentestResponse(BaseModel):
    task_id: str
    status: str
    message: str


@app.on_event("startup")
async def startup() -> None:
    global orchestrator
    orchestrator = PentestOrchestrator()
    await orchestrator.initialize()


@app.on_event("shutdown")
async def shutdown() -> None:
    if orchestrator:
        await orchestrator.close()


@app.post("/api/v1/pentest/start", response_model=PentestResponse)
async def start_pentest(request: PentestRequest, background_tasks: BackgroundTasks) -> PentestResponse:
    import uuid

    task_id = str(uuid.uuid4())
    background_tasks.add_task(orchestrator.execute_full_pentest, request.target, request.scope | {"require_approval": request.require_approval}, task_id)
    return PentestResponse(task_id=task_id, status="started", message=f"Pentest initiated for {request.target}")


@app.get("/api/v1/pentest/status/{task_id}")
async def get_status(task_id: str) -> Dict[str, Any]:
    status = await orchestrator.get_task_status(task_id)
    if not status:
        raise HTTPException(status_code=404, detail="Task not found")
    return status


@app.get("/health")
async def health_check() -> Dict[str, Any]:
    return {"status": "healthy", "agents": len(orchestrator.agents), "nim_stats": orchestrator.nim.get_statistics()}
