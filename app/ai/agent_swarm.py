"""Agent swarm orchestration with dependency-aware scheduling and native acceleration."""
import asyncio
import json
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from app.ai.accelerators import plan_swarm_waves
from app.ai.guardrails import guardrails_manager
from app.ai.memory_manager import memory_manager
from app.ai.model_router import model_router
from app.ai.prompts import get_agent_prompt
from app.config import (
    MAX_PENDING_CRAWL,
    SWARM_AUTONOMOUS_LEARNING_COOLDOWN_MIN,
    SWARM_MAX_PARALLEL,
    SWARM_MAX_RETRIES,
    SWARM_TASK_TIMEOUT_SEC,
)
from app.database import (
    add_memory_audit_event,
    add_swarm_event,
    count_pending_jobs,
    count_swarm_events_since,
    create_swarm_run,
    enqueue_job,
    get_swarm_run,
    get_swarm_task,
    list_swarm_events,
    list_swarm_tasks,
    update_swarm_run,
    update_swarm_task,
    upsert_swarm_task,
)
from app.security.allowlist import TargetNotAllowedError, require_target_allowed
from app.services.swarm_events import broadcast_swarm_event


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _utcnow_iso() -> str:
    return _utcnow().isoformat()


def _extract_json_object(raw_text: str) -> dict:
    if not raw_text:
        return {}
    start = raw_text.find("{")
    end = raw_text.rfind("}")
    if start < 0 or end <= start:
        return {}
    try:
        parsed = json.loads(raw_text[start : end + 1])
        return parsed if isinstance(parsed, dict) else {}
    except Exception:
        return {}


@dataclass
class SwarmTask:
    """A single unit of work for swarm orchestration."""
    task: str
    agent: str = "coordinator"
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    dependencies: list[str] = field(default_factory=list)
    priority: int = 0
    context: str = ""
    timeout_sec: int = SWARM_TASK_TIMEOUT_SEC
    retries: int = SWARM_MAX_RETRIES


class Agent:
    """A specialized AI agent with a specific role and prompt profile."""

    def __init__(self, name: str, prompt_key: str, model_preference: str = None):
        self.name = name
        self.prompt_key = prompt_key
        self.model_preference = model_preference

    async def execute(self, task: str, context: str = "") -> dict:
        """Execute a task using this agent specialization."""
        messages = get_agent_prompt(self.prompt_key, context)
        messages.append({"role": "user", "content": task})
        result = await model_router.query(
            messages=messages,
            force_model=self.model_preference,
        )
        return {
            "agent": self.name,
            "prompt_key": self.prompt_key,
            "task": task,
            "response": result.get("response", ""),
            "model_used": result.get("model"),
            "task_type": result.get("task_type"),
        }

    async def stream_execute(self, task: str, context: str = ""):
        """Stream task execution."""
        messages = get_agent_prompt(self.prompt_key, context)
        messages.append({"role": "user", "content": task})
        async for token in model_router.stream_query(
            messages=messages,
            force_model=self.model_preference,
        ):
            yield token


class CollaborativeSwarm:
    """Manages dependency-aware execution of tasks using specialized agents."""

    def __init__(self, agents: dict, max_parallel: int = SWARM_MAX_PARALLEL):
        self.agents = agents
        self.max_parallel = max(1, int(max_parallel))
        self.semaphore = asyncio.Semaphore(self.max_parallel)

    def _normalize_tasks(self, task_specs: list[dict]) -> list[SwarmTask]:
        tasks = []
        for spec in task_specs:
            tasks.append(
                SwarmTask(
                    id=spec.get("id", str(uuid.uuid4())),
                    agent=spec.get("agent", "coordinator"),
                    task=spec.get("task", ""),
                    dependencies=list(spec.get("dependencies", [])),
                    priority=int(spec.get("priority", 0)),
                    context=spec.get("context", ""),
                    timeout_sec=int(spec.get("timeout_sec", SWARM_TASK_TIMEOUT_SEC)),
                    retries=int(spec.get("retries", SWARM_MAX_RETRIES)),
                )
            )
        return tasks

    def _python_plan_waves(self, tasks: list[SwarmTask]) -> list[list[str]]:
        """Topological scheduling with priority and bounded parallel waves."""
        by_id = {task.id: task for task in tasks}
        indegree = {task.id: 0 for task in tasks}
        dependents: dict[str, set[str]] = {task.id: set() for task in tasks}

        for task in tasks:
            for dep in task.dependencies:
                if dep not in by_id:
                    continue
                indegree[task.id] += 1
                dependents[dep].add(task.id)

        available = [task.id for task in tasks if indegree[task.id] == 0]
        waves: list[list[str]] = []
        visited = 0

        while available:
            available.sort(key=lambda tid: (-by_id[tid].priority, tid))
            wave = available[:self.max_parallel]
            available = available[self.max_parallel:]
            waves.append(wave)
            for current in wave:
                visited += 1
                for dep in dependents[current]:
                    indegree[dep] -= 1
                    if indegree[dep] == 0:
                        available.append(dep)

        if visited != len(tasks):
            unresolved = [task_id for task_id, count in indegree.items() if count > 0]
            raise ValueError(f"Cyclic or unresolved dependencies in swarm tasks: {unresolved}")
        return waves

    async def _plan_waves(self, tasks: list[SwarmTask]) -> list[list[str]]:
        """Prefer Go planner if available, otherwise Python fallback."""
        planner_input = [
            {
                "id": task.id,
                "priority": task.priority,
                "dependencies": task.dependencies,
                "agent": task.agent,
            }
            for task in tasks
        ]
        waves = await plan_swarm_waves(planner_input, max_parallel=self.max_parallel)
        if not waves:
            return self._python_plan_waves(tasks)

        # Validate planner output to avoid silent orchestration bugs.
        expected = {task.id for task in tasks}
        flattened = [task_id for wave in waves for task_id in wave]
        if set(flattened) != expected or len(flattened) != len(expected):
            return self._python_plan_waves(tasks)
        return waves

    @staticmethod
    def _dependency_context(task: SwarmTask, dependency_results: dict[str, dict]) -> str:
        if not task.dependencies:
            return task.context
        blocks = []
        for dep_id in task.dependencies:
            dep = dependency_results.get(dep_id)
            if not dep:
                continue
            if dep.get("status") != "ok":
                blocks.append(f"[Dependency {dep_id} failed]: {dep.get('error', 'unknown error')}")
            else:
                response = dep.get("response", "")
                blocks.append(f"[Dependency {dep_id} output]\n{response[:2000]}")
        joined = "\n\n".join(blocks)
        if task.context:
            return f"{task.context}\n\n{joined}".strip()
        return joined

    async def _run_task(self, task: SwarmTask, dependency_results: dict[str, dict]) -> dict:
        agent = self.agents.get(task.agent, self.agents["coordinator"])
        context = self._dependency_context(task, dependency_results)

        last_error = None
        for attempt in range(0, max(0, task.retries) + 1):
            try:
                async with self.semaphore:
                    result = await asyncio.wait_for(
                        agent.execute(task.task, context=context),
                        timeout=max(5, task.timeout_sec),
                    )
                return {
                    "task_id": task.id,
                    "agent": task.agent,
                    "status": "ok",
                    "attempt": attempt,
                    **result,
                }
            except Exception as exc:
                last_error = str(exc)
        return {
            "task_id": task.id,
            "agent": task.agent,
            "status": "error",
            "attempt": max(0, task.retries),
            "error": last_error or "task execution failed",
            "response": "",
        }

    async def execute_graph(self, task_specs: list[dict]) -> list[dict]:
        """Execute tasks honoring dependencies, priorities, retries, and timeouts."""
        tasks = self._normalize_tasks(task_specs)
        if not tasks:
            return []

        try:
            waves = await self._plan_waves(tasks)
        except Exception:
            # Safety fallback: execute all tasks in one wave if planning fails.
            waves = [[task.id for task in tasks]]
        by_id = {task.id: task for task in tasks}
        results: dict[str, dict] = {}

        for wave in waves:
            run_coroutines = []
            for task_id in wave:
                task = by_id.get(task_id)
                if not task:
                    continue
                run_coroutines.append(self._run_task(task, results))
            wave_results = await asyncio.gather(*run_coroutines, return_exceptions=True)

            for item in wave_results:
                if isinstance(item, Exception):
                    synthetic_id = str(uuid.uuid4())
                    results[synthetic_id] = {
                        "task_id": synthetic_id,
                        "agent": "coordinator",
                        "status": "error",
                        "error": str(item),
                        "response": "",
                    }
                    continue
                results[item["task_id"]] = item

        # Preserve original task order for deterministic consumers.
        return [results.get(task.id, {"task_id": task.id, "status": "error", "response": ""}) for task in tasks]

    async def execute_parallel(self, tasks: list[dict]) -> list[dict]:
        """Compatibility wrapper for old callsites."""
        return await self.execute_graph(tasks)


class AgentSwarm:
    """Coordinates specialized agents for pentest operations."""

    def __init__(self, model_preference: str = None):
        self.agents = {
            "coordinator": Agent("Coordinator", "coordinator", model_preference),
            "web": Agent("WebSpecialist", "recon_agent", model_preference),
            "network": Agent("NetworkSpecialist", "recon_agent", model_preference),
            "vulnerability": Agent("VulnSpecialist", "vuln_agent", model_preference),
            "report": Agent("ReportSpecialist", "report_agent", model_preference),
        }
        self.swarm_executor = CollaborativeSwarm(self.agents)
        self._role_to_agent = {
            "coordinator": "coordinator",
            "recon": "web",
            "analysis": "vulnerability",
            "report": "report",
            "memory": "coordinator",
        }

    def _fallback_task_specs(self, target: str, objective: str, methodology: str, scan_type: str) -> list[dict]:
        return [
            {
                "id": "recon_surface",
                "agent": "web",
                "priority": 10,
                "task": (
                    f"Perform reconnaissance planning for target {target}. "
                    f"Objective: {objective}. Methodology: {methodology} ({scan_type})."
                ),
                "dependencies": [],
            },
            {
                "id": "network_mapping",
                "agent": "network",
                "priority": 9,
                "task": (
                    f"Map network exposure and enumerate likely services for target {target}. "
                    f"Methodology: {methodology}."
                ),
                "dependencies": [],
            },
            {
                "id": "vuln_assessment",
                "agent": "vulnerability",
                "priority": 8,
                "task": (
                    f"Analyze likely vulnerabilities and attack paths for {target} "
                    f"based on recon outputs and objective '{objective}'."
                ),
                "dependencies": ["recon_surface", "network_mapping"],
            },
            {
                "id": "synthesis_report",
                "agent": "report",
                "priority": 7,
                "task": (
                    "Generate an actionable execution summary with prioritized findings, "
                    "constraints, and next steps."
                ),
                "dependencies": ["vuln_assessment"],
            },
        ]

    async def _plan_task_specs_with_guardrails(
        self,
        *,
        run_id: str,
        target: str,
        objective: str,
        methodology: str,
        scan_type: str,
    ) -> list[dict]:
        planner_prompt = f"""Create a planner task graph JSON only.
Schema requirements:
- root keys: run_id, created_at, tasks
- tasks keys: task_id, agent_role, objective, dependencies, risk_level, timeout_sec, retry_policy,
  allowed_tools, hitl_required, success_criteria, output_contract
- use only agent_role in coordinator|recon|analysis|report|memory
- keep 3-7 tasks
- target: {target}
- methodology: {methodology}
- scan_type: {scan_type}
- objective: {objective}
"""
        plan_response = await self.agents["coordinator"].execute(planner_prompt)
        raw = str(plan_response.get("response") or "")
        payload = _extract_json_object(raw)
        payload["run_id"] = payload.get("run_id") or run_id
        payload["created_at"] = payload.get("created_at") or _utcnow_iso()
        is_valid, reason = guardrails_manager.validate_planner_task_graph(payload)
        if not is_valid:
            await add_memory_audit_event(
                event_type="swarm_plan_guardrail_fallback",
                actor="agent_swarm",
                session_id=run_id,
                reason="planner_schema_validation",
                payload={"reason": reason},
            )
            return self._fallback_task_specs(target, objective, methodology, scan_type)

        specs: list[dict] = []
        for item in payload.get("tasks", []):
            if not isinstance(item, dict):
                continue
            task_id = str(item.get("task_id") or "").strip()
            if not task_id:
                continue
            agent_role = str(item.get("agent_role") or "coordinator").strip().lower()
            retry_policy = item.get("retry_policy")
            if not isinstance(retry_policy, dict):
                retry_policy = {}
            deps = item.get("dependencies")
            if not isinstance(deps, list):
                deps = []
            specs.append(
                {
                    "id": task_id,
                    "agent": self._role_to_agent.get(agent_role, "coordinator"),
                    "task": str(item.get("objective") or "").strip(),
                    "dependencies": [str(dep) for dep in deps if str(dep).strip()],
                    "priority": int(item.get("priority", 0)),
                    "timeout_sec": max(5, min(int(item.get("timeout_sec", SWARM_TASK_TIMEOUT_SEC)), 180)),
                    "retries": int(retry_policy.get("max_attempts", SWARM_MAX_RETRIES)),
                }
            )
        return specs or self._fallback_task_specs(target, objective, methodology, scan_type)

    async def create_persistent_run(
        self,
        *,
        target: str,
        objective: str,
        methodology: str = "owasp",
        scan_type: str = "quick",
        config: dict | None = None,
    ) -> str:
        await require_target_allowed(target, actor="swarm", reason="swarm_run_create")
        run_id = str(uuid.uuid4())
        await create_swarm_run(
            run_id=run_id,
            target=target,
            objective=objective,
            methodology=methodology,
            scan_type=scan_type,
            config=config or {},
            status="queued",
        )
        run_config = config if isinstance(config, dict) else {}
        if bool(run_config.get("dry_run")):
            task_specs = self._fallback_task_specs(target, objective, methodology, scan_type)
        else:
            planner_timeout = max(5, min(int(SWARM_TASK_TIMEOUT_SEC), 45))
            try:
                task_specs = await asyncio.wait_for(
                    self._plan_task_specs_with_guardrails(
                        run_id=run_id,
                        target=target,
                        objective=objective,
                        methodology=methodology,
                        scan_type=scan_type,
                    ),
                    timeout=float(planner_timeout),
                )
            except asyncio.TimeoutError:
                await add_memory_audit_event(
                    event_type="swarm_plan_timeout_fallback",
                    actor="agent_swarm",
                    session_id=run_id,
                    reason="planner_timeout",
                    payload={"timeout_sec": planner_timeout},
                )
                task_specs = self._fallback_task_specs(target, objective, methodology, scan_type)
        for task in task_specs:
            await upsert_swarm_task(
                run_id=run_id,
                task_id=str(task.get("id")),
                agent=str(task.get("agent") or "coordinator"),
                task=str(task.get("task") or ""),
                dependencies=list(task.get("dependencies") or []),
                priority=int(task.get("priority", 0)),
                max_attempts=int(task.get("retries", SWARM_MAX_RETRIES)),
                timeout_sec=int(task.get("timeout_sec", SWARM_TASK_TIMEOUT_SEC)),
            )
        await add_swarm_event(run_id, "run_created", {"target": target, "task_count": len(task_specs)})
        return run_id

    async def queue_swarm_run(
        self,
        *,
        target: str,
        objective: str,
        methodology: str = "owasp",
        scan_type: str = "quick",
        config: dict | None = None,
    ) -> tuple[str, str]:
        run_id = await self.create_persistent_run(
            target=target,
            objective=objective,
            methodology=methodology,
            scan_type=scan_type,
            config=config,
        )
        job_id = await enqueue_job(
            job_type="swarm",
            payload={"run_id": run_id},
            max_attempts=2,
        )
        await add_swarm_event(run_id, "run_queued", {"job_id": job_id})
        await broadcast_swarm_event(run_id, {"type": "queued", "run_id": run_id, "job_id": job_id})
        return run_id, job_id

    async def stop_persistent_run(self, run_id: str):
        run = await get_swarm_run(run_id)
        if not run:
            return
        await update_swarm_run(run_id, status="stopping")
        await add_swarm_event(run_id, "run_stopping", {})
        await broadcast_swarm_event(run_id, {"type": "stopping", "run_id": run_id})

    async def _run_single_task(self, run_id: str, task: SwarmTask, dependency_results: dict[str, dict]) -> dict:
        existing = await get_swarm_task(run_id, task.id)
        prev_attempt = int((existing or {}).get("attempt") or 0)
        await update_swarm_task(
            run_id,
            task.id,
            status="running",
            started_at=_utcnow_iso(),
            error=None,
        )
        await add_swarm_event(run_id, "task_start", {"task_id": task.id, "agent": task.agent})
        await broadcast_swarm_event(run_id, {"type": "task_start", "run_id": run_id, "task_id": task.id})
        result = await self.swarm_executor._run_task(task, dependency_results)
        completed_at = _utcnow_iso()
        if result.get("status") == "ok":
            await update_swarm_task(
                run_id,
                task.id,
                status="completed",
                attempt=prev_attempt + int(result.get("attempt", 0)) + 1,
                result=result,
                error=None,
                completed_at=completed_at,
            )
            await add_swarm_event(
                run_id,
                "task_complete",
                {"task_id": task.id, "status": "completed", "attempt": prev_attempt + int(result.get("attempt", 0)) + 1},
            )
            await broadcast_swarm_event(
                run_id,
                {"type": "task_complete", "run_id": run_id, "task_id": task.id, "status": "completed"},
            )
            return result

        await update_swarm_task(
            run_id,
            task.id,
            status="error",
            attempt=prev_attempt + int(result.get("attempt", 0)) + 1,
            error=str(result.get("error") or "task_execution_failed"),
            result=result,
            completed_at=completed_at,
        )
        await add_swarm_event(
            run_id,
            "task_error",
            {"task_id": task.id, "error": str(result.get("error") or "task_execution_failed")},
        )
        await broadcast_swarm_event(
            run_id,
            {"type": "task_complete", "run_id": run_id, "task_id": task.id, "status": "error"},
        )
        return result

    async def _queue_autonomous_learning(self, run_id: str, target: str):
        now = _utcnow()
        since = (now - timedelta(minutes=max(1, SWARM_AUTONOMOUS_LEARNING_COOLDOWN_MIN))).isoformat()
        run_exists = bool(await get_swarm_run(run_id))
        recent = await count_swarm_events_since(
            event_type="autonomous_learning_enqueued",
            since_iso=since,
            run_id=run_id if run_exists else None,
        )
        if recent > 0:
            return None
        pending = await count_pending_jobs("crawl")
        if pending >= MAX_PENDING_CRAWL:
            if run_exists:
                await add_swarm_event(
                    run_id,
                    "autonomous_learning_skipped",
                    {"reason": "crawler_queue_full", "pending": pending, "limit": MAX_PENDING_CRAWL},
                )
            return None

        seed = str(target or "").strip()
        if not seed:
            return None
        if not seed.startswith(("http://", "https://")):
            seed = f"https://{seed}"

        crawl_job_id = await enqueue_job(
            job_type="crawl",
            payload={
                "trigger": "swarm",
                "run_id": run_id if run_exists else None,
                "seeds": [seed],
                "focused": True,
                "distill_after": True,
            },
            max_attempts=2,
        )
        if run_exists:
            await add_swarm_event(run_id, "autonomous_learning_enqueued", {"crawl_job_id": crawl_job_id, "seed": seed})
        await add_memory_audit_event(
            event_type="swarm_learning_enqueued",
            actor="agent_swarm",
            session_id=run_id,
            reason="autonomous_learning_loop",
            payload={"crawl_job_id": crawl_job_id, "seed": seed},
        )
        return crawl_job_id

    async def execute_persistent_run(self, run_id: str) -> dict:
        run = await get_swarm_run(run_id)
        if not run:
            raise ValueError("swarm_run_not_found")
        if run.get("status") == "completed":
            return await self.get_run_bundle(run_id)
        if run.get("status") == "stopping":
            return await self.get_run_bundle(run_id)

        if run.get("status") != "running":
            await update_swarm_run(run_id, status="running", started_at=run.get("started_at") or _utcnow_iso())
        await add_swarm_event(run_id, "run_started", {})
        await broadcast_swarm_event(run_id, {"type": "run_started", "run_id": run_id})
        run_config = run.get("config") if isinstance(run.get("config"), dict) else {}
        dry_run = bool(run_config.get("dry_run"))

        task_rows = await list_swarm_tasks(run_id)
        tasks: list[SwarmTask] = []
        task_map: dict[str, dict] = {}
        dependency_results: dict[str, dict] = {}
        for row in task_rows:
            task_obj = SwarmTask(
                id=str(row.get("task_id")),
                agent=str(row.get("agent") or "coordinator"),
                task=str(row.get("task") or ""),
                dependencies=list(row.get("dependencies") or []),
                priority=int(row.get("priority", 0)),
                timeout_sec=int(row.get("timeout_sec", SWARM_TASK_TIMEOUT_SEC)),
                retries=max(0, int(row.get("max_attempts", SWARM_MAX_RETRIES)) - 1),
            )
            tasks.append(task_obj)
            task_map[task_obj.id] = row
            if row.get("status") == "completed" and isinstance(row.get("result"), dict):
                dependency_results[task_obj.id] = row["result"]

        if not tasks:
            await update_swarm_run(run_id, status="error", error="no_tasks")
            await add_swarm_event(run_id, "run_error", {"reason": "no_tasks"})
            return await self.get_run_bundle(run_id)

        try:
            waves = await self.swarm_executor._plan_waves(tasks)
        except Exception:
            waves = [[task.id for task in tasks]]

        by_id = {task.id: task for task in tasks}
        for wave in waves:
            run_state = await get_swarm_run(run_id)
            if run_state and run_state.get("status") == "stopping":
                break
            coros = []
            for task_id in wave:
                task = by_id.get(task_id)
                row = task_map.get(task_id, {})
                if not task:
                    continue
                if row.get("status") == "completed":
                    continue
                if dry_run:
                    synthetic = {
                        "task_id": task.id,
                        "agent": task.agent,
                        "status": "ok",
                        "attempt": 0,
                        "response": (
                            f"[dry_run] Planned task '{task.id}' for agent '{task.agent}'. "
                            f"Objective: {task.task[:180]}"
                        ),
                        "task": task.task,
                        "model_used": "dry-run",
                        "task_type": "dry_run",
                    }
                    await update_swarm_task(
                        run_id,
                        task.id,
                        status="completed",
                        attempt=int(row.get("attempt") or 0) + 1,
                        started_at=row.get("started_at") or _utcnow_iso(),
                        completed_at=_utcnow_iso(),
                        result=synthetic,
                        error=None,
                    )
                    await add_swarm_event(
                        run_id,
                        "task_complete",
                        {"task_id": task.id, "status": "completed", "dry_run": True},
                    )
                    await broadcast_swarm_event(
                        run_id,
                        {"type": "task_complete", "run_id": run_id, "task_id": task.id, "status": "completed"},
                    )
                    dependency_results[task.id] = synthetic
                    continue
                coros.append(self._run_single_task(run_id, task, dependency_results))
            if not coros:
                continue
            wave_results = await asyncio.gather(*coros, return_exceptions=True)
            for item in wave_results:
                if isinstance(item, Exception):
                    continue
                dependency_results[str(item.get("task_id"))] = item

        final_tasks = await list_swarm_tasks(run_id)
        has_error = any(row.get("status") == "error" for row in final_tasks)
        has_incomplete = any(row.get("status") not in {"completed", "error"} for row in final_tasks)
        run_state = await get_swarm_run(run_id)
        if run_state and run_state.get("status") == "stopping":
            await add_swarm_event(run_id, "run_stopped", {})
            await broadcast_swarm_event(run_id, {"type": "run_stopped", "run_id": run_id})
            return await self.get_run_bundle(run_id)

        if has_error:
            await update_swarm_run(
                run_id,
                status="error",
                completed_at=_utcnow_iso(),
                error="one_or_more_tasks_failed",
            )
            await add_swarm_event(run_id, "run_error", {"reason": "task_failure"})
            await broadcast_swarm_event(run_id, {"type": "run_error", "run_id": run_id})
            return await self.get_run_bundle(run_id)

        if not has_incomplete:
            await update_swarm_run(run_id, status="completed", completed_at=_utcnow_iso(), error=None)
            await add_swarm_event(run_id, "run_completed", {})
            await broadcast_swarm_event(run_id, {"type": "run_completed", "run_id": run_id})
            await self._queue_autonomous_learning(run_id, str(run.get("target") or ""))
        return await self.get_run_bundle(run_id)

    async def get_run_bundle(self, run_id: str) -> dict:
        run = await get_swarm_run(run_id)
        tasks = await list_swarm_tasks(run_id)
        events = await list_swarm_events(run_id, limit=500)
        return {"run": run, "tasks": tasks, "events": events}

    async def collaborative_plan(self, target: str, goals: list):
        """Execute planning goals with dependency-aware orchestration."""
        tasks = [
            {
                "id": f"plan_{idx}",
                "agent": "coordinator",
                "priority": len(goals) - idx,
                "task": f"Plan strategy for goal: {goal} on target {target}",
            }
            for idx, goal in enumerate(goals)
        ]
        return await self.swarm_executor.execute_parallel(tasks)

    async def plan_scan(self, target: str, methodology: str, scan_type: str) -> dict:
        """Have the coordinator plan a full scan."""
        from app.frameworks.kali_tools import get_tools_by_category

        web_tools = [t["name"] for t in get_tools_by_category("web_application")]
        net_tools = [t["name"] for t in get_tools_by_category("information_gathering")]
        vuln_tools = [t["name"] for t in get_tools_by_category("vulnerability_analysis")]

        is_ip = re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target)
        target_type = "IP Address" if is_ip else "Domain/Hostname"
        if is_ip:
            net_tools = sorted(net_tools, key=lambda x: x in ["nmap", "masscan", "arp-scan"], reverse=True)
        else:
            web_tools = sorted(web_tools, key=lambda x: x in ["gobuster", "dirb", "nikto", "sublist3r"], reverse=True)

        tool_context = f"""
Target Type: {target_type}
Available Tools Reference (Prioritized):
- Recon/Network: {', '.join(net_tools[:30])}
- Web Analysis: {', '.join(web_tools[:30])}
- Vulnerability: {', '.join(vuln_tools[:30])}
"""
        mem_context = ""
        try:
            bundle = await memory_manager.retrieve_context(
                session_id="global",
                query=f"{methodology} {scan_type} pentest plan for {target}",
                limit=4,
            )
            mem_context = str(bundle.get("context") or "")
        except Exception:
            mem_context = ""
        task = f"""Plan a comprehensive {scan_type} penetration test for target: {target}
Methodology: {methodology}
{tool_context}

Provide a structured plan with:
1. Reconnaissance phase - specific tools and commands
2. Scanning & enumeration phase - tools and parameters
3. Vulnerability assessment phase - test cases to check
4. Analysis phase - what to look for in results

For each phase, specify:
- Exact tool commands to run (using Kali Linux tools from the list above or other standard Kali tools).
- IMPORTANT: Do NOT use --help or man pages. Use active scanning flags.
- Expected output to analyze
- OWASP/ATT&CK mapping where applicable

        Format as JSON with structure:
{{
  "phases": [
    {{
      "name": "phase_name",
      "description": "what this phase does",
      "steps": [
        {{
          "tool": "tool_name",
          "command": "exact command to run",
          "description": "what this step checks",
          "framework_ref": "OWASP-XX or ATT&CK TXXXX"
        }}
      ]
    }}
  ]
}}"""
        return await self.agents["coordinator"].execute(task, context=mem_context)

    async def analyze_results(self, tool_name: str, output: str, target: str) -> dict:
        """Have the vulnerability agent analyze tool output."""
        mem_context = ""
        try:
            bundle = await memory_manager.retrieve_context(
                session_id="global",
                query=f"{tool_name} findings for {target}",
                limit=4,
            )
            mem_context = str(bundle.get("context") or "")
        except Exception:
            mem_context = ""
        task = f"""Analyze the following output from {tool_name} against target {target}:

```
{output[:8000]}
```

Identify:
1. Vulnerabilities found (with severity: Critical/High/Medium/Low/Info)
2. OWASP WSTG test case mapping
3. MITRE ATT&CK technique mapping
4. Recommended follow-up actions
5. Remediation suggestions

Format findings as a structured list."""
        return await self.agents["vulnerability"].execute(task, context=mem_context)

    async def generate_report_content(self, scan_data: dict) -> dict:
        """Have the report agent generate report content."""
        mem_context = ""
        try:
            target = str(scan_data.get("target") or "")
            bundle = await memory_manager.retrieve_context(
                session_id="global",
                query=f"report guidance for {target}",
                limit=4,
            )
            mem_context = str(bundle.get("context") or "")
        except Exception:
            mem_context = ""
        task = f"""Generate a professional penetration test report based on these scan results:

Target: {scan_data.get('target', 'Unknown')}
Methodology: {scan_data.get('methodology', 'OWASP')}
Results Summary:
{str(scan_data.get('results', []))[:6000]}

Include:
1. Executive Summary
2. Methodology Used
3. Findings by Severity
4. Detailed Technical Findings
5. Risk Assessment Matrix
6. Remediation Priorities
7. Conclusion"""
        return await self.agents["report"].execute(task, context=mem_context)

    async def collaborative_analysis(self, target: str, findings: str) -> dict:
        """Run multi-agent analysis with a synthesis dependency."""
        mem_context = ""
        try:
            bundle = await memory_manager.retrieve_context(
                session_id="global",
                query=f"synthesize pentest findings for {target}",
                limit=4,
            )
            mem_context = str(bundle.get("context") or "")
        except Exception:
            mem_context = ""
        tasks = [
            {
                "id": "vuln_assessment",
                "agent": "vulnerability",
                "priority": 10,
                "context": mem_context,
                "task": f"Assess vulnerabilities for {target}:\n{findings[:4000]}",
            },
            {
                "id": "web_assessment",
                "agent": "web",
                "priority": 9,
                "context": mem_context,
                "task": f"Evaluate web-specific risks for {target}:\n{findings[:4000]}",
            },
            {
                "id": "synthesis",
                "agent": "coordinator",
                "priority": 8,
                "dependencies": ["vuln_assessment", "web_assessment"],
                "context": mem_context,
                "task": "Synthesize the dependency outputs into a combined risk narrative with clear next steps.",
            },
        ]
        results = await self.swarm_executor.execute_graph(tasks)
        mapped = {row.get("task_id"): row for row in results}
        return {
            "vulnerability_assessment": mapped.get("vuln_assessment", {}),
            "security_analysis": mapped.get("web_assessment", {}),
            "synthesis": mapped.get("synthesis", {}),
        }


# Singleton
agent_swarm = AgentSwarm()
