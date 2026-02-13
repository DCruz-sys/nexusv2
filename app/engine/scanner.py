"""Automated scan engine with methodology-based orchestration."""
import asyncio
import json
from datetime import datetime, timezone
from typing import Callable, Optional

from app.ai.agent_swarm import agent_swarm
from app.ai.memory_manager import memory_manager
from app.engine.executor import build_command, execute_tool, terminate_active_process_groups
from app.database import update_scan, add_scan_result, get_scan, get_scan_results
from app.frameworks.kali_tools import get_tool
from app.frameworks.owasp_wstg import WSTG_CATEGORIES
from app.frameworks.mitre_attack import ATTACK_TACTICS
from app.frameworks.cyber_kill_chain import KILL_CHAIN_PHASES
from app.security.allowlist import TargetNotAllowedError, require_target_allowed

# Active scans tracking
active_scans = {}
scan_cancel_events = {}


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


async def stop_scan(scan_id: str):
    """Signal a specific scan to stop."""
    # Signal local event if it exists (same worker)
    if scan_id in scan_cancel_events:
        scan_cancel_events[scan_id].set()
    
    # Update local state if it exists
    if scan_id in active_scans:
        active_scans[scan_id]["status"] = "stopping"
    
    # Update database for cross-worker signaling
    await update_scan(scan_id, status="stopping")


async def stop_all_scans():
    """Signal all active scans to stop."""
    # 1. Stop all local scans
    for scan_id in list(scan_cancel_events.keys()):
        await stop_scan(scan_id)
    
    # 2. Update all running scans in DB to 'stopping'
    from app.database import get_db
    db = await get_db()
    try:
        await db.execute("UPDATE scans SET status = 'stopping' WHERE status = 'running'")
        await db.commit()
    finally:
        await db.close()
    
    # 3. Kill process groups spawned by this service first (deterministic and scoped).
    try:
        killed_groups = await terminate_active_process_groups()
        if killed_groups:
            from app.database import add_memory_audit_event
            await add_memory_audit_event(
                event_type="scan_stop_active_groups",
                actor="scanner",
                reason="stop_all_scans",
                payload={"killed_process_groups": killed_groups},
            )
    except Exception as exc:
        from app.database import add_memory_audit_event
        await add_memory_audit_event(
            event_type="scan_stop_error",
            actor="scanner",
            reason="stop_all_scans",
            payload={"stage": "active_process_groups", "error": str(exc)},
        )

    # 4. Fallback: kill common pentest tool processes as a safety measure.
    import subprocess
    tools = ["nmap", "gobuster", "nikto", "whatweb", "feroxbuster", "masscan", "hydra", "sqlmap"]
    for tool in tools:
        try:
            subprocess.run(["pkill", "-f", tool], capture_output=True)
        except Exception as exc:
            from app.database import add_memory_audit_event
            await add_memory_audit_event(
                event_type="scan_stop_error",
                actor="scanner",
                reason="stop_all_scans",
                payload={"tool": tool, "error": str(exc)},
            )


def _get_owasp_scan_plan(target: str, config: dict) -> list:
    """Generate scan steps from OWASP WSTG methodology."""
    phases = []
    selected_cats = config.get("categories", None)

    for cat in WSTG_CATEGORIES:
        if selected_cats and cat["id"] not in selected_cats:
            continue

        steps = []
        seen_tools = set()
        for tc in cat["test_cases"]:
            for tool_name in tc.get("tools", []):
                if tool_name in seen_tools or tool_name in ("burpsuite", "zaproxy", "wappalyzer"):
                    continue
                tool = get_tool(tool_name)
                if tool:
                    seen_tools.add(tool_name)
                    steps.append({
                        "tool": tool_name,
                        "command": build_command(tool_name, target),
                        "test_case": tc["id"],
                        "description": tc["name"],
                    })

        if steps:
            phases.append({
                "name": cat["name"],
                "framework_ref": cat["id"],
                "steps": steps[:5],  # Limit steps per phase
            })

    return phases


def _get_attack_scan_plan(target: str, config: dict) -> list:
    """Generate scan steps from MITRE ATT&CK methodology."""
    phases = []
    focus_tactics = config.get("tactics", ["TA0043", "TA0001", "TA0007"])

    for tactic in ATTACK_TACTICS:
        if tactic["id"] not in focus_tactics:
            continue

        steps = []
        seen_tools = set()
        for tech in tactic["techniques"]:
            for tool_name in tech.get("tools", []):
                if tool_name in seen_tools or tool_name in ("metasploit", "burpsuite"):
                    continue
                tool = get_tool(tool_name)
                if tool:
                    seen_tools.add(tool_name)
                    steps.append({
                        "tool": tool_name,
                        "command": build_command(tool_name, target),
                        "technique": tech["id"],
                        "description": tech["name"],
                    })

        if steps:
            phases.append({
                "name": tactic["name"],
                "framework_ref": tactic["id"],
                "steps": steps[:4],
            })

    return phases


def _get_killchain_scan_plan(target: str, config: dict) -> list:
    """Generate scan steps from Cyber Kill Chain methodology."""
    phases = []
    selected_phases = config.get("phases", [1, 3, 4])

    for kc_phase in KILL_CHAIN_PHASES:
        if kc_phase["phase"] not in selected_phases:
            continue

        steps = []
        seen_tools = set()
        for tool_name in kc_phase.get("tools", []):
            if tool_name in seen_tools or tool_name in ("metasploit", "burpsuite"):
                continue
            tool = get_tool(tool_name)
            if tool:
                seen_tools.add(tool_name)
                steps.append({
                    "tool": tool_name,
                    "command": build_command(tool_name, target),
                    "description": f"{kc_phase['name']} - {tool_name}",
                })

        if steps:
            phases.append({
                "name": kc_phase["name"],
                "framework_ref": f"KC-Phase-{kc_phase['phase']}",
                "steps": steps[:5],
            })

    return phases


def _get_quick_scan_plan(target: str) -> list:
    """Generate a quick reconnaissance scan plan."""
    return [
        {
            "name": "Quick Reconnaissance",
            "framework_ref": "QUICK",
            "steps": [
                {"tool": "nmap", "command": build_command("nmap", target, "-sV -sC --top-ports 100 -T4"), "description": "Top 100 port scan with service detection"},
                {"tool": "whatweb", "command": build_command("whatweb", target), "description": "Web technology fingerprinting"},
            ]
        }
    ]


async def run_scan(scan_id: str, target: str, methodology: str = "owasp",
                   scan_type: str = "full", config: dict = None,
                   progress_callback: Optional[Callable] = None):
    """Run an automated scan with the selected methodology.

    Args:
        scan_id: Unique scan identifier
        target: Target URL/IP
        methodology: owasp, mitre, killchain, quick, or ai
        scan_type: full or quick
        config: Additional configuration dict
        progress_callback: Async callback for progress updates
    """
    methodology = (methodology or "owasp").strip().lower()
    if methodology not in {"owasp", "mitre", "killchain", "ai"}:
        methodology = "owasp"
    scan_type = "quick" if (scan_type or "").strip().lower() == "quick" else "full"
    config = config or {}
    active_scans[scan_id] = {"status": "running", "progress": 0}
    scan_cancel_events[scan_id] = asyncio.Event()

    async def check_cancellation():
        """Check if scan should be stopped (local event or DB status)."""
        if scan_id in scan_cancel_events and scan_cancel_events[scan_id].is_set():
            return True
        
        # Check database status
        scan = await get_scan(scan_id)
        if scan and scan.get("status") in ("stopping", "stopped"):
            if scan_id in scan_cancel_events:
                scan_cancel_events[scan_id].set()
            return True
        return False

    async def notify(msg_type: str, data: dict):
        if progress_callback:
            try:
                await progress_callback({"type": msg_type, "scan_id": scan_id, **data})
            except Exception:
                pass

    try:
        try:
            await require_target_allowed(target, actor="scanner", reason="execution_boundary")
        except TargetNotAllowedError as exc:
            await update_scan(scan_id, status="error", progress=-1)
            active_scans[scan_id] = {"status": "error", "progress": -1}
            await notify("error", {"message": str(exc)})
            return

        await update_scan(scan_id, status="running", progress=0)
        await notify("status", {"message": "Initializing scan...", "progress": 0})

        # Generate scan plan based on methodology
        if methodology == "ai":
            await notify("status", {"message": "AI planning scan strategy...", "progress": 5})
            plan_result = await agent_swarm.plan_scan(target, methodology, scan_type)
            # Try to parse AI plan, fallback to OWASP
            try:
                plan_text = plan_result.get("response", "")
                json_start = plan_text.find("{")
                json_end = plan_text.rfind("}") + 1
                if json_start >= 0 and json_end > json_start:
                    parsed = json.loads(plan_text[json_start:json_end])
                    phases = parsed.get("phases", [])
                else:
                    phases = _get_owasp_scan_plan(target, config)
            except (json.JSONDecodeError, KeyError):
                phases = _get_owasp_scan_plan(target, config)
            await notify("ai_plan", {"plan": plan_result.get("response", ""), "model": plan_result.get("model_used", "")})
        elif methodology == "mitre":
            phases = _get_attack_scan_plan(target, config)
        elif methodology == "killchain":
            phases = _get_killchain_scan_plan(target, config)
        elif scan_type == "quick":
            phases = _get_quick_scan_plan(target)
        else:
            phases = _get_owasp_scan_plan(target, config)

        if not phases:
            phases = _get_quick_scan_plan(target)

        total_steps = sum(len(p.get("steps", [])) for p in phases)
        completed_steps = 0

        # Execute scan phases
        from app.config import MAX_CONCURRENT_TOOLS
        sem = asyncio.Semaphore(MAX_CONCURRENT_TOOLS)

        async def execute_step(step):
            nonlocal completed_steps
            # Check for cancellation before starting
            if await check_cancellation():
                return

            async with sem:
                # Re-check inside semaphore in case it was cancelled while waiting
                if await check_cancellation():
                    return

                tool_name = step.get("tool", "unknown")
                command = step.get("command", "")
                description = step.get("description", "")

                await notify("tool_start", {
                    "tool": tool_name,
                    "command": command,
                    "description": description,
                    "progress": int((completed_steps / max(total_steps, 1)) * 90) + 5,
                })

                # Execute the tool
                async def on_line(line):
                    await notify("tool_output", {"tool": tool_name, "line": line})

                try:
                    # Pass the cancel event to allow immediate termination of subprocess
                    result = await execute_tool(
                        command, 
                        on_output=on_line, 
                        stop_event=scan_cancel_events.get(scan_id),
                        scan_id=scan_id
                    )
                except Exception as e:
                    result = {
                        "stdout": "",
                        "stderr": str(e),
                        "return_code": -1,
                        "duration": 0,
                        "timed_out": False
                    }

                # Check for cancellation after tool execution
                if await check_cancellation():
                    return

                # Analyze results with AI
                severity = "info"
                findings = []
                if result["stdout"] and len(result["stdout"]) > 50:
                    try:
                        analysis = await agent_swarm.analyze_results(
                            tool_name, result["stdout"][:4000], target
                        )
                        findings = [analysis.get("response", "")]
                        # Simple severity heuristic
                        resp_lower = analysis.get("response", "").lower()
                        if "critical" in resp_lower:
                            severity = "critical"
                        elif "high" in resp_lower:
                            severity = "high"
                        elif "medium" in resp_lower:
                            severity = "medium"
                        elif "low" in resp_lower:
                            severity = "low"
                    except Exception:
                        findings = []

                # Save result
                await add_scan_result(
                    scan_id=scan_id,
                    phase=phase_name,
                    tool_name=tool_name,
                    command=command,
                    output=result["stdout"][:50000],
                    findings=findings,
                    severity=severity,
                    status="completed" if result["return_code"] == 0 else "error",
                )
                asyncio.create_task(memory_manager.ingest_scan_result(
                    scan_id=scan_id,
                    target=target,
                    phase=phase_name,
                    tool_name=tool_name,
                    command=command,
                    output=result["stdout"][:4000],
                    findings=findings,
                    severity=severity,
                ))

                completed_steps += 1
                progress = int((completed_steps / max(total_steps, 1)) * 90) + 5

                await notify("tool_complete", {
                    "tool": tool_name,
                    "return_code": result["return_code"],
                    "duration": result["duration"],
                    "timed_out": result["timed_out"],
                    "severity": severity,
                    "progress": progress,
                })

                await update_scan(scan_id, progress=progress)

        for phase_idx, phase in enumerate(phases):
            # Check for cancellation before each phase
            if await check_cancellation():
                break

            phase_name = phase.get("name", f"Phase {phase_idx + 1}")
            await notify("phase_start", {"phase": phase_name, "phase_index": phase_idx})

            tasks = [execute_step(step) for step in phase.get("steps", [])]
            await asyncio.gather(*tasks)

            await notify("phase_complete", {"phase": phase_name})

        if await check_cancellation():
            await update_scan(scan_id, status="stopped")
            active_scans[scan_id] = {"status": "stopped", "progress": completed_steps / max(total_steps, 1) * 100}
            await notify("stopped", {"message": "Scan stopped by user", "progress": active_scans[scan_id]["progress"]})
            asyncio.create_task(memory_manager.create_checkpoint(
                session_id=scan_id,
                checkpoint_type="scan_stopped",
                state={
                    "target": target,
                    "methodology": methodology,
                    "progress": active_scans[scan_id]["progress"],
                },
                reason="scan_stop_checkpoint",
            ))
            return

        # Final AI summary
        await notify("status", {"message": "Generating final analysis...", "progress": 95})
        try:
            results = await get_scan_results(scan_id)
            findings_blob = "\n".join([
                f"{r.get('tool_name', 'tool')} [{r.get('severity', 'info')}]: {r.get('output', '')[:800]}"
                for r in results[:30]
            ])
            swarm_analysis = await agent_swarm.collaborative_analysis(target, findings_blob)
            synthesis = (
                swarm_analysis.get("synthesis", {}).get("response")
                or swarm_analysis.get("vulnerability_assessment", {}).get("response", "")
            )
            report_content = await agent_swarm.generate_report_content({
                "target": target,
                "methodology": methodology,
                "results": [{"tool": r["tool_name"], "output": r["output"][:1000],
                             "severity": r["severity"]} for r in results],
            })
            await notify("swarm_summary", {"summary": synthesis})
            await notify("ai_summary", {"summary": report_content.get("response", "")})
        except Exception:
            from app.database import add_memory_audit_event
            await add_memory_audit_event(
                event_type="scan_summary_error",
                actor="scanner",
                session_id=scan_id,
                reason="final_analysis",
                payload={"target": target},
            )

        await update_scan(
            scan_id,
            status="completed",
            progress=100,
            completed_at=_utcnow_iso(),
        )
        active_scans[scan_id] = {"status": "completed", "progress": 100}
        await notify("complete", {"message": "Scan completed successfully", "progress": 100})
        asyncio.create_task(memory_manager.create_checkpoint(
            session_id=scan_id,
            checkpoint_type="scan_complete",
            state={
                "target": target,
                "methodology": methodology,
                "scan_type": scan_type,
                "total_steps": total_steps,
                "completed_steps": completed_steps,
            },
            reason="scan_complete_checkpoint",
        ))

    except Exception as e:
        await update_scan(scan_id, status="error", progress=-1)
        active_scans[scan_id] = {"status": "error", "progress": -1}
        await notify("error", {"message": str(e)})
        asyncio.create_task(memory_manager.create_checkpoint(
            session_id=scan_id,
            checkpoint_type="scan_error",
            state={
                "target": target,
                "methodology": methodology,
                "scan_type": scan_type,
                "error": str(e),
            },
            reason="scan_error_checkpoint",
        ))
    finally:
        scan_cancel_events.pop(scan_id, None)


def get_active_scan_status(scan_id: str) -> dict:
    return active_scans.get(scan_id, {"status": "unknown", "progress": 0})
