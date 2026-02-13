"""Framework and tools API endpoints."""
from fastapi import APIRouter, Depends, HTTPException
from app.frameworks.kali_tools import KALI_TOOLS, TOOL_CATEGORIES, get_tools_by_category, search_tools, get_tool
from app.frameworks.owasp_wstg import get_all_categories as owasp_categories, get_category as owasp_category, get_all_test_cases
from app.frameworks.mitre_attack import get_all_tactics, get_tactic, get_techniques_by_tool
from app.frameworks.cyber_kill_chain import get_all_phases, get_phase
from app.config import MODELS, MODEL_ROUTING
from app.security.auth import require_viewer

router = APIRouter(tags=["frameworks"])


@router.get("/tools")
async def api_list_tools(
    category: str = None,
    search: str = None,
    limit: int = 200,
    offset: int = 0,
    _principal=Depends(require_viewer),
):
    """List available Kali Linux tools."""
    capped_limit = max(1, min(limit, 1000))
    bounded_offset = max(0, offset)
    if search:
        rows = search_tools(search)
        return {"tools": rows[bounded_offset: bounded_offset + capped_limit], "total": len(rows)}
    if category:
        rows = get_tools_by_category(category)
        return {"tools": rows[bounded_offset: bounded_offset + capped_limit], "total": len(rows)}
    return {
        "tools": KALI_TOOLS[bounded_offset: bounded_offset + capped_limit],
        "total": len(KALI_TOOLS),
        "categories": TOOL_CATEGORIES,
    }


@router.get("/tools/{tool_name}")
async def api_get_tool(tool_name: str, _principal=Depends(require_viewer)):
    """Get tool details."""
    tool = get_tool(tool_name)
    if not tool:
        raise HTTPException(status_code=404, detail={"code": "not_found", "message": "Tool not found", "details": {}})
    # Add ATT&CK mapping
    attack_refs = get_techniques_by_tool(tool_name)
    return {**tool, "attack_techniques": attack_refs}


@router.get("/frameworks/owasp")
async def api_owasp(_principal=Depends(require_viewer)):
    """Get OWASP WSTG v4.2 categories."""
    return {"framework": "OWASP WSTG v4.2", "categories": owasp_categories()}


@router.get("/frameworks/owasp/{category_id}")
async def api_owasp_category(category_id: str, _principal=Depends(require_viewer)):
    """Get OWASP category details with test cases."""
    cat = owasp_category(category_id)
    if not cat:
        raise HTTPException(status_code=404, detail={"code": "not_found", "message": "Category not found", "details": {}})
    return cat


@router.get("/frameworks/owasp/tests/all")
async def api_owasp_all_tests(_principal=Depends(require_viewer)):
    """Get all OWASP test cases."""
    return {"test_cases": get_all_test_cases()}


@router.get("/frameworks/attack")
async def api_mitre_attack(_principal=Depends(require_viewer)):
    """Get MITRE ATT&CK Enterprise tactics."""
    return {"framework": "MITRE ATT&CK Enterprise", "tactics": get_all_tactics()}


@router.get("/frameworks/attack/{tactic_id}")
async def api_mitre_tactic(tactic_id: str, _principal=Depends(require_viewer)):
    """Get ATT&CK tactic details with techniques."""
    tactic = get_tactic(tactic_id)
    if not tactic:
        raise HTTPException(status_code=404, detail={"code": "not_found", "message": "Tactic not found", "details": {}})
    return tactic


@router.get("/frameworks/killchain")
async def api_kill_chain(_principal=Depends(require_viewer)):
    """Get Cyber Kill Chain phases."""
    return {"framework": "Cyber Kill Chain", "phases": get_all_phases()}


@router.get("/frameworks/killchain/{phase_number}")
async def api_kill_chain_phase(phase_number: int, _principal=Depends(require_viewer)):
    """Get Kill Chain phase details."""
    phase = get_phase(phase_number)
    if not phase:
        raise HTTPException(status_code=404, detail={"code": "not_found", "message": "Phase not found", "details": {}})
    return phase


@router.get("/frameworks/summary")
async def api_frameworks_summary(_principal=Depends(require_viewer)):
    """Get a summary of all available frameworks."""
    return {
        "frameworks": [
            {"name": "OWASP WSTG v4.2", "type": "owasp", "categories": len(owasp_categories()),
             "test_cases": len(get_all_test_cases())},
            {"name": "MITRE ATT&CK Enterprise", "type": "mitre", "tactics": len(get_all_tactics())},
            {"name": "Cyber Kill Chain", "type": "killchain", "phases": len(get_all_phases())},
        ],
        "tools": {"total": len(KALI_TOOLS), "categories": len(TOOL_CATEGORIES)},
        "ai_models": {"available": list(MODELS.keys()), "routing": MODEL_ROUTING},
    }
