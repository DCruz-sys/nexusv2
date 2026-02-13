"""Report generation API - JSON, HTML, PDF formats."""
import uuid
import json
import re
from pathlib import Path
from datetime import datetime, timezone
import bleach
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from jinja2 import Environment, select_autoescape
from markupsafe import Markup

from app.config import REPORTS_DIR
from app.database import get_scan, get_scan_results, save_report, get_reports
from app.security.auth import require_operator, require_viewer

router = APIRouter(tags=["reports"])


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)

JINJA_ENV = Environment(autoescape=select_autoescape(default=True))
SAFE_RICH_TAGS = [
    "p",
    "br",
    "ul",
    "ol",
    "li",
    "strong",
    "em",
    "h2",
    "h3",
    "h4",
    "code",
    "pre",
]
SAFE_RICH_ATTRS = {"a": ["href", "title", "target", "rel"]}

HTML_REPORT_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Executive Security Assessment - {{ target }}</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&display=swap');
    :root {
        --primary: #00d4ff;
        --secondary: #0052cc;
        --bg: #050a14;
        --card-bg: rgba(17, 25, 40, 0.75);
        --border: rgba(255, 255, 255, 0.125);
        --text: #f0f4f8;
        --text-muted: #8899aa;
        --critical: #ff4757;
        --high: #ff6b35;
        --medium: #ffa502;
        --low: #2ed573;
        --info: #1e90ff;
    }
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { 
        font-family: 'Inter', sans-serif; 
        background-color: var(--bg); 
        color: var(--text); 
        line-height: 1.6;
        background-image: radial-gradient(circle at 50% -20%, #15243b 0%, #050a14 100%);
        background-attachment: fixed;
    }
    .container { max-width: 1200px; margin: 0 auto; padding: 60px 20px; }
    
    .glass-card {
        background: var(--card-bg);
        backdrop-filter: blur(16px);
        -webkit-backdrop-filter: blur(16px);
        border-radius: 12px;
        border: 1px solid var(--border);
        box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.37);
        padding: 30px;
        margin-bottom: 30px;
    }

    .header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        border-bottom: 2px solid var(--primary);
        padding-bottom: 20px;
        margin-bottom: 40px;
    }
    .header-logo { font-size: 32px; font-weight: 700; color: var(--primary); letter-spacing: -1px; }
    .header-meta { text-align: right; color: var(--text-muted); font-size: 14px; }

    .summary-grid { display: grid; grid-template-columns: 2fr 1fr; gap: 30px; }
    
    .stats-container { display: grid; grid-template-columns: repeat(5, 1fr); gap: 15px; margin-top: 20px; }
    .stat-box {
        text-align: center;
        padding: 15px;
        border-radius: 8px;
        border: 1px solid var(--border);
    }
    .stat-box .count { font-size: 32px; font-weight: 700; display: block; }
    .stat-box .label { font-size: 11px; text-transform: uppercase; color: var(--text-muted); margin-top: 5px; }

    .exec-summary { font-size: 18px; line-height: 1.8; color: #ced6e0; }
    .exec-summary h2 { color: var(--primary); margin-bottom: 15px; font-size: 24px; }
    
    .finding { margin-bottom: 20px; }
    .finding-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 15px 20px;
        background: rgba(255,255,255,0.03);
        border-radius: 8px 8px 0 0;
        cursor: pointer;
    }
    .finding-content {
        padding: 20px;
        background: rgba(255,255,255,0.01);
        border: 1px solid var(--border);
        border-top: none;
        border-radius: 0 0 8px 8px;
    }
    
    .badge { padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: 700; text-transform: uppercase; }
    .badge.critical { background: var(--critical); color: #fff; }
    .badge.high { background: var(--high); color: #fff; }
    .badge.medium { background: var(--medium); color: #fff; }
    .badge.low { background: var(--low); color: #fff; }
    
    pre { background: #000; padding: 15px; border-radius: 6px; font-size: 13px; color: #00ff00; overflow-x: auto; margin: 15px 0; border: 1px solid #333; }
    
    .chart-box { height: 250px; width: 100%; }
</style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="header-logo">NEXUS<span style="color:#fff">PENTEST</span></div>
            <div class="header-meta">
                <div>Report ID: {{ report_id }}</div>
                <div>Generated: {{ date }}</div>
            </div>
        </div>

        <div class="summary-grid">
            <div class="glass-card">
                <div class="exec-summary">
                    <h2>Executive Summary</h2>
                    {{ executive_summary|safe }}
                </div>
            </div>
            <div class="glass-card">
                <h3>Risk Distribution</h3>
                <div class="chart-box">
                    <canvas id="riskChart"></canvas>
                </div>
                <div class="stats-container">
                    <div class="stat-box" style="border-top: 4px solid var(--critical)"><span class="count">{{ counts.critical }}</span><span class="label">Crit</span></div>
                    <div class="stat-box" style="border-top: 4px solid var(--high)"><span class="count">{{ counts.high }}</span><span class="label">High</span></div>
                    <div class="stat-box" style="border-top: 4px solid var(--medium)"><span class="count">{{ counts.medium }}</span><span class="label">Med</span></div>
                </div>
            </div>
        </div>

        <div class="glass-card">
            <h2>Technical Findings</h2>
            {% for result in results %}
            <div class="finding">
                <div class="finding-header">
                    <span><strong>{{ result.tool_name }}</strong> &middot; {{ result.phase|capitalize }}</span>
                    <span class="badge {{ result.severity }}">{{ result.severity }}</span>
                </div>
                <div class="finding-content">
                    <p style="color: var(--text-muted); margin-bottom: 10px;">Command executed: <code>{{ result.command }}</code></p>
                    {% if result.output %}
                    <pre>{{ result.output[:2000] }}</pre>
                    {% endif %}
                    <div style="margin-top:20px; padding:15px; background:rgba(0,212,255,0.05); border-radius:6px;">
                        <strong style="color:var(--primary)">AI Analysis:</strong><br>
                        <p style="margin-top:10px; font-size:14px;">{{ result.findings_text }}</p>
                    </div>
                </div>
            </div>
            {% endfor %}
        </div>

        <div class="glass-card" style="border-left: 5px solid var(--primary);">
            <h2>CISO Strategic Roadmap</h2>
            <div style="margin-top:15px; font-size:15px; line-height:1.7;">
                {{ strategic_roadmap|safe }}
            </div>
        </div>
        
        <div style="text-align: center; color: var(--text-muted); font-size: 12px; margin-top: 40px;">
            CONFIDENTIAL - Internal Use Only &copy; 2026 NexusPenTest AI Operations
        </div>
    </div>

    <script>
        const ctx = document.getElementById('riskChart').getContext('2d');
        new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
                datasets: [{
                    data: [{{ counts.critical }}, {{ counts.high }}, {{ counts.medium }}, {{ counts.low }}, {{ counts.info }}],
                    backgroundColor: ['#ff4757', '#ff6b35', '#ffa502', '#2ed573', '#1e90ff'],
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                cutout: '70%'
            }
        });
    </script>
</body>
</html>"""


def _sanitize_report_html(raw_text: str) -> str:
    scrubbed = re.sub(r"(?is)<script[^>]*>.*?</script>", "", raw_text or "")
    scrubbed = re.sub(r"(?is)<style[^>]*>.*?</style>", "", scrubbed)
    cleaned = bleach.clean(
        scrubbed,
        tags=SAFE_RICH_TAGS,
        attributes=SAFE_RICH_ATTRS,
        protocols=["http", "https"],
        strip=True,
    )
    return cleaned[:12000]


@router.post("/reports/{scan_id}")
async def generate_report(scan_id: str, format: str = "json", _principal=Depends(require_operator)):
    """Generate a report for a completed scan."""
    scan = await get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail={"code": "not_found", "message": "Scan not found", "details": {}})

    results = await get_scan_results(scan_id)
    report_id = str(uuid.uuid4())
    timestamp = _utcnow().strftime("%Y%m%d_%H%M%S")

    # Count severities
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for r in results:
        sev = r.get("severity", "info")
        if sev in counts:
            counts[sev] += 1

    report_format = (format or "json").strip().lower()

    if report_format == "json":
        filename = f"report_{scan_id[:8]}_{timestamp}.json"
        filepath = REPORTS_DIR / filename
        report_data = {
            "report_id": report_id,
            "scan_id": scan_id,
            "target": scan["target"],
            "methodology": scan["methodology"],
            "status": scan["status"],
            "severity_counts": counts,
            "generated_at": _utcnow().isoformat(),
            "results": results,
        }
        filepath.write_text(json.dumps(report_data, indent=2, default=str))

    elif report_format == "html":
        filename = f"report_{scan_id[:8]}_{timestamp}.html"
        filepath = REPORTS_DIR / filename

        # Process findings text and prepare for AI summary
        findings_summary = []
        for r in results:
            try:
                f = json.loads(r.get("findings", "[]"))
                r["findings_text"] = "\n".join(f) if isinstance(f, list) else str(f)
                if r["severity"] in ["critical", "high", "medium"]:
                    findings_summary.append(f"- {r['tool_name']} ({r['severity']}): {r['findings_text'][:200]}")
            except Exception:
                r["findings_text"] = ""

        # AI-Driven CISO Content
        from app.ai.agent_swarm import agent_swarm
        summary_prompt = f"""Generate a professional CISO-ready Executive Summary for a pentest on {scan['target']}.
Results summary:
{chr(10).join(findings_summary)}
Respond with HTML formatted content (paragraphs, lists). Focus on risk and business impact."""
        
        roadmap_prompt = f"""Generate a Strategic Security Roadmap for {scan['target']} based on these findings:
{chr(10).join(findings_summary)}
Respond with HTML formatted content. Suggest 3 immediate steps and 2 long-term strategic goals."""

        swarm_outputs = await agent_swarm.swarm_executor.execute_graph([
            {"id": "exec_summary", "agent": "report", "priority": 10, "task": summary_prompt},
            {"id": "roadmap", "agent": "coordinator", "priority": 9, "task": roadmap_prompt},
        ])
        by_id = {row.get("task_id"): row for row in swarm_outputs}
        executive_summary = _sanitize_report_html(
            by_id.get("exec_summary", {}).get("response", "Pending audit review.")
        )
        strategic_roadmap = _sanitize_report_html(
            by_id.get("roadmap", {}).get("response", "Strategic assessment required.")
        )

        template = JINJA_ENV.from_string(HTML_REPORT_TEMPLATE)
        html = template.render(
            report_id=report_id,
            target=scan["target"],
            methodology=scan["methodology"],
            date=_utcnow().strftime("%Y-%m-%d %H:%M UTC"),
            counts=counts,
            results=results,
            executive_summary=Markup(executive_summary),
            strategic_roadmap=Markup(strategic_roadmap),
        )
        filepath.write_text(html, encoding="utf-8")

    elif report_format == "pdf":
        # Generate HTML first, then convert to PDF
        filename = f"report_{scan_id[:8]}_{timestamp}.pdf"
        filepath = REPORTS_DIR / filename

        for r in results:
            try:
                f = json.loads(r.get("findings", "[]"))
                r["findings_text"] = "\n".join(f) if isinstance(f, list) else str(f)
            except Exception:
                r["findings_text"] = ""

        template = JINJA_ENV.from_string(HTML_REPORT_TEMPLATE)
        html = template.render(
            report_id=report_id,
            target=scan["target"],
            methodology=scan["methodology"],
            date=_utcnow().strftime("%Y-%m-%d %H:%M UTC"),
            counts=counts,
            results=results,
            executive_summary="",
            strategic_roadmap="",
        )

        try:
            from fpdf import FPDF
            pdf = FPDF()
            pdf.set_auto_page_break(auto=True, margin=15)
            pdf.add_page()
            pdf.set_font("Helvetica", "B", 18)
            pdf.cell(0, 12, "NexusPenTest Security Report", new_x="LMARGIN", new_y="NEXT", align="C")
            pdf.set_font("Helvetica", "", 11)
            pdf.cell(0, 8, f"Target: {scan['target']}", new_x="LMARGIN", new_y="NEXT")
            pdf.cell(0, 8, f"Methodology: {scan['methodology'].upper()}", new_x="LMARGIN", new_y="NEXT")
            pdf.cell(0, 8, f"Date: {_utcnow().strftime('%Y-%m-%d %H:%M UTC')}", new_x="LMARGIN", new_y="NEXT")
            pdf.ln(5)
            pdf.set_font("Helvetica", "B", 14)
            pdf.cell(0, 10, "Severity Summary", new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Helvetica", "", 11)
            for sev, cnt in counts.items():
                pdf.cell(0, 7, f"  {sev.capitalize()}: {cnt}", new_x="LMARGIN", new_y="NEXT")
            pdf.ln(5)
            pdf.set_font("Helvetica", "B", 14)
            pdf.cell(0, 10, "Findings", new_x="LMARGIN", new_y="NEXT")
            for r in results:
                pdf.set_font("Helvetica", "B", 11)
                pdf.cell(0, 8, f"{r['tool_name']} [{r['severity']}]", new_x="LMARGIN", new_y="NEXT")
                pdf.set_font("Helvetica", "", 9)
                pdf.cell(0, 6, f"Command: {r['command']}", new_x="LMARGIN", new_y="NEXT")
                if r.get("output"):
                    output_text = r["output"][:2000].encode("latin-1", "replace").decode("latin-1")
                    pdf.multi_cell(0, 5, output_text)
                pdf.ln(3)
            pdf.output(str(filepath))
        except Exception as e:
            # Fallback: save as HTML
            filename = filename.replace(".pdf", ".html")
            filepath = REPORTS_DIR / filename
            filepath.write_text(html, encoding="utf-8")

    else:
        raise HTTPException(
            status_code=400,
            detail={"code": "invalid_format", "message": f"Unsupported format: {format}", "details": {}},
        )

    await save_report(report_id, scan_id, report_format, filename, str(filepath))

    return {
        "report_id": report_id,
        "scan_id": scan_id,
        "format": report_format,
        "filename": filename,
        "download_url": f"/api/reports/download/{report_id}",
    }


@router.get("/reports")
async def api_list_reports(scan_id: str = None, _principal=Depends(require_viewer)):
    """List all reports, optionally filtered by scan_id."""
    reports = await get_reports(scan_id)
    return {"reports": reports}


@router.get("/reports/download/{report_id}")
async def download_report(report_id: str, _principal=Depends(require_viewer)):
    """Download a generated report."""
    reports = await get_reports()
    for r in reports:
        if r["id"] == report_id:
            filepath = Path(r["file_path"])
            if filepath.exists():
                media_type = {
                    "json": "application/json",
                    "html": "text/html",
                    "pdf": "application/pdf",
                }.get(r["format"], "application/octet-stream")
                return FileResponse(str(filepath), filename=r["filename"], media_type=media_type)
    raise HTTPException(status_code=404, detail={"code": "not_found", "message": "Report not found", "details": {}})
