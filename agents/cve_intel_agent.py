import asyncio
import re
from typing import Any, Dict, List

import aiohttp

from agents.base_agent import BaseSecurityAgent


class CVEIntelligenceAgent(BaseSecurityAgent):
    def __init__(self, nim_provider: Any, memory: Any, guardrails: Any):
        super().__init__("CVEIntelligenceAgent", "CVE monitoring and exploit intelligence specialist", nim_provider, memory, guardrails)
        self.cve_sources = {"nvd": "https://services.nvd.nist.gov/rest/json/cves/2.0"}

    async def reason(self, prompt: str) -> Dict[str, Any]:
        return {"steps": []}

    async def act(self, action_plan: Dict[str, Any]) -> Dict[str, Any]:
        return {}

    async def analyze_vulnerabilities(self, scan_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        vulns = scan_results.get("vulnerabilities", [])
        tasks = [self._enrich_vulnerability(v) for v in vulns]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        enriched = [r for r in results if not isinstance(r, Exception)]
        return sorted(enriched, key=lambda x: x.get("priority_score", 0), reverse=True)

    async def _enrich_vulnerability(self, vuln: Dict[str, Any]) -> Dict[str, Any]:
        cve_ids = self._extract_cve_ids(vuln)
        cve_data = await self._query_cve_sources(cve_ids[0]) if cve_ids else {"cvss_score": 5.0, "exploit_count": 0}
        priority_score = cve_data.get("cvss_score", 5.0) * (1.5 if cve_data.get("exploit_count", 0) > 0 else 1.0)
        return {"original_finding": vuln, "cve_ids": cve_ids, "cve_data": cve_data, "priority_score": priority_score}

    def _extract_cve_ids(self, vuln: Dict[str, Any]) -> List[str]:
        return re.findall(r"CVE-\d{4}-\d{4,7}", f"{vuln.get('name','')} {vuln.get('description','')}", re.IGNORECASE)

    async def _query_cve_sources(self, cve_id: str) -> Dict[str, Any]:
        data = {"cve_id": cve_id, "description": "", "cvss_score": 5.0, "exploit_count": 0}
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{self.cve_sources['nvd']}?cveId={cve_id}") as resp:
                if resp.status == 200:
                    payload = await resp.json()
                    if payload.get("vulnerabilities"):
                        cve = payload["vulnerabilities"][0]["cve"]
                        data["description"] = cve.get("descriptions", [{}])[0].get("value", "")
        return data
