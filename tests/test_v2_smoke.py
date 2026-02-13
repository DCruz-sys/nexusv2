import asyncio
import importlib
import os

from fastapi.testclient import TestClient


def _reload_v2_app(monkeypatch, tmp_path):
    monkeypatch.setenv("AUTH_ENABLED", "false")
    monkeypatch.setenv("NEXUS_V2_DATABASE_PATH", str(tmp_path / "nexus_v2_test.db"))
    monkeypatch.setenv("NEXUS_V2_ARTIFACTS_DIR", str(tmp_path / "artifacts"))

    # Ensure settings are re-read with the temp env.
    import nexus_v2.config as cfg

    cfg.get_settings.cache_clear()
    import nexus_v2.api.main as main

    importlib.reload(main)
    return main.app


def test_v2_create_engagement_scope_and_run(monkeypatch, tmp_path):
    app = _reload_v2_app(monkeypatch, tmp_path)
    with TestClient(app) as client:
        # Create engagement
        resp = client.post("/api/v2/engagements", json={"name": "test"})
        assert resp.status_code == 200, resp.text
        eng = resp.json()
        assert eng["id"].startswith("eng_")

        # Add scope
        resp = client.post(
            f"/api/v2/engagements/{eng['id']}/scope-rules",
            json={"type": "domain", "pattern": "example.com", "enabled": True},
        )
        assert resp.status_code == 200, resp.text

        # Create run
        resp = client.post(
            f"/api/v2/engagements/{eng['id']}/runs",
            json={"kind": "scan", "target": "example.com", "scan_mode": "quick"},
        )
        assert resp.status_code == 200, resp.text
        run = resp.json()
        assert run["id"].startswith("run_")

        # Events should include run_created/tasks_queued
        resp = client.get(f"/api/v2/runs/{run['id']}/events?since_seq=0")
        assert resp.status_code == 200, resp.text
        data = resp.json()
        types = [e["type"] for e in data["events"]]
        assert "run_created" in types
        assert "tasks_queued" in types


def test_v2_validate_finding_queues_tasks(monkeypatch, tmp_path):
    app = _reload_v2_app(monkeypatch, tmp_path)
    with TestClient(app) as client:
        resp = client.post("/api/v2/engagements", json={"name": "test"})
        eng = resp.json()
        client.post(
            f"/api/v2/engagements/{eng['id']}/scope-rules",
            json={"type": "domain", "pattern": "example.com", "enabled": True},
        )
        resp = client.post(
            f"/api/v2/engagements/{eng['id']}/runs",
            json={"kind": "scan", "target": "example.com", "scan_mode": "quick"},
        )
        run = resp.json()

        # Create a finding directly (API does not yet create findings automatically without worker execution).
        from nexus_v2.infra.repos.findings import create_finding

        finding = asyncio.run(
            create_finding(
                run_id=run["id"],
                title="WordPress detected (hypothesis)",
                category="technology",
                severity="info",
                state="hypothesis",
                confidence=0.55,
                summary="hypothesis",
                meta={"must_contain_any": ["wp-content"]},
            )
        )

        resp = client.post(f"/api/v2/findings/{finding['id']}/validate", json={"kind": "http_exchange"})
        assert resp.status_code == 200, resp.text
        payload = resp.json()
        assert payload["run_id"] == run["id"]
        assert len(payload["queued_tasks"]) == 2
