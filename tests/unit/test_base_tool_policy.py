import asyncio


from app.security.allowlist import TargetNotAllowedError
from tools.base_tool import BaseTool


class DummyTool(BaseTool):
    def __init__(self):
        super().__init__("dummy", "nmap", "dummy tool")

    async def execute(self, **kwargs):
        return ""

    def parse(self, output: str):
        return {}


class FakeProcess:
    def __init__(self, exit_code: int, stdout: bytes = b"", stderr: bytes = b""):
        self.returncode = exit_code
        self._stdout = stdout
        self._stderr = stderr

    async def communicate(self):
        return self._stdout, self._stderr


def test_run_command_blocks_denied_argument_without_approval(monkeypatch):
    tool = DummyTool()

    async def _allow(*_args, **_kwargs):
        return None

    async def _noop_audit(*_args, **_kwargs):
        return "hash"

    monkeypatch.setattr("tools.base_tool.require_target_allowed", _allow)
    monkeypatch.setattr("tools.base_tool.add_memory_audit_event", _noop_audit)

    result = asyncio.run(tool._run_command(["nmap", "--privileged", "example.com"], target="example.com", use_docker=False))

    assert result["success"] is False
    assert "blocked_by_policy:denied_argument" in result["error"]


def test_run_command_blocks_out_of_scope_target(monkeypatch):
    tool = DummyTool()

    async def _deny(*_args, **_kwargs):
        raise TargetNotAllowedError("blocked")

    async def _noop_audit(*_args, **_kwargs):
        return "hash"

    monkeypatch.setattr("tools.base_tool.require_target_allowed", _deny)
    monkeypatch.setattr("tools.base_tool.add_memory_audit_event", _noop_audit)

    result = asyncio.run(tool._run_command(["nmap", "example.com"], target="example.com", use_docker=False))

    assert result["success"] is False
    assert "blocked_by_policy" in result["error"]


def test_run_command_retries_until_success(monkeypatch):
    tool = DummyTool()
    calls = {"count": 0}

    async def _allow(*_args, **_kwargs):
        return None

    async def _noop_audit(*_args, **_kwargs):
        return "hash"

    async def _fake_exec(*_args, **_kwargs):
        calls["count"] += 1
        if calls["count"] == 1:
            return FakeProcess(exit_code=1, stderr=b"first failed")
        return FakeProcess(exit_code=0, stdout=b"ok")

    monkeypatch.setattr("tools.base_tool.require_target_allowed", _allow)
    monkeypatch.setattr("tools.base_tool.add_memory_audit_event", _noop_audit)
    monkeypatch.setattr(asyncio, "create_subprocess_exec", _fake_exec)

    result = asyncio.run(tool._run_command(["nmap", "example.com"], target="example.com", use_docker=False, retries=1))

    assert calls["count"] == 2
    assert result["success"] is True
    assert result["attempt"] == 2
