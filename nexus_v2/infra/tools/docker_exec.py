"""Docker/namespace tool execution adapter (stub).

v2 is designed so tool isolation can be swapped from host execution to a
container sandbox later. For now, host execution is the default.
"""

from __future__ import annotations


class DockerExecNotImplemented(RuntimeError):
    pass


async def run_tool_in_docker(*_args, **_kwargs):
    raise DockerExecNotImplemented("docker_executor_not_enabled")

