"""Multi-model orchestration - routes tasks to optimal NVIDIA models."""
from app.config import MODEL_ROUTING, MODELS
from app.ai.guardrails import guardrails_manager
from app.ai.nim_client import nim_client


class ModelRouter:
    """Routes AI tasks to the best-fit NVIDIA model."""

    TASK_KEYWORDS = {
        "planning": ["plan", "strategy", "approach", "methodology", "pentest plan", "attack plan"],
        "strategy": ["prioritize", "risk assessment", "threat model"],
        "analysis": ["analyze", "interpret", "assess", "evaluate", "vulnerability"],
        "vulnerability_assessment": ["vuln", "cve", "exploit", "weakness", "flaw"],
        "reasoning": ["reason", "think", "chain of thought", "step by step", "deliberate"],
        "agentic_execution": ["execute", "agentic", "act", "autonomous", "run workflow"],
        "tool_planning": ["tool plan", "toolchain", "which tool", "sequence tools", "orchestrate tools"],
        "classification": ["classify", "categorize", "identify", "detect", "type"],
        "quick_lookup": ["what is", "define", "explain briefly", "quick"],
        "code_review": ["code", "script", "payload", "exploit code", "source", "review code"],
        "exploit_analysis": ["exploit", "poc", "proof of concept", "shellcode", "reverse"],
        "summarization": ["summarize", "summary", "brief", "overview", "tldr", "recap"],
        "report_generation": ["report", "document", "findings", "write up", "generate report"],
        "scan": ["scan", "nmap", "attack", "penetration test", "pentest", "assess target", "run scan"],
    }

    def classify_task(self, prompt: str) -> str:
        """Classify user prompt into a task type."""
        prompt_lower = prompt.lower()
        scores = {}
        for task_type, keywords in self.TASK_KEYWORDS.items():
            score = sum(1 for kw in keywords if kw in prompt_lower)
            if score > 0:
                scores[task_type] = score
        if scores:
            return max(scores, key=scores.get)
        return "general"

    def select_model(self, task_type: str) -> str:
        """Select the best model for a given task type."""
        return MODEL_ROUTING.get(task_type, "llama-3.1-70b")

    def route(self, prompt: str, force_model: str = None) -> tuple:
        """Route a prompt to the best model. Returns (model_key, task_type)."""
        task_type = self.classify_task(prompt)
        if force_model and force_model in MODELS:
            # Keep task classification stable even when the user pins a model.
            return force_model, task_type
        model_key = self.select_model(task_type)
        return model_key, task_type

    async def query(self, messages: list, task_type: str = None,
                    force_model: str = None, temperature: float = 0.7):
        """Route and execute a query."""
        if force_model:
            model_key = force_model
            task_type = task_type or "forced"
        elif task_type:
            model_key = self.select_model(task_type)
        else:
            prompt = messages[-1]["content"] if messages else ""
            model_key, task_type = self.route(prompt)

        response = await nim_client.chat_completion(
            messages,
            model_key=model_key,
            temperature=temperature,
            metadata={"task_type": task_type or "general", "router_model": model_key},
        )
        safe_response, violations = guardrails_manager.enforce_output_policy(response)
        return {
            "response": safe_response,
            "model": model_key,
            "task_type": task_type,
            "guardrail_violations": violations,
        }

    async def stream_query(self, messages: list, task_type: str = None,
                           force_model: str = None, temperature: float = 0.7):
        """Route and execute a streaming query."""
        if force_model:
            model_key = force_model
        elif task_type:
            model_key = self.select_model(task_type)
        else:
            prompt = messages[-1]["content"] if messages else ""
            model_key, task_type = self.route(prompt)

        async for token in nim_client.chat_completion_stream(
            messages,
            model_key=model_key,
            temperature=temperature,
            metadata={"task_type": task_type or "general", "router_model": model_key},
        ):
            yield token


# Singleton
model_router = ModelRouter()
