"""Application configuration from environment variables."""
import json
import os
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
from app.system.env_normalizer import normalize_env_file

ENV_NORMALIZED_KEYS = normalize_env_file(BASE_DIR / ".env")
_normalized_from_shell: list[str] = []
shell_norm_raw = (os.getenv("NEXUS_ENV_NORMALIZED_KEYS_JSON", "") or "").strip()
if shell_norm_raw:
    try:
        parsed = json.loads(shell_norm_raw)
        if isinstance(parsed, dict):
            candidate = parsed.get("normalized_keys") or []
            if isinstance(candidate, list):
                _normalized_from_shell = [str(x) for x in candidate]
        elif isinstance(parsed, list):
            _normalized_from_shell = [str(x) for x in parsed]
    except Exception:
        _normalized_from_shell = []
if not ENV_NORMALIZED_KEYS and _normalized_from_shell:
    ENV_NORMALIZED_KEYS = _normalized_from_shell
load_dotenv()


def _as_bool(name: str, default: bool = False) -> bool:
    val = os.getenv(name, str(default))
    return str(val).strip().lower() in {"1", "true", "yes", "on"}


def _as_csv_set(name: str) -> set[str]:
    raw = os.getenv(name, "")
    parts = [p.strip().lower() for p in str(raw).split(",")]
    return {p for p in parts if p}

# NVIDIA NIM API
NVIDIA_API_KEY = os.getenv("NVIDIA_API_KEY", "")
NVIDIA_BASE_URL = os.getenv("NVIDIA_BASE_URL", "https://integrate.api.nvidia.com/v1")

# Available NVIDIA NIM models
MODELS = {
    "llama-3.1-405b": "meta/llama-3.1-405b-instruct",
    "llama-3.1-70b": "meta/llama-3.1-70b-instruct",
    "llama-3.1-8b": "meta/llama-3.1-8b-instruct",
    "deepseek-r1": "deepseek-ai/deepseek-r1",
    "mistral-large": "mistralai/mistral-large-2-instruct",
    "kimi-k2": "moonshotai/kimi-k2-instruct",
    # Reasoning and agentic models from NVIDIA Build catalog
    "gpt-oss-20b": "openai/gpt-oss-20b",
    "nemotron-3-nano-30b-a3b": "nvidia/nemotron-3-nano-30b-a3b",
    "deepseek-v3.1": "deepseek-ai/deepseek-v3_1",
    "deepseek-v3.2": "deepseek-ai/deepseek-v3_2",
    "kimi-k2.5": "moonshotai/kimi-k2.5",
    "glm4.7": "z-ai/glm4_7",
    "devstral-2-123b": "mistralai/devstral-2-123b-instruct-2512",
}

# Model routing preferences by task type
MODEL_ROUTING = {
    "planning": "llama-3.1-70b",
    "strategy": "llama-3.1-70b",
    "analysis": "llama-3.1-70b",
    "vulnerability_assessment": "llama-3.1-70b",
    "classification": "llama-3.1-8b",
    "quick_lookup": "llama-3.1-8b",
    "code_review": "deepseek-r1",
    "exploit_analysis": "deepseek-r1",
    "summarization": "mistral-large",
    "report_generation": "mistral-large",
    "reasoning": "deepseek-v3.2",
    "agentic_execution": "nemotron-3-nano-30b-a3b",
    "tool_planning": "nemotron-3-nano-30b-a3b",
    "general": "llama-3.1-8b",
    "chat": "llama-3.1-8b",
}

# Server
HOST = os.getenv("HOST", "127.0.0.1")
PORT = int(os.getenv("PORT", "8000"))
KALI_ONLY_ENFORCE = _as_bool("KALI_ONLY_ENFORCE", True)

# Authentication and authorization
AUTH_ENABLED = _as_bool("AUTH_ENABLED", True)
AUTH_JWT_SECRET = os.getenv("AUTH_JWT_SECRET", "change-me-in-production")
AUTH_JWT_ALG = os.getenv("AUTH_JWT_ALG", "HS256")
AUTH_ACCESS_TOKEN_MIN = int(os.getenv("AUTH_ACCESS_TOKEN_MIN", "60"))
AUTH_ADMIN_USERNAME = os.getenv("AUTH_ADMIN_USERNAME", "admin")
AUTH_ADMIN_PASSWORD = os.getenv("AUTH_ADMIN_PASSWORD", "")
AUTH_BOOTSTRAP_API_KEY = os.getenv("AUTH_BOOTSTRAP_API_KEY", "")

# Chat safety controls
CHAT_AUTO_ALLOWLIST_ENABLED = _as_bool("CHAT_AUTO_ALLOWLIST_ENABLED", False)
CHAT_AUTO_ALLOWLIST_DOMAINS = _as_csv_set("CHAT_AUTO_ALLOWLIST_DOMAINS")

# Database
DATABASE_PATH = BASE_DIR / os.getenv("DATABASE_PATH", "data/nexus.db")
SQLITE_BUSY_TIMEOUT_MS = int(os.getenv("SQLITE_BUSY_TIMEOUT_MS", "5000"))
SQLITE_RETRY_ATTEMPTS = int(os.getenv("SQLITE_RETRY_ATTEMPTS", "3"))
SQLITE_RETRY_BACKOFF_MS = int(os.getenv("SQLITE_RETRY_BACKOFF_MS", "120"))

# Reports
REPORTS_DIR = BASE_DIR / os.getenv("REPORTS_DIR", "reports")
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

# Tool execution
TOOL_TIMEOUT = int(os.getenv("TOOL_TIMEOUT", "300"))  # seconds
MAX_CONCURRENT_TOOLS = int(os.getenv("MAX_CONCURRENT_TOOLS", "2"))
TARGET_ENFORCEMENT_ENABLED = _as_bool("TARGET_ENFORCEMENT_ENABLED", True)
HITL_ENFORCE = _as_bool("HITL_ENFORCE", True)

# Memory manager
MEMORY_RETRIEVAL_LIMIT = int(os.getenv("MEMORY_RETRIEVAL_LIMIT", "6"))
MEMORY_CANDIDATE_LIMIT = int(os.getenv("MEMORY_CANDIDATE_LIMIT", "250"))
MEMORY_MIN_SCORE = float(os.getenv("MEMORY_MIN_SCORE", "0.35"))
MEMORY_MAX_ITEMS = int(os.getenv("MEMORY_MAX_ITEMS", "5000"))
MEMORY_DECAY_DAYS = int(os.getenv("MEMORY_DECAY_DAYS", "7"))
MEMORY_ENABLE_NIM_EXTRACTION = _as_bool("MEMORY_ENABLE_NIM_EXTRACTION", True)
MEMORY_EXTRACTION_MODEL = os.getenv("MEMORY_EXTRACTION_MODEL", "llama-3.1-8b")
MEMORY_MAINTENANCE_INTERVAL_MIN = int(os.getenv("MEMORY_MAINTENANCE_INTERVAL_MIN", "360"))
MEMORY_AUTO_MAINTENANCE = _as_bool("MEMORY_AUTO_MAINTENANCE", True)
MEMORY_WRITE_SECRET = os.getenv("MEMORY_WRITE_SECRET", "")
MEMORY_RANKER_BIN = os.getenv("MEMORY_RANKER_BIN", str(BASE_DIR / "bin" / "memory_ranker"))
ACCELERATOR_TIMEOUT_MS = int(os.getenv("ACCELERATOR_TIMEOUT_MS", "1200"))
MEMORY_CHAT_SCOPE = (os.getenv("MEMORY_CHAT_SCOPE", "global") or "global").strip().lower()
if MEMORY_CHAT_SCOPE not in {"session", "global"}:
    MEMORY_CHAT_SCOPE = "global"
CHAT_SESSION_PERSIST = _as_bool("CHAT_SESSION_PERSIST", True)

# Swarm orchestration
SWARM_PLANNER_BIN = os.getenv("SWARM_PLANNER_BIN", str(BASE_DIR / "bin" / "swarm_planner"))
SWARM_MAX_PARALLEL = int(os.getenv("SWARM_MAX_PARALLEL", "4"))
SWARM_TASK_TIMEOUT_SEC = int(os.getenv("SWARM_TASK_TIMEOUT_SEC", "90"))
SWARM_MAX_RETRIES = int(os.getenv("SWARM_MAX_RETRIES", "1"))
SWARM_AUTONOMOUS_LEARNING_COOLDOWN_MIN = int(os.getenv("SWARM_AUTONOMOUS_LEARNING_COOLDOWN_MIN", "60"))

# Runtime feature flags
ENABLE_CRAWLER = _as_bool("ENABLE_CRAWLER", True)
ENABLE_AUTONOMOUS_EXECUTION = _as_bool("ENABLE_AUTONOMOUS_EXECUTION", True)
ENABLE_NATIVE_ACCELERATORS = _as_bool("ENABLE_NATIVE_ACCELERATORS", True)
ENABLE_DISTILLATION_PIPELINE = _as_bool("ENABLE_DISTILLATION_PIPELINE", True)
RUNTIME_PROFILE = (os.getenv("RUNTIME_PROFILE", "kali_8gb_balanced") or "kali_8gb_balanced").strip()
NEMO_GUARDRAILS_ENABLED = _as_bool("NEMO_GUARDRAILS_ENABLED", True)
NEMO_GUARDRAILS_CONFIG_PATH = os.getenv("NEMO_GUARDRAILS_CONFIG_PATH", "app/ai/rails")
NIM_STATELESS_METADATA = _as_bool("NIM_STATELESS_METADATA", True)

# Job workers and queue limits
JOB_RUNNER_MODE = (os.getenv("JOB_RUNNER_MODE", "embedded") or "embedded").strip().lower()
if JOB_RUNNER_MODE not in {"embedded", "external"}:
    JOB_RUNNER_MODE = "embedded"
WORKER_HEARTBEAT_SEC = int(os.getenv("WORKER_HEARTBEAT_SEC", "20"))
SCAN_WORKERS = int(os.getenv("SCAN_WORKERS", "1"))
CRAWLER_WORKERS = int(os.getenv("CRAWLER_WORKERS", "1"))
ANALYSIS_WORKERS = int(os.getenv("ANALYSIS_WORKERS", "1"))
MAX_PENDING_SCANS = int(os.getenv("MAX_PENDING_SCANS", "12"))
MAX_PENDING_CRAWL = int(os.getenv("MAX_PENDING_CRAWL", "8"))
MAX_PENDING_EXTRACT = int(os.getenv("MAX_PENDING_EXTRACT", "40"))
MAX_PENDING_DISTILL = int(os.getenv("MAX_PENDING_DISTILL", "6"))
MAX_PENDING_MAINTENANCE = int(os.getenv("MAX_PENDING_MAINTENANCE", "10"))
MAX_PENDING_REPORT = int(os.getenv("MAX_PENDING_REPORT", "20"))
JOB_LEASE_SECONDS = int(os.getenv("JOB_LEASE_SECONDS", "300"))
JOB_HEARTBEAT_SECONDS = int(os.getenv("JOB_HEARTBEAT_SECONDS", "30"))

# Scheduling
SCHEDULE_CRAWL_INTERVAL_HOURS = int(os.getenv("SCHEDULE_CRAWL_INTERVAL_HOURS", "24"))
SCHEDULE_MAINTENANCE_INTERVAL_HOURS = int(os.getenv("SCHEDULE_MAINTENANCE_INTERVAL_HOURS", "6"))
SCHEDULE_DISTILL_INTERVAL_HOURS = int(os.getenv("SCHEDULE_DISTILL_INTERVAL_HOURS", "24"))

# Crawler quotas
CRAWL_MAX_PAGES_PER_DAY = int(os.getenv("CRAWL_MAX_PAGES_PER_DAY", "300"))
CRAWL_MAX_PAGES_PER_DOMAIN = int(os.getenv("CRAWL_MAX_PAGES_PER_DOMAIN", "20"))
CRAWL_MAX_DEPTH = int(os.getenv("CRAWL_MAX_DEPTH", "2"))
CRAWL_MAX_DOC_BYTES = int(os.getenv("CRAWL_MAX_DOC_BYTES", "1000000"))
CRAWL_FETCH_TIMEOUT_SEC = int(os.getenv("CRAWL_FETCH_TIMEOUT_SEC", "20"))
CRAWL_BLOCK_PRIVATE_NETWORKS = _as_bool("CRAWL_BLOCK_PRIVATE_NETWORKS", True)
CRAWL_STORE_MAX_CHARS = int(os.getenv("CRAWL_STORE_MAX_CHARS", "50000"))
CRAWL_LINKS_PER_PAGE = int(os.getenv("CRAWL_LINKS_PER_PAGE", "80"))
CRAWL_FOCUSED_ALLOW_SUBDOMAINS = _as_bool("CRAWL_FOCUSED_ALLOW_SUBDOMAINS", True)
CRAWL_FOCUSED_WWW_ALIAS = _as_bool("CRAWL_FOCUSED_WWW_ALIAS", True)
CRAWL_ROBOTS_CACHE = _as_bool("CRAWL_ROBOTS_CACHE", True)

# Retention
CRAWL_LOW_CONF_TTL_DAYS = int(os.getenv("CRAWL_LOW_CONF_TTL_DAYS", "14"))
CRAWL_MEDIUM_CONF_TTL_DAYS = int(os.getenv("CRAWL_MEDIUM_CONF_TTL_DAYS", "60"))

# System metadata
DEADCODE_REPORT_PATH = BASE_DIR / os.getenv("DEADCODE_REPORT_PATH", "reports/deadcode_report.json")

# NIM client resilience
NIM_MAX_RETRIES = int(os.getenv("NIM_MAX_RETRIES", "3"))
NIM_BACKOFF_BASE_MS = int(os.getenv("NIM_BACKOFF_BASE_MS", "250"))
NIM_CIRCUIT_FAIL_THRESHOLD = int(os.getenv("NIM_CIRCUIT_FAIL_THRESHOLD", "5"))
NIM_CIRCUIT_RESET_SEC = int(os.getenv("NIM_CIRCUIT_RESET_SEC", "30"))

# NVIDIA NeMo Retriever (cloud endpoints) for reranking/embeddings.
NVIDIA_RETRIEVAL_BASE_URL = os.getenv("NVIDIA_RETRIEVAL_BASE_URL", "https://ai.api.nvidia.com").rstrip("/")

# Knowledge base (crawled passages) settings.
KB_ENABLE_FTS = _as_bool("KB_ENABLE_FTS", True)
KB_PASSAGE_CHARS = int(os.getenv("KB_PASSAGE_CHARS", "1200"))
KB_PASSAGE_OVERLAP_CHARS = int(os.getenv("KB_PASSAGE_OVERLAP_CHARS", "200"))
KB_MAX_PASSAGES_PER_DOC = int(os.getenv("KB_MAX_PASSAGES_PER_DOC", "30"))
KB_RETRIEVAL_LIMIT = int(os.getenv("KB_RETRIEVAL_LIMIT", "6"))
KB_RETRIEVAL_CANDIDATES = int(os.getenv("KB_RETRIEVAL_CANDIDATES", "25"))
KB_RERANK_ENABLED = _as_bool("KB_RERANK_ENABLED", False)
KB_RERANK_MODEL = os.getenv("KB_RERANK_MODEL", "nvidia/rerank-qa-mistral-4b")

# Autonomous learning sources (persistent background upskilling).
LEARNING_SOURCE_AUTONOMOUS_ENABLED = _as_bool("LEARNING_SOURCE_AUTONOMOUS_ENABLED", True)
LEARNING_DEFAULT_PROFILE = (os.getenv("LEARNING_DEFAULT_PROFILE", "aggressive_deep") or "aggressive_deep").strip().lower()
if LEARNING_DEFAULT_PROFILE not in {"aggressive_deep", "balanced", "conservative"}:
    LEARNING_DEFAULT_PROFILE = "aggressive_deep"
LEARNING_SOURCE_BATCH_SIZE = int(os.getenv("LEARNING_SOURCE_BATCH_SIZE", "40"))
LEARNING_SOURCE_RECRAWL_INTERVAL_MIN = int(os.getenv("LEARNING_SOURCE_RECRAWL_INTERVAL_MIN", "360"))
LEARNING_SOURCE_MAX_CONSECUTIVE_FAILURES = int(os.getenv("LEARNING_SOURCE_MAX_CONSECUTIVE_FAILURES", "5"))
LEARNING_SOURCE_DISTILL_MIN_NEW_DOCS = int(os.getenv("LEARNING_SOURCE_DISTILL_MIN_NEW_DOCS", "20"))
