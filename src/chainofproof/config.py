"""Settings model and loader for config/settings.yaml (+ optional .env overrides)."""

from __future__ import annotations

import os
from pathlib import Path

import yaml
from dotenv import load_dotenv
from pydantic import BaseModel

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SETTINGS_PATH = PROJECT_ROOT / "config" / "settings.yaml"


class OllamaSettings(BaseModel):
    host: str = "http://localhost:11434"
    default_model: str = "qwen2.5:7b-instruct"
    secondary_model: str = "llama3.1:8b"
    temperature: float = 0
    num_ctx: int = 8192
    seed: int = 42


class PathSettings(BaseModel):
    evidence_raw: Path
    evidence_working: Path
    db: Path
    ledger: Path
    runs: Path
    scenarios: Path


class Paths(BaseModel):
    """All data folders used by the code; tests build one under tmp_path."""

    base_dir: Path
    evidence_raw: Path
    evidence_working: Path
    db_dir: Path
    ledger_dir: Path
    runs_dir: Path

    @property
    def db_path(self) -> Path:
        """SQLite database file."""
        return self.db_dir / "chainofproof.db"

    @property
    def ledger_path(self) -> Path:
        """Append-only JSONL ledger file."""
        return self.ledger_dir / "ledger.jsonl"

    def ensure_dirs(self) -> None:
        """Create all data folders if missing."""
        for p in (self.evidence_raw, self.evidence_working, self.db_dir, self.ledger_dir):
            p.mkdir(parents=True, exist_ok=True)
        self.runs_dir.mkdir(parents=True, exist_ok=True)


class ToolsSettings(BaseModel):
    """External forensic tools (Phase 3). ``hayabusa_dir`` is resolved against the project root."""

    hayabusa_dir: Path = Path("tools_bin/hayabusa")
    timeout_seconds: int = 300
    exe_glob: str = "hayabusa*.exe"  # tests point this at a fake executable


class TimestompParams(BaseModel):
    """timestomp detector parameters."""

    min_delta_seconds: float = 3600


class ClockSkewParams(BaseModel):
    """clock_skew detector parameters."""

    min_abs_delta_seconds: float = 2.0
    min_independent_pairs: int = 2
    agreement_seconds: float = 1.0
    pair_window_seconds: float = 900.0


class LogGapParams(BaseModel):
    """log_gap detector parameters."""

    max_other_events_listed: int = 10


class LogClearParams(BaseModel):
    """log_clear detector parameters."""

    window_seconds: float = 60


class UnmatchedConnectionParams(BaseModel):
    """unmatched_connection detector parameters (none)."""


class DetectorSettings(BaseModel):
    """Defaults of every detector (section ``detectors`` of settings.yaml)."""

    timestomp: TimestompParams = TimestompParams()
    clock_skew: ClockSkewParams = ClockSkewParams()
    log_gap: LogGapParams = LogGapParams()
    log_clear: LogClearParams = LogClearParams()
    unmatched_connection: UnmatchedConnectionParams = UnmatchedConnectionParams()


class CloudSettings(BaseModel):
    enabled: bool = False
    provider: str = "none"
    groq_api_key: str = ""
    gemini_api_key: str = ""
    openrouter_api_key: str = ""


class Settings(BaseModel):
    ollama: OllamaSettings
    paths: PathSettings
    tools: ToolsSettings = ToolsSettings()
    detectors: DetectorSettings = DetectorSettings()
    optional_cloud: CloudSettings = CloudSettings()
    project_root: Path = PROJECT_ROOT


def load_settings(path: Path = SETTINGS_PATH, env_path: Path | None = None) -> Settings:
    """Load settings.yaml, resolve data paths against the project root, apply .env overrides.

    Recognised env vars: OLLAMA_HOST, GROQ_API_KEY, GEMINI_API_KEY, OPENROUTER_API_KEY.
    """
    load_dotenv(env_path or PROJECT_ROOT / ".env")
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    s = Settings.model_validate(raw)
    s.ollama.host = os.environ.get("OLLAMA_HOST") or s.ollama.host
    c = s.optional_cloud
    c.groq_api_key = os.environ.get("GROQ_API_KEY", "")
    c.gemini_api_key = os.environ.get("GEMINI_API_KEY", "")
    c.openrouter_api_key = os.environ.get("OPENROUTER_API_KEY", "")
    for name in PathSettings.model_fields:
        p = getattr(s.paths, name)
        setattr(s.paths, name, p if p.is_absolute() else s.project_root / p)
    hd = s.tools.hayabusa_dir
    s.tools.hayabusa_dir = hd if hd.is_absolute() else s.project_root / hd
    return s


def get_paths(settings: Settings | None = None, base_dir: Path | None = None) -> Paths:
    """Build a Paths object from an explicit base_dir (tests) or from settings.yaml.

    With base_dir, the standard layout (evidence_raw, evidence_working, db, ledger, runs)
    is created under it, so the real data/ folder is never touched.
    """
    if base_dir is not None:
        b = Path(base_dir).resolve()
        return Paths(
            base_dir=b,
            evidence_raw=b / "evidence_raw",
            evidence_working=b / "evidence_working",
            db_dir=b / "db",
            ledger_dir=b / "ledger",
            runs_dir=b / "runs",
        )
    s = settings or load_settings()
    p = s.paths
    return Paths(
        base_dir=p.evidence_raw.parent,
        evidence_raw=p.evidence_raw,
        evidence_working=p.evidence_working,
        db_dir=p.db,
        ledger_dir=p.ledger,
        runs_dir=p.runs,
    )
