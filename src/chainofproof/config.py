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


class CloudSettings(BaseModel):
    enabled: bool = False
    provider: str = "none"
    groq_api_key: str = ""
    gemini_api_key: str = ""
    openrouter_api_key: str = ""


class Settings(BaseModel):
    ollama: OllamaSettings
    paths: PathSettings
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
    return s
