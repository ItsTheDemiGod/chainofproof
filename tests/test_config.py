from pathlib import Path

from chainofproof.config import PROJECT_ROOT, load_settings


def test_settings_values():
    s = load_settings()
    assert s.ollama.host.startswith("http")
    assert s.ollama.default_model == "qwen2.5:7b-instruct"
    assert s.ollama.secondary_model == "llama3.1:8b"
    assert s.ollama.temperature == 0
    assert s.ollama.num_ctx == 8192
    assert s.ollama.seed == 42
    assert s.optional_cloud.enabled is False
    assert s.optional_cloud.provider == "none"


def test_paths_resolved_to_project_root():
    s = load_settings()
    assert s.paths.evidence_raw == PROJECT_ROOT / "data" / "evidence_raw"
    assert all(Path(p).is_absolute() for p in s.paths.model_dump().values())
