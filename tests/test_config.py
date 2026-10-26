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


def test_get_paths_from_base_dir(tmp_path):
    from chainofproof.config import get_paths

    p = get_paths(base_dir=tmp_path)
    assert p.base_dir == tmp_path.resolve()
    assert p.db_path == p.db_dir / "chainofproof.db"
    assert p.ledger_path == p.ledger_dir / "ledger.jsonl"
    assert PROJECT_ROOT not in p.evidence_raw.parents


def test_get_paths_from_settings():
    from chainofproof.config import get_paths

    p = get_paths()
    assert p.evidence_raw == PROJECT_ROOT / "data" / "evidence_raw"
    assert p.db_path == PROJECT_ROOT / "data" / "db" / "chainofproof.db"
