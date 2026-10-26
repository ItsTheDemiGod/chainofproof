import pytest

from chainofproof.config import get_paths


@pytest.fixture
def paths(tmp_path):
    p = get_paths(base_dir=tmp_path / "base")
    p.ensure_dirs()
    return p


@pytest.fixture
def make_file(tmp_path):
    def _make(name="a.txt", data=b"hello evidence"):
        f = tmp_path / "src" / name
        f.parent.mkdir(exist_ok=True)
        f.write_bytes(data)
        return f

    return _make
