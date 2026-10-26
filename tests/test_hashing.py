import hashlib

import pytest

from chainofproof.custody.hashing import (
    canonical_json,
    iso_utc,
    sha256_bytes,
    sha256_file,
    sha256_json,
    sha256_text,
    utc_now,
)


def test_vectors():
    assert sha256_text("") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert sha256_bytes(b"abc") == hashlib.sha256(b"abc").hexdigest()
    assert sha256_text("abc").startswith("ba7816bf")


def test_file_hash_multi_mb(tmp_path):
    f = tmp_path / "big.bin"
    data = b"0123456789abcdef" * (3 * 1024 * 1024 // 16) + b"tail"
    f.write_bytes(data)
    assert sha256_file(f) == hashlib.sha256(data).hexdigest()


def test_canonical_json():
    assert canonical_json({"b": 1, "a": [1, 2]}) == canonical_json({"a": [1, 2], "b": 1})
    assert canonical_json({"a": "é"}) == '{"a":"é"}'
    assert sha256_json({"x": 1, "y": 2}) == sha256_json({"y": 2, "x": 1})
    with pytest.raises(TypeError, match="not JSON-serializable"):
        canonical_json({"a": object()})


def test_time():
    now = utc_now()
    assert now.tzinfo is not None
    s = iso_utc(now)
    assert s.endswith("Z") and "." in s
