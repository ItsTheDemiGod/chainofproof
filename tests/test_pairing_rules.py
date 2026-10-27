"""Rules R1 to R3: synthetic records never assert what the paired real evidence does not show."""

from datetime import timedelta

import pytest
from pydantic import ValidationError

from chainofproof.scenarios.companions import (
    Pairing,
    parse_auth_log,
    parse_fs_csv,
    parse_marker,
    parse_ts,
    row_marker,
)
from chainofproof.schemas.scenario import SupportingRef, Variant

HOSTS = ("ws_fin_07", "srv_file_02", "dc_01")
ATTACK_NAMES = ("mimikatz", "sekurlsa", "psexec", "psexesvc", "ps_stager")
ATTACK_EVENTS = ("NAMED_PIPE_OPEN", "DIRECTORY_REPLICATION_REQUEST", "SMB_ADMIN_SHARE_CONNECT")


def _fs(v2, variant):
    return {
        (f"fs_{h}", int(r["record_id"])): r
        for h in HOSTS
        for r in parse_fs_csv(v2.dirs[variant] / f"fs_{h}.csv")
    }


def _auth(v2, variant):
    return {
        (f"auth_{h}", int(r["seq"])): r
        for h in HOSTS
        for r in parse_auth_log(v2.dirs[variant] / f"auth_{h}.log")
    }


def _synthetic_refs(v2, variant):
    real = {s.source_key for s in v2.scn.sources if not s.is_synthetic}
    return {
        (r.source_key, r.event_record_id): r
        for a in v2.keys[variant].actions
        for r in a.supporting_refs
        if r.source_key not in real
    }


def _slot(v2, source_key, pad=0):
    ts = [v2.aligned(source_key, r) for r in v2.rows(source_key)]
    return min(ts) - timedelta(seconds=pad), max(ts) + timedelta(seconds=pad)


@pytest.mark.parametrize("variant", list(Variant))
def test_r1_every_attacker_record_is_paired_or_synthetic_only(v2, variant):
    files = {**_fs(v2, variant), **_auth(v2, variant)}
    refs = _synthetic_refs(v2, variant)
    marked = {k for k, r in files.items() if row_marker(r) is not None}
    assert marked == set(refs), "marked records and key refs must be the same set"
    for k, ref in refs.items():
        mk = row_marker(files[k])
        assert ref.synthetic_only == (mk is True)
        if not ref.synthetic_only:
            assert (ref.pairing_field, ref.pairing_value) == mk
    # nothing that looks like attacker activity is left unmarked
    for k, r in files.items():
        if k in refs:
            continue
        assert not any(n in r.get("path", "").lower() for n in ATTACK_NAMES)
        assert r.get("event") not in ATTACK_EVENTS


def test_r1_pairing_values_exist_in_the_real_rows(v2):
    refs = _synthetic_refs(v2, Variant.clean)
    paired = [r for r in refs.values() if r.is_paired]
    assert len(paired) >= 6
    for ref in paired:
        rows = (
            {r["record_id"]: r for r in v2.rows(ref.paired_source_key)}
            if (ref.pairing_field != "logon_id")
            else {}
        )
        for rid in ref.paired_record_ids:
            if ref.pairing_field == "logon_id":  # logon ids are not in the inspection rows
                assert any(
                    rid == e.record_id and ref.paired_source_key == sk.source_key
                    for sk in v2.inv.key_events
                    for e in sk.result.events
                )
            elif ref.pairing_field == "pipe_name":
                assert rows[rid]["pipe_name"].lstrip("\\") == ref.pairing_value
            else:
                names = {rows[rid].get(k, "").lower() for k in ("image", "source_image")}
                assert ref.pairing_value in names


def test_r1_synthetic_only_records_are_declared_in_the_key(v2):
    only = [r for r in _synthetic_refs(v2, Variant.clean).values() if r.synthetic_only]
    assert [(r.source_key) for r in only] == ["fs_ws_fin_07"]  # the credential-dump output file


def test_r2_nothing_psexec_in_the_s3_slot(v2):
    lo, hi = _slot(v2, "s3_psexec_smb", pad=60)
    names = {
        v.lower().lstrip("\\")
        for r in v2.rows("s3_psexec_smb")
        for k, v in r.items()
        if k in ("image", "parent_image", "source_image", "pipe_name") and isinstance(v, str)
    }
    for variant in Variant:
        # the perturbed skew moves auth lines, so check fs for both and auth for the clean one
        for r in _fs(v2, variant).values():
            if r["host"] == "SRV-FILE-02" and any(
                lo <= parse_ts(r[c]) <= hi for c in ("fn_created", "fn_modified")
            ):
                low = r["path"].lower()
                assert not any(t in low for t in ("psexe", "svchost", "admin$"))
                if row_marker(r) is not None:
                    assert row_marker(r)[1] in names | {"powershell.exe"}
    for r in _auth(v2, Variant.clean).values():
        if r["host"] == "SRV-FILE-02" and lo <= parse_ts(r["ts"]) <= hi:
            assert r["event"] != "SMB_ADMIN_SHARE_CONNECT" and "pair" not in r
            assert "admin$" not in r.get("share", "").lower()


def test_r2_s3_synthetic_names_come_from_the_inspection(v2):
    marked = [
        ref
        for ref in _synthetic_refs(v2, Variant.clean).values()
        if ref.is_paired and ref.paired_source_key == "s3_psexec_smb"
    ]
    assert [r.pairing_value for r in marked] == ["powershell.exe"]
    rows = {r["record_id"]: r for r in v2.rows("s3_psexec_smb")}
    assert all(rows[i]["image"].lower() == "powershell.exe" for i in marked[0].paired_record_ids)


def test_r2_no_synthetic_network_logon_or_admin_share_anywhere(v2):
    for variant in Variant:
        text = (v2.dirs[variant] / "auth_srv_file_02.log").read_text(encoding="utf-8")
        assert "SMB_ADMIN_SHARE_CONNECT" not in text and "ADMIN$" not in text
        assert "PSEXESVC" not in text.upper()
        for r in _fs(v2, variant).values():
            assert "psexesvc" not in r["path"].lower()


def test_r3_psexec_artifacts_only_at_s4_on_srv_file_02(v2):
    lo, hi = _slot(v2, "s4_renamed_psexec", pad=15)
    seen = 0
    for variant in Variant:
        for r in _fs(v2, variant).values():
            base = r["path"].lower().rsplit("\\", 1)[-1]
            if base == "psexec.exe" or (base == "svchost.exe" and r["note"]):
                seen += 1
                assert r["host"] == "SRV-FILE-02"
                assert lo <= parse_ts(r["fn_created"]) <= hi
    assert seen == 4  # two files x two variants
    for r in _auth(v2, Variant.clean).values():
        if r.get("event") == "NAMED_PIPE_OPEN":
            assert r["host"] == "SRV-FILE-02"
            assert lo <= parse_ts(r["ts"]) <= hi


def test_r3_no_network_logon_line_is_invented_for_lateral_movement(v2):
    lines = [
        r for r in _auth(v2, Variant.clean).values() if "pair" in r and r["host"] == "SRV-FILE-02"
    ]
    assert {r["event"] for r in lines} == {"NAMED_PIPE_OPEN"}
    assert all(
        r["src_ip"] == "10.20.2.2" for r in lines
    )  # local: the real file shows no remote origin


# ---- marker format and schema rules -----------------------------------------------------------
def test_marker_roundtrip():
    assert parse_marker(Pairing("pipe_name", "a-b-1-stdin").marker()) == (
        "pipe_name",
        "a-b-1-stdin",
    )
    assert parse_marker(Pairing(synthetic_only=True).marker()) is True
    assert parse_marker("") is None and parse_marker("pair=x") is None
    assert row_marker({"note": "pair=image_basename:a.exe"}) == ("image_basename", "a.exe")
    assert row_marker({"pair": "logon_id:0x1"}) == ("logon_id", "0x1")
    assert row_marker({"synth_only": "1"}) is True and row_marker({"seq": "1"}) is None


def test_supporting_ref_pairing_must_be_complete():
    ok = {"source_key": "fs_x", "event_record_id": 1}
    SupportingRef(**ok, synthetic_only=True)
    SupportingRef(
        **ok,
        pairing_field="image_basename",
        pairing_value="a.exe",
        paired_source_key="s1",
        paired_record_ids=[5],
    )
    with pytest.raises(ValidationError):
        SupportingRef(**ok, pairing_field="image_basename")
    with pytest.raises(ValidationError):
        SupportingRef(
            **ok,
            synthetic_only=True,
            pairing_field="a",
            pairing_value="b",
            paired_source_key="s1",
            paired_record_ids=[1],
        )


def test_key_check_rejects_unpaired_synthetic_ref_and_paired_real_ref(v2):
    key = v2.keys[Variant.clean].model_copy(deep=True)
    ref = next(r for a in key.actions for r in a.supporting_refs if r.is_paired)
    ref.pairing_field = ref.pairing_value = ref.paired_source_key = None
    ref.paired_record_ids = []
    with pytest.raises(ValueError, match="unpaired"):
        key.check_against(v2.scn)
    key = v2.keys[Variant.clean].model_copy(deep=True)
    real = next(
        r for a in key.actions for r in a.supporting_refs if r.source_key == "s1_lsass_mimikatz"
    )
    real.synthetic_only = True
    with pytest.raises(ValueError, match="carries pairing"):
        key.check_against(v2.scn)
