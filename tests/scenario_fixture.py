"""A tiny SYNTHETIC scenario for tests: fake 'real' files, hand-built inventory, no real EVTX."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from chainofproof.custody.hashing import sha256_file
from chainofproof.scenarios.inventory import (
    Inventory,
    SourceInventory,
    StageKeys,
    save_inventory,
)
from chainofproof.scenarios.keyevents import KeyEvent, StageResult
from chainofproof.schemas.scenario import (
    AlignmentEntry,
    Confidence,
    NoiseConfig,
    Provenance,
    Role,
    Scenario,
    SourceKind,
    SourceSpec,
    Stage,
    VirtualHost,
    save_scenario,
)

SID = "fixture_v1"
FMT = "%Y-%m-%dT%H:%M:%S.%fZ"
START = datetime(2024, 3, 12, 9, 0, 0, tzinfo=UTC)
# stage, real file name, real time, virtual offset minutes, real computer, virtual host
STAGES = [
    ("S1", "s1", "2019-03-17T19:37:11.500000Z", 0, "PCA", "WS-FIN-07"),
    ("S2", "s2", "2019-03-18T11:06:29.250000Z", 25, "PCB", "WS-FIN-07"),
    ("S3", "s3", "2019-04-30T20:26:51.750000Z", 40, "SRV", "SRV-FILE-02"),
    ("S4", "s4", "2020-09-27T13:42:00.125000Z", 55, "SRV2", "SRV-FILE-02"),
    ("S5", "s5", "2019-05-08T02:10:43.500000Z", 95, "DC1", "DC-01"),
]


def _ke(rid: int, eid: int, t: str, supports: list[str], **facts: str) -> KeyEvent:
    return KeyEvent(rid, eid, "Chan", t, "fixture", supports, facts)


def _keys() -> dict[str, list[KeyEvent]]:
    t = {s[0]: s[2] for s in STAGES}
    return {
        "S1": [
            _ke(11, 10, t["S1"], ["T1003.001"], SourceImage=r"C:\Users\x\Desktop\mimi\mimikatz.exe")
        ],
        "S2": [
            _ke(
                21,
                4624,
                t["S2"],
                ["T1550.002"],
                TargetUserName="user01",
                LogonType="9",
                TargetLogonId="0x0000000004530f0f",
            )
        ],
        "S3": [_ke(31, 18, t["S3"], ["T1021.002"]), _ke(32, 13, t["S3"], ["T1569.002"])],
        "S4": [_ke(41, 17, t["S4"], ["T1036.003"]), _ke(42, 18, t["S4"], ["T1569.002"])],
        "S5": [
            _ke(
                51,
                4662,
                t["S5"],
                ["T1003.006"],
                SubjectUserName="Administrator",
                SubjectLogonId="0x00000000040c6511",
            )
        ],
    }


def build_fixture(root: Path, seed: int = 7) -> tuple[Scenario, Inventory, Path, Path]:
    """Write fake dataset files, scenario.yaml, inventory.json; returns (scn, inv, sdir, ddir)."""
    ddir, sdir = root / "dataset", root / "scenarios" / SID
    ddir.mkdir(parents=True)
    sdir.mkdir(parents=True)
    sources, align = [], []
    for st, name, real, minutes, comp, host in STAGES:
        f = ddir / f"{name}.evtx"
        f.write_bytes(f"fake evtx {name}".encode())
        sources.append(
            SourceSpec(
                source_key=name,
                kind=SourceKind.real_evtx,
                relative_path=f.name,
                stage_id=st,
                sha256=sha256_file(f),
                description=f"fixture {st}",
                is_synthetic=False,
            )
        )
        r = datetime.strptime(real, FMT).replace(tzinfo=UTC)
        off = int((START + timedelta(minutes=minutes) - r.replace(microsecond=0)).total_seconds())
        align.append(
            AlignmentEntry(
                source_key=name,
                real_first_key_event_time=real,
                virtual_first_key_event_time=(r + timedelta(seconds=off)).strftime(FMT),
                time_offset_seconds=off,
                host_aliases={comp: host},
            )
        )
    d = ddir / "d1.evtx"
    d.write_bytes(b"fake decoy")
    sources.append(
        SourceSpec(
            source_key="d1",
            kind=SourceKind.real_evtx,
            relative_path="d1.evtx",
            stage_id="D1",
            sha256=sha256_file(d),
            description="decoy",
            is_synthetic=False,
        )
    )
    align.append(
        AlignmentEntry(
            source_key="d1",
            real_first_key_event_time="2019-06-14T22:22:17.000000Z",
            virtual_first_key_event_time="2024-03-12T12:00:00.000000Z",
            time_offset_seconds=int(
                (
                    datetime(2024, 3, 12, 12, tzinfo=UTC)
                    - datetime(2019, 6, 14, 22, 22, 17, tzinfo=UTC)
                ).total_seconds()
            ),
            host_aliases={"DECOYPC": "WS-HR-03"},
        )
    )
    for h, kind, ext in [
        (h, k, e)
        for h in ("WS-FIN-07", "SRV-FILE-02", "DC-01")
        for k, e in (
            (SourceKind.synthetic_file_timeline, "csv"),
            (SourceKind.synthetic_auth_log, "log"),
        )
    ]:
        pre = "fs" if ext == "csv" else "auth"
        key = f"{pre}_{h.lower().replace('-', '_')}"
        sources.append(
            SourceSpec(
                source_key=key,
                kind=kind,
                relative_path=f"{key}.{ext}",
                stage_id=None,
                sha256=None,
                description="SYNTHETIC",
                is_synthetic=True,
            )
        )
    stages = [
        Stage(
            stage_id=s[0],
            name=f"stage {s[0]}",
            attack_technique_ids=[],
            description="x",
            role=Role.storyline,
        )
        for s in STAGES
    ]
    stages.append(
        Stage(
            stage_id="D1",
            name="decoy",
            attack_technique_ids=["T1547.004"],
            description="x",
            role=Role.decoy,
        )
    )
    hosts = [
        ("WS-FIN-07", "10.20.1.7"),
        ("SRV-FILE-02", "10.20.2.2"),
        ("DC-01", "10.20.0.1"),
        ("WS-HR-03", "10.20.1.3"),
    ]
    scn = Scenario(
        scenario_id=SID,
        title="Fixture",
        description="fixture",
        dataset_provenance=Provenance(
            repo_url="https://example.invalid/x",
            clone_commit="a" * 40,
            retrieved_at="2026-01-01",
            note="fixture",
        ),
        seed=seed,
        virtual_start_time="2024-03-12T09:00:00Z",
        virtual_hosts=[VirtualHost(hostname=h, role="r", ip=ip) for h, ip in hosts],
        noise=NoiseConfig(benign_fs_entries_per_host=60, benign_auth_lines_total=300),
        sources=sources,
        stages=stages,
        alignment=align,
    )
    keys = _keys()
    inv = Inventory(
        scenario_id=SID,
        dataset_commit="a" * 40,
        sources=[
            SourceInventory(
                source_key=s.source_key,
                relative_path=s.relative_path,
                sha256=s.sha256,
                record_count=1,
                corrupt_records=0,
                first_event_time=None,
                last_event_time=None,
                span_seconds=0,
                computers=[],
                channels=[],
                top_event_ids=[],
                accounts=[],
                instruction_like_fields=[],
            )
            for s in sources
            if s.kind == SourceKind.real_evtx
        ],
        key_events=[
            StageKeys(
                stage_id=st,
                source_key=name,
                result=StageResult(
                    keys[st], {t: Confidence.medium for e in keys[st] for t in e.supports}, ""
                ),
            )
            for st, name, *_ in STAGES
        ],
    )
    save_scenario(sdir / "scenario.yaml", scn)
    save_inventory(sdir / "inventory.json", inv)
    return scn, inv, root / "scenarios", ddir
