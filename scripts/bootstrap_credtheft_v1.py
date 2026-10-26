"""One-off authoring helper that wrote scenarios/credtheft_lateral_v1/scenario.yaml.

Kept for provenance. It hashes the chosen real files, runs the key-event rules, and derives the
alignment layer (time offsets) from the discovered key events. Run with .venv\\Scripts\\python.exe.
Re-running overwrites scenario.yaml; the committed file is the source of truth afterwards.
"""

from __future__ import annotations

import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

from chainofproof.config import get_paths
from chainofproof.custody.hashing import sha256_file
from chainofproof.scenarios.dataset import dataset_root, git_commit, scenario_dir
from chainofproof.scenarios.inventory import run_inventory
from chainofproof.schemas.scenario import (
    AlignmentEntry,
    Provenance,
    Role,
    Scenario,
    SourceKind,
    SourceSpec,
    Stage,
    VirtualHost,
    save_scenario,
)

SID = "credtheft_lateral_v1"
PH = "2000-01-01T00:00:00Z"  # placeholder alignment until the first inventory run
# (source_key, stage, relative path, description, offset minutes, {real computer: virtual host})
REAL = [
    (
        "s1_lsass_mimikatz",
        "S1",
        "Credential Access/sysmon_10_lsass_mimikatz_sekurlsa_logonpasswords.evtx",
        "Sysmon 10: process access to lsass.exe by a Mimikatz binary",
        0,
        {"PC04.example.corp": "WS-FIN-07"},
    ),
    (
        "s2_pth_logon",
        "S2",
        "Lateral Movement/LM_4624_mimikatz_sekurlsa_pth_source_machine.evtx",
        "Security log of the pass-the-hash source machine",
        25,
        {"PC01.example.corp": "WS-FIN-07"},
    ),
    (
        "s3_psexec_smb",
        "S3",
        "Lateral Movement/LM_sysmon_psexec_smb_meterpreter.evtx",
        "Sysmon: remote service creation over SMB (PsExec-style, Meterpreter payload)",
        40,
        {"IEWIN7": "SRV-FILE-02"},
    ),
    (
        "s4_renamed_psexec",
        "S4",
        "Defense Evasion/DE_renamed_psexec_service_sysmon_17_18.evtx",
        "Sysmon 17/18: PsExec service renamed to svchost.exe",
        55,
        {"MSEDGEWIN10": "SRV-FILE-02"},
    ),
    (
        "s5_dcsync",
        "S5",
        "Credential Access/CA_DCSync_4662.evtx",
        "Security 4662 on a domain controller: directory replication rights used",
        95,
        {"DC1.insecurebank.local": "DC-01"},
    ),
    (
        "d1_winlogon_persist",
        "D1",
        "Persistence/sysmon_13_1_persistence_via_winlogon_shell.evtx",
        "DECOY: unrelated incident, Winlogon Shell persistence (T1547.004)",
        180,
        {"IEWIN7": "WS-HR-03"},
    ),
    (
        "d2_rundll32_lolbin",
        "D2",
        "Execution/exec_sysmon_1_lolbin_rundll32_advpack_RegisterOCX.evtx",
        "DECOY: unrelated incident, rundll32 advpack.dll proxy execution (T1218.011)",
        300,
        {"IEWIN7": "SRV-WEB-01"},
    ),
]
STAGES = [
    (
        "S1",
        "Credential theft",
        Role.storyline,
        "Mimikatz reads LSASS memory on the victim workstation.",
    ),
    (
        "S2",
        "Use of stolen credential (pass-the-hash)",
        Role.storyline,
        "A NewCredentials logon with the stolen secret.",
    ),
    (
        "S3",
        "Lateral movement",
        Role.storyline,
        "Remote service creation on the file server over SMB.",
    ),
    (
        "S4",
        "Defense evasion via renamed PsExec service",
        Role.storyline,
        "PsExec service binary disguised as svchost.exe.",
    ),
    (
        "S5",
        "Domain credential dump",
        Role.storyline,
        "DCSync: replication rights abused against the DC.",
    ),
    ("D1", "Decoy: Winlogon persistence", Role.decoy, "Unrelated incident on another host."),
    ("D2", "Decoy: rundll32 proxy execution", Role.decoy, "Unrelated incident on another host."),
]
HOSTS = [
    ("WS-FIN-07", "victim workstation (S1/S2)", "10.20.1.7"),
    ("SRV-FILE-02", "lateral target (S3/S4)", "10.20.2.2"),
    ("DC-01", "domain controller (S5)", "10.20.0.1"),
    ("WS-HR-03", "decoy workstation (D1)", "10.20.1.3"),
    ("SRV-WEB-01", "decoy web server (D2)", "10.20.3.1"),
]
SYNTH = [  # (source_key, kind, file, host)
    *[
        (
            f"fs_{h.lower().replace('-', '_')}",
            SourceKind.synthetic_file_timeline,
            f"fs_{h.lower().replace('-', '_')}.csv",
            h,
        )
        for h in ("WS-FIN-07", "SRV-FILE-02", "DC-01")
    ],
    *[
        (
            f"auth_{h.lower().replace('-', '_')}",
            SourceKind.synthetic_auth_log,
            f"auth_{h.lower().replace('-', '_')}.log",
            h,
        )
        for h in ("WS-FIN-07", "SRV-FILE-02", "DC-01")
    ],
]


def _scenario(root: Path, align: list[AlignmentEntry], stages: list[Stage]) -> Scenario:
    sources = [
        SourceSpec(
            source_key=k,
            kind=SourceKind.real_evtx,
            relative_path=p,
            stage_id=st,
            sha256=sha256_file(root / p),
            description=d,
            is_synthetic=False,
        )
        for k, st, p, d, _, _ in REAL
    ] + [
        SourceSpec(
            source_key=k,
            kind=kind,
            relative_path=f,
            stage_id=None,
            sha256=None,
            description=f"SYNTHETIC {kind.value} for {h} (generated, not real telemetry)",
            is_synthetic=True,
        )
        for k, kind, f, h in SYNTH
    ]
    git_dir = root / ".git"
    got = datetime.fromtimestamp(git_dir.stat().st_ctime, UTC).date().isoformat()
    return Scenario(
        scenario_id=SID,
        title="Credential theft and lateral movement (composite)",
        description=(
            "Independent real EVTX captures stitched into one storyline by an alignment layer "
            "(time offsets + host aliases), plus SYNTHETIC companion sources. Two real captures "
            "from unrelated incidents are decoys."
        ),
        dataset_provenance=Provenance(
            repo_url="https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES",
            clone_commit=git_commit(root) or "0" * 40,
            retrieved_at=got,
            note="shallow clone (depth 1); license not verified (LICENSE.GPL present); "
            "raw files are never redistributed, only hashes and metadata are committed",
        ),
        seed=20240312,
        virtual_start_time="2024-03-12T09:00:00Z",
        virtual_hosts=[VirtualHost(hostname=h, role=r, ip=ip) for h, r, ip in HOSTS],
        sources=sources,
        stages=stages,
        alignment=align,
    )


def main() -> None:
    """Write scenario.yaml for credtheft_lateral_v1."""
    paths = get_paths()
    root = dataset_root(paths)
    out = scenario_dir(SID) / "scenario.yaml"
    out.parent.mkdir(parents=True, exist_ok=True)
    placeholder = [
        AlignmentEntry(
            source_key=k,
            real_first_key_event_time=PH,
            virtual_first_key_event_time=PH,
            time_offset_seconds=0,
            host_aliases=al,
        )
        for k, _, _, _, _, al in REAL
    ]
    base_stages = [
        Stage(stage_id=i, name=n, attack_technique_ids=[], description=d, role=r)
        for i, n, r, d in STAGES
    ]
    inv = run_inventory(_scenario(root, placeholder, base_stages), root)
    start = datetime(2024, 3, 12, 9, 0, 0, tzinfo=UTC)
    fmt = "%Y-%m-%dT%H:%M:%S.%fZ"
    align, stages = [], []
    for k, st, _, _, minutes, aliases in REAL:
        si = inv.source(k)
        keys = [e.real_time for e in inv.keys_for(st).result.events] if st.startswith("S") else []
        first = min(keys) if keys else si.first_event_time
        if first is None:
            sys.exit(f"{k}: no events")
        real_dt = datetime.strptime(first, fmt).replace(tzinfo=UTC)
        target = start + timedelta(minutes=minutes)
        offset = int((target - real_dt.replace(microsecond=0)).total_seconds())
        virt = real_dt + timedelta(seconds=offset)
        align.append(
            AlignmentEntry(
                source_key=k,
                real_first_key_event_time=first,
                virtual_first_key_event_time=virt.strftime(fmt),
                time_offset_seconds=offset,
                host_aliases=aliases,
            )
        )
    for i, n, r, d in STAGES:
        techs: list[str] = []
        if i in {k.stage_id for k in inv.key_events}:
            res = inv.keys_for(i).result
            techs = sorted({t for e in res.events for t in e.supports})
        elif r == Role.decoy:
            techs = {"D1": ["T1547.004"], "D2": ["T1218.011"]}[i]
        stages.append(Stage(stage_id=i, name=n, attack_technique_ids=techs, description=d, role=r))
    save_scenario(out, _scenario(root, align, stages))
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
