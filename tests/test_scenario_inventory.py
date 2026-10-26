"""Key-event rules on hand-built XML, corrupt-record handling, defusedxml hardening."""

import pytest
from defusedxml.common import DefusedXmlException

from chainofproof.scenarios import evtx_meta
from chainofproof.scenarios.evtx_meta import ReadStats, iter_events, normalize_time, parse_event_xml
from chainofproof.scenarios.keyevents import rule_s1, rule_s2, rule_s3, rule_s4, rule_s5
from chainofproof.schemas.scenario import Confidence

NS = "http://schemas.microsoft.com/win/2004/08/events/event"


def ev(rid, eid, channel="Microsoft-Windows-Sysmon/Operational", **data):
    body = "".join(f'<Data Name="{k}">{v}</Data>' for k, v in data.items())
    return parse_event_xml(
        f'<Event xmlns="{NS}"><System><EventID>{eid}</EventID><EventRecordID>{rid}</EventRecordID>'
        f"<Channel>{channel}</Channel><Computer>PC1</Computer>"
        f'<TimeCreated SystemTime="2019-03-17 19:37:11.661928+00:00"/></System>'
        f"<EventData>{body}</EventData></Event>"
    )


def test_parse_and_time_normalisation():
    e = ev(7, 10, TargetImage="x")
    assert (e.record_id, e.event_id, e.computer, e.data) == (7, 10, "PC1", {"TargetImage": "x"})
    assert e.time == "2019-03-17T19:37:11.661928Z"
    assert normalize_time("2024-01-02T03:04:05Z") == "2024-01-02T03:04:05.000000Z"


def test_s1_rule():
    hit = ev(
        1,
        10,
        TargetImage=r"C:\Windows\system32\lsass.exe",
        SourceImage=r"C:\t\m.exe",
        GrantedAccess="0x00001010",
    )
    other = ev(2, 10, TargetImage=r"C:\Windows\notepad.exe", GrantedAccess="0x1010")
    r = rule_s1([other, hit])
    assert [k.record_id for k in r.events] == [1]
    assert r.technique_confidence["T1003.001"] == Confidence.high
    odd = rule_s1([ev(3, 10, TargetImage=r"C:\x\LSASS.EXE", GrantedAccess="0x0040")])
    assert odd.technique_confidence["T1003.001"] == Confidence.medium


def test_unresolved_is_honest_not_invented():
    r = rule_s1([ev(1, 1, Image="a.exe"), ev(2, 3)])
    assert r.unresolved and r.events == []
    assert r.technique_confidence == {"T1003.001": Confidence.low}
    assert "no clear key event" in r.note and "[1, 3]" in r.note
    for rule in (rule_s2, rule_s3, rule_s4, rule_s5):
        assert rule([]).unresolved


def test_s2_rule_newcredentials_and_ntlm():
    sec = "Microsoft-Windows-Security-Auditing"
    nc = ev(
        5,
        4624,
        sec,
        LogonType="9",
        LogonProcessName="seclogo",
        TargetUserName="user01",
        TargetLogonId="0x1",
    )
    priv = ev(6, 4672, sec, SubjectUserName="user01", SubjectLogonId="0x1")
    r = rule_s2([nc, priv])
    assert [k.record_id for k in r.events] == [5, 6]
    assert r.technique_confidence["T1550.002"] == Confidence.medium
    ntlm = ev(8, 4624, sec, LogonType="3", AuthenticationPackageName="NTLM", TargetUserName="bob")
    assert [k.record_id for k in rule_s2([ntlm]).events] == [8]
    anon = ev(
        9,
        4624,
        sec,
        LogonType="3",
        AuthenticationPackageName="NTLM",
        TargetUserName="ANONYMOUS LOGON",
    )
    assert rule_s2([anon]).unresolved


def test_s3_s4_rules():
    s3 = rule_s3(
        [
            ev(1, 18, PipeName=r"\ntsvcs", Image="System"),
            ev(
                2,
                13,
                Image=r"C:\Windows\system32\services.exe",
                TargetObject=r"HKLM\System\CurrentControlSet\services\x\ImagePath",
            ),
            ev(
                3,
                13,
                Image=r"C:\Windows\system32\services.exe",
                TargetObject=r"HKLM\System\CurrentControlSet\services\x\Start",
            ),
            ev(4, 1, ParentImage=r"C:\Windows\system32\services.exe", Image="cmd.exe"),
        ]
    )
    assert [k.record_id for k in s3.events] == [1, 2, 4]
    s4 = rule_s4(
        [
            ev(10, 17, Image=r"C:\Windows\svchost.exe", PipeName=r"\svchost-H-8116-stdin"),
            ev(11, 18, Image=r"C:\Windows\system32\PsExec.exe", PipeName=r"\svchost-H-8116-stdin"),
            ev(12, 17, Image=r"C:\Windows\system32\svchost.exe", PipeName=r"\svchost"),
        ]
    )
    assert {t for k in s4.events for t in k.supports} == {"T1036.003", "T1569.002"}
    assert s4.technique_confidence["T1569.002"] == Confidence.high


def test_s5_rule_user_vs_machine_account():
    props = "%%7688 {1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}"
    sec = "Microsoft-Windows-Security-Auditing"
    user = rule_s5(
        [ev(1, 4662, sec, SubjectUserName="Administrator", SubjectLogonId="0x9", Properties=props)]
    )
    assert user.technique_confidence["T1003.006"] == Confidence.high
    machine = rule_s5([ev(1, 4662, sec, SubjectUserName="DC1$", Properties=props)])
    assert machine.technique_confidence["T1003.006"] == Confidence.medium
    assert rule_s5([ev(1, 4662, sec, SubjectUserName="a", Properties="{other}")]).unresolved


def test_defusedxml_rejects_entity_expansion():
    bomb = (
        '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol">'
        '<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">'
        '<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">]>'
        f'<Event xmlns="{NS}"><System><EventID>1</EventID></System>&lol3;</Event>'
    )
    with pytest.raises(DefusedXmlException):
        parse_event_xml(bomb)


class _Rec:
    def __init__(self, xml, boom=False):
        self._xml, self._boom = xml, boom

    def xml(self):
        if self._boom:
            raise ValueError("corrupt")
        return self._xml


class _Chunk:
    def __init__(self, recs):
        self._recs = recs

    def records(self):
        yield from self._recs


class _FakeEvtx:
    def __init__(self, chunks):
        self._chunks = chunks

    def __call__(self, path):
        return self

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def chunks(self):
        return iter(self._chunks)


def test_corrupt_records_are_skipped_and_counted(monkeypatch):
    good = (
        f'<Event xmlns="{NS}"><System><EventID>1</EventID><EventRecordID>1</EventRecordID>'
        "<Channel>c</Channel><Computer>h</Computer>"
        '<TimeCreated SystemTime="2019-01-01 00:00:00+00:00"/></System></Event>'
    )
    bomb = '<!DOCTYPE x [<!ENTITY a "b">]><Event xmlns="' + NS + '">&a;</Event>'

    def broken():
        yield _Rec(good)
        raise OSError("bad record header")

    class _BadChunk:
        def records(self):
            return broken()

    chunks = [
        _Chunk([_Rec(good), _Rec("", boom=True), _Rec("<not xml", False), _Rec(bomb)]),
        _BadChunk(),
    ]
    monkeypatch.setattr(evtx_meta, "Evtx", _FakeEvtx(chunks))
    stats = ReadStats()
    out = list(iter_events("whatever.evtx", stats))
    assert len(out) == 2 and stats.records == 2
    assert stats.corrupt == 4  # boom, bad xml, entity bomb, broken iterator
