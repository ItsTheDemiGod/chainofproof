"""Path vocabulary of the benign file-system background (v4): administrative tools and ordinary
files across Windows, Program Files, ProgramData and the user profiles, with the same extensions,
directory prefixes and depths as the attacker rows."""

from __future__ import annotations

import random

SYSTEM_DLLS = [
    "kernel32", "user32", "advapi32", "ntdll", "shell32", "ole32", "ws2_32", "crypt32", "wininet",
    "netapi32", "samlib", "secur32", "rpcrt4", "msvcrt", "gdi32", "comctl32", "version", "setupapi",
    "wldap32", "dnsapi", "iphlpapi", "mswsock", "bcrypt", "sspicli",
]  # fmt: skip
SYSTEM_EXES = [
    "cmd", "notepad", "calc", "mmc", "taskmgr", "net", "net1", "ipconfig", "tasklist", "whoami",
    "wmic", "sc", "schtasks", "reg", "ping", "nslookup", "certutil", "wevtutil", "msiexec",
    "rundll32", "regsvr32", "dllhost", "conhost", "services", "lsass", "winlogon", "spoolsv",
    "svchost", "taskhostw", "wuauclt", "mstsc", "robocopy", "xcopy", "findstr",
]  # fmt: skip
WINDOWS_ROOT = ["explorer", "notepad", "regedit", "hh", "write", "splwow64", "winhlp32"]
PROGRAM_DIRS = [
    r"C:\Program Files\Microsoft Office\root\Office16",
    r"C:\Program Files\Common Files\Microsoft Shared",
    r"C:\Program Files (x86)\Internet Explorer",
    r"C:\Program Files\Windows Defender",
    r"C:\Program Files\7-Zip",
    r"C:\Program Files\Mozilla Firefox",
    r"C:\Program Files (x86)\Google\Chrome\Application",
]
PROGDATA_DIRS = [
    r"C:\ProgramData\Microsoft\Windows",
    r"C:\ProgramData\Microsoft\Windows Defender",
    r"C:\ProgramData\Package Cache",
    r"C:\ProgramData\Adobe\ARM",
]
TOOLS = [
    "putty",
    "winscp",
    "7zFM",
    "procexp",
    "autoruns",
    "tcpview",
    "wireshark",
    "vlc",
    "notepad++",
]
TOOL_DIRS = ["putty_0.78", "winscp_5.21", "sysinternals", "wireshark_portable", "npp_8.4", "7z_22"]
SUB_DIRS = ["Win32", "x64", "bin", "x86"]
DOC_WORDS = [
    "report",
    "budget",
    "notes",
    "invoice",
    "plan",
    "draft",
    "summary",
    "agenda",
    "q1",
    "q2",
]
DOC_EXTS = ["docx", "xlsx", "pdf", "txt", "pptx", "csv"]
APP_EXTS = ["dll", "dll", "dll", "exe", "dat", "log", "ini"]
PREFETCH_APPS = SYSTEM_EXES + TOOLS + ["WINWORD", "EXCEL", "CHROME", "FIREFOX", "OUTLOOK"]
USERS = ["jsmith", "mlopez", "akhan", "rbrown"]
CATEGORIES = [
    ("sysdll", 22), ("sysexe", 8), ("winroot", 3), ("prefetch", 12), ("progfiles", 15),
    ("progdata", 8), ("docs", 12), ("downloads", 7), ("temp", 7), ("desktop", 6),
]  # fmt: skip
MANDATORY = [  # on every host: the normal places of the binaries the attacker rows imitate
    r"C:\Windows\System32\svchost.exe",
    r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    r"C:\Windows\System32\cmd.exe",
    r"C:\Windows\explorer.exe",
]


def benign_path(rng: random.Random, cat: str, profiles: list[str], i: int) -> str:
    """One path of a benign file of the given category."""
    prof = rng.choice(profiles)
    if cat == "sysdll":
        return rf"C:\Windows\System32\{rng.choice(SYSTEM_DLLS)}{rng.randint(0, 99):02d}.dll"
    if cat == "sysexe":
        return rf"C:\Windows\System32\{rng.choice(SYSTEM_EXES)}.exe"
    if cat == "winroot":
        return rf"C:\Windows\{rng.choice(WINDOWS_ROOT)}.exe"
    if cat == "prefetch":
        app = rng.choice(PREFETCH_APPS).upper()
        return rf"C:\Windows\Prefetch\{app}.EXE-{rng.getrandbits(32):08X}.pf"
    if cat == "progfiles":
        return rf"{rng.choice(PROGRAM_DIRS)}\{rng.choice(SYSTEM_DLLS)}_{i}.{rng.choice(APP_EXTS)}"
    if cat == "progdata":
        return rf"{rng.choice(PROGDATA_DIRS)}\{rng.choice(DOC_WORDS)}_{i}.{rng.choice(APP_EXTS)}"
    if cat == "docs":
        return rf"{prof}\Documents\{rng.choice(DOC_WORDS)}_{i}.{rng.choice(DOC_EXTS)}"
    if cat == "downloads":
        kind = rng.choice(["exe", "msi", "zip", "pdf"])
        return rf"{prof}\Downloads\{rng.choice(TOOLS)}_setup_{i}.{kind}"
    if cat == "temp":
        sub = rng.choice([rf"\{rng.getrandbits(24):06x}", ""])
        name = rng.choice(
            [f"tmp{rng.getrandbits(16):04x}.tmp", f"{rng.choice(TOOLS)}.exe", f"setup_{i}.log"]
        )
        return rf"{prof}\AppData\Local\Temp{sub}\{name}"
    return rf"{prof}\Desktop\{rng.choice(TOOL_DIRS)}\{rng.choice(SUB_DIRS)}\{rng.choice(TOOLS)}.exe"
