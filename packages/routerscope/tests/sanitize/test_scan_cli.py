"""Check mode, allowlist and the tools/sanitize_fixture.py wrapper."""

from __future__ import annotations

import importlib.util
import json
import re
from pathlib import Path
from types import ModuleType

import pytest
from routerscope.sanitize import Finding, load_allowlist, scan, scan_paths

TOOL = Path(__file__).resolve().parents[4] / "tools" / "sanitize_fixture.py"


def _tool() -> ModuleType:
    spec = importlib.util.spec_from_file_location("sanitize_fixture_tool", TOOL)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


CLEAN = (
    "hostname R1\nenable secret 5 <redacted>\nrouter bgp 64496\n"
    " neighbor 192.0.2.1 remote-as 64497\n ip address 10.0.0.1 255.255.255.0\n"
    " mac 0000.5e00.5300\n peer 2001:db8::1\n contact noc@example.com\n"
)


def test_scan_clean_text() -> None:
    assert scan(CLEAN) == []


def test_scan_reports_each_kind() -> None:
    text = (
        "enable secret 5 $1$abc$defgh\n"
        "ip route 8.8.8.0 255.255.255.0 8.8.8.1\n"
        "peer 2a01:4f8::1\n"
        "router bgp 15169\n"
        "mail ops@acme-isp.net\n"
        "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"
        "crypto pki certificate chain T\n certificate 01\n  3082AA\n  quit\n"
    )
    kinds = [(f.kind, f.line) for f in scan(text)]
    assert ("secret", 1) in kinds
    assert [k for k in kinds if k[0] == "ipv4"] == [("ipv4", 2), ("ipv4", 2)]
    assert ("ipv6", 3) in kinds and ("asn", 4) in kinds and ("email", 5) in kinds
    assert ("pem", 6) in kinds and any(k[0] == "certificate" for k in kinds)
    first = scan("a\n  password hunter2\n")[0]
    assert first == Finding("secret", 2, 12, "hunter2", "password")
    assert first.sensitive and not scan("peer 8.8.8.8\n")[0].sensitive


def test_allowlist_literal_and_regex(tmp_path: Path) -> None:
    text = "peer 8.8.8.8\npeer 8.8.4.4\nenable secret 5 abc\n"
    assert len(scan(text)) == 3
    assert len(scan(text, allow=["8.8.8.8"])) == 2
    assert [f.text for f in scan(text, allow=[r"8\.8\.\d\.\d", "abc"])] == []
    assert len(scan(text, allow=["(unclosed"])) == 3
    assert scan("peer 8.8.8.8\n", allow=[re.compile(r"8\..*")]) == []
    allow = tmp_path / ".sanitize-allow"
    allow.write_text("# comment\n\n8.8.8.8\n  abc  \n", encoding="utf-8")
    assert load_allowlist(allow) == ["8.8.8.8", "abc"]
    assert load_allowlist(tmp_path / "missing") == []


def test_scan_paths_walks_directories_and_never_skips_files(tmp_path: Path) -> None:
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "a.txt").write_text("enable secret 5 abc\n", encoding="utf-8")
    (tmp_path / "b.bin").write_bytes(b"\x00password x")
    (tmp_path / "c.png").write_bytes(b"password x")
    (tmp_path / "__pycache__").mkdir()
    (tmp_path / "__pycache__" / "x.txt").write_text("password y\n", encoding="utf-8")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config").write_text("password z\n", encoding="utf-8")
    found = {f.path.name: f.finding.kind for f in scan_paths([tmp_path])}
    assert found == {"a.txt": "secret", "b.bin": "binary", "c.png": "binary", "x.txt": "secret"}
    with pytest.raises(FileNotFoundError):
        scan_paths([tmp_path / "nope"])


def test_scan_paths_expands_wildcards(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    for d in ("p1", "p2"):
        (tmp_path / d / "tests" / "data").mkdir(parents=True)
        (tmp_path / d / "tests" / "data" / "x.txt").write_text("password abc\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    assert len(scan_paths(["p*/tests/data"])) == 2
    assert len(scan_paths([str(tmp_path / "p*" / "tests" / "data")])) == 2


# ----------------------------------------------------------------------------- CLI


def test_cli_check_fails_on_planted_secret_and_public_ip(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    tool = _tool()
    clean = tmp_path / "clean.txt"
    clean.write_text(CLEAN, encoding="utf-8")
    assert tool.main(["--check", str(tmp_path), "--allow-file", str(tmp_path / "none")]) == 0

    secret = tmp_path / "secret.txt"
    secret.write_text(CLEAN + "snmp-server community hunter2 RO\n", encoding="utf-8")
    assert tool.main(["--check", str(secret), "--allow-file", str(tmp_path / "none")]) == 1
    out = capsys.readouterr().out
    assert f"{secret}:9: secret (snmp-community)" in out
    assert "hunter2" not in out  # never echo secrets into CI logs

    public = tmp_path / "public.txt"
    public.write_text(CLEAN + "ip route 8.8.8.0/24 8.8.8.1\n", encoding="utf-8")
    secret.unlink()
    assert tool.main(["--check", str(tmp_path), "--allow-file", str(tmp_path / "none")]) == 1
    assert "public.txt:9: ipv4: 8.8.8.0" in capsys.readouterr().out


def test_cli_check_honours_allowlist_and_missing_paths(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    tool = _tool()
    f = tmp_path / "f.txt"
    f.write_text("peer 8.8.8.8\n", encoding="utf-8")
    allow = tmp_path / "allow"
    allow.write_text("8.8.8.8\n", encoding="utf-8")
    assert tool.main(["--check", str(f), "--allow-file", str(allow)]) == 0
    assert tool.main(["--check", str(tmp_path / "missing")]) == 2
    assert "no such path" in capsys.readouterr().err


def test_cli_sanitize_modes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    tool = _tool()
    src = tmp_path / "in.raw"
    raw = b"hostname PE1\r\nenable secret 5 $1$abc$defgh\r\n ip address 8.8.8.1 255.255.255.0\r\n"
    src.write_bytes(raw)
    out = tmp_path / "out.raw"
    mapping = tmp_path / "x.sanitize-map.json"
    code = tool.main([str(src), "-o", str(out), "--salt", "s", "--map-out", str(mapping)])
    assert code == 0
    assert "never commit" in capsys.readouterr().err
    data = out.read_bytes()
    assert data.count(b"\r\n") == 3 and b"PE1" not in data and b"8.8.8.1" not in data
    assert json.loads(mapping.read_text(encoding="utf-8"))["hostname"]["pe1"] == "R1"
    assert src.read_bytes() == raw

    assert tool.main([str(src), "--in-place", "--keep-descriptions", "--remap-private"]) == 0
    assert b"PE1" not in src.read_bytes() and src.read_bytes().count(b"\r\n") == 3
    # sanitizing the output again changes nothing
    assert tool.main([str(out), "--in-place"]) == 0
    assert out.read_bytes() == data


def test_cli_stdout_and_errors(tmp_path: Path, capsysbinary: pytest.CaptureFixture[bytes]) -> None:
    tool = _tool()
    src = tmp_path / "in.txt"
    src.write_bytes(b"peer 8.8.8.8 caf\xc3\xa9\n")
    assert tool.main([str(src)]) == 0
    out = capsysbinary.readouterr().out
    assert out.endswith(b" caf\xc3\xa9\n") and b"8.8.8.8" not in out
    assert tool.main([str(tmp_path / "missing")]) == 2
    for argv in ([], [str(src), "--in-place", "-o", "x"], [str(src), "--check", "a"]):
        with pytest.raises(SystemExit) as exc:
            tool.main(argv)
        assert exc.value.code == 2
