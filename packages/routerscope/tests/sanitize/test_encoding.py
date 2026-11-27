"""A1: encodings cannot hide data from the sanitizer or from the check."""

from __future__ import annotations

import codecs
import importlib.util
from pathlib import Path
from types import ModuleType

import pytest
from routerscope.sanitize import scan_paths
from routerscope.sanitize.encoding import UndecodableError, decode_bytes, encode_text

TOOL = Path(__file__).resolve().parents[4] / "tools" / "sanitize_fixture.py"
TEXT = "username a password SUPERSECRETPW\r\nip route 8.8.8.0 255.255.255.0 8.8.8.1\r\n"


def _tool() -> ModuleType:
    spec = importlib.util.spec_from_file_location("sanitize_fixture_tool", TOOL)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


ENCODINGS = {
    "utf8-bom": codecs.BOM_UTF8 + TEXT.encode("utf-8"),
    "utf16-le-bom": codecs.BOM_UTF16_LE + TEXT.encode("utf-16-le"),
    "utf16-be-bom": codecs.BOM_UTF16_BE + TEXT.encode("utf-16-be"),
    "utf32-le-bom": codecs.BOM_UTF32_LE + TEXT.encode("utf-32-le"),
    "utf32-be-bom": codecs.BOM_UTF32_BE + TEXT.encode("utf-32-be"),
    "utf16-le-nobom": TEXT.encode("utf-16-le"),
    "utf16-be-nobom": TEXT.encode("utf-16-be"),
    "utf32-le-nobom": TEXT.encode("utf-32-le"),
    "utf32-be-nobom": TEXT.encode("utf-32-be"),
    "utf8": TEXT.encode("utf-8"),
}


@pytest.mark.parametrize("name", ENCODINGS)
def test_decode_roundtrip(name: str) -> None:
    data = ENCODINGS[name]
    decoded = decode_bytes(data)
    assert decoded.text == TEXT
    assert encode_text(decoded.text, decoded) == data


@pytest.mark.parametrize("name", ENCODINGS)
def test_cli_sanitizes_every_encoding_and_keeps_it(name: str, tmp_path: Path) -> None:
    src = tmp_path / "in.raw"
    src.write_bytes(ENCODINGS[name])
    out = tmp_path / "out.raw"
    assert _tool().main([str(src), "-o", str(out)]) == 0
    result = out.read_bytes()
    decoded = decode_bytes(result)
    assert "SUPERSECRETPW" not in decoded.text and "8.8.8.0" not in decoded.text
    assert decoded.text.count("\r\n") == 2
    assert decoded.encoding == decode_bytes(ENCODINGS[name]).encoding
    assert result.startswith(decode_bytes(ENCODINGS[name]).bom)


@pytest.mark.parametrize("name", ENCODINGS)
def test_check_inspects_every_encoding(name: str, tmp_path: Path) -> None:
    (tmp_path / "f.raw").write_bytes(ENCODINGS[name])
    kinds = {f.finding.kind for f in scan_paths([tmp_path])}
    assert {"secret", "ipv4"} <= kinds


def test_nul_bytes_do_not_hide_a_file(tmp_path: Path) -> None:
    (tmp_path / "j.txt").write_bytes(b"x\x00y\npassword NULSECRET\n")
    assert any(f.finding.kind == "secret" for f in scan_paths([tmp_path]))


@pytest.mark.parametrize(
    "name,data",
    [
        ("latin1.txt", b"username a password LATINSECRET \xe9\xff\nip route 8.8.8.0\n"),
        ("h.gz", b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03+H,..\xcf/JQp\x8f\n"),
        ("x.zip", b"PK\x03\x04plain-ascii-looks-fine"),
        ("p.png", b"not really a png but the suffix says so"),
        ("blob", bytes(range(256))),
    ],
)
def test_check_fails_closed_on_undecodable_or_opaque_files(
    name: str, data: bytes, tmp_path: Path
) -> None:
    (tmp_path / name).write_bytes(data)
    findings = scan_paths([tmp_path])
    assert [f.finding.kind for f in findings] == ["binary"]


def test_cli_refuses_undecodable_input(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    src = tmp_path / "latin1.txt"
    src.write_bytes(b"password \xe9\xff\n")
    assert _tool().main([str(src)]) == 2
    assert "UTF-8" in capsys.readouterr().err
    with pytest.raises(UndecodableError):
        decode_bytes(b"\xff\xfe\x00")  # truncated UTF-16 after the BOM is still invalid... or not
    with pytest.raises(UndecodableError):
        decode_bytes(codecs.BOM_UTF8 + b"\xff")


def test_map_out_inside_a_git_repository_is_refused(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    src = tmp_path / "in.txt"
    src.write_text("hostname A\n", encoding="utf-8")
    assert _tool().main([str(src), "--map-out", str(repo / "sub" / "m.json")]) == 2
    assert "refusing" in capsys.readouterr().err
    assert not (repo / "sub").exists()
