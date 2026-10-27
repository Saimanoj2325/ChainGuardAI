import pytest

from app.errors import APIError
from app.validation import sanitize_filename, validate_upload


def test_ok():
    v = validate_upload("A.sol", b"contract A {}", 100)
    assert v.filename == "A.sol" and v.size_bytes == 13 and len(v.sha256) == 64


@pytest.mark.parametrize("name,expected", [
    ("../../etc/passwd.sol", "passwd.sol"), ("..\\..\\win\\x.sol", "x.sol"), ("my file (1).sol", "my_file_1_.sol"),
    ("", "contract.sol"), ("....sol", "sol.sol"), ("a" * 300 + ".sol", "a" * 96 + ".sol"),
])
def test_sanitize(name, expected):
    out = sanitize_filename(name)
    assert out == expected and "/" not in out and "\\" not in out and len(out) <= 100


@pytest.mark.parametrize("name,raw,status,code", [
    ("a.txt", b"contract A {}", 400, "invalid_file_type"),
    ("a.sol.exe", b"contract A {}", 400, "invalid_file_type"),
    (".sol", b"contract A {}", 400, "invalid_file_type"),
    ("a.sol", b"", 400, "empty_file"),
    ("a.sol", b"  \n\t ", 400, "empty_file"),
    ("a.sol", b"contract \x00 A {}", 400, "invalid_content"),
    ("a.sol", b"\xff\xfe\xfa contract", 400, "invalid_encoding"),
    ("a\x00.sol", b"contract A {}", 400, "invalid_filename"),
    ("a.sol", b"x" * 101, 413, "payload_too_large"),
    (None, b"contract A {}", 400, "invalid_filename"),
])
def test_rejects(name, raw, status, code):
    with pytest.raises(APIError) as ei:
        validate_upload(name, raw, 100)
    assert ei.value.status == status and ei.value.error == code


def test_bom_stripped_and_uppercase_ext():
    v = validate_upload("A.SOL", "\ufeffcontract A {}".encode(), 100)
    assert v.source == "contract A {}"
