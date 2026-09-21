"""Unit tests for JSONL record schemas and dispatch."""

from __future__ import annotations

import json

import pytest

from cyberfw.exceptions import ParseError
from cyberfw.pipeline.schemas import (
    FfufResult,
    GitleaksResult,
    HttpxResult,
    NaabuResult,
    NucleiResult,
    SubfinderResult,
    validate_record,
)


def _line(obj: dict[str, object]) -> str:
    return json.dumps(obj)


class TestValidation:
    def test_subfinder(self) -> None:
        rec = validate_record("subfinder", _line({"host": "api.example.com", "source": "crt.sh"}), 1)
        assert isinstance(rec, SubfinderResult)
        assert rec.target == "api.example.com"
        assert rec.kind == "host"

    def test_naabu(self) -> None:
        rec = validate_record("naabu", _line({"host": "1.2.3.4", "port": 443, "protocol": "tcp"}), 2)
        assert isinstance(rec, NaabuResult)
        assert rec.target == "1.2.3.4:443"
        assert rec.kind == "port"

    def test_httpx(self) -> None:
        rec = validate_record("httpx", _line({"url": "https://a.com/", "status_code": 200, "tech": ["n\nginix"]}), 3)
        assert isinstance(rec, HttpxResult)
        assert rec.kind == "http"
        assert rec.target == "https://a.com/"

    def test_ffuf(self) -> None:
        rec = validate_record("ffuf", _line({"input1": "FUZZ", "status": 200, "url": "https://a.com/x"}), 4)
        assert isinstance(rec, FfufResult)
        assert rec.kind == "fuzz"

    def test_nuclei(self) -> None:
        raw = {"template-id": "CVE-2020-1234", "matched-at": "https://a.com/", "info": {"severity": "high"}}
        rec = validate_record("nuclei", _line(raw), 5)
        assert isinstance(rec, NucleiResult)
        assert rec.severity == "high"
        assert rec.kind == "vuln"

    def test_gitleaks(self) -> None:
        raw = {"RuleID": "aws-key", "Secret": "AKIAXXXX", "File": "src/config.py", "Description": "AWS key"}
        rec = validate_record("gitleaks", _line(raw), 6)
        assert isinstance(rec, GitleaksResult)
        assert rec.file_path == "src/config.py"
        assert rec.kind == "secret"

    def test_extra_fields_ignored(self) -> None:
        # Unknown keys are tolerated (extra="ignore"), e.g. subfinder "input".
        rec = validate_record("subfinder", _line({"host": "x.com", "unexpected": 1}), 7)
        assert rec.target == "x.com"


class TestParse:
    def test_invalid_json_raises(self) -> None:
        with pytest.raises(ParseError, match="invalid JSON"):
            validate_record("subfinder", "not json", 1)

    def test_non_object_raises(self) -> None:
        with pytest.raises(ParseError, match="expected a JSON object"):
            validate_record("subfinder", _line([1, 2]), 1)

    def test_unknown_tool_raises(self) -> None:
        with pytest.raises(ParseError, match="no schema"):
            validate_record("doesnotexist", _line({}), 1)


class TestRecordDecodability:
    def test_as_dict_roundtrip(self) -> None:
        rec = validate_record("httpx", _line({"url": "https://x", "status_code": 200}), 1)
        payload = rec.as_dict()
        assert payload["tool"] == "httpx"
        assert payload["kind"] == "http"
        assert payload["url"] == "https://x"
