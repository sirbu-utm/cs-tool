"""Render a saved ``report.json`` payload as SARIF 2.1.0.

Only findings (problems) become SARIF results: a record with ``kind == "vuln"``
(nuclei and the posture checks) or ``kind == "secret"`` (gitleaks). Hosts,
ports, HTTP probes and screenshots are not problems and are left out. Consumed
by ``cyberfw export --sarif`` so GitHub code scanning / a CI gate can ingest a
run's vulnerabilities.
"""

from __future__ import annotations

from typing import Any

from cyberfw import __version__
from cyberfw.pipeline.schemas import as_mapping

__all__ = ["to_sarif"]

_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_INFO_URI = "https://github.com/sirbu-utm/cs-tool"

#: nuclei/posture severity → SARIF level.
_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}


def _result(record: dict[str, Any]) -> dict[str, Any] | None:
    """One SARIF result for a finding record, or ``None`` when it is not a finding."""
    kind = record.get("kind")
    info = as_mapping(record.get("info"))
    if kind == "vuln":
        rule_id = str(record.get("template_id") or "unknown")
        level = _LEVEL.get(str(info.get("severity") or "").lower(), "note")
        name = str(info.get("name") or rule_id)
        description = str(info.get("description") or "")
        message = f"{name} — {description}" if description else name
        where = str(record.get("matched_at") or record.get("target") or "")
    elif kind == "secret":
        rule_id = str(record.get("rule_id") or "secret")
        level = "error"  # a leaked secret is actionable
        message = str(record.get("description") or rule_id)
        where = str(record.get("target") or "")
    else:
        return None
    result: dict[str, Any] = {"ruleId": rule_id, "level": level, "message": {"text": message}}
    if where:
        result["locations"] = [{"physicalLocation": {"artifactLocation": {"uri": where}}}]
    return result


def _rule_name(record: dict[str, Any]) -> str:
    info = as_mapping(record.get("info"))
    return str(info.get("name") or record.get("description") or "")


def to_sarif(payload: dict[str, Any]) -> dict[str, Any]:
    """The SARIF 2.1.0 document for a saved report payload."""
    records = payload.get("records") or []
    results: list[dict[str, Any]] = []
    rules: list[dict[str, str]] = []
    seen: set[str] = set()
    for record in records:
        result = _result(record)
        if result is None:
            continue
        results.append(result)
        rule_id = result["ruleId"]
        if rule_id not in seen:
            seen.add(rule_id)
            rules.append({"id": rule_id, "name": _rule_name(record) or rule_id})
    version = str((payload.get("run") or {}).get("cyberfw_version") or __version__)
    return {
        "version": "2.1.0",
        "$schema": _SCHEMA,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "cyberfw",
                        "version": version,
                        "informationUri": _INFO_URI,
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
