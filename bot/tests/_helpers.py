"""Shared fixtures/builders for the bot tests."""

from __future__ import annotations

from pathlib import Path

from cyberfw_bot.config import BotConfig


def make_config(tmp_path: Path, **overrides: object) -> BotConfig:
    """A BotConfig pointing at a throwaway workspace, with test-friendly defaults."""
    defaults: dict[str, object] = {
        "token": "test-token",
        "allowed_user_ids": frozenset({42}),
        "cyberfw_cmd": ("cyberfw",),
        "workspace": tmp_path,
        "db_path": tmp_path / "scans.sqlite3",
        "pipeline": "recon-to-vuln",
        "max_concurrent": 2,
        "scan_timeout_s": 30.0,
        "stage_timeout_s": 10.0,
        "block_private": True,
        "max_findings_in_message": 10,
        "extra_pipeline_args": (),
    }
    defaults.update(overrides)
    return BotConfig(**defaults)  # type: ignore[arg-type]


SAMPLE_REPORT = {
    "ok": True,
    "run": {"pipeline": "recon-to-vuln", "seed": "example.com", "duration_s": 12.5},
    "stages": [
        {"tool": "subfinder", "stage": "subdomains", "ok": True, "skipped": False, "count": 2, "error": None},
        {"tool": "httpx", "stage": "live_http", "ok": True, "skipped": False, "count": 1, "error": None},
        {"tool": "nuclei", "stage": "vulns", "ok": True, "skipped": False, "count": 3, "error": None},
    ],
    "total_records": 6,
    "records": [
        {"tool": "subfinder", "kind": "host", "target": "a.example.com"},
        {"tool": "subfinder", "kind": "host", "target": "b.example.com"},
        {"tool": "httpx", "kind": "http", "target": "https://a.example.com/"},
        {
            "tool": "nuclei",
            "kind": "vuln",
            "target": "https://a.example.com/",
            "matched-at": "https://a.example.com/",
            "matched_at": "https://a.example.com/",
            "template_id": "medium-issue",
            "info": {"name": "Some medium issue", "severity": "medium"},
        },
        {
            "tool": "nuclei",
            "kind": "vuln",
            "target": "https://a.example.com/admin",
            "matched_at": "https://a.example.com/admin",
            "template_id": "rce",
            "info": {"name": "Critical RCE", "severity": "critical"},
        },
        {
            "tool": "nuclei",
            "kind": "vuln",
            "target": "https://a.example.com/x",
            "matched_at": "https://a.example.com/x",
            "template_id": "weird",
            "info": {"name": "Weird", "severity": "bananas"},
        },
    ],
}
