"""Smoke tests for every registered tool adapter command builder."""

from __future__ import annotations

from pathlib import Path

import pytest

from cyberfw.exceptions import ToolNotFoundError
from cyberfw.manager.registry import ToolSpec
from cyberfw.tools import adapter_for
from cyberfw.tools.base import ToolContext
from cyberfw.tools.rustscan import _hostname


def _adapter(name: str) -> object:
    spec = ToolSpec(name=name, repo=f"org/{name}", asset_patterns=[], binary=name)
    return adapter_for(spec, Path("tools_bin") / name)


@pytest.mark.parametrize(
    ("name", "target"),
    [
        ("subfinder", "example.com"),
        ("naabu", "example.com"),
        ("rustscan", "example.com"),
        ("httpx", "https://example.com"),
        ("nuclei", "https://example.com"),
        ("gitleaks", "."),
    ],
)
def test_registered_adapter_builds_command(name: str, target: str) -> None:
    adapter = adapter_for(
        ToolSpec(name=name, repo=f"org/{name}", asset_patterns=[], binary=name),
        Path("tools_bin") / name,
    )

    command = adapter.build_cmd(ToolContext(target=target))

    assert command[0].endswith(name)
    expected_target = "example.com" if name == "rustscan" else target
    assert expected_target in command


def test_projectdiscovery_tools_use_json_not_jsonl() -> None:
    """subfinder/httpx JSONL flag is -json; -jsonl is undefined and exits 2."""
    for name in ("subfinder", "httpx"):
        command = _adapter(name).build_cmd(ToolContext(target="https://example.com"))  # type: ignore[attr-defined]
        assert "-json" in command
        assert "-jsonl" not in command


def test_subfinder_reduces_url_seed_to_bare_domain() -> None:
    command = _adapter("subfinder").build_cmd(  # type: ignore[attr-defined]
        ToolContext(target="https://ltnvg.buiucanidets.md/")
    )
    assert "ltnvg.buiucanidets.md" in command
    assert "https://ltnvg.buiucanidets.md/" not in command


def test_gowitness_uses_v3_scan_single_command(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("cyberfw.tools.gowitness._find_chrome", lambda: "/usr/bin/chrome")
    command = _adapter("gowitness").build_cmd(ToolContext(target="https://example.com"))  # type: ignore[attr-defined]
    assert command[1:3] == ["scan", "single"]
    assert "--log-level" not in command  # v2 flag that no longer exists
    assert "--chrome-path" in command


def test_gowitness_without_chrome_raises_clear_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("cyberfw.tools.gowitness._find_chrome", lambda: None)
    with pytest.raises(ToolNotFoundError, match="Chrome"):
        _adapter("gowitness").build_cmd(ToolContext(target="https://example.com"))  # type: ignore[attr-defined]


def test_gowitness_without_target_raises_toolnotfound_like_other_adapters(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("cyberfw.tools.gowitness._find_chrome", lambda: "/usr/bin/chrome")
    with pytest.raises(ToolNotFoundError):
        _adapter("gowitness").build_cmd(ToolContext())  # type: ignore[attr-defined]


def test_ffuf_builds_command_with_a_real_wordlist(tmp_path: Path) -> None:
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\nlogin\n", encoding="utf-8")
    command = _adapter("ffuf").build_cmd(  # type: ignore[attr-defined]
        ToolContext(target="https://example.com", extra_input=str(wordlist))
    )
    assert "-w" in command
    assert str(wordlist) in command
    assert "https://example.com/FUZZ" in command


def test_ffuf_prefixes_https_onto_a_bare_host(tmp_path: Path) -> None:
    """ffuf rejects ``-u host/FUZZ`` (no scheme); a bare host from subfinder must become https://host."""
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    command = _adapter("ffuf").build_cmd(  # type: ignore[attr-defined]
        ToolContext(target="api.example.com", extra_input=str(wordlist))
    )
    assert "https://api.example.com/FUZZ" in command


def test_gitleaks_uses_v8_dir_command_not_detect() -> None:
    """gitleaks v8 uses `dir <path>`; the old `detect` verb is gone."""
    command = _adapter("gitleaks").build_cmd(ToolContext(target="/repo"))  # type: ignore[attr-defined]
    assert command[1] == "dir"
    assert "/repo" in command
    assert "detect" not in command
    # findings must not look like a crash (gitleaks exits 1 on leaks otherwise)
    assert "--exit-code" in command and "0" in command
    assert "--report-path" in command and "-" in command


def test_gitleaks_parses_json_array_report() -> None:
    """gitleaks emits a JSON array (not JSONL), parsed once via parse_output."""
    adapter = _adapter("gitleaks")
    report = (
        '[\n {\n  "RuleID": "gitlab-pat",\n  "Description": "GitLab token",\n'
        '  "Secret": "glpat-x",\n  "File": "/repo/leak.txt"\n }\n]'
    )
    records = adapter.parse_output(report)  # type: ignore[attr-defined]
    assert len(records) == 1
    assert records[0].kind == "secret"
    assert records[0].rule_id == "gitlab-pat"
    assert records[0].target == "/repo/leak.txt"


def test_gitleaks_empty_report_yields_no_records() -> None:
    adapter = _adapter("gitleaks")
    assert adapter.parse_output("[]") == []  # type: ignore[attr-defined]
    assert adapter.parse_output("") == []  # type: ignore[attr-defined]


def test_ffuf_without_wordlist_raises_clear_error() -> None:
    with pytest.raises(ToolNotFoundError, match="wordlist"):
        _adapter("ffuf").build_cmd(ToolContext(target="https://example.com"))  # type: ignore[attr-defined]


def test_ffuf_rejects_nonexistent_wordlist_path() -> None:
    with pytest.raises(ToolNotFoundError, match="not found"):
        _adapter("ffuf").build_cmd(  # type: ignore[attr-defined]
            ToolContext(target="https://example.com", extra_input="/no/such/words.txt")
        )


def test_rustscan_normalizes_url_to_hostname() -> None:
    assert _hostname("https://utm.md/path") == "utm.md"
    assert _hostname("192.0.2.10") == "192.0.2.10"


def test_rustscan_strips_port_from_naabu_style_host_port() -> None:
    """``--addresses`` takes hosts only; a ``host:port`` record from naabu must lose its port."""
    assert _hostname("192.168.1.50:8080") == "192.168.1.50"
    assert _hostname("api.example.com:443") == "api.example.com"
    assert _hostname("[::1]:8080") == "::1"


def test_rustscan_passes_a_host_list_file_instead_of_a_giant_argv(tmp_path: Path) -> None:
    """Thousands of subfinder hosts comma-joined into one argument overflow Windows' command-line limit."""
    hosts = tmp_path / "ports.input"
    hosts.write_text("a.example.com\nb.example.com\n", encoding="utf-8")
    command = _adapter("rustscan").build_cmd(  # type: ignore[attr-defined]
        ToolContext(inputs=["a.example.com", "b.example.com"], input_file=hosts)
    )
    assert command[command.index("--addresses") + 1] == str(hosts)
    assert not any("," in part for part in command)


def test_rustscan_declares_addresses_as_its_list_flag_and_normalises_hosts() -> None:
    adapter = _adapter("rustscan")
    assert adapter.input_flag == "--addresses"  # type: ignore[attr-defined]
    # scheme/path and port are stripped; dedup is the engine's job
    assert adapter.prepare_inputs(
        ["https://a.example.com/x", "10.0.0.1:8080", "a.example.com"]
    ) == [  # type: ignore[attr-defined]
        "a.example.com",
        "10.0.0.1",
        "a.example.com",
    ]


def test_rustscan_parses_greppable_output() -> None:
    """Real RustScan --greppable output is ``host -> [port,port]``, not "Open host:port"."""
    spec = ToolSpec(name="rustscan", repo="org/rustscan", asset_patterns=[], binary="rustscan")
    adapter = adapter_for(spec, Path("tools_bin") / "rustscan")

    record = adapter.parse_line("192.0.2.10 -> [443]", 1)

    assert record.target == "192.0.2.10"
    assert record.ports_list == "443"
    assert record.port_state == "open"


def test_rustscan_parses_multiple_ports_on_one_host() -> None:
    spec = ToolSpec(name="rustscan", repo="org/rustscan", asset_patterns=[], binary="rustscan")
    adapter = adapter_for(spec, Path("tools_bin") / "rustscan")

    record = adapter.parse_line("192.0.2.10 -> [22,80,443]", 1)

    assert record.target == "192.0.2.10"
    assert record.ports_list == "22,80,443"


def test_rustscan_uses_supported_output_arguments() -> None:
    spec = ToolSpec(name="rustscan", repo="org/rustscan", asset_patterns=[], binary="rustscan")
    adapter = adapter_for(spec, Path("tools_bin") / "rustscan")

    command = adapter.build_cmd(ToolContext(target="example.com"))

    assert "--addresses" in command
    assert "--greppable" in command
    assert "--json" not in command


@pytest.mark.parametrize(
    ("name", "target"),
    [
        ("subfinder", "example.com"),
        ("naabu", "example.com"),
        ("rustscan", "example.com"),
        ("httpx", "https://example.com"),
        ("nuclei", "https://example.com"),
        ("gitleaks", "."),
    ],
)
def test_each_tool_builds_standalone_command(name: str, target: str, tmp_path: Path) -> None:
    spec = ToolSpec(name=name, repo=f"org/{name}", asset_patterns=[], binary=name)
    adapter = adapter_for(spec, Path("tools_bin") / name)
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")

    command = adapter.build_cmd(ToolContext(target=target, extra_input=str(wordlist)))

    assert command[0].endswith(name)
    assert len(command) > 1


class TestTargetKnowledgeLivesInTheAdapter:
    """Prompts and target validation belong to the adapter, so the CLI/launcher need no
    per-tool branches and a new tool brings its own wording."""

    def test_gitleaks_rejects_a_url_before_any_binary_is_touched(self) -> None:
        from cyberfw.tools.gitleaks import GitleaksTool

        with pytest.raises(ValueError, match="local repository directory"):
            GitleaksTool.validate_target("https://utm.md/")

    def test_gitleaks_accepts_an_existing_directory(self, tmp_path: Path) -> None:
        from cyberfw.tools.gitleaks import GitleaksTool

        GitleaksTool.validate_target(str(tmp_path))

    def test_default_validation_accepts_anything(self) -> None:
        from cyberfw.tools.subfinder import SubfinderTool

        SubfinderTool.validate_target("https://example.com/whatever")

    def test_prompts_are_tool_specific(self) -> None:
        from cyberfw.tools.ffuf import FfufTool
        from cyberfw.tools.gitleaks import GitleaksTool
        from cyberfw.tools.rustscan import RustscanTool
        from cyberfw.tools.subfinder import SubfinderTool

        assert GitleaksTool.target_prompt == "Local repository path"
        assert RustscanTool.target_prompt == "Target host, IP or URL"
        assert SubfinderTool.target_prompt == "Target (domain, URL or host)"
        assert FfufTool.extra_input_prompt == "Wordlist path"
        assert SubfinderTool.extra_input_prompt is None

    def test_adapter_class_lookup_without_a_binary(self) -> None:
        from cyberfw.exceptions import RegistryError
        from cyberfw.tools import adapter_class
        from cyberfw.tools.gitleaks import GitleaksTool

        assert adapter_class("gitleaks") is GitleaksTool
        with pytest.raises(RegistryError, match="bogus"):
            adapter_class("bogus")
