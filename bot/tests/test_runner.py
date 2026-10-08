"""The runner drives a real subprocess (a fake ``cyberfw``) and finds its report."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from _helpers import make_config
from cyberfw_bot.runner import CyberfwRunner

pytestmark = pytest.mark.asyncio


def _fake_cyberfw(tmp_path: Path, *, body: str) -> tuple[str, ...]:
    """Return a cyberfw_cmd that runs a Python stand-in with the given body."""
    script = tmp_path / "fake_cyberfw.py"
    script.write_text(body, encoding="utf-8")
    return (sys.executable, str(script))


_WRITES_A_REPORT = (
    "import json, os, sys\n"
    "argv = sys.argv\n"
    "session = argv[argv.index('--session') + 1]\n"
    "target = argv[argv.index('--target') + 1]\n"
    "d = os.path.join('reports', session)\n"
    "os.makedirs(d, exist_ok=True)\n"
    "json.dump({'ok': True, 'run': {'seed': target}, 'records': "
    "[{'tool':'nuclei','kind':'vuln','matched_at':target,'template_id':'x',"
    "'info':{'name':'Issue','severity':'high'}}]}, open(os.path.join(d,'report.json'),'w'))\n"
    "open(os.path.join(d,'report.html'),'w').write('<html>ok</html>')\n"
)


async def test_run_locates_the_report_the_cli_wrote(tmp_path: Path) -> None:
    config = make_config(tmp_path, cyberfw_cmd=_fake_cyberfw(tmp_path, body=_WRITES_A_REPORT))
    outcome = await CyberfwRunner(config).run("example.com", session="bot-abcd")

    assert outcome.exit_code == 0
    assert outcome.report_json == tmp_path / "reports" / "bot-abcd" / "report.json"
    assert outcome.report_html is not None and outcome.report_html.is_file()


_PRINTS_OUTPUT = (
    "import sys\n"
    "print('scanning example.com')\n"
    "print('a tool warning', file=sys.stderr)\n"
)


async def test_run_writes_the_tool_output_to_a_scan_log(tmp_path: Path) -> None:
    config = make_config(tmp_path, cyberfw_cmd=_fake_cyberfw(tmp_path, body=_PRINTS_OUTPUT))
    outcome = await CyberfwRunner(config).run("example.com", session="bot-log")

    log = tmp_path / "reports" / "bot-log" / "scan.log"
    assert outcome.log_path == log
    assert log.is_file()
    text = log.read_text(encoding="utf-8")
    assert "scanning example.com" in text  # stdout
    assert "a tool warning" in text  # stderr


async def test_non_zero_exit_without_a_report_is_reported(tmp_path: Path) -> None:
    config = make_config(tmp_path, cyberfw_cmd=_fake_cyberfw(tmp_path, body="import sys\nsys.exit(2)\n"))
    outcome = await CyberfwRunner(config).run("example.com", session="bot-ef01")

    assert outcome.exit_code == 2
    assert outcome.report_json is None


async def test_a_scan_that_overruns_is_stopped(tmp_path: Path) -> None:
    config = make_config(
        tmp_path,
        scan_timeout_s=0.3,
        cyberfw_cmd=_fake_cyberfw(tmp_path, body="import time\ntime.sleep(30)\n"),
    )
    outcome = await CyberfwRunner(config).run("example.com", session="bot-slow")

    assert outcome.timed_out is True
    assert outcome.report_json is None


_DUMPS_ENV = (
    "import json, os\n"
    "open('env-dump.json', 'w').write(json.dumps(dict(os.environ)))\n"
)


async def test_the_bot_settings_never_reach_the_cyberfw_process(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """cyberfw and the scanners it starts have no use for the bot's own settings."""
    monkeypatch.setenv("BOT_TOKEN", "unit-test-placeholder")
    monkeypatch.setenv("ALLOWED_USER_IDS", "42")
    monkeypatch.setenv("KEEP_ME", "yes")
    config = make_config(tmp_path, cyberfw_cmd=_fake_cyberfw(tmp_path, body=_DUMPS_ENV))

    await CyberfwRunner(config).run("example.com", session="bot-env")

    child_env = json.loads((tmp_path / "env-dump.json").read_text(encoding="utf-8"))
    assert "BOT_TOKEN" not in child_env
    assert "ALLOWED_USER_IDS" not in child_env
    assert child_env.get("KEEP_ME") == "yes"  # unrelated vars still pass through
    assert child_env.get("CYBERFW_ROOT_DIR") == str(tmp_path)  # and cyberfw's own are set


_DUMPS_ARGV_ENV = (
    "import json, os, sys\n"
    "open('dump.json', 'w').write(json.dumps({'argv': sys.argv, 'vt': os.environ.get('CYBERFW_VT_API_KEY')}))\n"
)


async def test_vt_key_adds_the_flag_and_env(tmp_path: Path) -> None:
    config = make_config(tmp_path, cyberfw_cmd=_fake_cyberfw(tmp_path, body=_DUMPS_ARGV_ENV))
    await CyberfwRunner(config).run("example.com", session="bot-vt", vt_key="SECRET")

    dump = json.loads((tmp_path / "dump.json").read_text(encoding="utf-8"))
    assert "--vt" in dump["argv"]  # the flag reaches cyberfw
    assert dump["vt"] == "SECRET"  # the key reaches the child env (not argv)
    assert "SECRET" not in dump["argv"]


async def test_no_vt_key_means_no_flag(tmp_path: Path) -> None:
    config = make_config(tmp_path, cyberfw_cmd=_fake_cyberfw(tmp_path, body=_DUMPS_ARGV_ENV))
    await CyberfwRunner(config).run("example.com", session="bot-novt")

    dump = json.loads((tmp_path / "dump.json").read_text(encoding="utf-8"))
    assert "--vt" not in dump["argv"]
    assert dump["vt"] is None


async def test_a_missing_cyberfw_binary_is_an_outcome_not_a_crash(tmp_path: Path) -> None:
    config = make_config(tmp_path, cyberfw_cmd=("definitely-not-a-real-binary-xyz",))
    outcome = await CyberfwRunner(config).run("example.com", session="bot-none")

    assert outcome.exit_code == 127
    assert "could not launch" in outcome.stderr_tail
