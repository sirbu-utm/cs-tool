"""Generating OS-scheduler entries for `cyberfw schedule` (cyberfw.schedule).

The generation is pure string building — no crontab or schtasks is touched —
so expectations are hand-written literals.
"""

from __future__ import annotations

from subprocess import CompletedProcess

import pytest

from cyberfw import schedule
from cyberfw.schedule import Schedule


class TestCronExpr:
    def test_daily_at_a_time(self) -> None:
        assert schedule.cron_expr("daily", "09:00") == "0 9 * * *"
        assert schedule.cron_expr("daily", "23:05") == "5 23 * * *"

    def test_weekly_is_monday(self) -> None:
        assert schedule.cron_expr("weekly", "09:00") == "0 9 * * 1"

    def test_hourly_ignores_the_time(self) -> None:
        assert schedule.cron_expr("hourly", "09:00") == "0 * * * *"

    @pytest.mark.parametrize("bad", ["9:00", "0900", "24:00", "09:60", "nine"])
    def test_a_malformed_time_is_rejected(self, bad: str) -> None:
        with pytest.raises(ValueError):
            schedule.cron_expr("daily", bad)

    def test_an_unknown_cadence_is_rejected(self) -> None:
        with pytest.raises(ValueError):
            schedule.cron_expr("monthly", "09:00")


class TestScanCommand:
    def test_the_inner_pipeline_call(self) -> None:
        s = Schedule("recon-to-vuln", "example.com")
        assert schedule.scan_command(s, program="cyberfw") == (
            'cyberfw pipeline recon-to-vuln -t "example.com" --alert --alert-severity low'
        )

    def test_extra_flags_and_severity_ride_along(self) -> None:
        s = Schedule("recon-to-vuln", "example.com", alert_severity="high", scan_args=("--ffuf", "--no-mail"))
        assert schedule.scan_command(s, program="cyberfw") == (
            'cyberfw pipeline recon-to-vuln -t "example.com" --alert --alert-severity high --ffuf --no-mail'
        )


class TestTag:
    def test_identity_from_pipeline_and_target(self) -> None:
        assert schedule.tag(Schedule("recon-to-vuln", "sub.example.com")) == "cyberfw-recon-to-vuln-sub.example.com"

    def test_an_awkward_target_is_sanitised(self) -> None:
        tag = schedule.tag(Schedule("ports-to-vuln", "https://ex.com/a?b=c"))
        assert "/" not in tag and ":" not in tag and "?" not in tag
        assert tag.startswith("cyberfw-ports-to-vuln-")


class TestCronLine:
    def test_carries_the_workspace_log_and_tag(self) -> None:
        s = Schedule("recon-to-vuln", "example.com", every="daily", at="09:00")
        line = schedule.cron_line(s, program="cyberfw", root="/ws", log="/ws/logs/schedule.log")
        assert line == (
            '0 9 * * * CYBERFW_ROOT_DIR="/ws" '
            'cyberfw pipeline recon-to-vuln -t "example.com" --alert --alert-severity low '
            '>> "/ws/logs/schedule.log" 2>&1 # cyberfw-recon-to-vuln-example.com'
        )


class TestSchtasksCommand:
    def test_daily(self) -> None:
        s = Schedule("recon-to-vuln", "example.com", every="daily", at="09:00")
        argv = schedule.schtasks_command(s, program="cyberfw", root=r"C:\ws", log=r"C:\ws\logs\schedule.log")
        assert argv[:7] == ["schtasks", "/Create", "/SC", "DAILY", "/ST", "09:00", "/TN"]
        assert argv[7] == "cyberfw-recon-to-vuln-example.com"
        assert argv[8] == "/TR"
        assert "set CYBERFW_ROOT_DIR=C:\\ws" in argv[9] and "--alert" in argv[9]
        assert argv[-1] == "/F"

    def test_weekly_and_hourly_map_to_schtasks_schedules(self) -> None:
        weekly = schedule.schtasks_command(
            Schedule("recon-to-vuln", "x", every="weekly", at="08:30"), program="cyberfw", root="r", log="l"
        )
        assert weekly[2:6] == ["/SC", "WEEKLY", "/D", "MON"] and "08:30" in weekly

        hourly = schedule.schtasks_command(
            Schedule("recon-to-vuln", "x", every="hourly"), program="cyberfw", root="r", log="l"
        )
        assert hourly[2:4] == ["/SC", "HOURLY"]


class TestCrontabEditing:
    CURRENT = "# a header\n0 1 * * * old-call # cyberfw-recon-to-vuln-example.com\nother job\n"

    def test_install_replaces_the_tagged_line_and_keeps_the_rest(self) -> None:
        new = schedule.cron_with(self.CURRENT, "0 9 * * * new-call # cyberfw-recon-to-vuln-example.com",
                                 "cyberfw-recon-to-vuln-example.com")
        assert "old-call" not in new  # the previous entry of this identity is replaced, not duplicated
        assert "new-call" in new
        assert "# a header" in new and "other job" in new
        assert new.count("cyberfw-recon-to-vuln-example.com") == 1

    def test_install_into_an_empty_crontab(self) -> None:
        new = schedule.cron_with("", "0 9 * * * call # cyberfw-x", "cyberfw-x")
        assert new == "0 9 * * * call # cyberfw-x\n"

    def test_remove_drops_only_the_tagged_line(self) -> None:
        new = schedule.cron_without(self.CURRENT, "cyberfw-recon-to-vuln-example.com")
        assert "cyberfw-recon-to-vuln-example.com" not in new
        assert "# a header" in new and "other job" in new

    def test_remove_the_last_entry_leaves_an_empty_crontab(self) -> None:
        new = schedule.cron_without("0 9 * * * call # cyberfw-x\n", "cyberfw-x")
        assert new == ""


class TestCrontabBoundary:
    """install_cron / remove_cron drive `crontab` through the mockable _run boundary."""

    def test_install_writes_the_merged_crontab(self, monkeypatch: pytest.MonkeyPatch) -> None:
        writes: list[str] = []

        def fake_run(argv: list[str], *, stdin: str | None = None) -> CompletedProcess[str]:
            if argv == ["crontab", "-l"]:
                return CompletedProcess(argv, 0, "0 1 * * * old # cyberfw-recon-to-vuln-example.com\nkeep job\n", "")
            if argv == ["crontab", "-"]:
                writes.append(stdin or "")
            return CompletedProcess(argv, 0, "", "")

        monkeypatch.setattr(schedule, "_run", fake_run)
        schedule.install_cron(Schedule("recon-to-vuln", "example.com"), program="cyberfw", root="/ws", log="/ws/l")

        assert len(writes) == 1
        written = writes[0]
        assert "keep job" in written  # unrelated entries survive
        assert "old" not in written  # the previous entry of this identity is gone
        assert written.count("cyberfw-recon-to-vuln-example.com") == 1  # not duplicated

    def test_remove_reports_when_there_was_nothing_to_remove(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            schedule, "_run",
            lambda argv, *, stdin=None: CompletedProcess(argv, 0, "just another job\n", ""),
        )

        assert schedule.remove_cron(Schedule("recon-to-vuln", "nope")) is False
