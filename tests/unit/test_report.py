"""Unit tests for report generation (HTML + JSON) and the report package surface."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from cyberfw import __version__
from cyberfw.exceptions import ReportError
from cyberfw.pipeline.engine import Node, NodeResult, PipelineResult
from cyberfw.pipeline.schemas import NucleiResult, SubfinderResult, ToolRecord, validate_record
from cyberfw.report import generate_html_report, generate_json_report
from cyberfw.report.html_report import generate_html_report as html_report_gen
from cyberfw.report.json_report import generate_json_report as json_report_gen
from cyberfw.report.run_info import RunInfo


def _ok_result() -> PipelineResult:
    records = [
        SubfinderResult.from_json("subfinder", '{"host": "api.example.com", "source": "stub"}', 1),
        NucleiResult.from_json(
            "nuclei",
            '{"template-id": "t1", "matched-at": "https://api.example.com/", '
            '"info": {"name": "Chk", "severity": "low"}}',
            1,
        ),
    ]
    nodes = [
        NodeResult(node=Node(tool="subfinder", stage="subfinder"), ok=True, count=1),
        NodeResult(node=Node(tool="nuclei", stage="nuclei"), ok=True, count=1),
    ]
    return PipelineResult(nodes=nodes, records=records)


def _failed_result() -> PipelineResult:
    nodes = [NodeResult(node=Node(tool="subfinder", stage="subfinder"), ok=False, count=0, error="boom")]
    return PipelineResult(nodes=nodes, records=[])


class TestPackageSurface:
    def test_report_exports_both_generators(self) -> None:
        assert html_report_gen is generate_html_report
        assert json_report_gen is generate_json_report


class TestJsonReport:
    def test_writes_valid_report(self, tmp_path: Path) -> None:
        path = json_report_gen(_ok_result(), session_id="sess1", reports_dir=tmp_path)
        assert path == tmp_path / "sess1" / "report.json"
        payload = json.loads(path.read_text(encoding="utf-8"))
        assert payload["ok"] is True
        assert payload["total_records"] == 2
        assert len(payload["stages"]) == 2
        assert any(r["target"] == "api.example.com" for r in payload["records"])

    def test_stages_carry_outcome_not_just_node_config(self, tmp_path: Path) -> None:
        """Each stage entry must expose the *run* outcome (ok/count/error), not only the Node config."""
        path = json_report_gen(_failed_result(), output_path=tmp_path / "r.json")
        stage = json.loads(path.read_text(encoding="utf-8"))["stages"][0]
        assert stage == {
            "tool": "subfinder",
            "stage": "subfinder",
            "ok": False,
            "skipped": False,
            "count": 0,
            "error": "boom",
        }

    def test_skipped_stages_are_marked_as_such(self, tmp_path: Path) -> None:
        """A consumer reading the report must be able to tell "this tool found nothing"
        from "this stage never ran because its source failed"."""
        nodes = [
            NodeResult(node=Node(tool="naabu", stage="ports"), ok=False, error="not installed"),
            NodeResult(node=Node(tool="httpx", stage="live_http"), ok=False, skipped=True, error="skipped: ..."),
        ]
        path = json_report_gen(PipelineResult(nodes=nodes, records=[]), output_path=tmp_path / "r.json")

        stages = json.loads(path.read_text(encoding="utf-8"))["stages"]
        assert stages[0]["skipped"] is False
        assert stages[1]["skipped"] is True

    def test_explicit_output_path_wins(self, tmp_path: Path) -> None:
        out = tmp_path / "custom" / "r.json"
        path = json_report_gen(_ok_result(), output_path=out)
        assert path == out
        assert out.exists()

    def test_unwritable_target_raises(self, tmp_path: Path) -> None:
        blocked = tmp_path / "is-a-dir"
        blocked.mkdir()
        with pytest.raises(ReportError):
            json_report_gen(_ok_result(), output_path=blocked)


class TestHtmlReport:
    def test_writes_self_contained_page(self, tmp_path: Path) -> None:
        path = html_report_gen(_ok_result(), session_id="s", reports_dir=tmp_path)
        text = path.read_text(encoding="utf-8")
        assert "<title>cyberfw report</title>" in text
        assert "success" in text
        assert "api.example.com" in text
        assert "Chk" in text
        assert "Stages" in text and "Records" in text

    def test_failed_status_pill(self, tmp_path: Path) -> None:
        text = html_report_gen(_failed_result(), output_path=tmp_path / "r.html").read_text(encoding="utf-8")
        assert '<span class="pill failed"><i></i>failed</span>' in text

    def test_empty_result_renders_placeholders(self, tmp_path: Path) -> None:
        empty = PipelineResult(nodes=[], records=[])
        text = html_report_gen(empty, output_path=tmp_path / "e.html").read_text(encoding="utf-8")
        assert "no stages ran" in text
        assert "no records" in text

    def test_target_is_html_escaped(self, tmp_path: Path) -> None:
        result = PipelineResult(
            nodes=[NodeResult(node=Node(tool="subfinder", stage="subfinder"), ok=True, count=1)],
            records=[SubfinderResult.from_json("subfinder", '{"host": "<script>x</script>"}', 1)],
        )
        text = html_report_gen(result, output_path=tmp_path / "x.html").read_text(encoding="utf-8")
        assert "<script>x</script>" not in text
        assert "&lt;script&gt;x&lt;/script&gt;" in text


class TestRunProvenance:
    """A security report must say what was scanned, with which tool versions and when —
    otherwise a finding cannot be reproduced or attributed to a scanner release."""

    @staticmethod
    def _run_info() -> RunInfo:
        return RunInfo(
            pipeline="recon-to-vuln",
            seed="example.com",
            session_id="pipeline-recon-to-vuln-20260922-120000",
            platform="windows/amd64",
            tool_versions={"subfinder": "2.6.6", "nuclei": None},
        )

    def test_json_report_carries_the_run_block(self, tmp_path: Path) -> None:
        result = _ok_result()
        result.started_at = datetime(2026, 9, 22, 12, 0, 0, tzinfo=timezone.utc)
        result.finished_at = datetime(2026, 9, 22, 12, 0, 42, tzinfo=timezone.utc)

        path = json_report_gen(result, output_path=tmp_path / "r.json", run=self._run_info())

        run = json.loads(path.read_text(encoding="utf-8"))["run"]
        assert run["pipeline"] == "recon-to-vuln"
        assert run["seed"] == "example.com"
        assert run["session_id"] == "pipeline-recon-to-vuln-20260922-120000"
        assert run["platform"] == "windows/amd64"
        assert run["tool_versions"] == {"subfinder": "2.6.6", "nuclei": None}
        assert run["started_at"] == "2026-09-22T12:00:00+00:00"
        assert run["finished_at"] == "2026-09-22T12:00:42+00:00"
        assert run["duration_s"] == 42.0
        assert run["cyberfw_version"] == __version__
        assert run["generated_at"].endswith("+00:00")

    def test_json_report_without_run_info_still_has_the_block(self, tmp_path: Path) -> None:
        path = json_report_gen(_ok_result(), output_path=tmp_path / "r.json")

        run = json.loads(path.read_text(encoding="utf-8"))["run"]
        assert run["cyberfw_version"] == __version__
        assert run["pipeline"] is None and run["duration_s"] is None

    def test_html_report_shows_the_provenance(self, tmp_path: Path) -> None:
        result = _ok_result()
        result.started_at = datetime(2026, 9, 22, 12, 0, 0, tzinfo=timezone.utc)
        result.finished_at = datetime(2026, 9, 22, 12, 0, 42, tzinfo=timezone.utc)

        text = html_report_gen(result, output_path=tmp_path / "r.html", run=self._run_info()).read_text(
            encoding="utf-8"
        )

        assert "recon-to-vuln" in text
        assert "example.com" in text
        assert "subfinder 2.6.6" in text
        assert "windows/amd64" in text
        assert "42" in text and "2026-09-22" in text

    def test_html_seed_is_escaped(self, tmp_path: Path) -> None:
        run = RunInfo(pipeline="p", seed="<script>alert(1)</script>")
        text = html_report_gen(_ok_result(), output_path=tmp_path / "r.html", run=run).read_text(encoding="utf-8")
        assert "<script>alert(1)</script>" not in text
        assert "&lt;script&gt;" in text


def _rec(tool: str, obj: dict[str, object], lineno: int = 1) -> ToolRecord:
    return validate_record(tool, json.dumps(obj), lineno)


def _scan_result() -> PipelineResult:
    """A recon-to-vuln shaped run: subfinder → httpx → (nuclei, gowitness) fan-out, plus gitleaks."""
    records = [
        _rec("subfinder", {"host": "a.example.com", "source": "crtsh"}),
        _rec("subfinder", {"host": "b.example.com", "source": "crtsh"}, 2),
        _rec("httpx", {"url": "https://a.example.com", "status_code": 200, "title": "<img src=x onerror=alert(1)>"}),
        _rec("nuclei", {"template-id": "CVE-2024-1", "matched-at": "https://a.example.com/x",
                        "info": {"name": "Bad Thing", "severity": "critical",
                                 "classification": {"cve-id": ["CVE-2024-1"], "cvss-score": 9.8}}}),
        _rec("nuclei", {"template-id": "t2", "matched-at": "javascript:alert(1)", "info": {"severity": "info"}}, 2),
        _rec("gowitness", {"url": "https://a.example.com", "file_name": "dir/https a.example.com.jpeg", "response_code": 200}),
        _rec("gitleaks", {"RuleID": "aws-key", "Description": "AWS key", "File": "src/config.py"}),
    ]
    nodes = [
        NodeResult(node=Node(tool="subfinder", stage="subs"), ok=True, count=2),
        NodeResult(node=Node(tool="httpx", stage="live"), ok=True, count=1),
        NodeResult(node=Node(tool="nuclei", stage="vulns", input_from="live"), ok=True, count=2),
        NodeResult(node=Node(tool="gowitness", stage="shots", input_from="live"), ok=False, skipped=True, error="skipped"),
        NodeResult(node=Node(tool="gitleaks", stage="leaks"), ok=True, count=1),
    ]
    return PipelineResult(nodes=nodes, records=records)


class TestHtmlDashboard:
    @staticmethod
    def _page(tmp_path: Path, result: PipelineResult | None = None, run: RunInfo | None = None) -> str:
        path = html_report_gen(result or _scan_result(), output_path=tmp_path / "r.html", run=run)
        return path.read_text(encoding="utf-8")

    def test_csp_admits_exactly_the_inline_scripts(self, tmp_path: Path) -> None:
        """Editing a script without its hash would silently switch the page's JS off."""
        text = self._page(tmp_path)
        csp = re.search(r'http-equiv="Content-Security-Policy" content="([^"]+)"', text)
        assert csp is not None
        scripts = re.findall(r"<script>(.*?)</script>", text, flags=re.S)
        assert len(scripts) == 2
        for script in scripts:
            digest = base64.b64encode(hashlib.sha256(script.encode("utf-8")).digest()).decode("ascii")
            assert f"'sha256-{digest}'" in csp.group(1)
        assert "'unsafe-inline'" not in csp.group(1).split("script-src", 1)[1].split(";", 1)[0]

    def test_scan_data_is_escaped_and_only_web_urls_are_links(self, tmp_path: Path) -> None:
        text = self._page(tmp_path)
        assert "<img src=x onerror" not in text
        assert "&lt;img src=x onerror=alert(1)&gt;" in text
        assert 'href="javascript:' not in text
        assert '<a href="https://a.example.com/x" target="_blank" rel="noopener noreferrer">' in text

    def test_hosts_fold_findings_onto_the_discovered_host(self, tmp_path: Path) -> None:
        text = self._page(tmp_path)
        hosts = text.split('<table class="hosts">', 1)[1].split("</table>", 1)[0]
        assert hosts.count("a.example.com") == 1  # subfinder, httpx, nuclei and gowitness on one row
        assert '<span class="sevn sev-critical" title="critical">1 crit</span>' in hosts
        assert "b.example.com" in hosts
        assert '<i class="ld"></i>src</td>' not in hosts  # a gitleaks file path is not a host

    def test_hosts_show_virustotal_reputation_when_enriched(self, tmp_path: Path) -> None:
        records = [
            _rec("subfinder", {"host": "evil.example.com", "source": "crtsh"}),
            _rec("virustotal", {
                "target": "evil.example.com", "vt_kind": "domain", "found": True,
                "malicious": 7, "suspicious": 1, "harmless": 50,
                "permalink": "https://www.virustotal.com/gui/domain/evil.example.com",
            }),
        ]
        result = PipelineResult(
            nodes=[NodeResult(node=Node(tool="subfinder", stage="s"), ok=True, count=1)],
            records=records,
        )
        hosts = self._page(tmp_path, result).split('<table class="hosts">', 1)[1].split("</table>", 1)[0]
        assert "<th>reputation</th>" in hosts
        assert '<span class="badge sev-critical">7 malicious</span>' in hosts
        assert 'href="https://www.virustotal.com/gui/domain/evil.example.com"' in hosts

    def test_hosts_omit_the_reputation_column_without_virustotal(self, tmp_path: Path) -> None:
        hosts = self._page(tmp_path).split('<table class="hosts">', 1)[1].split("</table>", 1)[0]
        assert "<th>reputation</th>" not in hosts

    def test_cve_intel_puts_exploited_findings_first(self, tmp_path: Path) -> None:
        from cyberfw.pipeline.schemas import CveIntel, NucleiResult

        hot = _rec("nuclei", {"template-id": "CVE-2021-44228", "matched-at": "https://a.example.com/",
                              "info": {"name": "Log4Shell", "severity": "medium"}})
        cold = _rec("nuclei", {"template-id": "t-crit", "matched-at": "https://a.example.com/c",
                               "info": {"name": "Cold critical", "severity": "critical"}}, 2)
        assert isinstance(hot, NucleiResult)
        hot.intel = CveIntel(
            cves=["CVE-2021-44228"], priority="now", kev=True, kev_added="2021-12-10",
            ransomware=True, epss=0.944, exploits=["50592"], metasploit=True,
        )
        result = PipelineResult(
            nodes=[NodeResult(node=Node(tool="nuclei", stage="v"), ok=True, count=2)], records=[hot, cold]
        )
        text = self._page(tmp_path, result)

        panel = text.split('<div class="panel fixfirst">', 1)[1].split("</ol>", 1)[0]
        assert "Log4Shell" in panel and "Cold critical" not in panel  # only findings with a signal
        assert "fix now" in panel and "exploited in the wild (CISA KEV)" in panel and "EPSS 94%" in panel
        card = text.split('<article class="card sev-medium"', 1)[1].split("</article>", 1)[0]
        assert '<span class="badge sev-critical">fix now</span>' in card
        assert "KEV since 2021-12-10" in card and "Metasploit module" in card
        assert 'href="https://www.exploit-db.com/exploits/50592"' in card
        assert '<span class="lbl">exploited</span>' in text  # the overview tile
        assert "2 vulnerabilities · 0 secrets · 1 exploited in the wild" in text  # section heading

    def test_epss_near_certainty_is_not_rounded_to_100_percent(self, tmp_path: Path) -> None:
        from cyberfw.pipeline.schemas import CveIntel, NucleiResult

        rec = _rec("nuclei", {"template-id": "CVE-2021-44228", "matched-at": "https://a.example.com/",
                              "info": {"name": "Log4Shell", "severity": "critical"}})
        assert isinstance(rec, NucleiResult)
        rec.intel = CveIntel(cves=["CVE-2021-44228"], priority="soon", epss=0.99999)
        result = PipelineResult(nodes=[NodeResult(node=Node(tool="nuclei", stage="v"), ok=True, count=1)], records=[rec])
        text = self._page(tmp_path, result)
        assert "EPSS &gt;99.9%" in text
        assert "EPSS 100%" not in text

    def test_tls_section_lists_certificates_soonest_first(self, tmp_path: Path) -> None:
        now = datetime(2026, 10, 9, 12, 0, tzinfo=timezone.utc)

        def site(host: str, days: int, **flags: object) -> ToolRecord:
            not_after = (now + timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
            tls = {"host": host, "port": "443", "probe_status": True, "tls_version": "tls12",
                   "issuer_cn": "R11", "not_after": not_after, **flags}
            return _rec("httpx", {"url": f"https://{host}", "status_code": 200, "tls": tls})

        result = PipelineResult(
            nodes=[NodeResult(node=Node(tool="httpx", stage="live"), ok=True, count=3)],
            records=[site("later.example.com", 200), site("soon.example.com", 5),
                     site("dead.example.com", -3, expired=True)],
            started_at=now - timedelta(minutes=1),
            finished_at=now,  # countdowns are measured from the end of the scan
        )
        text = self._page(tmp_path, result)
        table = text.split('<table class="certs">', 1)[1].split("</table>", 1)[0]
        assert table.index("dead.example.com") < table.index("soon.example.com") < table.index("later.example.com")
        assert '<span class="badge sev-critical">expired</span>' in table
        assert '<span class="badge sev-critical">5 days</span>' in table  # inside a week
        assert '<span class="mono">200 days</span>' in table  # nothing to flag
        assert "3 seen · 1 expired · 1 expire within 30 days" in text
        assert '<span class="lbl">certificates</span>' in text
        assert "tls={" not in text  # the raw block stays out of the record table's detail column

    def test_email_section_and_card_carry_the_verdict_and_the_fix(self, tmp_path: Path) -> None:
        from cyberfw.posture import mail

        posture, found = mail.assess(
            "shop.test", mx=["mx.shop.test"], null_mx=False, spf=["v=spf1 mx ~all"],
            spf_policy="~all", dmarc=[], dmarc_domain="",
        )
        result = PipelineResult(
            nodes=[NodeResult(node=Node(tool="subfinder", stage="s"), ok=True, count=0)],
            records=[posture, *found],
        )
        text = self._page(tmp_path, result)
        section = text.split('<section id="email"', 1)[1].split("</section>", 1)[0]
        assert '<span class="badge t-err">can be spoofed</span>' in section
        assert "v=spf1 mx ~all" in section and "no DMARC record" in section and "mx.shop.test" in section
        card = text.split('<article class="card sev-medium"', 1)[1].split("</article>", 1)[0]
        assert "No DMARC record" in card and '<p class="fix"><b>Fix:</b>' in card
        assert "<code>_dmarc.shop.test</code>" in card  # backticked DNS names render as code
        assert '<span class="lbl">email spoofing</span>' in text

    def test_no_intel_means_no_fix_first_panel(self, tmp_path: Path) -> None:
        text = self._page(tmp_path)
        assert 'class="panel fixfirst"' not in text
        assert '<span class="lbl">exploited</span>' not in text

    def test_severity_donut_and_cards(self, tmp_path: Path) -> None:
        text = self._page(tmp_path)
        assert text.count('class="seg sev-') == 2  # critical + info
        assert '<b data-count="2">2</b><span>findings</span>' in text
        card = text.split('<article class="card sev-critical"', 1)[1].split("</article>", 1)[0]
        assert "Bad Thing" in card and "CVSS 9.8" in card
        assert card.count("CVE-2024-1") == 1  # the template id is not repeated as a CVE chip
        assert '<h4>aws-key</h4>' in text

    def test_clean_state_only_when_nuclei_actually_ran(self, tmp_path: Path) -> None:
        ran = PipelineResult(nodes=[NodeResult(node=Node(tool="nuclei", stage="v"), ok=True, count=0)])
        assert "No vulnerabilities found" in self._page(tmp_path, ran)
        skipped = PipelineResult(
            nodes=[NodeResult(node=Node(tool="nuclei", stage="v"), ok=False, skipped=True, error="skipped")]
        )
        assert "No vulnerabilities found" not in self._page(tmp_path, skipped)

    def test_pipeline_graph_follows_input_from(self, tmp_path: Path) -> None:
        text = self._page(tmp_path, run=RunInfo(seed="example.com"))
        flow = text.split('<div class="panel flow">', 1)[1].split("</svg>", 1)[0]
        assert flow.count('class="fn st-') == 5 and 'class="fn seed"' in flow
        assert flow.count('class="edge ') == 5  # one edge into every stage
        # nuclei and gowitness both read httpx, so their edges start at the same point
        starts = re.findall(r'class="edge (\w+)" pathLength="1" d="M([\d.,]+) ', flow)
        assert starts[2][1] == starts[3][1]
        assert starts[3][0] == "skip"
        assert '<g class="fn st-skipped"' in flow

    def test_screenshot_gallery_links_into_the_session(self, tmp_path: Path) -> None:
        text = self._page(tmp_path)
        assert 'src="screenshots/https%20a.example.com.jpeg"' in text
        assert 'id="lightbox"' in text
        assert 'id="lightbox"' not in self._page(tmp_path, _ok_result())

    def test_every_record_is_in_the_page_without_javascript(self, tmp_path: Path) -> None:
        records = [_rec("subfinder", {"host": f"h{i}.example.com"}, i) for i in range(1, 1201)]
        result = PipelineResult(nodes=[NodeResult(node=Node(tool="subfinder", stage="s"), count=1200)], records=records)
        text = self._page(tmp_path, result)
        table = text.split('<table id="record-table">', 1)[1].split("</table>", 1)[0]
        assert table.count('<tr data-tool="subfinder"') == 1200
        assert '<button id="more" class="more-btn" type="button" hidden>' in text

    def test_tiles_count_what_was_found(self, tmp_path: Path) -> None:
        text = self._page(tmp_path)
        assert '<span class="lbl">findings</span><b class="num"><span data-count="2">2</span></b>' in text
        assert '<span class="lbl">stages</span><b class="num"><span data-count="4">4</span><span class="of">/5</span>' in text
        assert '<span class="lbl">secrets</span>' in text
