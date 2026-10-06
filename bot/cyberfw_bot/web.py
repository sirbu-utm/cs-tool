"""A small local web dashboard for the bot — monitor and control scans.

It binds to localhost only (viewed over an SSH tunnel), so it carries no auth of
its own: reaching it already means shell access to the host. It shares the live
:class:`~cyberfw_bot.service.ScanService` and :class:`~cyberfw_bot.storage.ScanStore`
with the bot, so it can list history, trigger a scan, cancel one in flight, and
tail the bot log and each scan's tool output.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from aiohttp import web

from cyberfw_bot.config import BotConfig
from cyberfw_bot.models import Scan
from cyberfw_bot.service import ScanService
from cyberfw_bot.storage import ScanStore
from cyberfw_bot.validation import ValidationError

__all__ = ["start", "build_web_app"]

LOG = logging.getLogger("cyberfw_bot")

#: Scan ids are short hex tokens; this also stops a crafted id from walking the
#: filesystem when it is used to build a report/log path.
_SID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_LOG_TAIL_BYTES = 200_000


def _scan_dict(scan: Scan) -> dict[str, object]:
    severity = dict(scan.summary.severity_counts) if scan.summary else {}
    return {
        "id": scan.id,
        "target": scan.target,
        "status": scan.status,
        "user_id": scan.user_id,
        "created_at": scan.created_at.isoformat() if scan.created_at else None,
        "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
        "exit_code": scan.exit_code,
        "error": scan.error,
        "severity": severity,
        "has_report": bool(scan.report_html),
    }


def _sid(request: web.Request) -> str:
    sid = request.match_info["sid"]
    if not _SID_RE.match(sid):
        raise web.HTTPBadRequest(text="bad scan id")
    return sid


def _tail(path: Path | None, limit: int = _LOG_TAIL_BYTES) -> str:
    if path is None:
        return ""
    try:
        data = path.read_bytes()
    except OSError:
        return ""
    return data[-limit:].decode("utf-8", errors="replace")


async def _index(_request: web.Request) -> web.Response:
    return web.Response(text=_DASHBOARD, content_type="text/html")


async def _list_scans(request: web.Request) -> web.Response:
    store: ScanStore = request.app["store"]
    scans = await store.recent(100)
    return web.json_response([_scan_dict(s) for s in scans])


async def _scan_detail(request: web.Request) -> web.Response:
    store: ScanStore = request.app["store"]
    scan = await store.get(_sid(request))
    if scan is None:
        raise web.HTTPNotFound(text="no such scan")
    data = _scan_dict(scan)
    data["findings"] = (
        [
            {"name": f.name, "severity": f.severity, "target": f.target, "template_id": f.template_id}
            for f in scan.summary.findings
        ]
        if scan.summary
        else []
    )
    return web.json_response(data)


async def _scan_log(request: web.Request) -> web.Response:
    config: BotConfig = request.app["config"]
    path = config.reports_dir / f"bot-{_sid(request)}" / "scan.log"
    return web.Response(text=_tail(path) or "(no tool output yet)", content_type="text/plain")


async def _bot_log(request: web.Request) -> web.Response:
    config: BotConfig = request.app["config"]
    return web.Response(text=_tail(config.log_path) or "(log is empty)", content_type="text/plain")


async def _report(request: web.Request) -> web.StreamResponse:
    config: BotConfig = request.app["config"]
    path = config.reports_dir / f"bot-{_sid(request)}" / "report.html"
    if not path.is_file():
        raise web.HTTPNotFound(text="no report for this scan")
    return web.FileResponse(path)


async def _trigger(request: web.Request) -> web.Response:
    service: ScanService = request.app["service"]
    try:
        body = await request.json()
    except Exception:  # noqa: BLE001 - a malformed body is just a bad request
        raise web.HTTPBadRequest(text="expected a JSON body") from None
    target = str(body.get("target", "")).strip()
    try:
        scan = await service.trigger(target)
    except ValidationError as exc:
        raise web.HTTPBadRequest(text=str(exc)) from exc
    LOG.info("web UI started scan %s target=%s", scan.id, scan.target)
    return web.json_response({"id": scan.id})


async def _cancel(request: web.Request) -> web.Response:
    service: ScanService = request.app["service"]
    cancelled = await service.cancel(_sid(request))
    return web.json_response({"cancelled": cancelled})


def build_web_app(config: BotConfig, store: ScanStore, service: ScanService) -> web.Application:
    app = web.Application()
    app["config"] = config
    app["store"] = store
    app["service"] = service
    app.add_routes(
        [
            web.get("/", _index),
            web.get("/api/scans", _list_scans),
            web.post("/api/scans", _trigger),
            web.get("/api/scans/{sid}", _scan_detail),
            web.get("/api/scans/{sid}/log", _scan_log),
            web.get("/api/scans/{sid}/report", _report),
            web.post("/api/scans/{sid}/cancel", _cancel),
            web.get("/api/log", _bot_log),
        ]
    )
    return app


async def start(config: BotConfig, store: ScanStore, service: ScanService) -> web.AppRunner | None:
    """Start the dashboard on localhost. Returns the runner, or None if disabled."""
    if not config.web_port:
        LOG.info("web UI disabled (WEB_PORT=0)")
        return None
    runner = web.AppRunner(build_web_app(config, store, service))
    await runner.setup()
    site = web.TCPSite(runner, config.web_host, config.web_port)
    await site.start()
    LOG.info("web UI on http://%s:%d", config.web_host, config.web_port)
    return runner


_DASHBOARD = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>cyberfw monitor</title>
<style>
  :root { --red: #b00020; --amber: #a66b00; --line: #d9d9d9; --muted: #555; }
  * { box-sizing: border-box; }
  body { margin: 0; background: #fff; color: #121212; font: 14px/1.5 system-ui, sans-serif; }
  code, .mono, pre, td.t { font-family: ui-monospace, Consolas, monospace; }
  header { border-bottom: 1px solid var(--line); padding: 14px 20px; display: flex; align-items: baseline; gap: 12px; }
  header h1 { margin: 0; font-size: 16px; font-weight: 600; }
  header .dim { color: var(--muted); font: 12px ui-monospace, monospace; }
  main { max-width: 1100px; margin: 0 auto; padding: 20px; }
  .bar { display: flex; gap: 8px; margin-bottom: 18px; }
  .bar input { flex: 1; padding: 8px 10px; border: 1px solid var(--line); border-radius: 6px; font: 13px ui-monospace, monospace; }
  button { padding: 7px 12px; border: 1px solid #bbb; border-radius: 6px; background: #fff; cursor: pointer; font: 13px system-ui; color: #121212; }
  button:hover { border-color: #121212; }
  button.danger { color: var(--red); border-color: #e3b7bf; }
  table { width: 100%; border-collapse: collapse; }
  th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--line); font-size: 13px; vertical-align: top; }
  th { color: var(--muted); font-weight: 600; font-size: 11px; text-transform: uppercase; letter-spacing: .04em; }
  tr.sel td { background: #f3f3f3; }
  .st { font: 11px ui-monospace, monospace; padding: 1px 7px; border: 1px solid #ccc; border-radius: 4px; text-transform: uppercase; }
  .st.running, .st.queued { border-color: #bbb; }
  .st.failed, .st.cancelled { color: var(--red); border-color: #e3b7bf; }
  .sev { font: 11px ui-monospace, monospace; }
  .sev .crit, .sev .high { color: var(--red); font-weight: 700; }
  .sev .med { color: var(--amber); font-weight: 700; }
  .acts { display: flex; gap: 6px; flex-wrap: wrap; }
  .acts a, .acts button { font-size: 12px; padding: 3px 8px; }
  .acts a { text-decoration: none; color: #121212; border: 1px solid #bbb; border-radius: 6px; }
  .acts a:hover { border-color: #121212; }
  h2 { font-size: 13px; text-transform: uppercase; letter-spacing: .04em; color: var(--muted); margin: 26px 0 8px; }
  pre { margin: 0; padding: 12px; background: #fafafa; border: 1px solid var(--line); border-radius: 6px; max-height: 320px; overflow: auto; font-size: 12px; white-space: pre-wrap; word-break: break-word; }
  .flex { display: flex; gap: 20px; align-items: flex-start; }
  .flex > div { flex: 1; min-width: 0; }
  .empty { color: var(--muted); padding: 16px 0; }
  .err { color: var(--red); }
</style>
</head>
<body>
<header><h1>cyberfw monitor</h1><span class="dim" id="clock"></span></header>
<main>
  <div class="bar">
    <input id="target" placeholder="scan a target you are authorised to test — domain, http(s) URL or IP" autocomplete="off">
    <button id="go">Start scan</button>
  </div>
  <div id="msg" class="err"></div>

  <table>
    <thead><tr><th>id</th><th>target</th><th>status</th><th>findings</th><th>age</th><th>actions</th></tr></thead>
    <tbody id="rows"><tr><td colspan="6" class="empty">loading…</td></tr></tbody>
  </table>

  <div class="flex">
    <div>
      <h2 id="logtitle">Scan output</h2>
      <pre id="scanlog">select a scan's “Log” to see its tool output.</pre>
    </div>
    <div>
      <h2>Bot log</h2>
      <pre id="botlog">loading…</pre>
    </div>
  </div>
</main>
<script>
const $ = (id) => document.getElementById(id);
let selected = null;

function age(iso) {
  if (!iso) return "";
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return Math.round(s) + "s";
  if (s < 3600) return Math.round(s / 60) + "m";
  return Math.round(s / 3600) + "h";
}
function sevHtml(sev) {
  const parts = [];
  if (sev.critical) parts.push('<span class="crit">' + sev.critical + ' crit</span>');
  if (sev.high) parts.push('<span class="high">' + sev.high + ' high</span>');
  if (sev.medium) parts.push('<span class="med">' + sev.medium + ' med</span>');
  const low = (sev.low || 0) + (sev.info || 0) + (sev.unknown || 0);
  if (low) parts.push('<span>' + low + ' low/info</span>');
  return '<span class="sev">' + (parts.join(' · ') || '—') + '</span>';
}
const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

async function refresh() {
  $("clock").textContent = new Date().toLocaleTimeString();
  try {
    const scans = await (await fetch("api/scans")).json();
    const rows = $("rows");
    if (!scans.length) { rows.innerHTML = '<tr><td colspan="6" class="empty">no scans yet</td></tr>'; }
    else rows.innerHTML = scans.map((s) => {
      const acts = [];
      if (s.status === "queued" || s.status === "running")
        acts.push('<button class="danger" onclick="cancelScan(\'' + s.id + '\')">Cancel</button>');
      if (s.has_report)
        acts.push('<a href="api/scans/' + s.id + '/report" target="_blank">Report</a>');
      acts.push('<button onclick="showLog(\'' + s.id + '\')">Log</button>');
      return '<tr class="' + (s.id === selected ? 'sel' : '') + '">'
        + '<td class="t">' + esc(s.id) + '</td>'
        + '<td class="t">' + esc(s.target) + '</td>'
        + '<td><span class="st ' + esc(s.status) + '">' + esc(s.status) + '</span></td>'
        + '<td>' + sevHtml(s.severity || {}) + '</td>'
        + '<td class="t">' + age(s.created_at) + '</td>'
        + '<td><div class="acts">' + acts.join('') + '</div></td></tr>';
    }).join('');
  } catch (e) { /* keep last view */ }
  try { $("botlog").textContent = await (await fetch("api/log")).text(); } catch (e) {}
  if (selected) { try { $("scanlog").textContent = await (await fetch("api/scans/" + selected + "/log")).text(); } catch (e) {} }
}
async function showLog(id) {
  selected = id;
  $("logtitle").textContent = "Scan output · " + id;
  $("scanlog").textContent = await (await fetch("api/scans/" + id + "/log")).text();
  refresh();
}
async function cancelScan(id) {
  await fetch("api/scans/" + id + "/cancel", { method: "POST" });
  refresh();
}
async function start() {
  const target = $("target").value.trim();
  $("msg").textContent = "";
  if (!target) return;
  const r = await fetch("api/scans", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ target }) });
  if (!r.ok) { $("msg").textContent = await r.text(); return; }
  $("target").value = "";
  refresh();
}
$("go").addEventListener("click", start);
$("target").addEventListener("keydown", (e) => { if (e.key === "Enter") start(); });
refresh();
setInterval(refresh, 2000);
</script>
</body>
</html>
"""
