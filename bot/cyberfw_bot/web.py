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
#: A screenshot file name: any single path segment (no "/", no "..").
_NAME_RE = re.compile(r"^[^/]{1,255}$")
_LOG_TAIL_BYTES = 200_000


def _scan_dict(scan: Scan) -> dict[str, object]:
    severity = dict(scan.summary.severity_counts) if scan.summary else {}
    return {
        "id": scan.id,
        "target": scan.target,
        "status": scan.status,
        "user_id": scan.user_id,
        "username": scan.username,
        "chat_id": scan.chat_id,
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


def _check_origin(request: web.Request) -> None:
    """Refuse cross-site state-changing requests (CSRF).

    The dashboard has no auth and binds to localhost, so while the SSH tunnel is
    up a page on any site the operator visits could POST here. Same-origin fetches
    from our own page send an ``Origin`` that matches ``Host``; a forged one does
    not, and a browser sends ``Origin`` on every cross-site POST.
    """
    origin = request.headers.get("Origin")
    if origin is None:
        return  # curl / same-origin navigations carry no Origin — allowed
    host = request.headers.get("Host", "")
    if origin not in {f"http://{host}", f"https://{host}"}:
        raise web.HTTPForbidden(text="cross-origin request refused")


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


async def _screenshot(request: web.Request) -> web.StreamResponse:
    config: BotConfig = request.app["config"]
    name = request.match_info["name"]
    if ".." in name or not _NAME_RE.match(name):
        raise web.HTTPBadRequest(text="bad name")
    path = config.reports_dir / f"bot-{_sid(request)}" / "screenshots" / name
    if not path.is_file():
        raise web.HTTPNotFound()
    return web.FileResponse(path)


async def _trigger(request: web.Request) -> web.Response:
    _check_origin(request)
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
    _check_origin(request)
    service: ScanService = request.app["service"]
    cancelled = await service.cancel(_sid(request))
    return web.json_response({"cancelled": cancelled})


async def _message(request: web.Request) -> web.Response:
    """Send a message to a chat as the bot (operator-initiated, from the UI)."""
    _check_origin(request)
    bot = request.app.get("bot")
    if bot is None:
        raise web.HTTPServiceUnavailable(text="messaging is unavailable")
    try:
        body = await request.json()
    except Exception:  # noqa: BLE001 - a malformed body is just a bad request
        raise web.HTTPBadRequest(text="expected a JSON body") from None
    try:
        chat_id = int(body.get("chat_id"))
    except (TypeError, ValueError):
        raise web.HTTPBadRequest(text="chat_id must be a number") from None
    text = str(body.get("text", "")).strip()
    if not text:
        raise web.HTTPBadRequest(text="the message is empty")
    try:
        await bot.send_message(chat_id, text)
    except Exception as exc:  # noqa: BLE001 - surface the Telegram error to the operator
        raise web.HTTPBadGateway(text=f"Telegram refused: {exc}") from exc
    LOG.info("operator messaged chat %s (%d chars)", chat_id, len(text))
    return web.json_response({"sent": True})


async def _list_users(request: web.Request) -> web.Response:
    config: BotConfig = request.app["config"]
    store: ScanStore = request.app["store"]
    users: list[dict[str, object]] = [
        {"user_id": uid, "username": None, "source": "env"}
        for uid in sorted(config.allowed_user_ids)
    ]
    for row in await store.list_allowed():
        users.append(
            {"user_id": row["user_id"], "username": row["username"],
             "source": "db", "added_at": row["added_at"]}
        )
    return web.json_response(users)


async def _add_user(request: web.Request) -> web.Response:
    _check_origin(request)
    service: ScanService = request.app["service"]
    try:
        body = await request.json()
    except Exception:  # noqa: BLE001 - a malformed body is just a bad request
        raise web.HTTPBadRequest(text="expected a JSON body") from None
    try:
        user_id = int(body.get("user_id"))
    except (TypeError, ValueError):
        raise web.HTTPBadRequest(text="telegram id must be a number") from None
    if user_id <= 0:
        raise web.HTTPBadRequest(text="telegram id must be a positive number")
    username = str(body.get("username", "")).strip() or None
    await service.allow_user(user_id, username)
    return web.json_response({"added": user_id})


async def _remove_user(request: web.Request) -> web.Response:
    _check_origin(request)
    service: ScanService = request.app["service"]
    try:
        user_id = int(request.match_info["uid"])
    except ValueError:
        raise web.HTTPBadRequest(text="bad telegram id") from None
    removed = await service.disallow_user(user_id)
    return web.json_response({"removed": removed})


def build_web_app(
    config: BotConfig, store: ScanStore, service: ScanService, bot: object | None = None
) -> web.Application:
    app = web.Application()
    app["config"] = config
    app["store"] = store
    app["service"] = service
    app["bot"] = bot
    app.add_routes(
        [
            web.get("/", _index),
            web.get("/api/scans", _list_scans),
            web.post("/api/scans", _trigger),
            web.get("/api/scans/{sid}", _scan_detail),
            web.get("/api/scans/{sid}/log", _scan_log),
            web.get("/api/scans/{sid}/report", _report),
            web.get("/api/scans/{sid}/screenshots/{name}", _screenshot),
            web.post("/api/scans/{sid}/cancel", _cancel),
            web.post("/api/message", _message),
            web.get("/api/users", _list_users),
            web.post("/api/users", _add_user),
            web.delete("/api/users/{uid}", _remove_user),
            web.get("/api/log", _bot_log),
        ]
    )
    return app


async def start(
    config: BotConfig, store: ScanStore, service: ScanService, bot: object | None = None
) -> web.AppRunner | None:
    """Start the dashboard on localhost. Returns the runner, or None if disabled."""
    if not config.web_port:
        LOG.info("web UI disabled (WEB_PORT=0)")
        return None
    if config.web_host not in {"127.0.0.1", "::1", "localhost"}:
        # The dashboard has no auth of its own; binding it anywhere but loopback
        # would expose scan control to the network. Refuse rather than do that.
        LOG.error(
            "web UI NOT started: WEB_HOST=%s is not loopback and the dashboard has "
            "no authentication. Keep WEB_HOST=127.0.0.1 and reach it over an SSH tunnel.",
            config.web_host,
        )
        return None
    # access_log=None silences aiohttp's per-request line; the dashboard polls
    # a few endpoints every couple of seconds, which would otherwise bury the
    # bot log. Our own LOG.info calls (scan started, operator messaged) remain.
    runner = web.AppRunner(build_web_app(config, store, service, bot), access_log=None)
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
  :root {
    --bg: #fff; --fg: #121212; --panel: #fafafa; --line: #d9d9d9; --muted: #555; --sel: #f3f3f3;
    --red: #b00020; --amber: #a66b00;
  }
  :root[data-theme="dark"] {
    --bg: #121212; --fg: #f0f0f0; --panel: #1b1b1b; --line: #333; --muted: #a6a6a6; --sel: #242424;
    --red: #ff6b76; --amber: #e0a84e;
  }
  * { box-sizing: border-box; }
  body { margin: 0; background: var(--bg); color: var(--fg); font: 14px/1.5 system-ui, sans-serif; }
  code, .mono, pre, td.t { font-family: ui-monospace, Consolas, monospace; }
  header { border-bottom: 1px solid var(--line); padding: 14px 20px; display: flex; align-items: baseline; gap: 12px; }
  header h1 { margin: 0; font-size: 16px; font-weight: 600; }
  header .dim { color: var(--muted); font: 12px ui-monospace, monospace; }
  header #theme { margin-left: auto; align-self: center; }
  main { max-width: 1100px; margin: 0 auto; padding: 20px; }
  .bar { display: flex; gap: 8px; margin-bottom: 18px; }
  .bar input { flex: 1; padding: 8px 10px; border: 1px solid var(--line); border-radius: 6px; background: var(--bg); color: var(--fg); font: 13px ui-monospace, monospace; }
  button { padding: 7px 12px; border: 1px solid var(--line); border-radius: 6px; background: var(--panel); cursor: pointer; font: 13px system-ui; color: var(--fg); }
  button:hover { border-color: var(--fg); }
  button.danger { color: var(--red); }
  table { width: 100%; border-collapse: collapse; }
  th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--line); font-size: 13px; vertical-align: top; }
  th { color: var(--muted); font-weight: 600; font-size: 11px; text-transform: uppercase; letter-spacing: .04em; }
  tr.sel td { background: var(--sel); }
  .st { font: 11px ui-monospace, monospace; padding: 1px 7px; border: 1px solid var(--line); border-radius: 4px; text-transform: uppercase; }
  .st.failed, .st.cancelled { color: var(--red); }
  .sev { font: 11px ui-monospace, monospace; }
  .sev .crit, .sev .high { color: var(--red); font-weight: 700; }
  .sev .med { color: var(--amber); font-weight: 700; }
  .acts { display: flex; gap: 6px; flex-wrap: wrap; }
  .acts a, .acts button { font-size: 12px; padding: 3px 8px; }
  .acts a { text-decoration: none; color: var(--fg); border: 1px solid var(--line); border-radius: 6px; }
  .acts a:hover { border-color: var(--fg); }
  h2 { font-size: 13px; text-transform: uppercase; letter-spacing: .04em; color: var(--muted); margin: 26px 0 8px; }
  pre { margin: 0; padding: 12px; background: var(--panel); border: 1px solid var(--line); border-radius: 6px; max-height: 320px; overflow: auto; font-size: 12px; white-space: pre-wrap; word-break: break-word; }
  .flex { display: flex; gap: 20px; align-items: flex-start; }
  .flex > div { flex: 1; min-width: 0; }
  .empty { color: var(--muted); padding: 16px 0; }
  .err { color: var(--red); }
</style>
</head>
<body>
<header><h1>cyberfw monitor</h1><span class="dim" id="clock"></span><button id="theme" type="button" title="Toggle light/dark">Theme</button></header>
<main>
  <div class="bar">
    <input id="target" placeholder="scan a target you are authorised to test — domain, http(s) URL or IP" autocomplete="off">
    <button id="go">Start scan</button>
  </div>
  <div id="msg" class="err"></div>

  <table>
    <thead><tr><th>id</th><th>target</th><th>user</th><th>status</th><th>findings</th><th>age</th><th>actions</th></tr></thead>
    <tbody id="rows"><tr><td colspan="7" class="empty">loading…</td></tr></tbody>
  </table>

  <h2>Message a user (as the bot)</h2>
  <div class="bar">
    <input id="mchat" placeholder="chat id" style="flex: 0 0 150px" autocomplete="off">
    <input id="mtext" placeholder="message — sent to that chat as the bot" autocomplete="off">
    <button id="msend">Send</button>
  </div>
  <div id="mmsg"></div>

  <h2>Users (allow-list)</h2>
  <div class="bar">
    <input id="uid" placeholder="telegram id" style="flex: 0 0 150px" autocomplete="off">
    <input id="uname" placeholder="note / @username (optional)" autocomplete="off">
    <button id="uadd">Add user</button>
  </div>
  <div id="umsg"></div>
  <table>
    <thead><tr><th>telegram id</th><th>note</th><th>source</th><th>added</th><th></th></tr></thead>
    <tbody id="urows"><tr><td colspan="5" class="empty">loading…</td></tr></tbody>
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
try { if (localStorage.getItem("cyberfw-ui-theme") === "dark") document.documentElement.setAttribute("data-theme", "dark"); } catch (e) {}

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
    if (!scans.length) { rows.innerHTML = '<tr><td colspan="7" class="empty">no scans yet</td></tr>'; }
    else rows.innerHTML = scans.map((s) => {
      const acts = [];
      if (s.status === "queued" || s.status === "running")
        acts.push('<button class="danger" onclick="cancelScan(\'' + s.id + '\')">Cancel</button>');
      if (s.has_report)
        acts.push('<a href="api/scans/' + s.id + '/report" target="_blank">Report</a>');
      acts.push('<button onclick="showLog(\'' + s.id + '\')">Log</button>');
      acts.push('<button onclick="msgTo(\'' + s.chat_id + '\')">Msg</button>');
      return '<tr class="' + (s.id === selected ? 'sel' : '') + '">'
        + '<td class="t">' + esc(s.id) + '</td>'
        + '<td class="t">' + esc(s.target) + '</td>'
        + '<td class="t">' + esc(s.username || s.user_id) + '</td>'
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
$("theme").addEventListener("click", () => {
  const dark = document.documentElement.getAttribute("data-theme") === "dark";
  if (dark) document.documentElement.removeAttribute("data-theme");
  else document.documentElement.setAttribute("data-theme", "dark");
  try { localStorage.setItem("cyberfw-ui-theme", dark ? "light" : "dark"); } catch (e) {}
});
$("go").addEventListener("click", start);
$("target").addEventListener("keydown", (e) => { if (e.key === "Enter") start(); });
function msgTo(chat) { $("mchat").value = chat; $("mtext").focus(); }
async function sendMsg() {
  const chat_id = $("mchat").value.trim(), text = $("mtext").value.trim();
  $("mmsg").textContent = ""; $("mmsg").className = "";
  if (!chat_id || !text) return;
  const r = await fetch("api/message", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ chat_id: Number(chat_id), text }) });
  if (!r.ok) { $("mmsg").textContent = await r.text(); $("mmsg").className = "err"; }
  else { $("mmsg").textContent = "sent to " + chat_id; $("mtext").value = ""; }
}
$("msend").addEventListener("click", sendMsg);
$("mtext").addEventListener("keydown", (e) => { if (e.key === "Enter") sendMsg(); });

function when(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  return isNaN(d.getTime()) ? "—" : d.toLocaleString();
}
async function loadUsers() {
  try {
    const users = await (await fetch("api/users")).json();
    const rows = $("urows");
    if (!users.length) { rows.innerHTML = '<tr><td colspan="5" class="empty">none</td></tr>'; return; }
    rows.innerHTML = users.map((u) =>
      '<tr><td class="t">' + esc(u.user_id) + '</td>'
      + '<td>' + esc(u.username || "") + '</td>'
      + '<td class="t">' + esc(u.source) + '</td>'
      + '<td class="t">' + esc(when(u.added_at)) + '</td>'
      + '<td>' + (u.source === "db" ? '<button class="danger" onclick="rmUser(' + u.user_id + ')">Remove</button>' : '') + '</td></tr>'
    ).join('');
  } catch (e) {}
}
async function addUser() {
  const user_id = $("uid").value.trim(), username = $("uname").value.trim();
  $("umsg").textContent = ""; $("umsg").className = "";
  if (!user_id) return;
  const r = await fetch("api/users", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ user_id: Number(user_id), username }) });
  if (!r.ok) { $("umsg").textContent = await r.text(); $("umsg").className = "err"; return; }
  $("uid").value = ""; $("uname").value = ""; $("umsg").textContent = "added " + user_id;
  loadUsers();
}
async function rmUser(uid) {
  await fetch("api/users/" + uid, { method: "DELETE" });
  loadUsers();
}
$("uadd").addEventListener("click", addUser);
$("uid").addEventListener("keydown", (e) => { if (e.key === "Enter") addUser(); });
loadUsers();
refresh();
setInterval(refresh, 2000);
</script>
</body>
</html>
"""
