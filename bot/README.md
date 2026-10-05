# cyberfw_bot

A Telegram bot that runs the CS-TOOL `cyberfw` recon → vulnerability pipeline for
a target you give it, then sends back a severity summary and the report file.

The bot is a **thin front-end**: it shells out to the existing `cyberfw pipeline`
command (never a shell, always an argv list) and reads the JSON report cyberfw
writes. It does not re-implement any scanner.

## What it does

```
/scan example.com   →  cyberfw pipeline recon-to-vuln --target example.com --session bot-<id> --report
                       (subfinder + httpx → nuclei, in a background task)
                    →  parse reports/bot-<id>/report.json
                    →  reply: severity counts + top findings + report.html
```

## Commands

| Command | Effect |
|---|---|
| `/scan <target>` | Queue a scan of one domain, `http(s)` URL, or IP you are authorised to test. Returns a `scan_id` immediately; the result arrives when it finishes. |
| `/status` | Your recent scans and their state (`queued` / `running` / `done` / `failed`). |
| `/report <scan_id>` | Re-send a finished scan's summary and report file. |
| `/help` | Usage and the authorisation reminder. |

## Architecture

```
Telegram ──► bot.py ──► ScanService ──► CyberfwRunner ──► `cyberfw pipeline` (subprocess)
                 │            │                                   │
                 │            │                              reports/bot-<id>/report.json
                 │            ▼                                   │
                 │        ScanStore (SQLite)  ◄── summary ── reports.py (parse)
                 ▼
         formatting.py (HTML messages)
```

| Module | Responsibility |
|---|---|
| `config.py` | Env-driven `BotConfig` (token, allow-list, `cyberfw` command, workspace, limits). |
| `validation.py` | Prove a target is one safe host; reject metacharacters, a leading `-`, and (by default) private/loopback addresses. |
| `runner.py` | Launch `cyberfw` with `create_subprocess_exec`, wall-clock timeout, locate the report. |
| `reports.py` | Parse `report.json` into a `Summary` (severity counts, ranked findings). |
| `storage.py` | SQLite scan history via `asyncio.to_thread`. |
| `service.py` | Orchestrate validate → queue → run (under a concurrency limit) → summarise → notify. Telegram-free, fully unit-tested. |
| `bot.py` | `python-telegram-bot` handlers; pushes results to the chat. |
| `__main__.py` | Load config, init the store, start long polling. |

Data flow is asynchronous end to end: `/scan` returns at once, the scan runs as a
background `asyncio` task under a `Semaphore(BOT_MAX_CONCURRENT)`, and the finished
scan is pushed to the chat by a notifier callback.

## Security model

- **Only what you type.** A scan targets exactly the single host passed to
  `/scan` — no lists, no wildcards, no target ever sourced from elsewhere.
- **No shell.** The `cyberfw` command is built as an argv list and launched with
  `create_subprocess_exec`; the target is data, never interpreted.
- **Fail-closed authorisation.** `ALLOWED_USER_IDS` gates every command; empty
  means nobody, so an unconfigured bot scans for no one.
- **Input validation.** Targets must be a domain, `http(s)` URL, or IP. A leading
  `-` (argument injection) and whitespace/control characters are refused; by
  default loopback/private/link-local addresses and `localhost` are blocked
  (`BOT_BLOCK_PRIVATE=false` to allow them deliberately).
- **Limitation:** validation inspects the literal target only — DNS is not
  resolved, so a public name that resolves to a private address is not caught.

> ⚠️ Active scanning of systems you do not own or lack written permission to test
> may be illegal. This bot is for your own assets and authorised engagements.

## Setup

1. Install and provision CS-TOOL in the repo root (so `registry.yaml`,
   `tools_bin/` and the tool binaries exist):

   ```bash
   uv tool install --editable .
   cyberfw init
   ```

2. Install the bot's dependencies (a virtualenv is recommended):

   ```bash
   cd bot
   pip install -r requirements.txt
   ```

3. Configure it:

   ```bash
   cp .env.example .env
   # set BOT_TOKEN and ALLOWED_USER_IDS, point CYBERFW_WORKSPACE at the repo root
   ```

4. Run it:

   ```bash
   python -m cyberfw_bot
   ```

## Tests

The scanner-free layers (validation, report parsing, storage, orchestration with
a fake runner, message formatting) are unit-tested and need neither a Telegram
token nor `python-telegram-bot`:

```bash
python -m pytest bot/tests
```

`bot/tests` is outside the CS-TOOL test root, so the framework's own suite and CI
gate are unaffected.
