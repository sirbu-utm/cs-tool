"""Typer CLI — the public face of cyberfw.

Three commands, matching the acceptance criteria in the technical specification:

* ``cyberfw init [tools...]`` — fetch precompiled binaries into ``tools_bin/``
  (zero-friction: only Python, Git and curl/wget are required of the user).
* ``cyberfw run <tool> -t <target> (-l <hosts>)`` — run a single registered tool
  through its adapter and stream validated JSONL records.
* ``cyberfw pipeline <name> -t <domain>`` — run a ready-made pipeline
  (e.g. ``recon-to-vuln``) and render HTML + JSON reports.

A crashed/failed child never aborts the CLI: :class:`PipelineEngine` converts
stage failures into a ``NodeResult`` and the command exits with a helpful status.
"""

from __future__ import annotations

import importlib

from cyberfw.cli.app import app

# Importing the command modules registers their commands on `app` in this
# order — the order `cyberfw --help` lists them. The launcher comes last: it
# adds the callback that opens the menu when no command is given.
for _module in ('tools', 'reports', 'triage', 'scan', 'schedule', 'launcher'):
    importlib.import_module(f"cyberfw.cli.{_module}")

__all__ = ["app"]
