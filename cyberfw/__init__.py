"""cyberfw — Integrated Cybersecurity Framework.

A console orchestrator for offensive-security tools with the "Zero-Friction
Installation" paradigm: every external binary is fetched precompiled from
GitHub Releases, so the user only needs Python, Git and curl/wget.

Everything is reachable through the ``cyberfw`` CLI (see :mod:`cyberfw.cli`).
"""

from __future__ import annotations

import logging

__version__ = "1.0.0"

# A library's records go where its caller's logging sends them: the CLI sets up
# its handlers, a script that sets up none gets nothing — not Python's
# last-resort handler printing warnings to stderr.
logging.getLogger("cyberfw").addHandler(logging.NullHandler())

__all__ = ["__version__"]
