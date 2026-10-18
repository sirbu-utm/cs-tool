"""The Typer application every command module registers its commands on."""

from __future__ import annotations

import typer

app = typer.Typer(
    name="cyberfw",
    help="Integrated Cybersecurity Framework — orchestrates precompiled offensive tools.",
    no_args_is_help=False,
    rich_markup_mode="rich",
    add_completion=False,
)
