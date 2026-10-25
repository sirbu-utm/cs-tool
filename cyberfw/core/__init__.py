"""The core: prepares, runs and finishes scans without printing, prompting or exiting.

It imports domain modules only — never the CLI, typer, Rich, the presentation
modules (ui, hud, live_view, motion) or the shared console — and tells its
caller what happens through a :class:`~cyberfw.core.events.RunObserver`.
Like ``cyberfw.cli``, it is internal.
"""
