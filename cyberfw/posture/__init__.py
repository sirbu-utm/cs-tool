"""Security-posture checks cyberfw works out itself, beyond what the tools report.

* :mod:`cyberfw.posture.tls` — certificate health from httpx's ``-tls-grab`` data;
* :mod:`cyberfw.posture.mail` — whether mail can be forged as the seed domain.

Both emit :class:`~cyberfw.pipeline.schemas.PostureFinding` records shaped like
nuclei findings, so the report and ``report.json`` readers need nothing new.
"""
