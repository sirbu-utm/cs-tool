"""nmap adapter — service and version detection on already-discovered ports.

Meant to follow a port scanner (naabu / rustscan): it consumes the ``host:port``
targets the port stage passes downstream and runs ``nmap -sV`` against exactly
those ports, so the pipeline learns *what* is listening, not just that a port is
open. nmap is a ``source: local`` tool — installed by the user (apt/brew/winget),
not downloaded by the framework.

nmap has no JSONL mode, so the adapter is ``buffered``: it asks nmap for XML on
stdout (``-oX -``) and parses the whole document once in :meth:`parse_output`.
"""

from __future__ import annotations

from xml.etree.ElementTree import Element, ParseError

from defusedxml.common import DefusedXmlException
from defusedxml.ElementTree import fromstring

from cyberfw.pipeline.schemas import NmapResult
from cyberfw.plugin import BaseTool, ToolContext, ToolPlugin, ToolRecord
from cyberfw.tools.targets import hostname_of


class NmapTool(BaseTool):
    # One invocation per discovered host:port (via the engine's fan-out), each
    # producing one small XML document parsed at once.
    per_target = True
    buffered = True

    target_prompt = "Target host[:port], IP or URL"

    @staticmethod
    def _split(target: str) -> tuple[str, str | None]:
        """``example.com:22`` -> ``("example.com", "22")``; a bare host/URL -> ``(host, None)``.

        Only a trailing ``:<digits>`` on an otherwise scheme-less target is read
        as the port; a URL keeps its own port via :func:`hostname_of`.
        """
        if "://" not in target and target.count(":") == 1:
            host, _, port = target.partition(":")
            if port.isdigit():
                return hostname_of(host), port
        parsed = hostname_of(target)
        # hostname_of drops a URL's port; recover it so -sV targets that port.
        if "://" in target:
            tail = target.split("://", 1)[1]
            hostport = tail.split("/", 1)[0]
            if hostport.count(":") == 1 and hostport.rsplit(":", 1)[1].isdigit():
                return parsed, hostport.rsplit(":", 1)[1]
        return parsed, None

    def build_cmd(self, ctx: ToolContext) -> list[str]:
        target = ctx.target or ""
        host, port = self._split(target)
        cmd = [str(self.binary), "-sV", "-Pn"]
        if port is not None:
            cmd += ["-p", port]
        cmd += [host, "-oX", "-", *self.static_flags()]
        return cmd

    def parse_output(self, text: str) -> list[ToolRecord]:
        """Parse an nmap ``-oX`` document into one record per open port with a service."""
        text = text.strip()
        if not text:
            return []
        try:
            # defusedxml: nmap's service/version fields echo target-controlled
            # banners, so block XXE / entity-expansion while allowing the DOCTYPE.
            root = fromstring(text)
        except (ParseError, DefusedXmlException):
            return []
        records: list[ToolRecord] = []
        index = 0
        for host_el in root.findall("host"):
            host = self._host_name(host_el)
            for port_el in host_el.findall("./ports/port"):
                service_el = port_el.find("service")
                if service_el is None:
                    continue
                portid = port_el.get("portid", "")
                service = service_el.get("name", "")
                product = service_el.get("product", "")
                version = service_el.get("version", "")
                detail = " ".join(part for part in (service, product, version) if part)
                index += 1
                records.append(
                    NmapResult(
                        tool=self.name,
                        line_number=index,
                        host=host,
                        port=int(portid) if portid.isdigit() else 0,
                        service=service,
                        product=product,
                        version=version,
                        service_detail=detail,
                        target=f"{host}:{portid}",
                        kind="service",
                    )
                )
        return records

    @staticmethod
    def _host_name(host_el: Element) -> str:
        """The scanned host: its hostname when nmap reports one, else its address."""
        hostname = host_el.find("./hostnames/hostname")
        if hostname is not None and hostname.get("name"):
            return hostname.get("name", "")
        address = host_el.find("address")
        return address.get("addr", "") if address is not None else ""


PLUGIN = ToolPlugin(contract=1, adapter=NmapTool, record=NmapResult)
