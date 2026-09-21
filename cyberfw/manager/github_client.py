"""GitHub Releases client.

Thin ``httpx`` wrapper over ``https://api.github.com/repos/{owner}/{repo}/releases/latest``.
Authorises with ``GITHUB_TOKEN`` when present (5000 requests/hour vs 60 anonymous)
and, when configured, caches resolved release metadata under ``~/.cache/cyberfw``
for a short TTL so repeated checks don't burn the rate limit.
"""

from __future__ import annotations

import contextlib
import fnmatch
import json
import shutil
import time
from pathlib import Path
from typing import NoReturn

import httpx
from tenacity import (
    RetryError,
    retry,
    retry_if_exception,
    stop_after_attempt,
    wait_exponential,
)

from cyberfw.exceptions import DownloadError

__all__ = ["GitHubRelease", "ReleaseAsset", "GitHubClient", "CacheEntry", "RETRY_ATTEMPTS"]

#: Attempts made for one HTTP request (API call, asset download, checksum
#: fetch) before giving up.
RETRY_ATTEMPTS = 4


def _is_transient(exc: BaseException) -> bool:
    """Retry transport failures and upstream 5xx; never 4xx.

    404/403/429 from the GitHub API are deterministic for far longer than our
    backoff budget (rate-limit windows are up to an hour), so retrying them only
    burns quota.
    """
    if isinstance(exc, httpx.TransportError):
        return True
    return isinstance(exc, httpx.HTTPStatusError) and exc.response.status_code >= 500


_transient_retry = retry(
    retry=retry_if_exception(_is_transient),
    wait=wait_exponential(multiplier=1.0, max=20.0),
    stop=stop_after_attempt(RETRY_ATTEMPTS),
)


def _raise_download_error(what: str, exc: BaseException) -> NoReturn:
    """Convert a tenacity/httpx/OS failure into :class:`DownloadError`.

    Unwraps :class:`RetryError` so the chained cause is the real last failure.
    """
    if isinstance(exc, RetryError):
        cause = exc.last_attempt.exception()
        raise DownloadError(
            f"{what} after {RETRY_ATTEMPTS} attempts: {cause}. "
            "Check your connection, raise CYBERFW_REQUEST_TIMEOUT, or set HTTPS_PROXY."
        ) from cause
    raise DownloadError(f"{what}: {exc}") from exc


class ReleaseAsset:
    """A single downloadable asset of a GitHub release."""

    def __init__(self, name: str, url: str, size: int) -> None:
        self.name = name
        self.url = url
        self.size = size

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return f"ReleaseAsset(name={self.name!r}, size={self.size})"


class GitHubRelease:
    """Latest-release metadata for one repository."""

    def __init__(self, tag: str, assets: list[ReleaseAsset], checksums_url: str | None) -> None:
        self.tag = tag
        #: ``0.1.2`` when the tag is ``v0.1.2``.
        self.version = tag.lstrip("vV")
        self.assets = assets
        self.checksums_url = checksums_url

    def find_asset(self, *patterns: str) -> ReleaseAsset | None:
        """Return the first asset matching any fnmatch pattern.

        Matching is case-insensitive against the full asset name, so patterns
        such as ``*linux*amd64*`` work against ``subfinder_2.6.0_linux_amd64.zip``.
        """
        for asset in self.assets:
            name = asset.name.lower()
            if any(fnmatch.fnmatch(name, p.lower()) for p in patterns):
                return asset
        return None


class CacheEntry:
    """JSON document persisted to disk for a cached release."""

    def __init__(self, saved_at: float, checksums_url: str, assets: list[dict[str, object]]) -> None:
        self.saved_at = saved_at
        self.checksums_url = checksums_url
        self.assets = assets


class GitHubClient:
    """Resolves the latest release for a repo, with optional caching."""

    API = "https://api.github.com/repos/{owner}/{repo}/releases/latest"

    def __init__(
        self,
        token: str | None = None,
        *,
        cache_dir: Path | None = None,
        ttl: float = 900.0,
        timeout: float = 60.0,
    ) -> None:
        self.token = token
        self.cache_dir = cache_dir
        self.ttl = ttl
        # ``trust_env`` (the default) honours HTTP(S)_PROXY, which is how users
        # behind a slow or filtered path to objects.githubusercontent.com get through.
        self._client = httpx.Client(follow_redirects=True, timeout=timeout)

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> GitHubClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- caching helpers -----------------------------------------------------
    def _cache_path(self, owner: str, repo: str) -> Path | None:
        if self.cache_dir is None:
            return None
        return Path(self.cache_dir) / f"{owner}-{repo}.json"

    def _cache_may_load(self, owner: str, repo: str) -> GitHubRelease | None:
        path = self._cache_path(owner, repo)
        if path is None or not path.exists():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):  # pragma: no cover - corrupt cache
            return None
        stale = time.time() - float(data.get("saved_at", 0)) > self.ttl
        if stale:
            return None
        release = self._from_cache_dict(data)
        return release

    def _cache_save(self, owner: str, repo: str, release: GitHubRelease) -> None:
        path = self._cache_path(owner, repo)
        if path is None:
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "saved_at": time.time(),
            "tag": release.tag,
            "checksums_url": release.checksums_url,
            "assets": [{"name": a.name, "url": a.url, "size": a.size} for a in release.assets],
        }
        path.write_text(json.dumps(payload), encoding="utf-8")

    def _from_cache_dict(self, data: dict[str, object]) -> GitHubRelease:
        tag = str(data.get("tag", "v0.0.0-cached"))
        checksums = data.get("checksums_url")
        checksum_url = checksums if isinstance(checksums, str) and checksums.startswith("http") else None
        assets: list[ReleaseAsset] = []
        assets_raw = data.get("assets")
        if isinstance(assets_raw, list):
            for item in assets_raw:
                if not isinstance(item, dict):
                    continue
                url = item.get("url")
                if not isinstance(url, str) or not url.startswith("http"):
                    continue
                assets.append(
                    ReleaseAsset(str(item.get("name", "")), url, int(item.get("size", 0)))
                )
        return GitHubRelease(tag=tag, assets=assets, checksums_url=checksum_url)

    # -- network ------------------------------------------------------------
    @_transient_retry
    def _get(self, url: str, *, headers: dict[str, str] | None = None) -> httpx.Response:
        """GET ``url`` with the shared transient-retry policy; raises on any 4xx/5xx."""
        resp = self._client.get(url, headers=headers)
        resp.raise_for_status()
        return resp

    def latest(self, owner: str, repo: str) -> GitHubRelease:
        """Resolve the latest release, from cache when fresh.

        Raises :class:`DownloadError` for every failure mode (unreachable API,
        exhausted retries, rate limit, unknown repository).
        """
        cached = self._cache_may_load(owner, repo)
        if cached is not None:
            return cached

        headers: dict[str, str] = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        else:
            headers["User-Agent"] = "cyberfw"

        try:
            resp = self._get(self.API.format(owner=owner, repo=repo), headers=headers)
        except httpx.HTTPStatusError as exc:
            # Non-transient statuses come straight through tenacity, unwrapped.
            status = exc.response.status_code
            if status in (429, 403):
                raise DownloadError(
                    f"GitHub rate limit ({status}) for {owner}/{repo}: {exc.response.text[:200]}"
                ) from exc
            if status == 404:
                raise DownloadError(f"Repository not found: {owner}/{repo}") from exc
            raise DownloadError(f"Unexpected GitHub status {status} for {owner}/{repo}") from exc
        except (RetryError, httpx.HTTPError) as exc:
            _raise_download_error(f"GitHub API unreachable for {owner}/{repo}", exc)

        payload = resp.json()
        tag = payload.get("tag_name", "")
        checksums: str | None = None
        assets: list[ReleaseAsset] = []
        for asset in payload.get("assets", []):
            if not isinstance(asset, dict):
                continue
            name = str(asset.get("name", ""))
            url = asset.get("browser_download_url")
            if not isinstance(url, str) or not url.startswith("http"):
                continue
            if name.lower().endswith(("checksums.txt", "checksums.md")):
                checksums = url
                continue
            assets.append(
                ReleaseAsset(
                    name=name,
                    url=url,
                    size=int(asset.get("size", 0)),
                )
            )
        release = GitHubRelease(tag=tag, assets=assets, checksums_url=checksums)
        self._cache_save(owner, repo, release)
        return release

    def download(self, url: str, destination: Path, *, expected_size: int | None = None) -> None:
        """Stream an asset to ``destination``.

        Transient failures (timeouts, resets, TLS handshake stalls, upstream 5xx)
        are retried with exponential backoff; other HTTP status errors are not.
        Raises :class:`DownloadError` on final failure, filesystem trouble or
        size mismatch, and never leaves a ``.part`` file behind.
        """
        if not url.startswith(("http://", "https://")):
            raise DownloadError(f"Invalid download URL: {url!r}")
        try:
            self._download_stream(url, destination, expected_size)
        except (RetryError, httpx.HTTPError, OSError) as exc:
            _raise_download_error(f"Failed to download {url}", exc)

    @_transient_retry
    def _download_stream(self, url: str, destination: Path, expected_size: int | None) -> None:
        destination.parent.mkdir(parents=True, exist_ok=True)
        tmp = destination.with_suffix(destination.suffix + ".part")
        try:
            with self._client.stream("GET", url) as resp:
                resp.raise_for_status()
                bytes_written = 0
                with tmp.open("wb") as handle:
                    for chunk in resp.iter_bytes(chunk_size=64 * 1024):
                        handle.write(chunk)
                        bytes_written += len(chunk)
            if expected_size is not None and bytes_written != expected_size:  # pragma: no cover - malformed
                raise DownloadError(
                    f"Size mismatch: expected {expected_size} bytes, got {bytes_written} for {url}"
                )
            shutil.move(str(tmp), str(destination))
        except BaseException:
            # Every retry restarts from byte 0, so a truncated .part is never useful.
            with contextlib.suppress(OSError):
                tmp.unlink(missing_ok=True)
            raise

    def fetch_text(self, url: str) -> str:
        """Fetch a small text resource (e.g. ``checksums.txt``)."""
        if not url.startswith(("http://", "https://")):
            raise DownloadError(f"Invalid text URL: {url!r}")
        try:
            return self._get(url).text
        except (RetryError, httpx.HTTPError) as exc:
            _raise_download_error(f"Failed to fetch {url}", exc)
