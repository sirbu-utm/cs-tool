# Container image for the cyberfw framework.
#
# Multi-arch by construction: the base image, the apt chromium package and the
# tool binaries cyberfw fetches all exist for linux/amd64 AND linux/arm64, so
# the same Dockerfile runs on a free Oracle Cloud Ampere (arm64) VM and on x86.
# See DEPLOY.md.
FROM python:3.12-slim-bookworm

# chromium: gowitness drives a headless browser, and Chrome for Testing has no
# linux/arm64 build — so the system package is the browser on arm64 (cyberfw's
# _find_chrome picks up /usr/bin/chromium). ca-certificates: HTTPS downloads
# from GitHub releases. git: gitleaks can scan git history of a mounted repo.
RUN apt-get update \
    && apt-get install -y --no-install-recommends chromium ca-certificates git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir .

# Run as an unprivileged user, not root: cyberfw downloads and executes external
# tool binaries, so the scan must not have root in the container, and headless
# Chrome refuses its sandbox when run as root. /data is owned by that user so a
# fresh named volume inherits writable ownership.
RUN useradd --create-home --uid 10001 cyberfw \
    && mkdir -p /data \
    && chown cyberfw:cyberfw /data

# tools_bin/, reports/ and logs/ all live under here; mount a volume so the
# downloaded binaries and the reports survive container restarts. The wheel
# ships registry.yaml and the pipelines as package data, so cyberfw works from
# this empty workdir without the source tree.
ENV CYBERFW_ROOT_DIR=/data HOME=/home/cyberfw
USER cyberfw
VOLUME ["/data"]
WORKDIR /data

ENTRYPOINT ["cyberfw"]
CMD ["status"]
