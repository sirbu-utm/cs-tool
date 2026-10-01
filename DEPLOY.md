# Deploying cyberfw on a free VM (Oracle Cloud ARM)

cyberfw runs well on **Oracle Cloud's Always Free** Ampere A1 instance (ARM /
aarch64, up to 4 OCPU / 24 GB RAM, 200 GB disk) — the only mainstream "free
forever" tier that gives a real VM you control. Every tool cyberfw installs has
a native arm64 build, so nothing is emulated.

> ⚠️ **Authorisation.** Active scanning (naabu, rustscan, nuclei, ffuf) of
> systems you do not own or lack written permission to test may be illegal, and
> scanning from a cloud IP can breach the provider's acceptable-use policy and
> get the account suspended. Only scan your own assets or authorised engagements.

## 1. Create the VM

1. Oracle Cloud → Compute → Instances → Create.
2. Shape: **Ampere (VM.Standard.A1.Flex)**, e.g. 1–2 OCPU / 6–12 GB (within the
   Always Free allowance). Image: **Ubuntu 22.04/24.04 (aarch64)**.
3. No inbound ports are needed to *run* scans — SSH in and work from the shell.
4. `ssh ubuntu@<public-ip>`.

## 2a. Native install (simplest)

```bash
# System Chromium for gowitness screenshots. Chrome for Testing has no
# linux/arm64 build, so the distro package is the browser on ARM; cyberfw's
# _find_chrome picks up /usr/bin/chromium automatically.
sudo apt-get update && sudo apt-get install -y chromium-browser git
#   (on Debian the package is `chromium`, not `chromium-browser`)

# uv (installs Python + the project without touching system Python)
curl -LsSf https://astral.sh/uv/install.sh | sh
exec $SHELL -l

git clone https://github.com/sirbu-utm/cs-tool.git && cd cs-tool
uv tool install --editable .          # puts `cyberfw` on PATH (uv tool update-shell if needed)

cyberfw init                          # downloads the arm64 tool binaries
cyberfw status                        # should show 8/8 ready (chromium: present)
cyberfw pipeline recon-to-vuln --target example.com
```

Reports land in `reports/<session>/` (JSON + self-contained HTML). Copy one back
with `scp ubuntu@<ip>:~/cs-tool/reports/<session>/report.html .`.

### Scheduled scans (optional)

cyberfw is a CLI, not a daemon; for recurring scans use cron rather than a
long-running service:

```bash
# daily 02:00, authorised target only
0 2 * * *  cd $HOME/cs-tool && /home/ubuntu/.local/bin/cyberfw pipeline recon-to-vuln -t example.com --report >> $HOME/cyberfw-cron.log 2>&1
```

## 2b. Docker (alternative)

A `Dockerfile` and `.dockerignore` live at the repo root. The image is multi-arch
by construction (the base image, the apt `chromium` package and the tool
binaries all exist for amd64 and arm64), so it builds the same on the Ampere VM.

```bash
sudo apt-get update && sudo apt-get install -y docker.io
sudo docker build -t cyberfw .

# A named volume keeps the downloaded binaries and the reports across runs
# (CYBERFW_ROOT_DIR=/data inside the image).
sudo docker run --rm -v cyberfw-data:/data cyberfw init
sudo docker run --rm -v cyberfw-data:/data cyberfw pipeline recon-to-vuln -t example.com --report

# Read a report back out of the volume:
sudo docker run --rm -v cyberfw-data:/data --entrypoint sh cyberfw -c 'ls reports'
```

Build for arm64 explicitly from another arch with buildx:
`docker buildx build --platform linux/arm64 -t cyberfw .`

## Notes

- **arm64 coverage.** subfinder, httpx, nuclei, naabu, ffuf, gitleaks, rustscan
  and gowitness all ship aarch64 binaries. The only piece without an arm64 build
  is Chrome for Testing, which is why the system `chromium` is used for
  gowitness on ARM.
- **AMD Always Free alternative.** Oracle also offers 2× small AMD (x86)
  micro-VMs free, where Chrome for Testing *does* have a build, so
  `cyberfw init` can auto-download a portable Chromium — but 1 GB RAM is tight
  for nuclei + a browser; add swap if you use it.
- **No QEMU needed.** Emulating x86 on the ARM VM (qemu-user or full-system TCG
  without KVM) is slow and flaky for headless Chrome; the native arm64 path
  above avoids it entirely.
- **GitHub rate limit.** If `cyberfw init` hits the API limit, set
  `export CYBERFW_GITHUB_TOKEN=<token>` before running it.
