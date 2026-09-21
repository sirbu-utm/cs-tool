#Requires -Version 5.1
<#
.SYNOPSIS
    Install a pinned uv release from its GitHub release zip after verifying the SHA-256.

.DESCRIPTION
    `irm https://astral.sh/uv/install.ps1 | iex` executes whatever the CDN serves,
    and astral's PowerShell installer does not checksum the archive it downloads.
    This script instead fetches the release zip for the current architecture,
    compares its digest to the one pinned below (copied from the release's
    uv-<target>.zip.sha256 asset), and only then extracts uv.exe.

    Bumping uv: update $PinnedHashes for the new version. Overrides for CI /
    advanced use: UV_VERSION, UV_INSTALL_DIR, UV_ZIP_SHA256 (required when
    UV_VERSION names a version that is not pinned here).
#>
[CmdletBinding()]
param(
    [string]$Version = $(if ($env:UV_VERSION) { $env:UV_VERSION } else { '0.12.17' }),
    [string]$InstallDir = $(if ($env:UV_INSTALL_DIR) { $env:UV_INSTALL_DIR } else { Join-Path $env:USERPROFILE '.local\bin' })
)

$ErrorActionPreference = 'Stop'

# SHA-256 of uv-<arch>-pc-windows-msvc.zip per pinned version.
$PinnedHashes = @{
    '0.12.17' = @{
        'x86_64'  = 'a252121d5b59398fcb137c6ea448176459a44010f33f67e0072305a637119ca7'
        'aarch64' = '3e1aa6849d77f0e00dc865e4afab5c5b32de053e21fe35bf5ad5cec3734ec976'
    }
}

$arch = 'x86_64'
if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64' -or $env:PROCESSOR_ARCHITEW6432 -eq 'ARM64') {
    $arch = 'aarch64'
}

$expected = $env:UV_ZIP_SHA256
if (-not $expected) {
    if ($PinnedHashes.ContainsKey($Version) -and $PinnedHashes[$Version].ContainsKey($arch)) {
        $expected = $PinnedHashes[$Version][$arch]
    }
}
if (-not $expected) {
    throw "install-uv: no pinned SHA-256 for uv $Version ($arch); set UV_ZIP_SHA256 to install it."
}
$expected = $expected.ToLowerInvariant()

$asset = "uv-$arch-pc-windows-msvc.zip"
$url = "https://github.com/astral-sh/uv/releases/download/$Version/$asset"
$zip = Join-Path ([System.IO.Path]::GetTempPath()) "uv-$Version-$arch-$PID.zip"

try {
    Write-Host "[*] Downloading uv $Version ($asset)"
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing

    $actual = (Get-FileHash -Path $zip -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $expected) {
        throw "uv archive checksum mismatch - refusing to install.`n    expected: $expected`n    actual:   $actual"
    }

    Write-Host "[*] Checksum OK, extracting to $InstallDir"
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    Expand-Archive -Path $zip -DestinationPath $InstallDir -Force
    Write-Host "[+] uv $Version installed to $InstallDir"
}
finally {
    if (Test-Path $zip) { Remove-Item -Force $zip }
}
