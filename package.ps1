# package.ps1 — build Argus in release mode and create a distributable zip.
#
# Usage:
#   .\package.ps1               # uses version from Cargo.toml
#   .\package.ps1 -Version 1.2.0

param(
    [string]$Version = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Resolve version ──────────────────────────────────────────────────────────
if (-not $Version) {
    $Version = (Select-String -Path "Cargo.toml" -Pattern '^version\s*=\s*"(.+)"' |
        Select-Object -First 1).Matches.Groups[1].Value
}
if (-not $Version) { $Version = "0.0.0" }
Write-Host "Packaging Argus v$Version" -ForegroundColor Cyan

# ── Build ────────────────────────────────────────────────────────────────────
Write-Host "Building release binary..." -ForegroundColor Cyan
cargo build --release
if ($LASTEXITCODE -ne 0) { Write-Error "cargo build failed"; exit 1 }

# ── Staging dir ─────────────────────────────────────────────────────────────
$stage = "target\release\argus-$Version"
if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
New-Item -ItemType Directory -Path $stage | Out-Null

# ── Copy files ───────────────────────────────────────────────────────────────
Copy-Item "target\release\argus.exe"    "$stage\argus.exe"
Copy-Item "target\release\WinDivert.dll"  "$stage\WinDivert.dll"
Copy-Item "target\release\WinDivert64.sys" "$stage\WinDivert64.sys"
Copy-Item "README.md"                   "$stage\README.md"
Copy-Item "LICENSE"                     "$stage\LICENSE"
Copy-Item "configs"                     "$stage\configs"   -Recurse
Copy-Item "default_files"               "$stage\default_files" -Recurse
Copy-Item "python"                      "$stage\python"    -Recurse

# ── Zip ──────────────────────────────────────────────────────────────────────
$zip = "target\release\argus-$Version.zip"
if (Test-Path $zip) { Remove-Item $zip -Force }
Compress-Archive -Path "$stage\*" -DestinationPath $zip

# ── Cleanup staging dir ───────────────────────────────────────────────────────
Remove-Item $stage -Recurse -Force

Write-Host ""
Write-Host "Done: $zip" -ForegroundColor Green
