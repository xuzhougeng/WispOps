# Build WispOps for Windows and package it as a portable zip:
# dist/WispOps-v<version>-windows-x64.zip, holding WispOps.exe in a folder of
# the same name.
#
#   pwsh -File scripts/package-windows.ps1          # unsigned, for a look on this machine
#   pwsh -File scripts/package-windows.ps1 -Sign    # Authenticode-sign it, as a signed release does
#
# -Sign goes through scripts/sign-windows-esigner.ps1 (SSL.com eSigner): run that
# script with -Install once before, and have the ESIGNER_* variables set. A
# signature that fails stops the packaging, so no unsigned zip is written.
#
# Environment: CARGO_TARGET_DIR is where cargo builds (default: target).

param(
    [switch]$Sign
)

$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $root

# The version is written once, in the root Cargo.toml.
$match = Select-String -LiteralPath 'Cargo.toml' -Pattern '^version = "(.*)"$' | Select-Object -First 1
if (-not $match) { throw 'No version in Cargo.toml' }
$version = $match.Matches[0].Groups[1].Value

& cargo build --release -p wisp_ops
if ($LASTEXITCODE -ne 0) { throw "cargo build exited $LASTEXITCODE" }

$targetDir = $env:CARGO_TARGET_DIR
if ([string]::IsNullOrWhiteSpace($targetDir)) { $targetDir = 'target' }
$release = Join-Path $targetDir 'release'

$name = "WispOps-v$version-windows-x64"
$dist = Join-Path $root 'dist'
$folder = Join-Path $dist $name
$zip = Join-Path $dist "$name.zip"
if (Test-Path -LiteralPath $folder) { Remove-Item -LiteralPath $folder -Recurse -Force }
if (Test-Path -LiteralPath $zip) { Remove-Item -LiteralPath $zip -Force }
New-Item -ItemType Directory -Force -Path $folder | Out-Null

# A GUI-subsystem program (src/main.rs); the icon and version info are its resources (build.rs).
$app = Join-Path $folder 'WispOps.exe'
Copy-Item -LiteralPath (Join-Path $release 'wisp_ops.exe') -Destination $app
Copy-Item -LiteralPath 'LICENSE', 'THIRD_PARTY.md', 'README.md' -Destination $folder

if ($Sign) {
    $signer = Join-Path $PSScriptRoot 'sign-windows-esigner.ps1'
    & pwsh -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $signer -Path $app
    if ($LASTEXITCODE -ne 0) { throw "Signing WispOps.exe failed (exit $LASTEXITCODE)" }
} else {
    Write-Host 'Not signed: pass -Sign for a signed release.'
}

# The folder itself goes into the zip, so unpacking gives one folder.
Compress-Archive -LiteralPath $folder -DestinationPath $zip -CompressionLevel Optimal
Write-Host "folder: $folder"
Write-Host ("zip: $zip ({0:N1} MB)" -f ((Get-Item -LiteralPath $zip).Length / 1MB))
