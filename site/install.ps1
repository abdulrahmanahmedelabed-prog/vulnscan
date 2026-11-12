# Kashif (vulnscan) installer for Windows (x64).
#
#   irm https://abdulrahmanahmedelabed-prog.github.io/vulnscan/install.ps1 | iex
#
# Downloads the latest kashif-windows-x86_64.exe (vulnscan-windows.exe for releases made before the rename), verifies
# its SHA-256 against the release's SHA256SUMS.txt, installs it as kashif.exe (plus a vulnscan.cmd alias, the pre-rename
# name) into $env:KASHIF_INSTALL_DIR (default: %LOCALAPPDATA%\Programs\Kashif) and adds that folder to the user PATH.
# Set $env:KASHIF_VERSION = "v0.8.0" to pin a release.
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$Repo = "abdulrahmanahmedelabed-prog/vulnscan"
$Asset = "kashif-windows-x86_64.exe"
$LegacyAsset = "vulnscan-windows.exe"
$Dir = if ($env:KASHIF_INSTALL_DIR) { $env:KASHIF_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA "Programs\Kashif" }
$Version = if ($env:KASHIF_VERSION) { $env:KASHIF_VERSION } else { "latest" }

if (-not [Environment]::Is64BitOperatingSystem) { throw "kashif: a 64-bit Windows is required" }
if ($Version -eq "latest") { $Base = "https://github.com/$Repo/releases/latest/download" }
elseif ($Version -match '^v\d+\.\d+\.\d+$') { $Base = "https://github.com/$Repo/releases/download/$Version" }
else { throw "kashif: KASHIF_VERSION must look like v1.2.3" }

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$Tmp = Join-Path ([IO.Path]::GetTempPath()) ("kashif-" + [Guid]::NewGuid())
New-Item -ItemType Directory -Path $Tmp | Out-Null
try {
    Write-Host "kashif: downloading $Asset ($Version)"
    try {
        Invoke-WebRequest -UseBasicParsing -Uri "$Base/$Asset" -OutFile (Join-Path $Tmp $Asset)
    }
    catch {
        # releases before the rename publish only the vulnscan-* name (verified the same way, against its own line)
        Write-Host "kashif: $Asset not in this release; downloading $LegacyAsset"
        $Asset = $LegacyAsset
        Invoke-WebRequest -UseBasicParsing -Uri "$Base/$Asset" -OutFile (Join-Path $Tmp $Asset)
    }
    Invoke-WebRequest -UseBasicParsing -Uri "$Base/SHA256SUMS.txt" -OutFile (Join-Path $Tmp "SHA256SUMS.txt")

    $line = Get-Content (Join-Path $Tmp "SHA256SUMS.txt") | Where-Object { ($_ -split '\s+')[1] -in @($Asset, "*$Asset") } | Select-Object -First 1
    if (-not $line) { throw "kashif: SHA256SUMS.txt has no entry for $Asset" }
    $expected = ($line -split '\s+')[0].ToLowerInvariant()
    $actual = (Get-FileHash -Algorithm SHA256 -Path (Join-Path $Tmp $Asset)).Hash.ToLowerInvariant()
    if ($expected -ne $actual) { throw "kashif: checksum mismatch (expected $expected, got $actual); nothing was installed" }
    Write-Host "kashif: checksum verified"

    New-Item -ItemType Directory -Force -Path $Dir | Out-Null
    Copy-Item -Force (Join-Path $Tmp $Asset) (Join-Path $Dir "kashif.exe")
    # "vulnscan" keeps working as an alias, the same shim the setup wizard installs (packaging/windows/vulnscan.cmd)
    Set-Content -Encoding Ascii -Path (Join-Path $Dir "vulnscan.cmd") -Value "@echo off`r`n`"%~dp0kashif.exe`" %*"
    # an older install put a full copy at vulnscan.exe, which would win over vulnscan.cmd on PATH and never be updated
    Remove-Item -Force (Join-Path $Dir "vulnscan.exe") -ErrorAction SilentlyContinue
    $version = & (Join-Path $Dir "kashif.exe") --version
    Write-Host "kashif: installed $version to $Dir (vulnscan is kept as an alias)"

    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if (-not (($userPath -split ';') -contains $Dir)) {
        [Environment]::SetEnvironmentVariable("Path", (($userPath.TrimEnd(';') + ";" + $Dir).TrimStart(';')), "User")
        Write-Host "kashif: added $Dir to your PATH (open a new terminal to use it)"
    }
    Write-Host "kashif: run 'kashif ui' for the web interface, or 'kashif .\project' to scan from the terminal"
}
finally {
    Remove-Item -Recurse -Force $Tmp -ErrorAction SilentlyContinue
}
