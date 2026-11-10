# Kashif (vulnscan) installer for Windows (x64).
#
#   irm https://abdulrahmanahmedelabed-prog.github.io/vulnscan/install.ps1 | iex
#
# Downloads the latest vulnscan-windows.exe, verifies its SHA-256 against the release's SHA256SUMS.txt, installs it
# as vulnscan.exe (plus kashif.exe) into $env:KASHIF_INSTALL_DIR (default: %LOCALAPPDATA%\Programs\Kashif) and adds
# that folder to the user PATH. Set $env:KASHIF_VERSION = "v0.8.0" to pin a release.
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$Repo = "abdulrahmanahmedelabed-prog/vulnscan"
$Asset = "vulnscan-windows.exe"
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
    Invoke-WebRequest -UseBasicParsing -Uri "$Base/$Asset" -OutFile (Join-Path $Tmp $Asset)
    Invoke-WebRequest -UseBasicParsing -Uri "$Base/SHA256SUMS.txt" -OutFile (Join-Path $Tmp "SHA256SUMS.txt")

    $line = Get-Content (Join-Path $Tmp "SHA256SUMS.txt") | Where-Object { ($_ -split '\s+')[1] -in @($Asset, "*$Asset") } | Select-Object -First 1
    if (-not $line) { throw "kashif: SHA256SUMS.txt has no entry for $Asset" }
    $expected = ($line -split '\s+')[0].ToLowerInvariant()
    $actual = (Get-FileHash -Algorithm SHA256 -Path (Join-Path $Tmp $Asset)).Hash.ToLowerInvariant()
    if ($expected -ne $actual) { throw "kashif: checksum mismatch (expected $expected, got $actual); nothing was installed" }
    Write-Host "kashif: checksum verified"

    New-Item -ItemType Directory -Force -Path $Dir | Out-Null
    Copy-Item -Force (Join-Path $Tmp $Asset) (Join-Path $Dir "vulnscan.exe")
    Copy-Item -Force (Join-Path $Tmp $Asset) (Join-Path $Dir "kashif.exe")
    $version = & (Join-Path $Dir "vulnscan.exe") --version
    Write-Host "kashif: installed $version to $Dir"

    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if (-not (($userPath -split ';') -contains $Dir)) {
        [Environment]::SetEnvironmentVariable("Path", (($userPath.TrimEnd(';') + ";" + $Dir).TrimStart(';')), "User")
        Write-Host "kashif: added $Dir to your PATH (open a new terminal to use it)"
    }
    Write-Host "kashif: run 'vulnscan ui' for the web interface, or 'vulnscan .\project' to scan from the terminal"
}
finally {
    Remove-Item -Recurse -Force $Tmp -ErrorAction SilentlyContinue
}
