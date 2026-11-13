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
    $Dir = (Resolve-Path -LiteralPath $Dir).ProviderPath       # a relative KASHIF_INSTALL_DIR must not go on PATH as is
    # A running kashif.exe (e.g. `kashif ui`) cannot be overwritten or deleted, but it can be renamed: move it out of
    # the way first, as the in-app updater does (vulnscan/updater.py), and put it back if the copy fails. The running
    # program keeps working from the renamed file; the next install or `kashif update` removes it.
    $Exe = Join-Path $Dir "kashif.exe"
    $Old = $null
    if (Test-Path -LiteralPath $Exe) {
        $Old = "$Exe.old"
        Remove-Item -Force -LiteralPath $Old -ErrorAction SilentlyContinue
        if (Test-Path -LiteralPath $Old) {
            # an older kashif.exe.old is itself still running: use a name of its own
            $Old = "$Exe." + [Guid]::NewGuid().ToString("N").Substring(0, 8) + ".old"
        }
        Move-Item -LiteralPath $Exe -Destination $Old
    }
    try {
        Copy-Item -Force (Join-Path $Tmp $Asset) $Exe
    }
    catch {
        if ($Old) {
            # a copy that failed half-way (disk full, antivirus) may have left a truncated kashif.exe: drop it first
            Remove-Item -Force -LiteralPath $Exe -ErrorAction SilentlyContinue
            if (-not (Test-Path -LiteralPath $Exe)) { Move-Item -LiteralPath $Old -Destination $Exe }
        }
        throw
    }
    # leftovers of earlier installs over a running kashif.exe; any that are still running stay until the next time
    $leftovers = Get-ChildItem -LiteralPath $Dir -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^kashif\.exe\.[0-9a-f]{8}\.old$' }
    foreach ($leftover in @($leftovers)) {
        Remove-Item -Force -LiteralPath $leftover.FullName -ErrorAction SilentlyContinue
    }
    if ($Old) {
        Remove-Item -Force -LiteralPath $Old -ErrorAction SilentlyContinue
        if (Test-Path -LiteralPath $Old) {
            Write-Host "kashif: the previous version is still running; it keeps working until you close it"
        }
    }
    # "vulnscan" keeps working as an alias, the same shim the setup wizard installs (packaging/windows/vulnscan.cmd)
    Set-Content -Encoding Ascii -Path (Join-Path $Dir "vulnscan.cmd") -Value "@echo off`r`n`"%~dp0kashif.exe`" %*"
    # an older (0.9.x) install put a full copy at vulnscan.exe, which would win over vulnscan.cmd on PATH and never be
    # updated; its in-app updater may also have left vulnscan.exe.old next to it
    foreach ($name in @("vulnscan.exe", "vulnscan.exe.old")) {
        $stale = Join-Path $Dir $name
        Remove-Item -Force -LiteralPath $stale -ErrorAction SilentlyContinue
        if (Test-Path -LiteralPath $stale) {
            Write-Warning "kashif: could not remove the old $stale (is it running?); close it and delete it, or 'vulnscan' keeps starting the old version"
        }
    }
    $version = & (Join-Path $Dir "kashif.exe") --version
    Write-Host "kashif: installed $version to $Dir (vulnscan is kept as an alias)"

    # The user PATH may be unset ($null), empty, end with ';' or hold empty entries, and may already list this folder
    # in another letter case or with a trailing '\': compare case-insensitively without the trailing '\', and append
    # the folder (dropping empty entries) only when it is missing.
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    $entries = @("$userPath" -split ';' | Where-Object { $_.Trim() -ne "" })
    $want = $Dir.TrimEnd('\').ToLowerInvariant()
    $present = @($entries | Where-Object { $_.Trim().TrimEnd('\').ToLowerInvariant() -eq $want }).Count -gt 0
    if (-not $present) {
        [Environment]::SetEnvironmentVariable("Path", ((@($entries) + $Dir) -join ';'), "User")
        Write-Host "kashif: added $Dir to your PATH (open a new terminal to use it)"
    }
    Write-Host "kashif: run 'kashif ui' for the web interface, or 'kashif .\project' to scan from the terminal"
}
finally {
    Remove-Item -Recurse -Force $Tmp -ErrorAction SilentlyContinue
}
