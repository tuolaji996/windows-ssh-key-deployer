[CmdletBinding()]
param(
    [string]$Version = '1.0.0',

    [string]$InstallDirectory,

    [string]$ArchivePath,

    [string]$ChecksumPath,

    [switch]$NoStartMenuShortcut
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'SSH Key Deployer can only be installed on Windows.'
}

if ($Version -notmatch '^\d+\.\d+\.\d+(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$') {
    throw "Version '$Version' is not a supported semantic version."
}

if ([string]::IsNullOrWhiteSpace($InstallDirectory)) {
    if ([string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
        throw 'LOCALAPPDATA is not available for the current Windows account.'
    }
    $InstallDirectory = Join-Path $env:LOCALAPPDATA 'Programs\SSH Key Deployer'
}

$InstallDirectory = [System.IO.Path]::GetFullPath($InstallDirectory)
$archiveName = "SSH-Key-Deployer-v$Version-win-x64.zip"
$releaseBaseUrl = "https://github.com/tuolaji996/windows-ssh-key-deployer/releases/download/v$Version"
$temporaryDirectory = Join-Path ([System.IO.Path]::GetTempPath()) ("ssh-key-deployer-" + [Guid]::NewGuid().ToString('N'))
$downloadedArchive = Join-Path $temporaryDirectory $archiveName
$downloadedChecksum = "$downloadedArchive.sha256"

New-Item -ItemType Directory -Path $temporaryDirectory -Force | Out-Null

try {
    if ([string]::IsNullOrWhiteSpace($ArchivePath)) {
        [Net.ServicePointManager]::SecurityProtocol =
            [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

        Write-Host "Downloading SSH Key Deployer v$Version..."
        Invoke-WebRequest -Uri "$releaseBaseUrl/$archiveName" -OutFile $downloadedArchive -UseBasicParsing
        Invoke-WebRequest -Uri "$releaseBaseUrl/$archiveName.sha256" -OutFile $downloadedChecksum -UseBasicParsing
        $resolvedArchivePath = $downloadedArchive
        $resolvedChecksumPath = $downloadedChecksum
    }
    else {
        $resolvedArchivePath = (Resolve-Path -LiteralPath $ArchivePath).Path
        if ([string]::IsNullOrWhiteSpace($ChecksumPath)) {
            $ChecksumPath = "$resolvedArchivePath.sha256"
        }
        $resolvedChecksumPath = (Resolve-Path -LiteralPath $ChecksumPath).Path
    }

    $checksumText = [System.IO.File]::ReadAllText($resolvedChecksumPath)
    $checksumMatch = [Regex]::Match($checksumText, '(?i)\b[0-9a-f]{64}\b')
    if (-not $checksumMatch.Success) {
        throw "No valid SHA-256 value was found in '$resolvedChecksumPath'."
    }

    $expectedHash = $checksumMatch.Value.ToLowerInvariant()
    $actualHash = (Get-FileHash -LiteralPath $resolvedArchivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualHash -ne $expectedHash) {
        throw 'SHA-256 verification failed. The archive was not installed.'
    }

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zipArchive = [System.IO.Compression.ZipFile]::OpenRead($resolvedArchivePath)
    try {
        $entries = @($zipArchive.Entries)
        if (
            $entries.Count -ne 1 -or
            $entries[0].FullName -ne 'SshKeyDeployer.exe' -or
            $entries[0].Length -le 0
        ) {
            throw 'The verified archive must contain only one non-empty SshKeyDeployer.exe.'
        }

        $stagedExecutable = Join-Path $temporaryDirectory 'SshKeyDeployer.exe'
        [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entries[0], $stagedExecutable)
    }
    finally {
        $zipArchive.Dispose()
    }

    New-Item -ItemType Directory -Path $InstallDirectory -Force | Out-Null
    $installedExecutable = Join-Path $InstallDirectory 'SshKeyDeployer.exe'
    Copy-Item -LiteralPath $stagedExecutable -Destination $installedExecutable -Force

    if (-not $NoStartMenuShortcut) {
        $programsDirectory = [Environment]::GetFolderPath('Programs')
        if (-not [string]::IsNullOrWhiteSpace($programsDirectory)) {
            $shortcutPath = Join-Path $programsDirectory 'SSH Key Deployer.lnk'
            $shell = New-Object -ComObject WScript.Shell
            $shortcut = $shell.CreateShortcut($shortcutPath)
            $shortcut.TargetPath = $installedExecutable
            $shortcut.WorkingDirectory = $InstallDirectory
            $shortcut.Description = 'Deploy an Ed25519 SSH key to an authorized Debian server.'
            $shortcut.Save()
        }
    }

    Write-Host "Installed SSH Key Deployer v$Version to '$InstallDirectory'." -ForegroundColor Green
}
finally {
    if (Test-Path -LiteralPath $temporaryDirectory) {
        Remove-Item -LiteralPath $temporaryDirectory -Recurse -Force
    }
}
