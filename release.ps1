[CmdletBinding()]
param(
    [string]$Version = '1.1.0',

    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release',

    [string]$OutputDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($Version -notmatch '^\d+\.\d+\.\d+(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$') {
    throw "Version '$Version' is not a supported semantic version."
}

$repositoryRoot = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $repositoryRoot 'artifacts'
}

$artifactsRoot = [System.IO.Path]::GetFullPath($OutputDirectory)
$projectPath = Join-Path $repositoryRoot 'src\SshKeyDeployer\SshKeyDeployer.csproj'
$selfTestProjectPath = Join-Path $repositoryRoot 'tests\SshKeyDeployer.SelfTest\SshKeyDeployer.SelfTest.csproj'
$publishDirectory = Join-Path $artifactsRoot 'publish-win-x64'
$archiveName = "SSH-Key-Deployer-v$Version-win-x64.zip"
$archivePath = Join-Path $artifactsRoot $archiveName
$checksumPath = "$archivePath.sha256"
$dotnetCommand = Get-Command dotnet -ErrorAction SilentlyContinue

if ($null -eq $dotnetCommand) {
    throw '.NET 8 SDK was not found. Install it from https://dotnet.microsoft.com/download/dotnet/8.0.'
}

function Invoke-DotNet {
    param(
        [Parameter(Mandatory)]
        [string[]]$Arguments
    )

    & $dotnetCommand.Path @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "dotnet $($Arguments -join ' ') failed with exit code $LASTEXITCODE."
    }
}

Push-Location $repositoryRoot
try {
    & (Join-Path $repositoryRoot 'build.ps1') -Configuration $Configuration

    Invoke-DotNet -Arguments @(
        'run',
        '--project', $selfTestProjectPath,
        '--configuration', $Configuration,
        '--no-build',
        '--no-restore'
    )

    New-Item -ItemType Directory -Path $artifactsRoot -Force | Out-Null
    if (Test-Path -LiteralPath $publishDirectory) {
        Remove-Item -LiteralPath $publishDirectory -Recurse -Force
    }
    if (Test-Path -LiteralPath $archivePath) {
        Remove-Item -LiteralPath $archivePath -Force
    }
    if (Test-Path -LiteralPath $checksumPath) {
        Remove-Item -LiteralPath $checksumPath -Force
    }

    Invoke-DotNet -Arguments @(
        'restore',
        $projectPath,
        '--runtime', 'win-x64',
        '--nologo'
    )

    Invoke-DotNet -Arguments @(
        'publish',
        $projectPath,
        '--configuration', $Configuration,
        '--runtime', 'win-x64',
        '--self-contained', 'true',
        '--no-restore',
        '--output', $publishDirectory,
        '--nologo',
        '-p:PublishSingleFile=true',
        '-p:IncludeNativeLibrariesForSelfExtract=true',
        '-p:EnableCompressionInSingleFile=true',
        '-p:PublishTrimmed=false',
        '-p:DebugType=None',
        '-p:DebugSymbols=false',
        "-p:Version=$Version"
    )

    $publishedFiles = @(Get-ChildItem -LiteralPath $publishDirectory -File -Recurse)
    if ($publishedFiles.Count -ne 1 -or $publishedFiles[0].Name -ne 'SshKeyDeployer.exe') {
        $fileNames = ($publishedFiles | ForEach-Object Name) -join ', '
        throw "Expected one single-file executable named SshKeyDeployer.exe, found: $fileNames"
    }

    Compress-Archive -LiteralPath $publishedFiles[0].FullName -DestinationPath $archivePath -CompressionLevel Optimal

    $hash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    $checksumLine = "$hash  $archiveName$([Environment]::NewLine)"
    [System.IO.File]::WriteAllText($checksumPath, $checksumLine, [System.Text.Encoding]::ASCII)

    Write-Host "Release archive: $archivePath" -ForegroundColor Green
    Write-Host "SHA-256 file:   $checksumPath" -ForegroundColor Green
}
finally {
    Pop-Location
}
