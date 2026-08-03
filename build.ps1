[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release',

    [switch]$SkipRestore
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = $PSScriptRoot
$solutionPath = Join-Path $repositoryRoot 'SshKeyDeployer.sln'
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
    if (-not $SkipRestore) {
        Invoke-DotNet -Arguments @(
            'restore',
            $solutionPath,
            '--nologo'
        )
    }

    Invoke-DotNet -Arguments @(
        'build',
        $solutionPath,
        '--configuration', $Configuration,
        '--no-restore',
        '--nologo',
        '--verbosity', 'minimal'
    )

    Write-Host "Build completed: $Configuration" -ForegroundColor Green
}
finally {
    Pop-Location
}
