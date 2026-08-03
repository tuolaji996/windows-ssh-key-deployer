[CmdletBinding()]
param(
    [string]$Root
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($Root)) {
    $Root = Split-Path -Parent $PSScriptRoot
}

$resolvedRoot = (Resolve-Path -LiteralPath $Root).Path
$excludedDirectories = @('.git', '.vs', 'artifacts', 'bin', 'obj', 'TestResults')
$textExtensions = @(
    '.bat', '.cmd', '.config', '.cs', '.csproj', '.editorconfig', '.gitignore',
    '.ini', '.json', '.md', '.nuspec', '.props', '.ps1', '.psm1', '.pub',
    '.resx', '.sh', '.sln', '.targets', '.toml', '.txt', '.xaml', '.xml',
    '.yaml', '.yml'
)
$extensionSet = [System.Collections.Generic.HashSet[string]]::new(
    [StringComparer]::OrdinalIgnoreCase
)
foreach ($textExtension in $textExtensions) {
    [void]$extensionSet.Add($textExtension)
}

$patterns = @(
    [pscustomobject]@{
        Name = 'Private key block'
        Expression = '-----BEGIN ' + '(?:(?:RSA|EC|DSA|OPENSSH|ENCRYPTED) )?PRIVATE KEY-----'
    },
    [pscustomobject]@{
        Name = 'PuTTY private key'
        Expression = 'PuTTY-' + 'User-Key-File-[0-9]+:'
    },
    [pscustomobject]@{
        Name = 'SSH key material'
        Expression = 'ssh-' + '(?:rsa|ed25519)\s+[A-Za-z0-9+/]{40,}={0,3}'
    },
    [pscustomobject]@{
        Name = 'GitHub token'
        Expression = '(?:gh' + '[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,})'
    },
    [pscustomobject]@{
        Name = 'AWS access key'
        Expression = '(?:A' + 'KIA|ASIA)[A-Z0-9]{16}'
    },
    [pscustomobject]@{
        Name = 'Google API key'
        Expression = 'AI' + 'za[0-9A-Za-z_-]{35}'
    },
    [pscustomobject]@{
        Name = 'Slack token'
        Expression = 'xox' + '[aboprs]-[0-9A-Za-z-]{20,}'
    },
    [pscustomobject]@{
        Name = 'Bearer token'
        Expression = '(?i)\bBear' + 'er\s+[A-Za-z0-9._~+/-]{20,}={0,2}'
    },
    [pscustomobject]@{
        Name = 'Assigned credential'
        Expression = '(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token)\s*[:=]\s*["''][^\s"'']{8,}["'']'
    }
)

$findings = [System.Collections.Generic.List[object]]::new()
$files = Get-ChildItem -LiteralPath $resolvedRoot -File -Recurse -Force

foreach ($file in $files) {
    $relativePath = $file.FullName.Substring($resolvedRoot.Length).TrimStart('\', '/')
    $segments = $relativePath -split '[\\/]'
    if (@($segments | Where-Object { $excludedDirectories -contains $_ }).Count -gt 0) {
        continue
    }

    if ($file.Length -gt 2MB) {
        continue
    }

    $extension = [System.IO.Path]::GetExtension($file.Name)
    $isEnvironmentFile =
        $file.Name.Equals('.env', [StringComparison]::OrdinalIgnoreCase) -or
        $file.Name.StartsWith('.env.', [StringComparison]::OrdinalIgnoreCase)
    if (
        $extension.Length -gt 0 -and
        -not $extensionSet.Contains($extension) -and
        -not $isEnvironmentFile -and
        $file.Name -notin @('LICENSE', 'Dockerfile')
    ) {
        continue
    }

    $content = [System.IO.File]::ReadAllText($file.FullName)
    foreach ($pattern in $patterns) {
        $matches = [Regex]::Matches(
            $content,
            $pattern.Expression,
            [Text.RegularExpressions.RegexOptions]::CultureInvariant
        )

        foreach ($match in $matches) {
            $prefix = $content.Substring(0, $match.Index)
            $lineNumber = [Regex]::Matches($prefix, "\r\n|\r|\n").Count + 1
            $findings.Add([pscustomobject]@{
                File = $relativePath
                Line = $lineNumber
                Kind = $pattern.Name
            })
        }
    }
}

if ($findings.Count -gt 0) {
    Write-Host 'Potential secrets were detected:' -ForegroundColor Red
    foreach ($finding in $findings) {
        Write-Host "::error file=$($finding.File),line=$($finding.Line)::$($finding.Kind)"
    }
    throw "Secret scan failed with $($findings.Count) finding(s)."
}

Write-Host "Secret scan passed: $resolvedRoot" -ForegroundColor Green
