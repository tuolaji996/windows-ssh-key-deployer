[CmdletBinding()]
param([string]$OutputPath)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path $PSScriptRoot '..\src\SshKeyDeployer\app.ico'
}

Add-Type -AssemblyName System.Drawing
Add-Type @'
using System;
using System.Runtime.InteropServices;

public static class IconNativeMethods
{
    [DllImport("user32.dll", SetLastError = true)]
    public static extern bool DestroyIcon(IntPtr handle);
}
'@

$bitmap = New-Object System.Drawing.Bitmap(256, 256)
$graphics = [System.Drawing.Graphics]::FromImage($bitmap)
$graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
$graphics.Clear([System.Drawing.Color]::Transparent)

$backgroundPath = New-Object System.Drawing.Drawing2D.GraphicsPath
$radius = 42
$diameter = $radius * 2
$backgroundPath.AddArc(12, 12, $diameter, $diameter, 180, 90)
$backgroundPath.AddArc(244 - $diameter, 12, $diameter, $diameter, 270, 90)
$backgroundPath.AddArc(244 - $diameter, 244 - $diameter, $diameter, $diameter, 0, 90)
$backgroundPath.AddArc(12, 244 - $diameter, $diameter, $diameter, 90, 90)
$backgroundPath.CloseFigure()

$backgroundBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(22, 132, 93))
$keyPen = New-Object System.Drawing.Pen([System.Drawing.Color]::White, 18)
$keyPen.StartCap = [System.Drawing.Drawing2D.LineCap]::Round
$keyPen.EndCap = [System.Drawing.Drawing2D.LineCap]::Round
$keyPen.LineJoin = [System.Drawing.Drawing2D.LineJoin]::Round

try {
    $graphics.FillPath($backgroundBrush, $backgroundPath)
    $graphics.DrawEllipse($keyPen, 50, 48, 82, 82)
    $graphics.DrawLine($keyPen, 113, 119, 194, 200)
    $graphics.DrawLine($keyPen, 158, 164, 178, 144)
    $graphics.DrawLine($keyPen, 179, 185, 199, 165)

    $directory = Split-Path -Parent ([System.IO.Path]::GetFullPath($OutputPath))
    [System.IO.Directory]::CreateDirectory($directory) | Out-Null
    $iconHandle = $bitmap.GetHicon()
    try {
        $icon = [System.Drawing.Icon]::FromHandle($iconHandle)
        $stream = [System.IO.File]::Create([System.IO.Path]::GetFullPath($OutputPath))
        try {
            $icon.Save($stream)
        }
        finally {
            $stream.Dispose()
            $icon.Dispose()
        }
    }
    finally {
        [void][IconNativeMethods]::DestroyIcon($iconHandle)
    }
}
finally {
    $keyPen.Dispose()
    $backgroundBrush.Dispose()
    $backgroundPath.Dispose()
    $graphics.Dispose()
    $bitmap.Dispose()
}

Write-Host "Generated app icon: $OutputPath" -ForegroundColor Green
