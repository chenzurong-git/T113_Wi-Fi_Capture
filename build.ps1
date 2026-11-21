param(
    [switch]$NoClean
)

$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot

if (-not (Test-Path -LiteralPath "assets\t113_capture.ico")) {
    throw "缺少 assets\t113_capture.ico"
}

$arguments = @(
    "-m", "PyInstaller",
    "--noconfirm",
    "--onedir",
    "--windowed",
    "--name", "T113Capture",
    "--icon", "assets\t113_capture.ico",
    "--add-data", "assets;assets"
)
if (-not $NoClean) {
    $arguments += "--clean"
}
$arguments += "main.py"

& python @arguments
if ($LASTEXITCODE -ne 0) {
    throw "PyInstaller 构建失败，退出码：$LASTEXITCODE"
}

$appDir = Join-Path $PSScriptRoot "dist\T113Capture"
$exePath = Join-Path $appDir "T113Capture.exe"
$zipPath = Join-Path $PSScriptRoot "dist\T113Capture.zip"
Compress-Archive -LiteralPath $appDir -DestinationPath $zipPath -Force

$legacyExe = Join-Path $PSScriptRoot "dist\T113Capture.exe"
if (Test-Path -LiteralPath $legacyExe) {
    Remove-Item -LiteralPath $legacyExe -Force
}

Write-Host ""
Write-Host "构建完成：$exePath" -ForegroundColor Green
Write-Host "分发压缩包：$zipPath" -ForegroundColor Green
