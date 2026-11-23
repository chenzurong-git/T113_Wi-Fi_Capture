param(
    [switch]$NoClean
)

$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot

$buildRoot = Join-Path $PSScriptRoot "build"
$stageRoot = Join-Path $buildRoot "release"
$workRoot = Join-Path $buildRoot "pyinstaller"
$appDir = Join-Path $PSScriptRoot "dist\T113Capture"
$stageApp = Join-Path $stageRoot "T113Capture"

if (-not (Test-Path -LiteralPath "assets\t113_capture.ico")) {
    throw "缺少 assets\t113_capture.ico"
}

if (Test-Path -LiteralPath $stageRoot) {
    Remove-Item -LiteralPath $stageRoot -Recurse -Force
}

$arguments = @(
    "-m", "PyInstaller",
    "--noconfirm",
    "--onedir",
    "--windowed",
    "--name", "T113Capture",
    "--distpath", $stageRoot,
    "--workpath", $workRoot,
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

if (-not (Test-Path -LiteralPath $stageApp)) {
    throw "构建输出不存在：$stageApp"
}

$running = Get-Process T113Capture -ErrorAction SilentlyContinue
if ($running) {
    throw "检测到 T113Capture.exe 正在运行，请先关闭后再构建"
}

New-Item -ItemType Directory -Path $appDir -Force | Out-Null
$installedInternal = Join-Path $appDir "_internal"
if (Test-Path -LiteralPath $installedInternal) {
    Remove-Item -LiteralPath $installedInternal -Recurse -Force
}
Copy-Item -LiteralPath (Join-Path $stageApp "_internal") -Destination $installedInternal -Recurse -Force
Get-ChildItem -LiteralPath $stageApp -File | Copy-Item -Destination $appDir -Force

$exePath = Join-Path $appDir "T113Capture.exe"
$zipPath = Join-Path $PSScriptRoot "dist\T113Capture.zip"
Compress-Archive -LiteralPath $stageApp -DestinationPath $zipPath -Force

$legacyExe = Join-Path $PSScriptRoot "dist\T113Capture.exe"
if (Test-Path -LiteralPath $legacyExe) {
    Remove-Item -LiteralPath $legacyExe -Force
}

Write-Host ""
Write-Host "构建完成：$exePath" -ForegroundColor Green
Write-Host "分发压缩包：$zipPath" -ForegroundColor Green
