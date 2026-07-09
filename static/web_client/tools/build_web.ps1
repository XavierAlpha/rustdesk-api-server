param(
  [ValidateSet('release', 'profile', 'debug')]
  [string]$Mode = 'release',
  [switch]$Run,
  [switch]$SkipJs,
  [switch]$SkipDeps,
  [switch]$SkipIcons
)

$ErrorActionPreference = 'Stop'

function Ensure-Command {
  param([string]$Name, [string]$Hint)
  if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
    throw "Missing '$Name'. $Hint"
  }
}

function Test-WebDepsPresent {
  param([string]$WebDir)
  $markers = @(
    (Join-Path $WebDir 'libopus.js'),
    (Join-Path $WebDir 'libopus.wasm'),
    (Join-Path $WebDir 'yuv-canvas-1.2.6.js'),
    (Join-Path $WebDir 'ogvjs-1.8.6\ogv.js')
  )
  return ($markers | ForEach-Object { Test-Path $_ }) -notcontains $false
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$flutterRoot = (Resolve-Path (Join-Path $scriptDir '..\..')).Path
Set-Location $flutterRoot

$flutter = $env:FLUTTER_BIN
if ([string]::IsNullOrWhiteSpace($flutter)) {
  $flutter = 'flutter'
}
Ensure-Command $flutter "Install Flutter and ensure it is in PATH, or set FLUTTER_BIN."

$webDir = Join-Path $flutterRoot 'web'
$webIndex = Join-Path $webDir 'index.html'
$webJsDir = Join-Path $webDir 'js'
$webJsPkg = Join-Path $webJsDir 'package.json'
$webJsLock = Join-Path $webJsDir 'package-lock.json'
$repoRoot = (Resolve-Path (Join-Path $flutterRoot '..')).Path
$pubspecPath = Join-Path $flutterRoot 'pubspec.yaml'
$appVersion = $env:APP_VERSION
$appName = $env:APP_NAME
if ([string]::IsNullOrWhiteSpace($appVersion) -and (Test-Path $pubspecPath)) {
  $versionLine = Select-String -Path $pubspecPath -Pattern '^\s*version:\s*(.+)\s*$' | Select-Object -First 1
  if ($versionLine) {
    $appVersion = $versionLine.Matches[0].Groups[1].Value.Trim()
  }
}

if (-not (Test-Path $webIndex)) {
  throw "Missing web assets: $webIndex. Ensure flutter/web has index.html, manifest.json, and favicon assets before building."
}

$faviconSource = Join-Path $repoRoot 'res/icon.png'
$faviconTarget = Join-Path $webDir 'favicon.png'
if (Test-Path $faviconSource) {
  Copy-Item -Path $faviconSource -Destination $faviconTarget -Force
}

& $flutter pub get
if (-not $SkipIcons) {
  & $flutter pub run flutter_launcher_icons
}

if (-not $SkipJs) {
  if (-not (Test-Path $webJsPkg)) {
    throw "Missing '$webJsPkg'. Add the web JS bridge toolchain, or use -SkipJs."
  }
  Ensure-Command npm "Install Node.js (npm) to build web JS dependencies."
  Push-Location $webJsDir
  try {
    if (Test-Path $webJsLock) {
      npm ci --no-fund --no-audit
    }
    else {
      npm install --no-fund --no-audit
    }
    npm run build
  }
  finally {
    Pop-Location
  }
}

if (-not $SkipDeps) {
  if (Test-WebDepsPresent -WebDir $webDir) {
    Write-Host "Web deps already present, skipping download."
  }
  else {
    $depsUrl = 'https://github.com/rustdesk/doc.rustdesk.com/releases/download/console/web_deps.tar.gz'
    $depsTar = Join-Path $webDir 'web_deps.tar.gz'
    Write-Host "Downloading web deps: $depsUrl"
    Invoke-WebRequest -Uri $depsUrl -OutFile $depsTar
    Push-Location $webDir
    try {
      tar -xzf $depsTar
    }
    finally {
      Pop-Location
      if (Test-Path $depsTar) {
        Remove-Item $depsTar -Force
      }
    }
  }
}

$flutterArgs = @()
if ($Run) {
  $flutterArgs = @("run", "-d", "chrome", "-v")
  if ($Mode -eq 'release') {
    $flutterArgs += "--release"
  }
  elseif ($Mode -eq 'profile') {
    $flutterArgs += "--profile"
  }
}
else {
  $flutterArgs = @("build", "web", "--$Mode")
}
if (-not [string]::IsNullOrWhiteSpace($env:RS_PUB_KEY)) {
  $flutterArgs += "--dart-define=RS_PUB_KEY=$($env:RS_PUB_KEY)"
}
if (-not [string]::IsNullOrWhiteSpace($env:RENDEZVOUS_SERVERS)) {
  $flutterArgs += "--dart-define=RENDEZVOUS_SERVERS=$($env:RENDEZVOUS_SERVERS)"
}
if (-not [string]::IsNullOrWhiteSpace($env:API_SERVER)) {
  $flutterArgs += "--dart-define=API_SERVER=$($env:API_SERVER)"
}
if (-not [string]::IsNullOrWhiteSpace($appName)) {
  $flutterArgs += "--dart-define=APP_NAME=$appName"
}
if (-not [string]::IsNullOrWhiteSpace($appVersion)) {
  $flutterArgs += "--dart-define=APP_VERSION=$appVersion"
}
$buildDate = (Get-Date).ToString('yyyy-MM-dd HH:mm')
$flutterArgs += "--dart-define=BUILD_DATE=$buildDate"

& $flutter @flutterArgs
