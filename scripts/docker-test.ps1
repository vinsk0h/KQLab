# KQLab — Docker Full Test Suite
# Run from project root:
#   .\scripts\docker-test.ps1              # production mode
#   .\scripts\docker-test.ps1 -Mode dev    # dev mode (hot-reload, debug port)
#   .\scripts\docker-test.ps1 -SkipCleanup # keep stack running after tests
param(
    [ValidateSet("prod","dev")]
    [string]$Mode = "prod",
    [switch]$SkipCleanup
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

$PROD_COMPOSE = "docker-compose.yml"
$DEV_COMPOSE  = "docker/compose.dev.yml"
$PASS   = 0
$FAIL   = 0
$WARNS  = [System.Collections.Generic.List[string]]::new()

# ── Helpers ───────────────────────────────────────────────────────────────────

function Write-Header($msg) {
    Write-Host ""
    Write-Host "  ══════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  $msg" -ForegroundColor Cyan
    Write-Host "  ══════════════════════════════════════" -ForegroundColor Cyan
}
function Write-Ok($msg)   { Write-Host "  [PASS] $msg" -ForegroundColor Green;  $script:PASS++ }
function Write-Fail($msg) { Write-Host "  [FAIL] $msg" -ForegroundColor Red;    $script:FAIL++ }
function Write-Warn($msg) { Write-Host "  [WARN] $msg" -ForegroundColor Yellow; $script:WARNS.Add($msg) }
function Write-Info($msg) { Write-Host "  [INFO] $msg" -ForegroundColor Gray }

# ── Mode config ───────────────────────────────────────────────────────────────

$composeFile = if ($Mode -eq "dev") { $DEV_COMPOSE  } else { $PROD_COMPOSE }
$envFile     = if ($Mode -eq "dev") { ".env.test"   } else { ".env" }
$cname       = if ($Mode -eq "dev") { "kqlab-dev"   } else { "kqlab" }
$volName     = if ($Mode -eq "dev") { "kqlab-dev-db"} else { "kqlab-db" }
$target      = if ($Mode -eq "dev") { "dev"          } else { "production" }
$imageName   = if ($Mode -eq "dev") { "kqlab:dev"    } else { "kqlab:production" }

Write-Host ""
Write-Host "  KQLab Docker Test Suite — Mode: $Mode" -ForegroundColor White
Write-Host "  Compose : $composeFile" -ForegroundColor DarkGray
Write-Host "  Env     : $envFile" -ForegroundColor DarkGray
Write-Host "  Image   : $imageName" -ForegroundColor DarkGray

# ── Read PORT from env file ────────────────────────────────────────────────────

$PORT = 3000
if (Test-Path $envFile) {
    $portLine = Get-Content $envFile | Where-Object { $_ -match '^PORT\s*=' } | Select-Object -First 1
    if ($portLine) {
        $portVal = ($portLine -split '=', 2)[1].Trim()
        if ($portVal -match '^\d+$') { $PORT = [int]$portVal }
    }
}
Write-Host "  Port    : $PORT" -ForegroundColor DarkGray

$BASE_URL = "http://localhost:$PORT"

# ═════════════════════════════════════════════════════════════════════════════
Write-Header "0 · Pre-flight"
# ═════════════════════════════════════════════════════════════════════════════

$cliVer = docker --version 2>$null
if ($LASTEXITCODE -eq 0) { Write-Ok "Docker CLI: $cliVer" }
else { Write-Fail "Docker CLI not found — install Docker Desktop"; exit 1 }

docker info 2>$null | Out-Null
if ($LASTEXITCODE -eq 0) { Write-Ok "Docker daemon running" }
else { Write-Fail "Docker daemon not running — start Docker Desktop first"; exit 1 }

if (Test-Path $composeFile) { Write-Ok "Compose file: $composeFile" }
else { Write-Fail "Missing compose file: $composeFile"; exit 1 }

if (Test-Path $envFile) { Write-Ok "Env file: $envFile" }
else { Write-Fail "Missing $envFile — copy .env.example and fill in keys"; exit 1 }

# ═════════════════════════════════════════════════════════════════════════════
Write-Header "1 · Environment cleanup (fresh deploy)"
# ═════════════════════════════════════════════════════════════════════════════

Write-Info "Stopping and removing existing containers + volumes ..."
docker compose -f $composeFile down --volumes --remove-orphans 2>&1 | Out-Null
Write-Ok "Compose stack torn down"

# Remove project images so we rebuild from scratch
$imagesToRemove = @("kqlab:production", "kqlab:dev", "kqlab-test:latest")
foreach ($img in $imagesToRemove) {
    $exists = docker image inspect $img 2>$null
    if ($LASTEXITCODE -eq 0) {
        docker rmi --force $img 2>$null | Out-Null
        Write-Info "Removed image: $img"
    }
}

# Remove named volumes explicitly (in case compose down missed them)
$volumesToRemove = @("kqlab-db", "kqlab-dev-db")
foreach ($vol in $volumesToRemove) {
    docker volume inspect $vol 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) {
        docker volume rm $vol 2>$null | Out-Null
        Write-Info "Removed volume: $vol"
    }
}

# Prune dangling build cache
docker builder prune -f 2>$null | Out-Null
docker image prune -f 2>$null | Out-Null
Write-Ok "Environment clean — ready for fresh build"

# ═════════════════════════════════════════════════════════════════════════════
Write-Header "2 · Compose config validation"
# ═════════════════════════════════════════════════════════════════════════════

$configOut = docker compose -f $composeFile --env-file $envFile config 2>&1
if ($LASTEXITCODE -eq 0) { Write-Ok "Compose config valid" }
else {
    Write-Fail "Compose config invalid:"
    Write-Host $configOut -ForegroundColor Red
    exit 1
}

# ═════════════════════════════════════════════════════════════════════════════
Write-Header "3 · Image build (no-cache)"
# ═════════════════════════════════════════════════════════════════════════════

Write-Info "Building via docker compose (target=$target) ..."
$buildStart = Get-Date

docker compose -f $composeFile --env-file $envFile build --no-cache --progress plain 2>&1 | ForEach-Object {
    Write-Host "    $_" -ForegroundColor DarkGray
}

$buildTime = [int](New-TimeSpan -Start $buildStart).TotalSeconds
if ($LASTEXITCODE -eq 0) { Write-Ok "Build succeeded in ${buildTime}s" }
else { Write-Fail "Build failed — check output above"; exit 1 }

# Image size check
$sizeRaw = docker image inspect $imageName --format "{{.Size}}" 2>$null
if ($LASTEXITCODE -eq 0) {
    $sizeMB = [math]::Round([int64]$sizeRaw / 1MB, 1)
    Write-Info "Image size: ${sizeMB} MB"
    if ($sizeMB -gt 500) { Write-Warn "Image ${sizeMB}MB exceeds 500MB target" }
    else { Write-Ok "Image size ${sizeMB}MB within 500MB limit" }
} else {
    Write-Warn "Could not inspect image size for: $imageName"
}

$layerCount = (docker history $imageName --no-trunc --format "{{.ID}}" 2>$null |
               Where-Object { $_ -ne "<missing>" } | Measure-Object).Count
Write-Info "Layer count: $layerCount"

# ═════════════════════════════════════════════════════════════════════════════
Write-Header "4 · Security inspection"
# ═════════════════════════════════════════════════════════════════════════════

$inspectJson = docker image inspect $imageName 2>$null | ConvertFrom-Json
if ($inspectJson) {
    $cfg = $inspectJson[0].Config

    $runUser = $cfg.User
    if ($runUser -and $runUser -ne "" -and $runUser -ne "root" -and $runUser -ne "0") {
        Write-Ok "Runs as non-root user: $runUser"
    } else {
        Write-Fail "Runs as root — security risk"
    }

    $ports = if ($cfg.ExposedPorts) { ($cfg.ExposedPorts.PSObject.Properties.Name) -join ", " } else { "none" }
    Write-Info "Exposed ports: $ports"

    if ($null -ne $cfg.Healthcheck) { Write-Ok "HEALTHCHECK configured" }
    else { Write-Warn "No HEALTHCHECK in image" }

    $ep = if ($cfg.Entrypoint) { $cfg.Entrypoint -join " " } else { "" }
    if ($ep -match "tini") { Write-Ok "tini PID-1 present (clean signal handling)" }
    else { Write-Warn "No tini/dumb-init — zombie process risk on SIGTERM" }
} else {
    Write-Warn "Could not inspect image: $imageName"
}

Write-Info "Docker Scout vulnerability scan ..."
docker scout quickview $imageName 2>&1 | ForEach-Object {
    Write-Host "    $_" -ForegroundColor DarkGray
}

# ═════════════════════════════════════════════════════════════════════════════
Write-Header "5 · Deploy"
# ═════════════════════════════════════════════════════════════════════════════

Write-Info "Starting stack (force-recreate, no dangling containers) ..."
docker compose -f $composeFile --env-file $envFile up -d --force-recreate 2>&1 | ForEach-Object {
    Write-Host "    $_" -ForegroundColor DarkGray
}
if ($LASTEXITCODE -eq 0) { Write-Ok "docker compose up succeeded" }
else { Write-Fail "docker compose up failed"; exit 1 }

Write-Info "Waiting for container healthy (max 90s) ..."
$healthy = $false
for ($i = 0; $i -lt 18; $i++) {
    Start-Sleep -Seconds 5

    $state   = docker inspect --format "{{.State.Status}}" $cname 2>$null
    $hStatus = docker inspect --format "{{.State.Health.Status}}" $cname 2>$null

    Write-Info "  [$( ($i+1)*5 )s] state=$state health=$hStatus"

    if ($state -ne "running") {
        Write-Fail "Container stopped unexpectedly (state=$state)"
        Write-Host ""
        Write-Host "  Last 30 log lines:" -ForegroundColor Red
        docker logs $cname --tail 30 2>&1 | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }
        exit 1
    }

    if ($hStatus -eq "healthy") { $healthy = $true; break }
}

if ($healthy) { Write-Ok "Container is healthy" }
else          { Write-Warn "Container did not reach 'healthy' in 90s (may still be starting)" }

# ═════════════════════════════════════════════════════════════════════════════
Write-Header "6 · HTTP endpoint validation"
# ═════════════════════════════════════════════════════════════════════════════

# Health endpoint
try {
    $resp = Invoke-RestMethod -Uri "$BASE_URL/health" -TimeoutSec 10 -ErrorAction Stop
    if ($resp.ok -eq $true) { Write-Ok "GET /health → ok=true, uptime=$($resp.uptime)s" }
    else { Write-Fail "GET /health returned ok!=true: $($resp | ConvertTo-Json -Compress)" }
} catch {
    Write-Fail "GET /health failed: $($_.Exception.Message)"
    Write-Info "Dumping last 20 container logs:"
    docker logs $cname --tail 20 2>&1 | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }
}

# Frontend SPA
try {
    $ui = Invoke-WebRequest -Uri "$BASE_URL/" -TimeoutSec 10 -ErrorAction Stop
    if ($ui.StatusCode -eq 200) { Write-Ok "GET / → 200 (frontend served)" }
    else { Write-Warn "GET / returned HTTP $($ui.StatusCode)" }
} catch {
    Write-Warn "GET / failed: $($_.Exception.Message)"
}

# ═════════════════════════════════════════════════════════════════════════════
Write-Header "7 · Admin credentials"
# ═════════════════════════════════════════════════════════════════════════════

Write-Info "Parsing admin passphrase from first-boot logs ..."
$logs = docker logs $cname 2>&1 | Out-String

$pwMatch = [regex]::Match($logs, 'Passphrase\s*:\s*([a-f0-9A-F]{16,})')
if ($pwMatch.Success) {
    $adminPw = $pwMatch.Groups[1].Value.Trim()
    Write-Ok "Admin passphrase found: $adminPw"

    try {
        $loginBody = @{ login = "admin"; password = $adminPw } | ConvertTo-Json
        $loginResp = Invoke-RestMethod `
            -Uri         "$BASE_URL/api/auth/login" `
            -Method      POST `
            -Body        $loginBody `
            -ContentType "application/json" `
            -Headers     @{ "X-Requested-With" = "XMLHttpRequest" } `
            -TimeoutSec  10 `
            -ErrorAction Stop

        if ($loginResp.user.role -eq "admin") { Write-Ok "Admin login succeeded (role=admin)" }
        else { Write-Warn "Unexpected role: $($loginResp.user.role)" }
        if ($loginResp.must_change_password -eq $true) { Write-Ok "must_change_password=true confirmed" }
    } catch {
        Write-Fail "Admin login POST failed: $($_.Exception.Message)"
    }
} else {
    Write-Warn "Admin passphrase not found in logs"
    Write-Info "DB may have pre-existed — this is expected on second run without volume wipe."
}

# Demo login
try {
    $demoResp = Invoke-RestMethod `
        -Uri         "$BASE_URL/api/auth/demo" `
        -Method      POST `
        -Headers     @{ "X-Requested-With" = "XMLHttpRequest" } `
        -ContentType "application/json" `
        -TimeoutSec  10 `
        -ErrorAction Stop
    if ($demoResp.user) { Write-Ok "Demo login → user=$($demoResp.user.login) role=$($demoResp.user.role)" }
    else { Write-Warn "Demo login returned unexpected body" }
} catch {
    Write-Fail "Demo login failed: $($_.Exception.Message)"
}

# ═════════════════════════════════════════════════════════════════════════════
Write-Header "8 · Runtime inspection"
# ═════════════════════════════════════════════════════════════════════════════

$runStatus = docker inspect --format "{{.State.Status}}" $cname 2>$null
Write-Info "Container state: $runStatus"
if ($runStatus -eq "running") { Write-Ok "Container running" }
else { Write-Fail "Container state '$runStatus' — expected 'running'" }

Write-Info "Last 15 log lines:"
docker logs $cname --tail 15 2>&1 | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }

$procs = docker exec $cname ps aux 2>$null | Out-String
Write-Info "Processes inside container:"
$procs.Split("`n") | ForEach-Object { if ($_) { Write-Host "    $_" -ForegroundColor DarkGray } }
if ($procs -match "tini")     { Write-Ok "tini running as PID 1" }
if ($procs -match "\bnode\b") { Write-Ok "node process running" }

docker volume inspect $volName 2>$null | Out-Null
if ($LASTEXITCODE -eq 0) { Write-Ok "Volume '$volName' exists" }
else { Write-Fail "Volume '$volName' not found" }

$dbCheck = docker exec $cname sh -c "test -f /app/backend/db/kqlab.db && echo yes || echo no" 2>$null
if ($dbCheck -eq "yes") { Write-Ok "kqlab.db present in volume" }
else { Write-Warn "kqlab.db not found (may not be initialised yet)" }

# ═════════════════════════════════════════════════════════════════════════════
Write-Header "9 · Lifecycle: stop / start"
# ═════════════════════════════════════════════════════════════════════════════

Write-Info "Stopping container ..."
docker compose -f $composeFile stop 2>$null | Out-Null
Start-Sleep -Seconds 3
$stoppedState = docker inspect --format "{{.State.Status}}" $cname 2>$null
if ($stoppedState -eq "exited") { Write-Ok "Stop: container exited cleanly" }
else { Write-Fail "Stop: unexpected state '$stoppedState'" }

Write-Info "Starting container ..."
docker compose -f $composeFile start 2>$null | Out-Null
Start-Sleep -Seconds 10
$restartedState = docker inspect --format "{{.State.Status}}" $cname 2>$null
if ($restartedState -eq "running") { Write-Ok "Start: container running again" }
else { Write-Fail "Start: state '$restartedState'" }

Start-Sleep -Seconds 5
try {
    $r2 = Invoke-RestMethod -Uri "$BASE_URL/health" -TimeoutSec 10 -ErrorAction Stop
    if ($r2.ok) { Write-Ok "App responds after stop/start cycle" }
    else { Write-Fail "App returned ok!=true after restart" }
} catch {
    Write-Fail "App not responding after restart: $($_.Exception.Message)"
}

# ═════════════════════════════════════════════════════════════════════════════
Write-Header "10 · Volume persistence"
# ═════════════════════════════════════════════════════════════════════════════

Write-Info "docker compose down (keep volume) ..."
docker compose -f $composeFile down 2>$null | Out-Null

docker volume inspect $volName 2>$null | Out-Null
if ($LASTEXITCODE -eq 0) { Write-Ok "Volume survived 'down' — data safe" }
else { Write-Fail "Volume removed with container — data loss risk" }

Write-Info "Redeploying to verify volume re-attaches ..."
docker compose -f $composeFile --env-file $envFile up -d 2>$null | Out-Null
Start-Sleep -Seconds 15

$dbCheck2 = docker exec $cname sh -c "test -f /app/backend/db/kqlab.db && echo yes || echo no" 2>$null
if ($dbCheck2 -eq "yes") { Write-Ok "DB persisted and accessible after redeploy" }
else { Write-Warn "DB not found after redeploy — check volume mount" }

$logs2 = docker logs $cname 2>&1 | Out-String
if (-not [regex]::IsMatch($logs2, 'COMPTE ADMIN')) {
    Write-Ok "No new admin account — existing DB reused (correct)"
} else {
    Write-Warn "New admin account seeded — DB was re-initialised"
}

# ═════════════════════════════════════════════════════════════════════════════
Write-Header "11 · Cleanup"
# ═════════════════════════════════════════════════════════════════════════════

if ($SkipCleanup) {
    Write-Info "-SkipCleanup — stack left running."
    Write-Info "  Container : $cname"
    Write-Info "  Volume    : $volName"
    Write-Info "  Interface : $BASE_URL"
    Write-Info "  Stop with : docker compose -f $composeFile down --volumes"
    Write-Host ""
    Write-Host "  Opening browser at $BASE_URL ..." -ForegroundColor Cyan
    Start-Process $BASE_URL
} else {
    Write-Info "Removing containers and volumes ..."
    docker compose -f $composeFile down --volumes 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) { Write-Ok "Stack removed (containers + volume)" }
    else { Write-Fail "Stack removal failed" }

    Write-Info "Removing project images ..."
    docker rmi $imageName 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) { Write-Ok "Image $imageName removed" }
    else { Write-Warn "Image removal skipped (still referenced or already gone)" }

    docker image prune -f 2>$null | Out-Null
    Write-Ok "Dangling images pruned"
}

# ═════════════════════════════════════════════════════════════════════════════
Write-Header "Summary"
# ═════════════════════════════════════════════════════════════════════════════

Write-Host ""
Write-Host "  PASSED  : $PASS" -ForegroundColor Green
Write-Host "  FAILED  : $FAIL" -ForegroundColor $(if ($FAIL -gt 0) { "Red" } else { "Green" })

if ($WARNS.Count -gt 0) {
    Write-Host "  WARNINGS:" -ForegroundColor Yellow
    $WARNS | ForEach-Object { Write-Host "    - $_" -ForegroundColor Yellow }
}

Write-Host ""
if ($FAIL -gt 0) {
    Write-Host "  RESULT: FAILED ($FAIL test(s) failed)" -ForegroundColor Red
    exit 1
} else {
    Write-Host "  RESULT: ALL TESTS PASSED" -ForegroundColor Green
    exit 0
}
