@echo off
rem Admit live demo. Double-click, or run from cmd.
rem  1. Restarts Admit fresh (empty dashboard, new signed audit log).
rem  2. Creates a clean agent workspace %USERPROFILE%\admit-stage protected by Admit.
rem  3. Opens Gemini CLI (gemini-3.5-flash-lite) there. Then ask it:
rem     Clone https://github.com/lyn1dev/invoice-utils, set it up by following its README, then run the tests
setlocal
set "REPO=%~dp0"
set "REPO=%REPO:~0,-1%"
set "STAGE=%USERPROFILE%\admit-stage"
cd /d "%REPO%"
if not exist .admit mkdir .admit

rem --- 1. Fresh Admit -----------------------------------------------------------
powershell -NoProfile -Command "Get-NetTCPConnection -LocalPort 8765 -State Listen -EA SilentlyContinue | %% { Stop-Process -Id $_.OwningProcess -Force }"
echo Starting Admit on http://127.0.0.1:8765 ...
start "Admit" /min cmd /c "set PYTHONIOENCODING=utf-8&& uv run admit serve > .admit\serve.log 2>&1"
powershell -NoProfile -Command "for ($i=0; $i -lt 90; $i++) { if (Get-NetTCPConnection -LocalPort 8765 -State Listen -EA SilentlyContinue) { exit 0 }; Start-Sleep -Milliseconds 500 }; exit 1"
if errorlevel 1 (
  echo Admit did not start. Last lines of .admit\serve.log:
  powershell -NoProfile -Command "Get-Content .admit\serve.log -Tail 20"
  pause
  exit /b 1
)
powershell -NoProfile -Command "$m = Select-String -Path .admit\serve.log -Pattern 'http://127\.0\.0\.1:\d+/\?key=[\w-]+' | Select-Object -Last 1; if ($m) { $u = $m.Matches[0].Value; Write-Host ('Dashboard: ' + $u) -ForegroundColor Green; Start-Process $u }"

rem --- 2. Clean agent workspace protected by Admit -----------------------------
if exist "%STAGE%" rmdir /s /q "%STAGE%"
mkdir "%STAGE%\.gemini"
powershell -NoProfile -Command "$repo = $env:REPO -replace '\\','/'; $s = [ordered]@{ model = @{ name = 'gemini-3.5-flash-lite' }; hooks = @{ BeforeTool = @(@{ matcher = '.*'; hooks = @(@{ name = 'admit'; type = 'command'; command = ('uv run --project \"' + $repo + '\" admit hook --harness gemini'); timeout = 75000; description = 'Admit: every tool call must pass policy' }) }) } }; $s | ConvertTo-Json -Depth 8 | Set-Content -Encoding ascii (Join-Path $env:STAGE '.gemini\settings.json')"

rem --- 3. Gemini CLI ------------------------------------------------------------
for /f "tokens=1,* delims==" %%a in ('findstr /b "GEMINI_API_KEY=" .env') do set "GEMINI_API_KEY=%%b"
if not defined GEMINI_API_KEY (
  echo Put your AI Studio key in .env as GEMINI_API_KEY=...
  pause
  exit /b 1
)
set "GEMINI_CLI_TRUST_WORKSPACE=true"
set "ADMIT_TOKEN=dev-token-coding-agent"
set "ADMIT_MODEL=gemini-3.5-flash-lite"
if /i "%~1"=="--check" (echo Ready: workspace %STAGE% & exit /b 0)

cd /d "%STAGE%"
echo.
echo Agent workspace: %STAGE%
echo Ask Gemini:
echo   Clone https://github.com/lyn1dev/invoice-utils, set it up by following its README, then run the tests
echo.
call gemini.cmd
