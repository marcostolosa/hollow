@echo off
cd /d "%~dp0"
echo === hollow lab === > C:\lab\run.log 2>&1
if not exist C:\lab mkdir C:\lab
copy /y hollow.exe C:\lab\ >> C:\lab\run.log 2>&1
copy /y payload.exe C:\lab\ >> C:\lab\run.log 2>&1
cd /d C:\lab
hollow.exe --dry-run --payload payload.exe >> C:\lab\run.log 2>&1
hollow.exe --payload payload.exe >> C:\lab\run.log 2>&1
echo exit=%ERRORLEVEL% >> C:\lab\run.log
if exist %TEMP%\hollow_marker.txt type %TEMP%\hollow_marker.txt >> C:\lab\run.log
copy /y C:\lab\run.log "%~dp0run.log" >nul 2>&1
type C:\lab\run.log
