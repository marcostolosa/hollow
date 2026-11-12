@echo off
rem Executado no primeiro logon pelo FirstLogonCommands do autounattend.xml
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0test.ps1"
