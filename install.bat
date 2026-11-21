@echo off
setlocal
title Re:Rem Plus - English Patch Installer
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0patch\install.ps1" %*
echo.
pause
