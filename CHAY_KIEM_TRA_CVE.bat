@echo off
chcp 65001 >nul
title CVE 2026 Security Command Center
cd /d "%~dp0"
python cve_center.py %*
if "%~1"=="" pause
