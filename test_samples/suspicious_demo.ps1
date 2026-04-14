<# 
Safe demo file for testing "SUSPICIOUS" heuristics.
This is NOT intended to be executed.
It contains keywords as plain text to trigger indicator detection.
#>

$note = @"
Indicators (plain text):
- powershell
- cmd.exe
- wget
- curl
- base64
- invoke-expression
- downloadstring
- createobject
- wscript
- regsvr32
- mshta
- rundll32

This file is a harmless test sample.
"@

Write-Output $note

