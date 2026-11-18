Get-ChildItem C:\Logs -Filter *.log | Where-Object { $_.Length -gt 1MB } | Remove-Item -WhatIf
