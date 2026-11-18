$wc = New-Object Net.WebClient
$wc.DownloadFile('https://example.invalid/agent.msi', "$env:TEMP\agent.msi")
Start-Process msiexec -ArgumentList '/i', "$env:TEMP\agent.msi", '/qn' -Wait
