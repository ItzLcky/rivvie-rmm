# Installs the monitoring agent: download to a file, check its hash, install quietly.
$url = 'https://example.invalid/agent.msi'
$out = Join-Path $env:TEMP 'agent.msi'
Invoke-WebRequest -Uri $url -OutFile $out
if ((Get-FileHash $out -Algorithm SHA256).Hash -ne $env:AGENT_SHA256) { throw 'hash mismatch' }
Start-Process msiexec.exe -ArgumentList '/i', $out, '/qn' -Wait
Write-Host 'installed'
