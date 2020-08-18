Write-Host "Running DeepBlue.ps1 on all EVTX files to identify any syntax errors."
cd .. ; gci -path . -recurse -name "*.evtx" | % {.\DeepBlue.ps1 -File $_ | Out-Null }
