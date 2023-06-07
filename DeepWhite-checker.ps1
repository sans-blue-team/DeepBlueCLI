# Requires Posh-VirusTotal: https://github.com/darkoperator/Posh-VirusTotal
#
# Plus a (free) VirusTotal API Key: https://www.virustotal.com/en/documentation/public-api/
#
$hashdirectory = ".\hashes"
$safelistfile=".\file-safelist.csv"
# Load the safelist into a hash table
if (Test-Path $safelistfile){
    $safelist = Get-Content $safelistfile | Select-String '^[^#]' | ConvertFrom-Csv
    $hashes=@{}
    foreach($entry in $safelist){
        $hashes[$entry.sha256]=$entry.path
    }
}

Get-ChildItem $hashdirectory | Foreach-Object{
    if ($_.Name -Match '^[0-9A-F]{64}$'){ # SHA256 hashes are 64 character hex strings
        $SHA256=$_.Name
        if ($hashes.containsKey($SHA256)){
           Rename-Item -Path "$hashdirectory\$SHA256" -NewName "$SHA256.safelisted"
        }
        Else{
            try{
                $VTreport = Get-VTFileReport $SHA256
            }
            catch {
                Write-Host "`r`nAttempted to run: Get-VTFileReport $SHA256`r`r"
    	        Write-Host "Error: " $_.Exception.Message "`n"
                Write-Host "Have you installed Posh-VirusTotal and set the VirusTotal API key?"
                Write-Host " - See: https://github.com/darkoperator/Posh-VirusTotal`r`n"
                Write-Host "Once you have installed Posh-VirusTotal and have a VirusTotal API key, run the following command:`r`n"
                Write-Host "Set-VTAPIKey -APIKey <API Key>`r`n"
                Write-Host "Exiting...`n"
                exit
            }
            if ($VTreport.positives -eq 0){
                # File is clean
                Rename-Item -Path "$hashdirectory\$SHA256" -NewName "$SHA256.clean"
            }
            ElseIf ($VTreport.positives -gt 0){
                # File is flagged by Virustotal
                $positives=$VTreport.positives
                Write-Host " - Hash was detected by $positives Virustotal scanners"
                if ($positives -eq 1){
                    Write-Host " - Don't Panic (yet)! There is only one positive, which may be a sign of a false positive."
                    Write-Host " - Check the VirusTotal report for more information."
                }
                Write-Host " - See $hashdirectory\$SHA256.Virustotal for the full report`r`n"
                $VTreport | Set-Content "$hashdirectory\$SHA256.Virustotal"
                # Rename original hash file, add the Virustotal positive count as a numbered extension
                # $SHA256.$positives
                Rename-Item -Path "$hashdirectory\$SHA256" -NewName "$SHA256.$positives"
             }
             # Wait 15 seconds between submissions, for public Virustotal API keys
             Start-Sleep -s 15
        }
    }
}
