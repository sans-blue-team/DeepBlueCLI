# Requires VirusTotalAnalyzer: https://github.com/darkoperator/Posh-VirusTotal
#
# Plus a (free) VirusTotal API Key: https://www.virustotal.com/en/documentation/public-api/
#
Import-Module VirusTotalAnalyzer -Force

# API KEY can be found once you register to Virus Total service (it's free)
$VTApi = '<Your API Key>'

$hashdirectory = ".\hashes"
$safelistfile=".\safelists\win10-x64.csv"
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
                $VTreport = Get-VirusReport -ApiKey $VTApi -Hash "$SHA256"
            }
            catch {
                Write-Host "`r`nAttempted to run: Get-Virusreport $SHA256`r`r"
    	        Write-Host "Error: " $_.Exception.Message "`n"
                Write-Host "Have you installed VirusTotalAnalyzer and set the VirusTotal API key?"
                Write-Host " - See: https://github.com/darkoperator/Posh-VirusTotal`r`n"
                Write-Host "Exiting...`n"
                exit
            }
            $positives=$VTreport.Data.attributes.last_analysis_stats.malicious
            if ($positives -eq 0){
                # File is clean
                Rename-Item -Path "$hashdirectory\$SHA256" -NewName "$SHA256.clean"
            }
            ElseIf ($positives -gt 0){
                # File is flagged by Virustotal
                Write-Host " - Hash was detected by $positives Virustotal scanners"
                if ($positives -eq 1){
                    Write-Host " - Don't Panic (yet)! There is only one positive, which may be a sign of a false positive."
                    Write-Host " - Check the VirusTotal report for more information."
                }
                Write-Host " - See $hashdirectory\$SHA256.Virustotal for the full report`r`n"
                $VTreport.Data.attributes | Set-Content "$hashdirectory\$SHA256.Virustotal"
                # Rename original hash file, add the Virustotal positive count as a numbered extension
                # $SHA256.$positives
                Rename-Item -Path "$hashdirectory\$SHA256" -NewName "$SHA256.$positives"
             }
             # Wait 15 seconds between submissions, for public Virustotal API keys
             Start-Sleep -s 15
        }
    }
}
