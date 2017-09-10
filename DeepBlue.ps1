<#
.SYNOPSIS

A PowerShell module for hunt teaming via Windows event logs
.DESCRIPTION

DeepBlueCLI can automatically determine events that are typically triggered during a majority of successful breaches, including use of malicious command lines including PowerShell. 
.Example

Process local Windows security event log:
.\DeepBlue.ps1
.\DeepBlue.ps1 -log security
.Example
Process local Windows system event log:

.\DeepBlue.ps1 -log system
.\DeepBlue.ps1 "" system
.Example
Process evtx file:

.\DeepBlue.ps1 .\evtx\new-user-security.evtx
.\DeepBlue.ps1 -file .\evtx\new-user-security.evtx
.LINK
https://github.com/sans-blue-team/DeepBlueCLI

#>

# DeepBlueCLI 0.4 Beta
# Eric Conrad, Backshore Communications, LLC
# deepblue <at> backshore <dot> net
# Twitter: @eric_conrad
# http://ericconrad.com
#

param ([string]$file=$env:file,[string]$log=$env:log)           

function Main {
    $text="" # Temporary scratch pad variable to hold output text
    $minlength=1000 # Minimum length of command line to alert
    # Load cmd match regexes from csv file, ignore comments
    $regexes = Get-Content ".\regexes.txt" | Select-String '^[^#]' | ConvertFrom-Csv
    # Load cmd whitelist regexes from csv file, ignore comments
    $whitelist = Get-Content ".\whitelist.txt" | Select-String '^[^#]' | ConvertFrom-Csv 
    $logname=Check-Options $file $log
    "Processing the " + $logname + " log..."
    $filter=Create-Filter $file $logname
    $failedlogons=0 # Count of failed logons (Security event 4625)
    $maxfailedlogons=100 # Alert after this many failed logons
    # Get the events:
    try{
        $events = iex "Get-WinEvent $filter -ErrorAction Stop"
    }
    catch {
        Write-Host "Get-WinEvent $filter -ErrorAction Stop"
    	Write-Host "Get-WinEvent error: " $_.Exception.Message "`n"
        Write-Host "Exiting...`n"
        exit
    }
    ForEach ($event in $events) {
        $output="" # Final output text string
        $eventXML = [xml]$event.ToXml()
        if ($logname -eq "Security"){
            if ($event.id -eq 4688){
                # A new process has been created. (Command Line Logging)
                $commandline=$eventXML.Event.EventData.Data[8]."#text"
                $output += (Check-Command $commandline $minlength $regexes $whitelist 0)
            }
            ElseIf ($event.id -eq 4720){ 
                # A user account was created.
                $username=$eventXML.Event.EventData.Data[0]."#text"
                $securityid=$eventXML.Event.EventData.Data[2]."#text"
                $output += "  New user created: $username`n"
                $output += "    - User SID: $securityid`n"
            }
            ElseIf(($event.id -eq 4728) -or ($event.id -eq 4732)){
                # A member was added to a security-enabled (global|local) group.
                $groupname=$eventXML.Event.EventData.Data[2]."#text"
                # Check if group is Administrators, may later expand to all groups
                if ($groupname -eq "Administrators"){    
                    $username=$eventXML.Event.EventData.Data[0]."#text"
                    $securityid=$eventXML.Event.EventData.Data[1]."#text"
                    switch ($event.id){
                        4728 {$output += "  User added to global $groupname group`n"}
                        4732 {$output += "  User added to local $groupname group`n"}
                    }
                    $output += "    - Username: $username`n"
                    $output += "    - User SID: $securityid`n"
                }
            }
            ElseIf($event.id -eq 4625){
                # An account failed to log on.
                # Requires auditing logon failures
                # https://technet.microsoft.com/en-us/library/cc976395.aspx
                $username=$eventXML.Event.EventData.Data[5]."#text"
                $failedlogons += 1
            }
        }
        ElseIf ($logname -eq "System"){
            if ($event.id -eq 7045){
                # A service was installed in the system.
                $servicename=$eventXML.Event.EventData.Data[0]."#text"
                # Check for suspicious service name
                $text = (Check-Regex $servicename $regexes 1)
                if ($text){
                    $output += "  Service created, service name: $servicename`n"
                    $output += $text
                }
                # Check for suspicious cmd
                $commandline=$eventXML.Event.EventData.Data[1]."#text"
                $output += (Check-Command $commandline $minlength $regexes $whitelist 1)
            }
            ElseIf ($event.id -eq 7030){
                # The ... service is marked as an interactive service.  However, the system is configured 
                # to not allow interactive services.  This service may not function properly.
                $servicename=$eventXML.Event.EventData.Data."#text"
                $output += "  Interactive service warning, service name: $servicename`n"
                # Check for suspicious service name
                $output += (Check-Regex $servicename $regexes 1)
            }
            ElseIf ($event.id -eq 7036){
                # The ... service entered the stopped|running state.
                $servicename=$eventXML.Event.EventData.Data[0]."#text"
                $text = (Check-Regex $servicename $regexes 1)
                if ($text){
                    $output += "  " + $event.Message + "`n"
                    $output += $text
                }
            }
        } 
        ElseIf ($logname -eq "Application"){
            if (($event.id -eq 2) -and ($event.Providername -eq "EMET")){
                # EMET Block
                $output += "  EMET Block`n"
                if ($event.Message){ 
                    # EMET Message is a blob of text that looks like this:
                    #########################################################
                    # EMET detected HeapSpray mitigation and will close the application: iexplore.exe
                    #
                    # HeapSpray check failed:
                    #   Application   : C:\Program Files (x86)\Internet Explorer\iexplore.exe
                    #   User Name     : WIN-CV6AHH1BNU9\Instructor
                    #   Session ID    : 1
                    #   PID           : 0xBA8 (2984)
                    #   TID           : 0x9E8 (2536)
                    #   Module        : mshtml.dll
                    #  Address       : 0x6FBA7512, pull out relevant parts
                    $array = $event.message -split '\n' # Split each line of the message into an array
                    $message = $array[0]
                    $application = Remove-Spaces($array[3])
                    $username = Remove-Spaces($array[4])
                    $output += "  - Message: $message`n"
                    $output += "  - $application`n"
                    $output += "  - $username`n" 
                }
                Else{
                    # If the message is blank: EMET is not installed locally.
                    # This occurs when parsing remote event logs sent from systems with EMET installed
                    $output += "  Warning: EMET Message field is blank. Install EMET locally to see full details of this alert"
                }
            }
        }  
        ElseIf ($logname -eq "Applocker"){
            if ($event.id -eq 8004){ 
                # ...was prevented from running.
                $output += "  Applocker block: " + $event.message
            }
        } 
        ElseIf ($logname -eq "PowerShell"){
            #$event.pd
            if ($event.id -eq 4103){
                $pscommand= $eventXML.Event.EventData.Data[2]."#text"
                if ($pscommand -Match "Host Application"){ 
                    # Multiline replace, remove everything before "Host Application = "
                    $pscommand = $pscommand -Replace "(?ms)^.*Host.Application = ",""
                    # Remove every line after the "Host Application = " line.
                    $pscommand = $pscommand -Replace "(?ms)`n.*$",""
                    $output += (Check-Command $pscommand $minlength $regexes $whitelist 0)
                }
            }
            ElseIf ($event.id -eq 4104){
                # This section requires PowerShell command logging for event 4104 , which seems to be default with 
                # Windows 10, but may not not the default with older Windows versions (which may log the script 
                # block but not the command that launched it). 
                # Caveats included because more testing of various Windows versions is needed
                # 
                # If the command itself is not being logged:
                # Add the following to \Windows\System32\WindowsPowerShell\v1.0\profile.ps1
                # $LogCommandHealthEvent = $true
                # $LogCommandLifecycleEvent = $true
                #
                # See the following for more information:
                #
                # https://logrhythm.com/blog/powershell-command-line-logging/
                # http://hackerhurricane.blogspot.com/2014/11/i-powershell-logging-what-everyone.html
                #
                # Thank you: @heinzarelli and @HackerHurricane
                # 
                # The command's path is $eventxml.Event.EventData.Data[4]
                #
                # Blank path means it was run as a commandline. CLI parsing is *much* simpler than
                # script parsing. See Revoke-Obfuscation for parsing the script blocks:
                # 
                # https://github.com/danielbohannon/Revoke-Obfuscation
                #
                # Thanks to @danielhbohannon and @Lee_Holmes
                #
                # This ignores scripts and grabs PowerShell CLIs
                if (-not ($eventxml.Event.EventData.Data[4]."#text")){
                      $pscommand=$eventXML.Event.EventData.Data[2]."#text"
                      $output += (Check-Command $pscommand 500 $regexes $whitelist 0)
                }
            }
        }
        ElseIf ($logname -eq "Sysmon"){
        #@{logname="Microsoft-Windows-Sysmon/Operational";id=1} | %{$_.Properties[11].Value}| sort -Unique
        #get-winevent @{logname="Microsoft-Windows-Sysmon/Operational";id=1} | % {$_.Properties[11].Value}| Sort-Object -unique
        #Get-WinEvent @{logname="Microsoft-Windows-Sysmon/Operational";id=7}|fl
            # Check command lines
            if ($event.id -eq 1){
                #get-winevent @{logname="Microsoft-Windows-Sysmon/Operational";id=1} | % {$_.Properties[4].Value}
                $commandline=$eventXML.Event.EventData.Data[4]."#text"
                # Remove "Command Line: " from the $commandline
                #$commandline= $commandline -Replace "^Command Line:",""
                #$commandline
                $output += (Check-Command $commandline $minlength $regexes $whitelist 0)
            }
            # Check for unsigned EXEs/DLLs:
            ElseIf ($event.id -eq 7){
                if ($eventXML.Event.EventData.Data[6]."#text" -eq "false"){
                    $image=$eventXML.Event.EventData.Data[3]."#text"
                    $imageload=$eventXML.Event.EventData.Data[4]."#text"
                    # $hash=$eventXML.Event.EventData.Data[5]."#text"
                    $pscommand=  "  - Image: " + $image + "`r`n"
                    $pscommand+= "  - ImageLoaded: " + $imageload + "`r`n"      
                    $output+= "  Unsigned image:`r`n"
                    $output+= $pscommand
                 }
             }
        }
        if ($output){
            $event.TimeCreated 
            $output
            ""
        }
    }
    if ($failedlogons -gt $maxfailedlogons){
         "High number of failed logons in the security event log: " + $failedlogons 
    }
} 

function Check-Options($file, $log)
{
    $log_error="Unknown and/or unsupported log type"
    $logname=""
    # Checks the command line options, return logname to parse
    if($file -eq ""){ # No filename provided, parse local logs
        if(($log -eq "") -or ($log -eq "Security")){ # Parse the security log if no log was selected
            $logname="Security"
        }
        ElseIf ($log -eq "System"){
            $logname="System"
        }
        ElseIf ($log -eq "Application"){
            $logname="Application"
        }
        ElseIf ($log -eq "Sysmon"){
            $logname="Sysmon"
        }
            ElseIf ($log -eq "Powershell"){
            $logname="Powershell"
        }
        Else{
            write-host $log_error
            exit 1
        }    
    }
    else{ # Filename provided, check if it exists:
        if (Test-Path $file){ # File exists. Todo: verify it is an evtx file. 
            # Get-WinEvent will generate this error for non-evtx files: "...file does not appear to be a valid log file. 
            # Specify only .evtx, .etl, or .evt filesas values of the Path parameter."
            #
            # Check the LogName of the first event
            try{
                $event=Get-WinEvent -path $file -max 1 -ErrorAction Stop
            }
            catch
            {
                Write-Host "Get-WinEvent error: " $_.Exception.Message "`n"
                Write-Host "Exiting...`n"
                exit
            }
            switch ($event.LogName){
                "Security"    {$logname="Security"}
                "System"      {$logname="System"}
                "Application" {$logname="Application"}
                "Microsoft-Windows-AppLocker*"   {$logname="Applocker"}
                "Microsoft-Windows-PowerShell/Operational"   {$logname="Powershell"}
                "Microsoft-Windows-Sysmon/Operational"   {$logname="Sysmon"}
                default       {"Logic error 3, should not reach here...";Exit 1}
            }
        }
        else{ # Filename does not exist, exit
            Write-host "Error: no such file. Exiting..."
            exit 1
        }
    }
    return $logname
}

function Create-Filter($file, $logname)
{
    # Return the Get-Winevent filter 
    #
    $sys_events="7030,7036,7045"
    $sec_events="4688,4720,4728,4732,4625"
    $app_events="2"
    $applocker_events="8003,8004,8006,8007"
    $powershell_events="4103,4104"
    $sysmon_events="1,7"
    if ($file -ne ""){
        switch ($logname){
            "Security"    {$filter="@{path=""$file"";ID=$sec_events}"}
            "System"      {$filter="@{path=""$file"";ID=$sys_events}"}
            "Application" {$filter="@{path=""$file"";ID=$app_events}"}
            "Applocker"   {$filter="@{path=""$file"";ID=$applocker_events}"}
            "Powershell"  {$filter="@{path=""$file"";ID=$powershell_events}"}
            "Sysmon"      {$filter="@{path=""$file"";ID=$sysmon_events}"}
            default       {"Logic error 1, should not reach here...";Exit 1}
        }
    }
    else{
        switch ($logname){
            "Security"    {$filter="@{Logname=""Security"";ID=$sec_events}"}
            "System"      {$filter="@{Logname=""System"";ID=$sys_events}"}
            "Application" {$filter="@{Logname=""Application"";ID=$app_events}"}
            "Applocker"   {$filter="@{logname=""Microsoft-Windows-AppLocker"";ID=$applocker_events}"}
            "Powershell"  {$filter="@{logname=""Microsoft-Windows-PowerShell/Operational"";ID=$powershell_events}"}
            "Sysmon"      {$filter="@{logname=""Microsoft-Windows-Sysmon/Operational"";ID=$sysmon_events}"}
            default       {"Logic error 2, should not reach here...";Exit 1}
        }
    }
    return $filter
}


function Check-Command($commandline,$minlength,$regexes,$whitelist,$servicecmd){
    $text=""
    $base64=""
    # Check to see if command is whitelisted
    foreach ($entry in $whitelist) {
        if ($commandline -Match $entry.regex) {
            # Command is whitelisted, return nothing
            return
        }
    }
    #$cmdlength=$commandline.length
    #if ($cmdlength -gt $minlength){
    if ($commandline.length -gt $minlength){
        $text += "   - Long Command Line: greater than $minlength bytes`n"
    }
    $text += (Check-Obfu $commandline)
    $text += (Check-Regex $commandline $regexes 0)
    # Check for base64 encoded function, decode and print if found
    # This section is highly use case specific, other methods of base64 encoding and/or compressing may evade these checks
    if ($commandline -Match "\-enc.*[A-Za-z0-9/+=]{100}"){
        $base64= $commandline -Replace "^.* \-Enc(odedCommand)? ",""
    }
    ElseIf ($commandline -Match ":FromBase64String\("){
        $base64 = $commandline -Replace "^.*:FromBase64String\(\'*",""
        $base64 = $base64 -Replace "\'.*$",""
    }
    if ($base64){
        if ($commandline -Match "Compression.GzipStream.*Decompress"){
            # Metasploit-style compressed and base64-encoded function. Uncompress it.
            $decoded=New-Object IO.MemoryStream(,[Convert]::FromBase64String($base64))
            $uncompressed=(New-Object IO.StreamReader(((New-Object IO.Compression.GzipStream($decoded,[IO.Compression.CompressionMode]::Decompress))),[Text.Encoding]::ASCII)).ReadToEnd()
            $text += "  Decoded/decompressed Base64:" + $uncompressed 
            $text += "   - Base64-encoded and compressed function`n"
        }
        else{
            $decoded = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($base64))
            $text += "  Decoded Base64:" + $decoded + "`n"
            $text += "   - Base64-encoded function`n"
            $text += (Check-Obfu $decoded)
            $text += (Check-Regex $decoded $regexes 0)
            #foreach ($regex in $regexes){
            #    if ($regex.Type -eq 0) { # Image Path match
            #        if ($decoded -Match $regex.regex) {
            #            $text += "   - " + $regex.String + "`n"
            #        }
            #    }
            #}
        }
    }
    if ($text){
        if ($servicecmd){
            return "  Service File Name: $commandline`n" + $text
        }
        Else{
            return "  Command Line: $commandline`n" + $text
        }
    }
    return ""
}    

function Check-Regex($string,$regexes,$type){
    $regextext="" # Local variable for return output 
    if ($regex.Type -eq $type) { # Type is 0 for Commands, 1 for services. Set in regexes.csv
        if ($string -Match $regex.regex) {
           $regextext += "   - " + $regex.String + "`n"
        }
    }
    return $regextext
}

function Check-Obfu($string){
    # Check for special characters in the command. Inspired by Invoke-Obfuscation: https://twitter.com/danielhbohannon/status/778268820242825216
    # There are many ways to do this, including regex. Need a way that doesn't kill the CPU. 
    #
    $obfutext=""       # Local variable for return output
    $minpercent=.75    # minimum percentage of alphanumeric and common symbols
    $maxbinary=.25 # Maximum percentage of zeros and ones
    $lowercasestring=$string.ToLower()
    $length=$lowercasestring.length
    $noalphastring = $lowercasestring -replace "[a-z0-9/\;:|.]"
    $nobinarystring = $lowercasestring -replace "[01]" # To catch binary encoding
    # Calculate the percent alphanumeric/common symbols
    if ($length -gt 0){
        $percent=(($length-$noalphastring.length)/$length)    
        if ($percent -lt $minpercent){
            $percent = "{0:P0}" -f $percent      # Convert to a percent
            $obfutext += "   - Possible command obfuscation: only $percent alphanumeric and common symbols`n"
        }
        # Calculate the percent of binary characters
        #$percent=(($length-$nobinarystring.length/$length)/$length)   
        $percent=(($nobinarystring.length-$length/$length)/$length)
        $binarypercent = 1-$percent
        if ($binarypercent -gt $maxbinary){
            #$binarypercent = 1-$percent
            $binarypercent = "{0:P0}" -f $binarypercent      # Convert to a percent
            $obfutext += "   - Possible command obfuscation: $binarypercent zeroes and ones (possible numeric or binary encoding)`n"
        }
    }
    return $obfutext
}

function Remove-Spaces($string){
    # Changes this:   Application       : C:\Program Files (x86)\Internet Explorer\iexplore.exe
    #      to this: Application: C:\Program Files (x86)\Internet Explorer\iexplore.exe
    $string = $string.trim() -Replace "\s+:",":"
    return $string
}

. Main

