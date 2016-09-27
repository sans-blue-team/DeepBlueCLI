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

# DeepBlueCLI 0.1 Beta
# Eric Conrad, Backshore Communications, LLC
# deepblue <at> backshore <dot> net
# Twitter: @eric_conrad
# http://ericconrad.com
#
[CmdletBinding()]   # gives access to -Verbose and -Debug flags
param ([string]$file=$env:file,[string]$log=$env:log)

function Main {
    $propertiesArray = @()
    $text="" # Temporary scratch pad variable to hold output text
    $minlength=1000 # Minimum length of command line to alert
    # Load cmd match regexes from csv file, ignore comments
    $regexes = Get-Content ".\regexes.txt" | Select-String '^[^#]' | ConvertFrom-Csv
    # Load cmd whitelist regexes from csv file, ignore comments
    $whitelist = Get-Content ".\whitelist.txt" | Select-String '^[^#]' | ConvertFrom-Csv
    $logname=Check-Options $file $log
    Write-Verbose "Processing the $logname log...`n"
    $filter=Create-Filter $file $logname
    $failedlogons=0 # Count of failed logons (Security event 4625)
    $maxfailedlogons=100 # Alert after this many failed logons
    # Get the events:
    try{
        # Temporarily ignore Verbosity so Get-WinEvent doesn't print extra data
        $OldVP = $VerbosePreference
        $VerbosePreference = "SilentlyContinue"
        $events = iex "Get-WinEvent -FilterHashtable $filter -ErrorAction Stop"
        $VerbosePreference = $OldVP
    }
    catch {
        Write-Host "Get-WinEvent -FilterHashtable $filter -ErrorAction Stop"
    	Write-Host "Get-WinEvent error: " $_.Exception.Message "`n"
        Write-Host "Exiting...`n"
        exit
    }
    ForEach ($event in $events) {
        $output = @{}   # output contains key/val of event properties analyzed
        $eventXML = [xml]$event.ToXml()
        if ($logname -eq "Security"){
            if ($event.id -eq 4688){
                # A new process has been created. (Command Line Logging)
                $commandline=$eventXML.Event.EventData.Data[8]."#text"
                try {
                    $output += (Check-Command $commandline $minlength $regexes $whitelist 0)
                } catch [System.Management.Automation.RuntimeException] {Write-Debug $_}
            }
            ElseIf ($event.id -eq 4720){
                # A user account was created.
                $username=$eventXML.Event.EventData.Data[0]."#text"
                $securityid=$eventXML.Event.EventData.Data[2]."#text"
                $desc = "New user created"
                Write-Verbose "  $desc"
                Write-Verbose "    - Username: $username"
                Write-Verbose "    - User SID: $securityid"
                $output += @{
                    "Username" = $username;
                    "SID" = $securityid;
                    "Message" = $desc
                }
            }
            ElseIf(($event.id -eq 4728) -or ($event.id -eq 4732)){
                # A member was added to a security-enabled (global|local) group.
                $groupname=$eventXML.Event.EventData.Data[2]."#text"
                # Check if group is Administrators, may later expand to all groups
                if ($groupname -eq "Administrators"){
                    $username=$eventXML.Event.EventData.Data[0]."#text"
                    $securityid=$eventXML.Event.EventData.Data[1]."#text"
                    switch ($event.id){
                        4728 {$desc = "User added to global $groupname group"}
                        4732 {$desc = "User added to local $groupname group"}
                    }
                    Write-Verbose "  $desc"
                    Write-Verbose "    - Username: $username"
                    Write-Verbose "    - User SID: $securityid"
                    $output += @{
                        "Username" = $username;
                        "SID" = $securityid;
                        "Group" = $groupname;
                        "Message" = $desc
                    }
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
                    Write-Verbose "  A service was installed on the system: $servicename"
                    $output += @{"Message" = "Service created: $text"}
                    $output += @{"Service Name" = $servicename}
                }
                # Check for suspicious cmd
                $commandline=$eventXML.Event.EventData.Data[1]."#text"
                try {
                    $output += (Check-Command $commandline $minlength $regexes $whitelist 1)
                } catch [System.Management.Automation.RuntimeException] {Write-Debug $_}
            }
            ElseIf ($event.id -eq 7030){
                # The ... service is marked as an interactive service.  However, the system is configured
                # to not allow interactive services.  This service may not function properly.
                $servicename=$eventXML.Event.EventData.Data."#text"
                Write-Verbose "  Interactive service warning, service name: $servicename`n"
                # Check for suspicious service name
                try {
                    $output += (Check-Command $servicename $regexes 1)
                } catch [System.Management.Automation.RuntimeException] {Write-Debug $_}
            }
            ElseIf ($event.id -eq 7036){
                # The ... service entered the stopped|running state.
                $servicename=$eventXML.Event.EventData.Data[0]."#text"
                # check for suspicious service name
                $text = (Check-Regex $servicename $regexes 1)
                if ($text){
                    Write-Verbose "The '$servicename' service entered the stopped|running state"
                    $output += @{"Message" = $event.Message + $text}
                }
            }
        }
        ElseIf ($logname -eq "Application"){
            if (($event.id -eq 2) -and ($event.Providername -eq "EMET")){
                # EMET Block
                Write-Verbose "  EMET Block found"
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
                    $output += @{"Message" = $message}
                    $output += @{"Application" = $application}
                    $output += @{"Username" = $username}
                }
                Else{
                    # If the message is blank: EMET is not installed locally.
                    # This occurs when parsing remote event logs sent from systems with EMET installed
                    Write-Warning "EMET Message field is blank. Install EMET locally to see full details of this alert"
                }
            }
        }
        ElseIf ($logname -eq "Applocker"){
            if ($event.id -eq 8004){
                # ...was prevented from running.
                $output += @{"Applocker Block" = $event.message}
                Write-Verbose $event.message
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
                    try {
                        $output += (Check-Command $pscommand $minlength $regexes $whitelist 0)
                        Write-Verbose "  Suspicious PowerShell command: $pscommand"
                    } catch [System.Management.Automation.RuntimeException] {Write-Debug $_}
                }
            }
            # Ignoring PowerShell event 4014 for now, DeepBlueCLI currently detects its own strings, and hilarity ensures
            #ElseIf ($event.id -eq 4104){
            #  $pscommand=$eventXML.Event.EventData.Data[2]."#text"
            #  $output += (Check-Command $pscommand 9999 $regexes $whitelist 0)
            #}
        }
        if ($output.Count -gt 0){
            $output += @{"Time Created" = $event.TimeCreated}
            $propertiesArray += $output
        }
    }
    if ($failedlogons -gt $maxfailedlogons){
         Write-Warning "High number of failed logons in the security event log: $failedlogons"
    }
    $objAry = @()
    foreach ($properties in $propertiesArray) {
        $objAry += (New-Object -Type PSCustomObject -Property $properties)
    }
    Write-Output $objAry    # write the array of objects to the main pipeline so we can pass them to other functions
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
                "Microsoft-Windows-PowerShell/Operational"   {$logname="PowerShell"}
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
    # Return the Get-Winevent -FilterHashtable filter
    #
    $sys_events="7030,7036,7045"
    $sec_events="4688,4720,4728,4732,4625"
    $app_events="2"
    $applocker_events="8003,8004,8006,8007"
    $powershell_events="4103"
    if ($file -ne ""){
        switch ($logname){
            "Security"    {$filter="@{path=""$file"";ID=$sec_events}"}
            "System"      {$filter="@{path=""$file"";ID=$sys_events}"}
            "Application" {$filter="@{path=""$file"";ID=$app_events}"}
            "Applocker"   {$filter="@{path=""$file"";ID=$applocker_events}"}
            "PowerShell"  {$filter="@{path=""$file"";ID=$powershell_events}"}
            default       {"Logic error 1, should not reach here...";Exit 1}
        }
    }
    else{
        switch ($logname){
            "Security"    {$filter="@{Logname=""Security"";ID=$sec_events}"}
            "System"      {$filter="@{Logname=""System"";ID=$sys_events}"}
            "Application" {$filter="@{Logname=""Application"";ID=$app_events}"}
            "Applocker"   {$filter="@{logname=""Microsoft-Windows-AppLocker"";ID=$applocker_events}"}
            "PowerShell"  {$filter="@{logname=""Microsoft-Windows-PowerShell/Operational"";ID=$powershell_events}"}
            default       {"Logic error 2, should not reach here...";Exit 1}
        }
    }
    return $filter
}


function Check-Command($commandline,$minlength,$regexes,$whitelist,$servicecmd){
    $text = @()
    $base64=""
    # Check to see if command is whitelisted
    foreach ($entry in $whitelist) {
        if ($commandline -Match $entry.regex) {
            # Command is whitelisted, return nothing
            return $false
        }
    }
    #$cmdlength=$commandline.length
    #if ($cmdlength -gt $minlength){
    if ($commandline.length -gt $minlength){
        $text += "   - Long Command Line: greater than $minlength bytes`n"
    }
    $obfu = Check-Obfu $commandline
    # check for suspicious commandline entries
    $regex = Check-Regex $commandline $regexes 0
    if ($obfu -ne "") {$text += $obfu}
    if ($regex -ne "") {$text += $regex}
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
            # check for suspicious commandline entries
            $regex = Check-Regex $commandline $regexes 0
            if ($regex -ne "") {$text += $regex}
            #foreach ($regex in $regexes){
            #    if ($regex.Type -eq 0) { # Image Path match
            #        if ($decoded -Match $regex.regex) {
            #            $text += "   - " + $regex.String + "`n"
            #        }
            #    }
            #}
        }
    }
    if ($text.length -gt 0){
        if ($servicecmd){$type = "Service File Name"}
        Else{$type = "Command Line"}
        $properties = @{
            "Type" = $type;
            "Command" = $commandline;
            "Message" = $text
        }
        return $properties
    }
    return $false
}

function Check-Regex($string,$regexes,$type){
    $regexmatch = @()
    foreach ($regex in $regexes){
        if ($regex.Type -eq $type) { # Type is 0 for Commands, 1 for services. Set in regexes.csv
            if ($string -Match $regex.regex) {
               $regexmatch += "   - " + $regex.String + "`n"
            }
        }
    }
    return $regexmatch
}

function Check-Obfu($string){
    # Check how many "+" characters are in the command. Inspired by Invoke-Obfuscation: https://twitter.com/danielhbohannon/status/778268820242825216
    # There are many ways to do this, including regex. Need a way that doesn't kill the CPU. This works, but isn't super concise. There is probably a
    # better way.
    #
    # Plan to add a loop to go through more characters.
    $obfutext="" # Local variable for return output
    $maxchars=25
    # Remove the "+" characters
    $string2 = $string -replace "\+"
    # Compare the length
    if (($string.length - $string2.length) -gt $maxchars){
        $obfutext += "   - Possible command obfuscation: greater than $maxchars + characters`n"
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

