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

# DeepBlueCLI 3.0
# Eric Conrad, Backshore Communications, LLC
# deepblue <at> backshore <dot> net
# Twitter: @eric_conrad
# http://ericconrad.com
#

param ([string]$file=$env:file,[string]$log=$env:log)

function Main {
    # Set up the global variables
    $text="" # Temporary scratch pad variable to hold output text
    $minlength=1000 # Minimum length of command line to alert
    # Load cmd match regexes from csv file, ignore comments
    $regexes = Get-Content ".\regexes.txt" | Select-String '^[^#]' | ConvertFrom-Csv
    # Load cmd safelist regexes from csv file, ignore comments
    $safelist = Get-Content ".\safelist.txt" | Select-String '^[^#]' | ConvertFrom-Csv 
    $logname=Check-Options $file $log
    #"Processing the " + $logname + " log..."
    $filter=Create-Filter $file $logname
    # Password guessing/spraying variables:
    $maxfailedlogons=5 # Alert after this many failed logons
    $failedlogons=@{}   # HashTable of failed logons per user
    $totalfailedlogons=0 # Total number of failed logons (for all accounts)
    $totalfailedaccounts=0 # Total number of accounts with a failed logon
    # Track total Sensitive Privilege Use occurrences
    $totalsensprivuse=0
    $maxtotalsensprivuse=4
    # Admin logon variables:
    $totaladminlogons=0  # Total number of logons with SeDebugPrivilege
    $maxadminlogons=10   # Alert after this many admin logons
    $adminlogons=@{}     # HashTable of admin logons
    $multipleadminlogons=@{} #Hashtable to track multiple admin logons per account
    $alert_all_admin=0   # Set to 1 to alert every admin logon (set to 0 disable this)
    # Obfuscation variables:
    $minpercent=.65  # minimum percentage of alphanumeric and common symbols
    $maxbinary=.50   # Maximum percentage of zeros and ones to detect binary encoding
    # Password spray variables:
    $passspraytrack = @{}
    $passsprayuniqusermax = 6
    $passsprayloginmax = 6
    $passsprayuniqaccounts = 0
    # Sysmon variables:
    # Check for unsigned EXEs/DLLs. This can be very chatty, so it's disabled. 
    # Set $checkunsigned to 1 to enable:
    $checkunsigned = 0
    #
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
        # Custom reporting object:
        $obj = [PSCustomObject]@{
            Date    = $event.TimeCreated
            Log     = $logname
            EventID = $event.id
            Message = $event.message
            Results = ""
            Command = ""
            Decoded = ""
        }
        $eventXML = [xml]$event.ToXml()
        $servicecmd=0 # CLIs via service creation get extra checks, this defaults to 0 (no extra checks)
        if ($logname -eq "Security"){
            if ($event.id -eq 4688){
                # A new process has been created. (Command Line Logging)
                $commandline=$eventXML.Event.EventData.Data[8]."#text" # Process Command Line
                $creator=$eventXML.Event.EventData.Data[13]."#text"    # Creator Process Name
                if ($commandline){
                    Check-Command -EventID 4688
                }
            }
            ElseIf ($event.id -eq 4672){ 
                # Special privileges assigned to new logon (possible admin access)
                $username=$eventXML.Event.EventData.Data[1]."#text"
                $domain=$eventXML.Event.EventData.Data[2]."#text"
                $securityid=$eventXML.Event.EventData.Data[3]."#text"
                $privileges=$eventXML.Event.EventData.Data[4]."#text"
                if ($privileges -Match "SeDebugPrivilege") { #Admin account with SeDebugPrivilege
                    if ($alert_all_admin){ # Alert for every admin logon
                        $obj.Message = "Logon with SeDebugPrivilege (admin access)" 
                        $obj.Results = "Username: $username`n"
                        $obj.Results += "Domain: $domain`n"
                        $obj.Results += "User SID: $securityid`n"
                        $obj.Results += "Privileges: $privileges"
                        Write-Output $obj
                    }
                    # Track User SIDs used during admin logons (can track one account logging into multiple systems)
                    $totaladminlogons+=1
                    if($adminlogons.ContainsKey($username)){ 
                        $string=$adminlogons.$username
                        if (-Not ($string -Match $securityid)){ # One username with multiple admin logon SIDs 
                            $multipleadminlogons.Set_Item($username,1)
                            $string+=" $securityid"
                            $adminlogons.Set_Item($username,$string)
                        }
                    }
                    Else{
                        $adminlogons.add($username,$securityid) 

                        #$adminlogons.$username=$securityid
                    }
                    #$adminlogons.Set_Item($username,$securitysid)
                    #$adminlogons($username)+=($securitysid)
                }
                # This unique privilege list is used by Mimikatz 2.2.0
                # Disabling due to false-positive with MS Exchange.
#                If ($privileges -Match "SeAssignPrimaryTokenPrivilege" `
#                        -And $privileges -Match "SeTcbPrivilege" `
#                        -And $privileges -Match "SeSecurityPrivilege" `
#                        -And $privileges -Match "SeTakeOwnershipPrivilege" `
#                        -And $privileges -Match "SeLoadDriverPrivilege" `
#                        -And $privileges -Match "SeBackupPrivilege" `
#                        -And $privileges -Match "SeRestorePrivilege" `
#                        -And $privileges -Match "SeDebugPrivilege" `
#                        -And $privileges -Match "SeAuditPrivilege" `
#                        -And $privileges -Match "SeSystemEnvironmentPrivilege" `
#                        -And $privileges -Match "SeImpersonatePrivilege" `
#                        -And $privileges -Match "SeDelegateSessionUserImpersonatePrivilege") {
#                    $obj.Message = "Mimikatz token::elevate Privilege Use" 
#                    $obj.Results = "Username: $username`n"
#                    $obj.Results += "Domain: $domain`n"
#                    $obj.Results += "User SID: $securityid`n"
#                    $pprivileges = $privileges -replace "`n",", " -replace "\s+"," "
#                    $obj.Results += "Privileges: $pprivileges"
#                    Write-Output($obj)
#                }
                # This unique privilege list is used by Metasploit exploit/windows/smb/psexec (v5.0.4 tested)
#               # Disabling due to false-positive with MS Exchange Server
#                If ($privileges -Match "SeSecurityPrivilege" `
#                        -And $privileges -Match "SeBackupPrivilege" `
#                        -And $privileges -Match "SeRestorePrivilege" `
#                        -And $privileges -Match "SeTakeOwnershipPrivilege" `
#                        -And $privileges -Match "SeDebugPrivilege" `
#                        -And $privileges -Match "SeSystemEnvironmentPrivilege" `
#                        -And $privileges -Match "SeLoadDriverPrivilege" `
#                        -And $privileges -Match "SeImpersonatePrivilege" `
#                        -And $privileges -Match "SeDelegateSessionUserImpersonatePrivilege") {
#                    $obj.Message = "Metasploit psexec Privilege Use" 
#                    $obj.Results = "Username: $username`n"
#                    $obj.Results += "Domain: $domain`n"
#                    $obj.Results += "User SID: $securityid`n"
#                    $pprivileges = $privileges -replace "`n",", " -replace "\s+"," "
#                    $obj.Results += "Privileges: $pprivileges"
#                    Write-Output($obj)
#                }
            }
            ElseIf ($event.id -eq 4720){
                # A user account was created.
                $username=$eventXML.Event.EventData.Data[0]."#text"
                $securityid=$eventXML.Event.EventData.Data[2]."#text"
                $obj.Message = "New User Created"
                $obj.Results = "Username: $username`n"
                $obj.Results += "User SID: $securityid`n"
                Write-Output $obj
            }
            ElseIf(($event.id -eq 4728) -or ($event.id -eq 4732) -or ($event.id -eq 4756)){
                # A member was added to a security-enabled (global|local|universal) group.
                $groupname=$eventXML.Event.EventData.Data[2]."#text"
                # Check if group is Administrators, may later expand to all groups
                if ($groupname -eq "Administrators"){
                    $username=$eventXML.Event.EventData.Data[0]."#text"
                    $securityid=$eventXML.Event.EventData.Data[1]."#text"
                    switch ($event.id){
                        4728 {$obj.Message = "User added to global $groupname group"}
                        4732 {$obj.Message = "User added to local $groupname group"}
                        4756 {$obj.Message = "User added to universal $groupname group"}
                    }
                    $obj.Results = "Username: $username`n"
                    $obj.Results += "User SID: $securityid`n"
                    Write-Output $obj
                }
            }
            ElseIf($event.id -eq 4625){
                # An account failed to log on.
                # Requires auditing logon failures
                # https://technet.microsoft.com/en-us/library/cc976395.aspx
                $totalfailedlogons+=1
                $username=$eventXML.Event.EventData.Data[5]."#text"
                if($failedlogons.ContainsKey($username)){
                    $count=$failedlogons.Get_Item($username)
                    $failedlogons.Set_Item($username,$count+1)
                }
                Else{
                    $failedlogons.Set_Item($username,1)
                    $totalfailedaccounts+=1
                }
            }
            ElseIf($event.id -eq 4673){
                # Sensitive Privilege Use (Mimikatz)
                $totalsensprivuse+=1
                # use -eq here to avoid multiple log notices
                if ($totalsensprivuse -eq $maxtotalsensprivuse) {
                    $obj.Message = "Sensitive Privilege Use Exceeds Threshold"
                    $obj.Results = "Potentially indicative of Mimikatz, multiple sensitive privilege calls have been made.`n"

                    $username=$eventXML.Event.EventData.Data[1]."#text"
                    $domainname=$eventXML.Event.EventData.Data[2]."#text"

                    $obj.Results += "Username: $username`n"
                    $obj.Results += "Domain Name: $domainname`n"
                    Write-Output $obj
                }
            }
            ElseIf($event.id -eq 4674){
                # An operation was attempted on a privileged object.
                if ($event.Message){
                    # Message is a blob of text that looks like this:
                    #########################################################
                    # An operation was attempted on a privileged object.
                    #
                    # Subject:
                    # 	Security ID:		SEC504STUDENT\Sec504
                    # 	Account Name:		Sec504
                    # 	Account Domain:		SEC504STUDENT
                    # 	Logon ID:		
                    #
                    # Object:
                    # 	Object Server:	SC Manager
                    # 	Object Type:	SERVICE OBJECT
                    # 	Object Name:	nginx
                    # 	Object Handle:	
                    #
                    # Process Information:
                    # 	Process ID:	0x21c
                    # 	Process Name:	C:\Windows\System32\services.exe
                    #
                    # Requested Operation:
                    # 	Desired Access:	WRITE_DAC
                    #
                    # 	Privileges:		SeSecurityPrivilege
                    $array = $event.message -split '\n' # Split each line of the message into an array
                    $text = $array[0]
                    $application = Remove-Spaces($array[3])
                    $user = Remove-Spaces(($array[4] -split ':')[1])
                    $service = Remove-Spaces(($array[11] -split ':')[1])
                    $application = Remove-Spaces(($array[16] -split ':	')[1])
                    $accessreq = Remove-Spaces(($array[19] -split ':')[1])

                    if ($application.ToUpper() -Eq "C:\WINDOWS\SYSTEM32\SERVICES.EXE" `
                            -And $accessreq.ToUpper() -Match "WRITE_DAC") {
                        $obj.Message="Possible Hidden Service Attempt"
                        $obj.Command = ""
                        $obj.Results = "User requested to modify the Dynamic Access Control (DAC) permissions of a service, possibly to hide it from view.`n"
                        $obj.Results += "User: $user`n"
                        $obj.Results += "Target service: $service`n"
                        $obj.Results += "Desired Access: $accessreq`n"
                        Write-Output $obj
                    }
                }
            }
            ElseIf($event.id -eq 4648){
                # A logon was attempted using explicit credentials.
                $username=$eventXML.Event.EventData.Data[1]."#text"
                $hostname=$eventXML.Event.EventData.Data[2]."#text"
                $targetusername=$eventXML.Event.EventData.Data[5]."#text"
                $sourceip=$eventXML.Event.EventData.Data[12]."#text"

                # For each #4648 event, increment a counter in $passspraytrack. If that counter exceeds 
                # $passsprayloginmax, then check for $passsprayuniqusermax also exceeding threshold and raise
                # a notice.
                if ($passspraytrack[$targetusername] -eq $null) {
                    $passspraytrack[$targetusername] = 1
                } else {
                    $passspraytrack[$targetusername] += 1
                }
                if ($passspraytrack[$targetusername] -gt $passsprayloginmax) {
                    # This user account has exceedd the threshoold for explicit logins. Identify the total number
                    # of accounts that also have similar explicit login patterns.
                    $passsprayuniquser=0
                    foreach($key in $passspraytrack.keys) {
                        if ($passspraytrack[$key] -gt $passsprayloginmax) { 
                            $passsprayuniquser+=1
                        }
                    }
                    if ($passsprayuniquser -gt $passsprayuniqusermax) {
                        $usernames=""
                        foreach($key in $passspraytrack.keys) {
                            $usernames += $key
                            $usernames += " "
                            $passsprayuniqaccounts += 1
                        }
                        $obj.Message = "Distributed Account Explicit Credential Use (Password Spray Attack)"
                        $obj.Results = "The use of multiple user account access attempts with explicit credentials is "
                        $obj.Results += "an indicator of a password spray attack.`n"
                        $obj.Results += "Target Usernames: $usernames`n"
                        $obj.results += "Unique accounts sprayed: $passsprayuniqaccounts`n"
                        $obj.Results += "Accessing Username: $username`n"
                        $obj.Results += "Accessing Host Name: $hostname`n"
                        Write-Output $obj
                        $passspraytrack = @{} # Reset
                    }
                }
            }
            ElseIf ($event.id -eq 1102){ 
                # The Audit log file was cleared.
                if ($event.Message){ 
                    # Security 1102 Message is a blob of text that looks like this:
                    # The audit log was cleared.
                    # Subject:
                    # 	Security ID:	SEC504STUDENT\Sec504
                    # 	Account Name:	Sec504
                    # 	Domain Name:	SEC504STUDENT
                    # 	Logon ID:	0x257CD                    
                    $array = $event.message -split '\n' # Split each line of the message into an array
                    $user = Remove-Spaces($array[3])
                }
                $obj.Message = "Audit Log Clear"
                $obj.Results = "The Audit log was cleared.`n"
                $obj.Results += $user
                Write-Output $obj
            }
        }
        ElseIf ($logname -eq "System"){
            if ($event.id -eq 7045){
                # A service was installed in the system.
                $servicename=$eventXML.Event.EventData.Data[0]."#text"
                $commandline=$eventXML.Event.EventData.Data[1]."#text"
                # Check for suspicious service name
                $text = (Check-Regex $servicename 1)
                if ($text){
                    $obj.Message = "New Service Created"
                    $obj.Command = $commandline
                    $obj.Results = "Service name: $servicename`n"
                    $obj.Results +=$text 
                    Write-Output $obj
                }
                # Check for suspicious cmd
                if ($commandline){
                    $servicecmd=1 # CLIs via service creation get extra checks 
                    Check-Command -EventID 7045
                }
            }
            ElseIf ($event.id -eq 7030){
                # The ... service is marked as an interactive service.  However, the system is configured 
                # to not allow interactive services.  This service may not function properly.
                $servicename=$eventXML.Event.EventData.Data."#text"
                $obj.Message = "Interactive service warning"
                $obj.Results = "Service name: $servicename`n"
                $obj.Results += "Malware (and some third party software) trigger this warning"
                # Check for suspicious service name
                $servicecmd=1 # CLIs via service creation get extra check
                $obj.Results += (Check-Regex $servicename 1)
                Write-Output $obj
            }
            ElseIf ($event.id -eq 7036){
                # The ... service entered the stopped|running state.
                $servicename=$eventXML.Event.EventData.Data[0]."#text"
                $text = (Check-Regex $servicename 1)
                if ($text){
                    $obj.Message = "Suspicious Service Name"
                    $obj.Results = "Service name: $servicename`n"
                    $obj.Results += $text
                    Write-Output $obj
                }
            }
            ElseIf ($event.id -eq 7040){
                # The start type of the Windows Event Log service was changed from auto start to disabled.
                $servicename=$eventXML.Event.EventData.Data[0]."#text"
                $action = $eventXML.Event.EventData.Data[2]."#text"
                if ($servicename -ccontains "Windows Event Log") {
                    $obj.Results = "Service name: $servicename`n"
                    $obj.Results += $text
                    if ($action -eq "disabled") {
                        $obj.Message = "Event Log Service Stopped"
                        $obj.Results += "Selective event log manipulation may follow this event."
                    } elseIf ($action -eq "auto start") {
                        $obj.Message = "Event Log Service Started"
                        $obj.Results += "Selective event log manipulation may precede this event."
                    }
                    Write-Output $obj
                }
            }
            ElseIf ($event.id -eq 104){
                # The System log file was cleared.
                $obj.Message = "System Log Clear"
                $obj.Results = $event.message
                Write-Output $obj
            }
        } 
        ElseIf ($logname -eq "Application"){
            if (($event.id -eq 2) -and ($event.Providername -eq "EMET")){
                # EMET Block
                $obj.Message="EMET Block"
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
                    $text = $array[0]
                    $application = Remove-Spaces($array[3])
                    $command= $application -Replace "^Application: ",""
                    $username = Remove-Spaces($array[4])
                    $obj.Message="EMET Block"
                    $obj.Command = "$command"
                    $obj.Results = "$text`n"
                    $obj.Results += "$username`n" 
                }
                Else{
                    # If the message is blank: EMET is not installed locally.
                    # This occurs when parsing remote event logs sent from systems with EMET installed
                    $obj.Message="Warning: EMET Message field is blank. Install EMET locally to see full details of this alert"
                }
                Write-Output $obj
            }
        }  
        ElseIf ($logname -eq "Applocker"){
            if ($event.id -eq 8003){
                # ...was allowed to run but would have been prevented from running if the AppLocker policy were enforced.
                $obj.Message="Applocker Warning"
                $command = $event.message -Replace " was .*$",""
                $obj.Command=$command
                $obj.Results = $event.message
                Write-Output $obj
            }
            ElseIf ($event.id -eq 8004){ 
                $obj.Message="Applocker Block"
                # ...was prevented from running.
                $command = $event.message -Replace " was .*$",""
                $obj.Command=$command
                $obj.Results = $event.message
                Write-Output $obj
            }
        } 
        ElseIf ($logname -eq "PowerShell"){
            if ($event.id -eq 4103){
                $commandline= $eventXML.Event.EventData.Data[2]."#text"
                if ($commandline -Match "Host Application"){ 
                    # Multiline replace, remove everything before "Host Application = "
                    $commandline = $commandline -Replace "(?ms)^.*Host.Application = ",""
                    # Remove every line after the "Host Application = " line.
                    $commandline = $commandline -Replace "(?ms)`n.*$",""
                    if ($commandline){
                      Check-Command -EventID 4103
                    }
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
                      $commandline=$eventXML.Event.EventData.Data[2]."#text"
                      if ($commandline){
                          Check-Command -EventID 4104
                      }
                }
            }
        }
        ElseIf ($logname -eq "Sysmon"){
            # Check command lines
            if ($event.id -eq 1){
                if ($eventXML.Event.EventData.Data.Count -le 16){
                    $creator=$eventXML.Event.EventData.Data[14]."#text"
                    $commandline=$eventXML.Event.EventData.Data[10]."#text"
                }
                Else {
				    $creator=$eventXML.Event.EventData.Data[20]."#text"
				    $commandline=$eventXML.Event.EventData.Data[10]."#text"
				}
                if ($commandline){
                    Check-Command -EventID 1
                }
            }
            ElseIf ($event.id -eq 7){
                # Check for unsigned EXEs/DLLs:
                # This can be very chatty, so it's disabled. 
                # Set $checkunsigned to 1 (global variable section) to enable:
                if ($checkunsigned){
                    if ($event.Properties.Count -lt 14){
                    	if ($eventXML.Event.EventData.Data[6]."#text" -eq "false"){
                        	$obj.Message="Unsigned Image (DLL)"
                        	$image=$eventXML.Event.EventData.Data[3]."#text"
                        	$imageload=$eventXML.Event.EventData.Data[4]."#text"
                        	# $hash=$eventXML.Event.EventData.Data[5]."#text"
                        	$obj.Command=$imageload
                        	$obj.Results=  "Loaded by: $image"
                        	Write-Output $obj
                     	}
			        }
			        Else{   
				        if ($eventXML.Event.EventData.Data[11]."#text" -eq "false"){
                        	$obj.Message="Unsigned Image (DLL)"
                        	$image=$eventXML.Event.EventData.Data[4]."#text"
                        	$imageload=$eventXML.Event.EventData.Data[5]."#text"
                        	# $hash=$eventXML.Event.EventData.Data[10]."#text"
                        	$obj.Command=$imageload
                        	$obj.Results=  "Loaded by: $image"
                        	Write-Output $obj
                     	}		 
                    }
                 }
             }
             ElseIf ($event.id -eq 8){
                #Check remote thread (lsass activity, process migration, etc)
                $image=$eventXML.Event.EventData.Data[7]."#text"
                $user=$eventXML.Event.EventData.Data[12]."#text"
                $sourceimage=$eventXML.Event.EventData.Data[4]."#text"
                If ($image -Match "lsass.exe"){
                  $creatortext += "Remote thread to $image`n"
                  $obj.Message="Suspicious remote thread"
                  $imageload=$eventXML.Event.EventData.Data[7]."#text"
                  $obj.Command=$imageload
                  $obj.Results=  "Remote thread created to: $image from: $sourceimage by $user"
                  Write-Output $obj
                }
                ElseIf ($user -notmatch "SYSTEM"){
                  $creatortext += "Remote thread to $image`n"
                  $obj.Message="Suspicious remote thread"
                  $imageload=$eventXML.Event.EventData.Data[7]."#text"
                  $obj.Command=$imageload
                  $obj.Results=  "Remote thread created to: $image from: $sourceimage by $user"
                  Write-Output $obj
                }
            }

        }
	ElseIf ($logname -eq "WMI-Activity"){
        # Check commandlines for suspicious commands
            if ($event.id -eq 5861){
	        if($event.Message -match ".*CommandLineTemplate\s=\s(.*?);"){	
                    $command = $event.message
                    $obj.Message = "Suspicous WMI Event Filter"
	            $obj.Results += "Event Triggered Execution: WMI - T1546.003`n"
                    $obj.Results += $event.message
	            $obj.Command=$matches[0].Split("=")[1]
	            Write-Output $obj	  
	        }
            }
        }
    }
    # Iterate through admin logons hashtable (key is $username)
    foreach ($username in $adminlogons.Keys) {
        $securityid=$adminlogons.Get_Item($username) 
        if($multipleadminlogons.$username){
            $obj.Message="Multiple admin logons for one account"
            $obj.Results= "Username: $username`n"
            $obj.Results += "User SID Access Count: " + $securityid.split().Count
            $obj.EventId = 4672
            Write-Output $obj
        }
    }
    # Iterate through failed logons hashtable (key is $username)
    foreach ($username in $failedlogons.Keys) {
        $count=$failedlogons.Get_Item($username)
        if ($count -gt $maxfailedlogons){
            $obj.Message="High number of logon failures for one account"
            $obj.Results= "Username: $username`n"
            $obj.Results += "Total logon failures: $count"
            $obj.EventId = 4625
            Write-Output $obj
        }
    }
    # Password spraying:
    if (($totalfailedlogons -gt $maxfailedlogons) -and ($totalfailedaccounts -gt 1)) {
        $obj.Message="High number of total logon failures for multiple accounts"
        $obj.Results= "Total accounts: $totalfailedaccounts`n"
        $obj.Results+= "Total logon failures: $totalfailedlogons`n"
        $obj.EventId = 4625
        Write-Output $obj
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
                "Microsoft-Windows-AppLocker/EXE and DLL"   {$logname="Applocker"}
                "Microsoft-Windows-PowerShell/Operational"   {$logname="Powershell"}
                "Microsoft-Windows-Sysmon/Operational"   {$logname="Sysmon"}
		"Microsoft-Windows-WMI-Activity/Operational" {$logname="WMI-Activity"}
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
    $sys_events="7030,7036,7045,7040,104"
    $sec_events="4688,4672,4720,4728,4732,4756,4625,4673,4674,4648,1102"
    $app_events="2"
    $applocker_events="8003,8004,8006,8007"
    $powershell_events="4103,4104"
    $sysmon_events="1,7,8"
	$wmi_events="5861"
    if ($file -ne ""){
        switch ($logname){
            "Security"    {$filter="@{path=""$file"";ID=$sec_events}"}
            "System"      {$filter="@{path=""$file"";ID=$sys_events}"}
            "Application" {$filter="@{path=""$file"";ID=$app_events}"}
            "Applocker"   {$filter="@{path=""$file"";ID=$applocker_events}"}
            "Powershell"  {$filter="@{path=""$file"";ID=$powershell_events}"}
            "Sysmon"      {$filter="@{path=""$file"";ID=$sysmon_events}"}
	    "WMI-Activity"{$filter="@{path=""$file"";ID=$wmi_events}"}
            default       {"Logic error 1, should not reach here...";Exit 1}
        }
    }
    else{
        switch ($logname){
            "Security"    {$filter="@{Logname=""Security"";ID=$sec_events}"}
            "System"      {$filter="@{Logname=""System"";ID=$sys_events}"}
            "Application" {$filter="@{Logname=""Application"";ID=$app_events}"}
            "Applocker"   {$filter="@{logname=""Microsoft-Windows-AppLocker/EXE and DLL"";ID=$applocker_events}"}
            "Powershell"  {$filter="@{logname=""Microsoft-Windows-PowerShell/Operational"";ID=$powershell_events}"}
            "Sysmon"      {$filter="@{logname=""Microsoft-Windows-Sysmon/Operational"";ID=$sysmon_events}"}
	    "WMI-Activity"{$filter="@{logname=""Microsoft-Windows-WMI-Activity/Operational"";ID=$wmi_events}"}
            default       {"Logic error 2, should not reach here...";Exit 1}
        }
    }
    return $filter
}


function Check-Command(){

    Param($EventID)

    $text=""
    $base64=""
    # Check to see if command is safelisted
    foreach ($entry in $safelist) {
        if ($commandline -Match $entry.regex) {
            # Command is safelisted, return nothing
            return
        }
    }
    if ($commandline.length -gt $minlength){
        $text += "Long Command Line: greater than $minlength bytes`n"
    }
    $text += (Check-Obfu $commandline)
    $text += (Check-Regex $commandline 0)
    $text += (Check-Creator $commandline $creator)
    # Check for base64 encoded function, decode and print if found
    # This section is highly use case specific, other methods of base64 encoding and/or compressing may evade these checks
    if ($commandline -Match "\-enc.*[A-Za-z0-9/+=]{100}"){
        $base64= $commandline -Replace "^.* \-Enc(odedCommand)? ",""
    }
    ElseIf ($commandline -Match "\-En.*[A-Za-z0-9/+=]{100}"){
            $base64= $commandline -Replace "^.* \-En",""
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
            $obj.Decoded=$uncompressed
            $text += "Base64-encoded and compressed function`n"
        }
        else{
            $decoded = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($base64))
            $obj.Decoded=$decoded
            $text += "Base64-encoded function`n"
            $text += (Check-Obfu $decoded)
            $text += (Check-Regex $decoded 0)
        }
    }
    if ($text){
        if ($servicecmd){
            $obj.Message = "Suspicious Service Command"
            $obj.Results = "Service name: $servicename`n"
        }
        Else{
            $obj.Message = "Suspicious Command Line"
        }
        $obj.Command = $commandline
        $obj.Results += $text
        $obj.EventID = $EventID
        Write-Output $obj
    }
    return
}

function Check-Regex($string,$type){
    $regextext="" # Local variable for return output
    foreach ($regex in $regexes){
        if ($regex.Type -eq $type) { # Type is 0 for Commands, 1 for services. Set in regexes.csv
            if ($string -Match $regex.regex) {
               $regextext += $regex.String + "`n"
            }
        }
    }
    #if ($regextext){ 
    #   $regextext = $regextext.Substring(0,$regextext.Length-1) # Remove final newline.
    #}
    return $regextext
}

function Check-Obfu($string){
    # Check for special characters in the command. Inspired by Invoke-Obfuscation: https://twitter.com/danielhbohannon/status/778268820242825216
    #
    $obfutext=""       # Local variable for return output
    $lowercasestring=$string.ToLower()
    $length=$lowercasestring.length
    $noalphastring = $lowercasestring -replace "[a-z0-9/\;:|.]"
    $nobinarystring = $lowercasestring -replace "[01]" # To catch binary encoding
    # Calculate the percent alphanumeric/common symbols
    if ($length -gt 0){
        $percent=(($length-$noalphastring.length)/$length)
        # Adjust minpercent for very short commands, to avoid triggering short warnings
        if (($length/100) -lt $minpercent){ 
            $minpercent=($length/100) 
        }
        if ($percent -lt $minpercent){
            $percent = "{0:P0}" -f $percent      # Convert to a percent
            $obfutext += "Possible command obfuscation: only $percent alphanumeric and common symbols`n"
        }
        # Calculate the percent of binary characters  
        $percent=(($nobinarystring.length-$length/$length)/$length)
        $binarypercent = 1-$percent
        if ($binarypercent -gt $maxbinary){
            #$binarypercent = 1-$percent
            $binarypercent = "{0:P0}" -f $binarypercent      # Convert to a percent
            $obfutext += "Possible command obfuscation: $binarypercent zeroes and ones (possible numeric or binary encoding)`n"
        }
    }
    return $obfutext
}

function Check-Creator($command,$creator){
    $creatortext=""  # Local variable for return output
    if ($creator){
        if ($command -Match "powershell"){
            if ($creator -Match "PSEXESVC"){
                $creatortext += "PowerShell launched via PsExec: $creator`n"
            }
            ElseIf($creator -Match "WmiPrvSE"){
                $creatortext += "PowerShell launched via WMI: $creator`n"
            }
        }
        ElseIf ($command -Match "cmd.exe"){
            if ($creator -Match "PSEXESVC"){
                $creatortext += "cmd.exe launched via PsExec: $creator`n"
            }
            ElseIf($creator -Match "WmiPrvSE"){
                $creatortext += "cmd.exe launched via WMI: $creator`n"
            }
        }
    }
    return $creatortext
}

function Remove-Spaces($string){
    # Changes this:   Application       : C:\Program Files (x86)\Internet Explorer\iexplore.exe
    #      to this: Application: C:\Program Files (x86)\Internet Explorer\iexplore.exe
    $string = $string.trim() -Replace "\s+:",":"
    return $string
}

. Main

