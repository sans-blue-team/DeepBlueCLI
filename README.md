# DeepBlueCLI

DeepBlueCLI - a PowerShell Module for Threat Hunting via Windows Event Logs

Eric Conrad, Backshore Communications, LLC

deepblue `at` backshore `dot` net

Twitter: @eric_conrad

http://ericconrad.com

Sample evtx files are in the .\evtx directory

## Table of Contents  
- [Usage](#usage)  
- [Windows Event Logs processed](#windows-event-logs-processed)
- [Detected events](#detected-events)
- [Examples](#examples)
- [Logging setup](#logging-setup)
- See the [DeepBlue.py Readme](README-DeepBlue.py.md) for information on DeepBlue.py
- See the [DeepWhite Readme](README-DeepWhite.md) for information on DeepWhite (detective whitelisting using Sysmon event logs)

## Usage:

`.\DeepBlue.ps1 <event log name> <evtx filename>`

If you see this error: `.\DeepBlue.ps1 : File .\DeepBlue.ps1 cannot be loaded because running scripts is
disabled on this system. For more information, see about_Execution_Policies at
http://go.microsoft.com/fwlink/?LinkID=135170.`

You must run Set-ExecutionPolicy as Administrator, here is an example (this will warn every time you run a ps1 script): `Set-ExecutionPolicy RemoteSigned`

This command will bypass Set-Execution entirely: `Set-ExecutionPolicy Bypass`

See `get-help Set-ExecutionPolicy` for more options.

Please note that "Set-ExecutionPolicy is not a security control" (quoting @Ben0xA)

### Process local Windows security event log (PowerShell must be run as Administrator):

`.\DeepBlue.ps1`

or:

`.\DeepBlue.ps1 -log security`

### Process local Windows system event log:

`.\DeepBlue.ps1 -log system`

or:

`.\DeepBlue.ps1 "" system`

### Process evtx file:

`.\DeepBlue.ps1 .\evtx\new-user-security.evtx`

or:

`.\DeepBlue.ps1 -file .\evtx\new-user-security.evtx`

## Windows Event Logs processed

- Windows Security 
- Windows System
- Windows Application
- Windows PowerShell 
- Sysmon

### Command Line Logs processed

See 'Logging setup' section below for how to configure these logs

- Windows Security event ID 4688 
- Windows PowerShell event IDs 4103 and 4104
- Sysmon event ID 1

## Detected events

* Suspicious account behavior
  * User creation
  * User added to local/global/universal groups
  * Password guessing (multiple logon failures, one account)
  * Password spraying via failed logon (multiple logon failures, multiple accounts)
  * Password spraying via explicit credentials
  * Bloodhound (admin privileges assigned to the same account with multiple Security IDs)
* Command line/Sysmon/PowerShell auditing
  * Regex searches
  * Obfuscated commands
  * PowerShell launched via WMIC or PsExec
  * Compressed/Base64 encoded commands (with automatic decompression/decoding)
  * Unsigned EXEs or DLLs
* Service auditing
  * Suspicious service creation
  * Service creation errors
  * Stopping/starting the Windows Event Log service (potential event log manipulation)
* EMET & Applocker Blocks
* Sensitive Privilege Use (Mimikatz)

...and more

## Examples

|Event|Command|
|-----|-------|
|Event log manipulation|`.\DeepBlue.ps1 .\evtx\disablestop-eventlog.evtx`|
|Metasploit native target (security)|`.\DeepBlue.ps1 .\evtx\metasploit-psexec-native-target-security.evtx`|
|Metasploit native target (system)|`.\DeepBlue.ps1 .\evtx\metasploit-psexec-native-target-system.evtx`|
|Metasploit PowerShell target (security)|` .\DeepBlue.ps1 .\evtx\metasploit-psexec-native-target-security.evtx`|
|Metasploit PowerShell target (system)|` .\DeepBlue.ps1 .\evtx\metasploit-psexec-native-target-system.evtx`|
|Mimikatz hashdump|`.\DeepBlue.ps1 .\evtx\mimikatz-privesc-hashdump.evtx`|
|Mimiktaz token::elevate|`.\DeepBlue.ps1 .\evtx\mimikatz-privilegedebug-tokenelevate-hashdump.evtx`|
|New user creation|`.\DeepBlue.ps1 .\evtx\new-user-security.evtx`|
|Obfuscation (encoding)|`.\DeepBlue.ps1 .\evtx\Powershell-Invoke-Obfuscation-string-menu.evtx\`|
|Obfuscation (string)|`.\DeepBlue.ps1 .\evtx\Powershell-Invoke-Obfuscation-string-menu.evtx`|
|Password guessing|`.\DeepBlue.ps1 .\evtx\smb-password-guessing-security.evtx`|
|Password spraying|`.\DeepBlue.ps1 .\evtx\password-spray.evtx`|
|PowerSploit (security)|`.\DeepBlue.ps1 .\evtx\powersploit-security.evtx`|
|PowerSploit (system)|`.\DeepBlue.ps1 .\evtx\powersploit-system.evtx`|
|PSAttack|`.\DeepBlue.ps1 .\evtx\psattack-security.evtx`|
|User added to administrator group|`.\DeepBlue.ps1 .\evtx\new-user-security.evtx`|

## Logging setup

### Security event 4688 (Command line auditing):

Enable Windows command-line auditing: https://support.microsoft.com/en-us/kb/3004375 

### Security event 4625 (Failed logons):

Requires auditing logon failures: https://technet.microsoft.com/en-us/library/cc976395.aspx
### PowerShell auditing (PowerShell 5.0):

DeepBlueCLI uses module logging (PowerShell event 4013) and script block logging (4104). It does not use transcription.

See: https://www.fireeye.com/blog/threat-research/2016/02/greater_visibilityt.html

To get the PowerShell commandline (and not just script block) on Windows 7 through Windows 8.1, add the following to \Windows\System32\WindowsPowerShell\v1.0\profile.ps1
```
$LogCommandHealthEvent = $true
$LogCommandLifecycleEvent = $true
```
See the following for more information:
 - https://logrhythm.com/blog/powershell-command-line-logging/
 - http://hackerhurricane.blogspot.com/2014/11/i-powershell-logging-what-everyone.html

Thank you: @heinzarelli and @HackerHurricane

### Sysmon

Install Sysmon from Sysinternals: https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon

DeepBlue and DeepWhite currently use Sysmon events, 1, 6 and 7.

Log SHA256 hashes. Others are fine; DeepBlueCLI will use SHA256.

