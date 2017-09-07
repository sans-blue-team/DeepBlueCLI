# DeepWhite

Detective whitelisting using Sysmon event logs.

Parses the Sysmon event logs, grabbing the SHA256 hashes from process creation (event 1), driver load (event 6, sys), and image load (event 7, DLL) events. 

## VirusTotal and Whitelisting setup

Setting up VirusTotal hash submissions and whitelisting:

The hash checker requires Post-VirusTotal:

 - https://github.com/darkoperator/Posh-VirusTotal

It also requires a VirusTotal API key: 

 - https://www.virustotal.com/en/documentation/public-api/

Then configure your VirusTotal API key:
```powershell
set-VTAPIKey -APIKey <API Key>
```
The script assumes a personal API key, and waits 15 seconds between submissions.

## Sysmon setup

Sysmon is required: https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon

Must log the SHA256 hash, DeepWhite will ignore the others.

This minimal Sysmon 6.0 config will log the proper events/hashes:

```xml
<Sysmon schemaversion="3.3">
  <!-- Capture SHA256 hashes only -->
  <HashAlgorithms>SHA256</HashAlgorithms>
  <EventFiltering>
    <!-- Log all drivers (.sys) except if the signature contains Microsoft or Windows -->
    <DriverLoad onmatch="exclude">
      <Signature condition="contains">microsoft</Signature>
      <Signature condition="contains">windows</Signature>
    </DriverLoad>
    <!-- Log all images (.dll) except if the signature contains Microsoft or Windows -->
    <ImageLoad onmatch="exclude">
      <Signature condition="contains">microsoft</Signature>
      <Signature condition="contains">windows</Signature>
    </ImageLoad>
    <!-- Do not log process termination -->
    <ProcessTerminate onmatch="include" />
    <!-- Log process creation  -->
    <ProcessCreate onmatch="exclude" />
  </EventFiltering>
</Sysmon>
```
These are the events used by DeepBlueCLI and DeepWhite.

You can go *much* further than this with Sysmon. The Sysinternals Sysmon page has a good basic configuration: https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon

Also see @swiftonsecurity's awesome sysmon config here: https://github.com/SwiftOnSecurity/sysmon-config

## Generating a Whitelist

Install hashdeep: https://github.com/jessek/hashdeep/releases

Generate a custom whitelist on Windows (note: this is optional):

```
C:\> hashdeep.exe -r / -c md5,sha1,sha56 > raw-hashes.csv
```
Note that hashdeep, etc., has a dumb recursive design (from the manpage):

> Enables recursive mode. All subdirectories are traversed. Please note that recursive mode cannot be used to examine all files of a given file extension. For example, calling hashdeep -r *.txt will examine all files in directories that end in .txt. 

On Linux/Unix: create a new CSV with the proper header (required by PowerShell's ConvertFrom-Csv), take the raw CSV, remove the carriage returns, select DLLs, EXEs and SYS files, grab the 2nd field to the end, and append to the new CSV:

```shell
$ echo "md5,sha1,sha256,path" > file-whitelist.csv
$ cat raw-hashes.csv | tr -d '\r' | egrep "\.dll$|\.exe$|\.sys$" | cut -d, -f2- >> file-whitelist.csv
```

Todo: add PowerShell instructions to do this on Windows. Contributions welcome! 

