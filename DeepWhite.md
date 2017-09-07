## DeepWhite

Detective whitelisting using Sysmon event logs

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

## Generating a Whitelist

Install hashdeep: https://github.com/jessek/hashdeep/releases

Generate your own whitelist on Windows:

```
hashdeep.exe -r / -c md5,sha1,sha56 > raw-hashes.csv
```
Note that hashdeep, etc., has a dumb recursive design (from the manpage):

> Enables recursive mode. All subdirectories are traversed. Please note that recursive mode cannot be used to examine all files of a given file extension. For example, calling hashdeep -r *.txt will examine all files in directories that end in .txt. Move file to Unix/Linux, remove Windows carriage returns, grab EXEs and DLLs, make CSV.
:
```
cat raw-hashes.csv | tr -d '\r' | egrep "\.dll$|\.exe$" | cut -d, -f2- > win10-x64.csv
```

Add this entry to the first line of the file (only sha256 and path are currently needed)
```
md5,sha1,sha256,path
```

