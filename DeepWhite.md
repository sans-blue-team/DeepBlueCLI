# DeepWhite

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

