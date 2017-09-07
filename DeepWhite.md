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

On Linux/Unix: take the raw CSV, remove the carriage returns, select DLLs, EXEs and SYS files, grab the 2nd field to the end, and create a new whitelist:
```shell
echo "md5,sha1,sha256,path" > file-whitelist.csv
cat raw-hashes.csv | tr -d '\r' | egrep "\.dll$|\.exe$|\.sys$" | cut -d, -f2- >> file-whitelist.csv
```

