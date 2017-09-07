### DeepBlueCLI Whitelist

Placeholder, more to come...

Install hashdeep: https://github.com/jessek/hashdeep/releases

Generate your own whitelist on Windows:
```
hashdeep.exe -r / -c md5,sha1,sha56 > raw-hashes.csv
```

Note that hashdeep, etc., has a dumb recursive design (from the manpage):

> Enables recursive mode. All subdirectories are traversed. Please note  that recursive mode cannot be used to examine all files of a given file extension. For example, calling hashdeep  -r  *.txt will examine all files in directories that end in .txt.

Move file to Unix/Linux, remove Windows carriage returns, grab EXEs and DLLs, make CSV. 

CSV format will be: md5,sha1,sha256,full path:

```
cat raw-hashes.csv | tr -d '\r' | egrep "\.dll$|\.exe$" | cut -d, -f2- > win10-x64.csv
```
