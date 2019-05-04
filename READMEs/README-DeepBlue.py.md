# DeepBlue.py

DeepBlueCLI, ported to Python. Designed for parsing evtx files on Unix/Linux.

Current version: alpha. It supports command line parsing for Security event log 4688, PowerShell log 4014, and Sysmon log 1. Will be porting more functionality from DeepBlueCLI after DerbyCon 7.

## libevtx

Requires libevtx:  https://github.com/libyal/libevtx

## Other evtx frameworks

Note that I tested a few Unix/Linux/Python evtx frameworks. 

This is quite popular: https://github.com/williballenthin/python-evtx

I ran into trouble with *some* .evtx files, where it would crash with this error:

```
UnicodeDecodeError: 'utf16' codec can't decode bytes in position 0-1: illegal UTF-16 surrogate
```

I found libevtx 'just worked', and had the added benefit of both Python and compiled options.
