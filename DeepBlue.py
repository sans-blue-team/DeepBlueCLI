#!/usr/bin/python

#Test
# DeepBlue.py Alpha 0.12 (post-DerbyCon release)
# Eric Conrad
# Twitter: @eric_conrad
# http://ericconrad.com
# deepblue at backshore dot net

# Currently alpha level functionality, supports CLI parsing only
# More features to come

# Requires libevtx: https://github.com/libyal/libevtx
 
import sys
import re
import csv
import base64
import os.path
import string
from subprocess import Popen, PIPE

def filter(str):
    # Used to convert base64 decoded data (unicode) to ASCII
    return ''.join([c for c in str if ord(c) > 31 or ord(c) == 9])

def CheckRegex(regexes,command):
    string=""
    for regex in regexes:
        if (regex[0] == "0"):
            if re.search(regex[1],command,re.IGNORECASE):
                string+=" - "+regex[2]+"\n"
    return(string)

def CheckObfu(cli,minpercent,minlength):
    string=""
    noalphastring=re.sub("[A-Za-z0-9]","",cli)
    length1=float(len(cli))
    if (length1 > minlength):
        length2=float(len(noalphastring))
        if ((length1/150) < minpercent):
            minpercent=length1/150        # Shorter strings get lower minpercent, based on the string length
        percent =((length1-length2)/length1)
        if (percent < minpercent):
            percent=(round(percent,2))*100
            string += " - Potential command obfuscation: "+str(int(percent))+"% alpha characters"
    return(string)

def CheckCommand(time, log, eventid, cli):
    minpercent=.65
    minlength=25 # Minimum CLI length to check for obfuscation
    string=""
    decoded=""
    noalphastring=""
    string=CheckRegex(regexes,cli)
    if re.search("\-enc.*[A-Za-z0-9/+=]{100}",cli,re.IGNORECASE):
        b64=re.sub("^.* \-Enc(odedCommand)? ","",cli,re.IGNORECASE)
        decoded=base64.b64decode(b64)
        decoded=str(filter(decoded))  # Convert base64 to ASCII
        string+=CheckRegex(regexes,decoded)
    string += CheckObfu(cli,minpercent,minlength) 
    if(string):
        print "Date: %s\nLog: %s\nEventID: %s" % (time,log,eventid)
        print "Results:\n%s\n" % (string.rstrip())
        print "Command:  %s\n" % (cli)
    if(decoded):
        print "Decoded: %s" % (decoded)
    if(string):
        print "\n"

filename=""
regexfile="regexes.txt"
regexes=[]
if len(sys.argv)==2:
    if os.path.isfile(sys.argv[1]):
        filename=sys.argv[1]
        if os.path.isfile(regexfile):
            with open(regexfile) as csvfile:
                reader = csv.reader(csvfile, delimiter=',')
                for row in reader:
                    if not row[0].startswith('#'):
                        regexes.append(row)
        else:
            print "Error: cannot open "+regexfile+"\n" 
    else:
        print "Error: no such file: %s\n" % (sys.argv)
else:
    print "Error: filename required as an argument\n"

if (filename and regexes):
    process=""
    try:
        process = Popen(['evtxexport', filename], stdout=PIPE, stderr=PIPE)
    except:
        print 'Can\'t find libevtx. Check the path and verify it is installed. See: https://github.com/libyal/libevtx'

    if (process):
        time=""
        log=""
        eventid=""
        cli=""
        path=""
        for line in iter(process.stdout.readline,''):
            if re.search("^Written time",line):
                #Written time			: Aug 30, 2017 19:16:26.133985000 UTC
                time = re.sub("^.*: ","",line)
                time = time[:21]
            elif re.search("^Source name",line):
                log = re.sub("^.*: ","",line).rstrip()
            elif re.search("^Event identifier",line):
                # Looks like this, grab the number between the parentheses:
                #Event identifier		: 0x00001008 (4104)
                #Event identifier		: 0x00000001 (1)
                eventid = re.sub("^.*\(","",line.rstrip())
                eventid = re.sub("\).*$","",eventid)
            elif re.search("^String: 3",line):
                #Source name			: Microsoft-Windows-PowerShell
                if log=="Microsoft-Windows-PowerShell":
                    cli = line[14:].rstrip()
            elif re.search("^String: 5",line):
                if log=="Microsoft-Windows-PowerShell":
                    path = line[14:].rstrip()
                elif log=="Microsoft-Windows-Sysmon":
                    cli = line[14:].rstrip()
            elif re.search("^String: 9",line):
                if log=="Microsoft-Windows-Security-Auditing":
                    cli = line[14:].rstrip()
            elif re.search("^$",line):
                # 4688: CLI via System log
                # 4104: PowerShell CLI if path is blank (non-blank path == PowerShell script)
                #    1: Sysmon CLI 
                if ((eventid=="4688")or(eventid=="1")or((eventid=="4104")and(path==""))):
                    CheckCommand(time,log,eventid,cli)
