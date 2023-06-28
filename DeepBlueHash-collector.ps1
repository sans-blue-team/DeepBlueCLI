$hashdirectory=".\hashes\"
$events = get-winevent @{logname="Microsoft-Windows-Sysmon/Operational";id=1,6,7,29} 
ForEach ($event in $events) {
    if ($event.id -eq 1){ # Process creation   
	if ($event.Properties.Count -le 16){
 		$path=$event.Properties[3].Value   # Full path of the file
       		$hash=$event.Properties[11].Value  # Hashes
	}
        ElseIf ($event.Properties.Count -le 17){
		$path=$event.Properties[4].Value   # Full path of the file
	        $hash=$event.Properties[16].Value  # Hashes		
	}
	Else {
 		$path=$event.Properties[4].Value   # Full path of the file
		$hash=$event.Properties[17].Value  # Hashes		
	}
    }
    ElseIf ($event.id -eq 29){ # FileExecutableDetected
    	$path=$event.Properties[6].Value  # Full path of the file
     	$hash=$event.Properties[7].Value  # Hashes		
    }
    Else{
        # Hash and path are part of the message field in Sysmon events 6 and 7. Need to parse the XML
        $eventXML = [xml]$event.ToXml()
        If ($event.id -eq 6){ # Driver (.sys) load    
            if ($event.Properties.Count -le 6){
	            $path=$eventXML.Event.EventData.Data[1]."#text" # Full path of the file
                $hash=$eventXML.Event.EventData.Data[2]."#text" # Hashes
                $hash
	        }
	        Else{
	            $path=$eventXML.Event.EventData.Data[2]."#text" # Full path of the file
		        $hash=$eventXML.Event.EventData.Data[3]."#text" # Hashes
		    }
        }
        ElseIf ($event.id -eq 7){ # Image (.dll) load
            if ($event.Properties.Count -lt 14){
                $path=$eventXML.Event.EventData.Data[4]."#text" # Full path of the file
                $hash=$eventXML.Event.EventData.Data[5]."#text" # Hashes   
		 }
	        Elseif ($event.Properties.Count -lt 15){
		        $path=$eventXML.Event.EventData.Data[5]."#text" # Full path of the file
            		$hash=$eventXML.Event.EventData.Data[10]."#text" # Hashes   
	     	}  
            Else{
		        $path=$eventXML.Event.EventData.Data[5]."#text" # Full path of the file
            		$hash=$eventXML.Event.EventData.Data[11]."#text" # Hashes   
	     	}  
        }
        Else{
            Out-Host "Logic error 1, should not reach here..."
            Exit 1
        }
    }
    # Multiple hashes may be logged, we want SHA256. Remove everything through "SHA256="
    $SHA256= $hash -Replace "^.*SHA256=",""
    # Split the string on commas, grab field 0
    $SHA256=$SHA256.Split(",")[0]        
    if ($SHA256 -Match '^[0-9A-F]{64}$'){ # SHA256 hashes are 64 character hex strings
        $hashfile="$hashdirectory\$SHA256"
        if (-not (Test-Path "$hashfile*")){  
            # Hash file doesn't exist (or any variants with extensions), create it
            $path | Set-Content $hashfile
        }
    }
    Else{
        Out-Host "No SHA256 hash found. Ensure Sysmon is creating SHA256 hashes"
    }
}
