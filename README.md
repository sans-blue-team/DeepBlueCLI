# DeepBlueCLI

DeepBlueCLI 0.1 Beta

Eric Conrad, Backshore Communications, LLC

deepblue <at> backshore <dot> net

Twitter: @eric_conrad

http://ericconrad.com

Sample evtx files are in the .\evtx directory

## Usage:


`.\DeepBlue.ps1 <event log name> <evtx filename>`

## Examples:

### Process local Windows security event log:

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

