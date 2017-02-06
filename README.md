# DeepBlueCLI

DeepBlueCLI 0.1 Beta

Eric Conrad, Backshore Communications, LLC

deepblue `at` backshore `dot` net

Twitter: @eric_conrad

http://ericconrad.com

Sample evtx files are in the .\evtx directory

## Usage:


`.\DeepBlue.ps1 <event log name> <evtx filename>`

If you see this error:

`.\DeepBlue.ps1 : File .\DeepBlue.ps1 cannot be loaded because running scripts is
disabled on this system. For more information, see about_Execution_Policies at
http://go.microsoft.com/fwlink/?LinkID=135170.`

You must run Set-ExecutionPolicy as Administrator, here is an example:

`Set-ExecutionPolicy RemoteSigned`

See `get-help Set-ExecutionPolicy` for more options.

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

or:

`\DeepBlue.ps1 -file .\evtx\psattack-security.evtx -format csv -path ./`

