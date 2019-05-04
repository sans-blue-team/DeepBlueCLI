## Set-ExecutionPolicy

If you see this error: `.\DeepBlue.ps1 : File .\DeepBlue.ps1 cannot be loaded because running scripts is
disabled on this system. For more information, see about_Execution_Policies at
http://go.microsoft.com/fwlink/?LinkID=135170.`

You must run Set-ExecutionPolicy as Administrator, here is an example (this will warn every time you run a ps1 script): 

`Set-ExecutionPolicy RemoteSigned`

This command will bypass Set-Execution entirely: `Set-ExecutionPolicy Bypass`

See `get-help Set-ExecutionPolicy` for more options.

Please note that "Set-ExecutionPolicy is not a security control" (quoting [@Ben0xA](https://twitter.com/ben0xa))
