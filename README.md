# WritePathLPE
# Windows Local Privilege Escalation via StorSvc service (writable SYSTEM path DLL Hijacking)

# Description
StorSvc is a service which runs as `NT AUTHORITY\SYSTEM` and tries to load the missing **SprintCSP.dll** DLL from the `system %PATH%` when triggering the `SvcRebootToFlashingMode` RPC method locally.

The `StorSvc.dll!SvcRebootToFlashingMode` RPC method, calls `StorSvc.dll!InitResetPhone` which also calls `StorSvc.dll!ResetPhoneWorkerCallback`, that tries to load **SprintCSP.dll**

# Exploit

For this Poc to work, you will need to add a  `C:\CoolesProgramm` Folder, and add it to the `system %PATH%`, Then you need to put your DLL in there, and execute the RpcCleint.exe, to make the RPC call. 

I have provided a DLL, writing the output of the command `whoami` into the path `C:\CoolesProgramm`
You can however, put any DLL that does anything into that folder and execute the programm.

There is a compiled version of the RpcClient.exe provided in this repository.
