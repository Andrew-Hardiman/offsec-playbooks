**IMPORTANT: The target machine must have a minimum of two CPUs for this exploit to work, due to the fact that it exploits a race condition.**

## Step 1: Check vCPU count on the target machine

Command

`powershell -command "(Get-WmiObject -Class Win32_Processor).NumberOfLogicalProcessors"`

If this command returns '1' or less you cannot proceed with this exploit.


