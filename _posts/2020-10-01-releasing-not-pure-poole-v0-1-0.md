---
layout: post
title: Inhibit. Encrypt. Extort. — The War on Shadow Copies and System Recovery
author: Songzi Vong
tags:
- ShadowCopy
- vss
date: 2025-06-01 13:56 +0800
---

**Ransomware remains one of the most pressing cybersecurity threats facing organizations globally.**  Over the past several years, its adoption has surged — not only among sophisticated APT groups and commodity malware operators but also among opportunistic threat actors with no prior history of using ransomware. Initially, attackers leveraged ransomware to exploit gaps in incident response, such as the absence of reliable backups or robust disaster recovery plans. Their goal was often to pressure victims into paying to restore operations and minimize downtime.

However, a harsh reality persists:  **even when ransoms are paid, full recovery is rarely achieved.**  Many victims are left with corrupted systems, incomplete data restoration, and lingering operational disruptions — highlighting the critical importance of proactive defense and resilience over reliance on payment.

![](https://miro.medium.com/v2/resize:fit:796/0*5RyChtGjLuJLnylD.jpg)

# **What’s a vssadmin ?**

**Vssadmin is a Windows command-line utility used to manage Volume Shadow Copy Services (VSS),**  which are responsible for creating and maintaining backup snapshots — known as shadow copies — of volumes or files. Shadow copies allow users and system processes to restore previous versions of files, even if the originals are deleted or modified.

Attackers and ransomware often target  `vssadmin`  to delete these shadow copies, effectively removing the victim’s ability to recover data without paying a ransom. Disabling or wiping shadow copies is a common anti-recovery tactic seen in modern ransomware campaigns.

# **what is a shadow copy?**

A  **shadow copy**  (also known as a  **Volume Shadow Copy**  or  **VSS snapshot**) is a  **snapshot of a file or volume at a specific point in time**, created by the Windows Volume Shadow Copy Service (VSS). It allows the system — or users — to  **recover previous versions of files**, even while those files are in use.

# Key Points:

-   It’s  **used by backup software**  and Windows features like “Previous Versions” to restore files or system states.
-   Shadow copies are  **read-only**  and stored locally on disk.
-   They’re commonly used for  **system restore points**, ensuring you can roll back to a stable configuration.

# Inhibiting System Recovery — MITRE ATT&CK Technique T1490

[](https://attack.mitre.org/techniques/T1490/?source=post_page-----0d2d69214e24---------------------------------------)

## Inhibit System Recovery

### Adversaries may delete or remove built-in data and turn off services designed to aid in the recovery of a corrupted…

attack.mitre.org

**Ransomware**  frequently employs a range of techniques to disrupt system recovery, prevent future restorations, and corrupt or delete existing recovery points.

the most commonly observed tactic was the use of  `vssadmin`  to delete Volume Shadow Copies from the system. As this technique became widespread and easily detectable, ransomware developers began exploring alternative methods, leveraging built-in Windows utilities such as PowerShell,  `wmic`,  `bcdedit`,  `net.exe`, and  `wbadmin`.

According to data provided by  **MITRE**,  **more than 25 ransomware groups and malware families have been documented using techniques to delete or tamper with Volume Shadow Copies (VSS)**. This widespread abuse of the Windows Volume Shadow Copy Service underscores a critical tactic used to  **inhibit system recovery and force ransom payments**. While early variants relied primarily on  `vssadmin.exe`, modern strains now leverage a variety of native Windows utilities—including  `PowerShell`,  `wmic`,  `bcdedit`,  `net.exe`, and  `wbadmin`—to ensure the destruction of backups. The prevalence of this behavior highlights how difficult it is to attribute ransomware based solely on recovery prevention methods.

# Shadow Copy and Recovery Inhibition via Built-in Tools

**Objective:**  
Identify processes commonly used by ransomware or threat actors to delete shadow copies, disable recovery mechanisms, or otherwise inhibit system recovery.

**Detection Criteria:**

-   **Process Name is any of the following:**
-   `vssadmin.exe`
-   `bcdedit.exe`
-   `wmic.exe`
-   `powershell.exe`
-   `wbadmin.exe`
-   **Command Line contains any of the following indicative keywords or parameters:**
-   `recoveryenabled no`
-   `IgnoreAllFailures`
-   `delete shadows`
-   `delete systemstatebackup`
-   `resize shadowstorage`
-   `_ShadowCopy`
-   `safeboot minimal`
-   `shadowcopy /nointeractive`
-   `shadowcopy delete`

vssadmin.exe Delete Shadows /All /Quiet

# Explanation:

-   `**vssadmin.exe**`: Native Windows utility for managing Volume Shadow Copies (VSS).
-   `**Delete Shadows**`: Instructs Windows to delete shadow copies.
-   `**/All**`: Deletes  _all_  shadow copies on the system.
-   `**/Quiet**`: Suppresses confirmation prompts and output — executes silently.  
    Known Ransomware Families Using It:
-   **Conti**
-   **Ryuk**
-   **LockBit**
-   **Avaddon**
-   **Ragnar**
-   **Netwalker**
-   **Nemty**
-   **ProLock**

wmic  shadowcopy delete

# Explanation:

-   `**wmic**`: Windows Management Instrumentation Command-line tool, used to interact with system management infrastructure.
-   `**shadowcopy**`: WMIC class for managing Volume Shadow Copies (VSS).
-   `**delete**`: Removes all existing shadow copies from the system.

# Ransomware Families Known to Use It:

-   **LockBit**
-   **Nemty**
-   **Ragnar**
-   **Ryuk**
-   **Avaddon**
-   **Ako**

Get-WmiObject Win32_Shadowcopy | ForEach-Object {$_.Delete();}

# Explanation:

-   `**Get-WmiObject Win32_Shadowcopy**`: Retrieves all existing Volume Shadow Copies via WMI (Windows Management Instrumentation).
-   `**ForEach-Object { $_.Delete(); }**`: Iterates over each shadow copy object and calls its  `.Delete()`  method to remove it.

bcdedit  /set {default} bootstatuspolicy ignoreallfailures    
bcdedit  /set {default} recoveryenabled no

## Explanation:

-   `bcdedit`: A command-line tool to manage Boot Configuration Data (BCD).
-   `/set {default}`: Modifies the default boot entry.
-   `bootstatuspolicy ignoreallfailures`: Tells the system  **not to launch recovery options**, even after critical failures (e.g., blue screens).

wbadmin DELETE SYSTEMSTATEBACKUP   
wbadmin DELETE SYSTEMSTATEBACKUP -deleteOldest

## Explanation:

-   `**wbadmin**`: A native Windows command-line utility for managing backup and recovery.
-   `**DELETE SYSTEMSTATEBACKUP**`: Deletes all  **System State backups**, which include critical files for system recovery (e.g., registry, boot files, Active Directory for domain controllers).
-   Deletes  **only the oldest System State backup**.
-   Used either to clear disk space or, in the case of malware, to  **incrementally remove recovery points**.

net stop BackupExecAgentAccelerator /y   
net stop BackupExecVSSProvider /y

## Explanation:

-   `**net stop**`: A Windows command used to stop running services.
-   `**BackupExecAgentAccelerator**`: A service used by  **Veritas Backup Exec**  to speed up backup operations.
-   `**BackupExecVSSProvider**`: A Veritas component that integrates with the  **Volume Shadow Copy Service (VSS)**  to manage backup snapshots.

The  `/y`  flag  **automatically confirms dependent service stops**  without prompting.
