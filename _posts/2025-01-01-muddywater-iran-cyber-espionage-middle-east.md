---
layout: post
title: "Threat Profile: MuddyWater (TA450 / Static Kitten)"
description: "Inside Iran’s persistent cyber-espionage group targeting the Middle East."
date: 2025-01-01
categories: [Threat Intelligence, State-Sponsored Threats, Iran]
classes: wide
header:
  teaser: /assets/images/muddywater-teaser.png
ribbon: Red
toc: true
---
**MuddyWater**, a long-running **Iranian cyber-espionage** group **affiliated with Iran’s Ministry of Intelligence and Security (MOIS)**, has established itself as one of the most persistent state-backed threats on the global stage. Active since at least **2017**, the group has built a reputation for blending **off-the-shelf tools with custom malware** to achieve its goals. Over the past year, **MuddyWater** has intensified its activity, spearheading **phishing campaigns across the Middle East** — with Israel emerging as a primary target.

Since October 2023, these operations have **ramped up in both frequency and sophistication**, signaling a heightened strategic push. True to their modus operandi, the attackers rely heavily on **emails sent from compromised accounts**, exploiting trust within organizations and across supply chains. These phishing campaigns often pave the way for the installation of **commercial Remote Management Tools (RMMs)** such as Atera Agent or **ScreenConnect** — legitimate software twisted into tools of persistence and surveillance.

What makes their recent activity more alarming is the introduction of a **new custom backdoor, “BugSleep,”** designed to provide discreet and long-lasting access to compromised systems. Alongside **BugSleep**, investigators have observed **MuddyWater** **abusing legitimate platforms like Egnyte** — a trusted file-sharing service — as part of their command-and-control infrastructure. This blend of “living-off-the-land” tactics with bespoke malware underscores the group’s ability to adapt and evolve its toolbox while remaining difficult to detect.

---

**Targeted Sectors**

**MuddyWater’s** campaigns are marked by the mass distribution of phishing emails from compromised accounts, often targeting hundreds of recipients across more than 10 sectors. While their lures span a wide range of organizations and individuals, the group routinely zeroes in on specific industries or sectors, revealing their strategic interests. Most notably, recent campaigns have targeted **Israeli** municipalities, **airlines, travel agencies, and journalists**. These phishing efforts ramped up dramatically from **February 2024,** with researchers identifying over 50 spear phishing emails linked to **MuddyWater’s** operations.

Within each campaign, **MuddyWater** customizes its phishing lures for specific targets — such as encouraging municipal employees to download a supposed new app. This tactic, coupled with their broad targeting and volume, reflects the group’s persistent efforts to infiltrate sensitive networks and influence key industries in Israel and beyond.

![](https://cdn-images-1.medium.com/max/1000/0*xIEw7Al4T2-6oUoW)

---

****Attack Chain****

**MuddyWater** attacks unfold through a calculated, multi-stage process that leverages both social engineering and technical skill to compromise targets:

- **Initial Access:** The group is notorious for its use of spear-phishing campaigns, often sending seemingly legitimate emails from compromised accounts to a wide range of targets. These emails typically contain malicious attachments or links hosted on trusted file-sharing services, enticing users to open weaponized documents.
- **Payload Deployment**: Upon successful engagement, **MuddyWater** rapidly shifts to establishing persistent access — often by deploying legitimate Remote Monitoring and Management (RMM) tools like Atera Agent, ScreenConnect, Remote Utilities, and eHorus. This misuse of commercial software enables attackers to sidestep detection and blend in with normal network activity.
- **Privilege Escalation & Lateral Movement:** Once a foothold is established, MuddyWater actors use credential-dumping utilities such as Mimikatz to harvest credentials, aiming for local administrator access. They also deploy PowerShell scripts and web shells to broaden their compromise and maintain persistence.
- **Command & Control (C2):** Communication with C2 servers commonly occurs over DNS tunneling or through obfuscated data channels. MuddyWater utilizes tools like vpnui[.]exe (a unique Ligolo fork) and leverages protocols familiar to defenders, making detection challenging.
- **Malware and Backdoors:** Recently, the group has been seen delivering custom malware like BugSleep to maintain deep and long-term access, adapting payloads for different environments and sectors.
- **Evasion Techniques:** Their arsenal includes DLL side-loading, masquerading, and heavy use of obfuscated scripts to evade security controls and sandboxing.

![](https://cdn-images-1.medium.com/max/1000/0*56HzXZ31l6WQG_ly)

---

### **MuddyWater’s toolkit:**

- **PowGoop DLL Loader**: This malware acts as a loader, masquerading as a legitimate Google Update executable to evade detection. It is used to execute additional malicious payloads, hiding its communications with command-and-control (C2) servers under the guise of trusted software.
- **Small Sieve:** A Telegram Bot API-based Python backdoor distributed via a Nullsoft Scriptable Install System (NSIS) installer, typically named gram_app.exe. Once installed, it achieves persistence by adding a registry run key and leverages custom obfuscation to avoid detection. Communication and tasking are performed via the Telegram API over HTTPS, with data further obfuscated using a hex byte swapping technique and an encoded Base64 function.
- **Canopy (Starwhale):** A spyware module that collects basic system information such as username, computer name, and IP address, and sends it to **MuddyWater-controlled** infrastructure for reconnaissance and targeting.
- **Mori:** A backdoor exploiting DNS tunneling to covertly communicate with MuddyWater’s C2 servers. This approach makes network monitoring and detection particularly challenging.
- **POWERSTATS:** A powerful backdoor that runs obfuscated PowerShell scripts, enabling persistent access and further command execution on compromised systems, broadening the attacker’s capabilities while minimizing detection.
- **BugSleep:** A custom backdoor engineered to execute commands on demand and facilitate file transfers between an infected machine and MuddyWater’s C2 servers. Still under active development, **BugSleep** is continuously being enhanced and improved by the group.

---

In the fall of 2022, uncovered the IP address **51.254.25[.]36** as part of **MuddyWater’s** infrastructure — showing activity linked to this APT group going back to at least **February 2022**. Further analysis tied this IP to a suspicious executable named new aviation communications.exe, which is characteristic of **MuddyWater’s** tactic of deploying disguised payloads to target the aviation and communications sectors. This finding highlights the group’s ability to leverage custom malware linked to specific operational goals and underscores their ongoing focus on infrastructure and lateral movement in targeted intrusions.

![](https://cdn-images-1.medium.com/max/1000/0*oTRdjr01kkxUiFfm)

---

**SimpleHelp** by SimpleHelp Ltd (UK) is an administration panel for system administrators and tech support teams. It looks like this:

![](https://cdn-images-1.medium.com/max/1000/0*2FqFWlp-g9nOzmQN)

---

---

### Atera Agent

**MuddyWater** has recently intensified the use of Atera Agent, a legitimate Remote Monitoring and Management (RMM) tool, as part of its aggressive attack campaigns. Since late 2023, the group has refined its phishing tactics, distributing spear-phishing emails that carry malicious RAR archives. These RAR files are encrypted to evade detection by security software, forcing recipients to engage step-by-step with email content and download instructions that lead ultimately to the execution of the RMM tools.

![](https://cdn-images-1.medium.com/max/1000/0*wWsJ-jaP4Kn3qQxY)

---

MuddyWater’s recent campaigns using Atera Agent typically involve sending a compressed RAR file named digitalform.rar as an email attachment, which is decrypted using the password **“123456”**. Inside this archive is an **MSI** installation package for the Atera Agent remote monitoring tool.

During installation, the Atera Agent uses a built-in system account and a corresponding unique ID to connect directly to the Atera control console. This allows attackers to remotely control the infected system through Atera’s legitimate platform without setting up their own infrastructure. The installation process is silent and does not require user interaction beyond executing the MSI file extracted from the RAR archive.

![](https://cdn-images-1.medium.com/max/1000/0*smFge14TEr29ttng)

---

Once installed, the attacker gains full remote control over the victim’s computer through the **Atera** Agent platform. This control enables a broad range of actions including:

- Executing arbitrary commands remotely on the compromised system.
- Downloading and uploading files to and from the infected machine.
- Monitoring system activity in real time.
- Running additional third-party remote monitoring and management (RMM) software such as **Splashtop**, **AnyDesk**, **TeamViewer**, and **ScreenConnect** to maintain flexible and redundant remote access.

![](https://cdn-images-1.medium.com/max/1000/0*bSQexXSbnZ6RZRQJ)

---

It should be noted that a recent MuddyWater campaign involved distributing an Atera Agent installation package through the trusted file-sharing platform **Egnyte**, using a subdomain disguised to resemble a university in a Middle Eastern country (**kinnneretacil.egnyte[.]com**). The attackers crafted spear-phishing emails with links pointing to this Egnyte-hosted resource, which contained a ZIP archive holding the malicious Atera Agent installer.

![](https://cdn-images-1.medium.com/max/1000/0*kHbFzhWih-2Nmfq1)

---

### ScreenConnect

MuddyWater’s phishing campaigns have employed a layered social engineering approach, using decoy documents to lure victims deeper into infection. In one notable campaign, the attackers induced users to progress layer by layer through email content, which ultimately led to the installation of the **ScreenConnect** remote monitoring software on the victim’s system.

![](https://cdn-images-1.medium.com/max/1000/0*5zurQRNsbXDoFLxI)

---

In a recent MuddyWater phishing campaign, the decoy document contained a counterfeit hyperlink that led victims to the legitimate cloud storage service OneHub at the URL:  
[ws.onehub.com/files/7w1372el](http://ws.onehub.com/files/7w1372el).

This link downloaded a ZIP file named “**المنحالدراسیة.zip”** (which translates to “**scholarship.zip**”) with the MD5 hash **960594cbdf938bcb03bd0637843d9154**. Inside the ZIP archive was an executable file with the same name, which, when run, installed the legitimate **ScreenConnect** remote access software.

This delivery mechanism allowed **MuddyWater** to disguise its malicious activity under the veil of a seemingly benign and contextually relevant file — a scholarship announcement likely appealing to targets in the region. Upon execution, the **ScreenConnect** tool provided the threat actors remote control over the compromised system, enabling persistent espionage operations.

![](https://cdn-images-1.medium.com/max/1000/0*V1v0B9veBIXuRz36)

---

After the installation completes, the **ScreenConnect** Client service is created and automatically launched on the victim’s system. This service runs stealthily in the background, making it difficult for users to detect its presence through normal system use or casual inspection.

![](https://cdn-images-1.medium.com/max/1000/0*QDNTbzgT1j8N_j-S)

---

The ScreenConnect Client service startup parameters include critical connection details that enable the client to actively connect to the control terminal (C2 server). These parameters typically encode information such as:

- Session type (e.g., Access)
- Client type or role (e.g., Guest)
- Server URL or instance hostname (e.g., [instance-sy9at2-relay.screenconnect.com](http://instance-sy9at2-relay.screenconnect.com/))
- Port (e.g., 443 for HTTPS)
- Client GUIDs and other identifiers (e.g., **c=mfa&[c=mfa.gov](http://c=mfa.gov/)&c=mfa**)

example string:

e=Access&y=Guest&[h=instance-sy9at2-relay.screenconnect.com](http://h=instance-sy9at2-relay.screenconnect.com/)&p=443&c=mfa&[c=mfa.gov](http://c=mfa.gov/)&c=mfa&c=pc

The attacker opens **[instance-sy9at2-relay.screenconnect.com](http://instance-sy9at2-relay.screenconnect.com/)** and is able to remotely control the victim computer, execute various commands and install tools, among a range of other actions.
