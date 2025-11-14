---
title: "Threat Profile: APT35 (Charming Kitten)"
description: "In-depth threat profile of APT35 — Iran’s state-sponsored cyber-espionage group."
date: 2025-10-17
categories: [Threat Intelligence, State-Sponsored Threats]
classes: wide
header:
  teaser: /assets/images/apt35-teaser.png
ribbon: Red
toc: true
---

# Threat Profile: APT35 (Charming Kitten)

**Executive Summary**

APT35, also known as  _Magic Hound_  and  _Charming Kitten_, is an  **Iranian state-backed cyber espionage group**  active since at least  **2014**. The threat actor is known for  **strategic intelligence-gathering, data theft, and disruption operations**  aligned with  **Iran’s geopolitical and military objectives**.

The group’s primary targets include  **energy, government, defense, and technology sectors**, with particular focus on  **Saudi Arabia and Middle Eastern allies**. APT35 leverages  **spear-phishing, credential theft, and social engineering**  to gain  **initial access**, followed by  **custom malware and persistence techniques**  to maintain long-term footholds in high-value networks.

----------

**APT35 (Magic Hound)**  is a  **state-sponsored threat group**  linked to the  **Islamic Revolutionary Guard Corps (IRGC)**  of Iran. First observed in  **2012**, the group conducts  **information theft and espionage operations**  in support of Iran’s strategic and intelligence objectives.

Its operations blend  **espionage with influence operations**, often targeting  **government, private-sector, and research institutions**  to  **collect intelligence and shape narratives**  in favor of Iranian interests. Through persistent and well-coordinated cyber operations, APT35 has established itself as a  **key intelligence arm of Iranian cyber warfare**, blending espionage with influence operations to achieve long-term geopolitical goals.

----------

**Known Aliases**

-   APT35 | Ballistic Bobcat | Charming Kitten | CharmingCypress | Cobalt Illusion | COBALT MIRAGE | Educated Manticore | G0059 | Magic Hound | Mint Sandstorm | Newscaster Team | Phosphorus | TA453 | TEMP.Beanie | Tarh Andishan | Timberworm | TunnelVision | UNC788 | Yellow Garuda

**Notable Campaigns**  attributed to APT35 include:

-   BadBlood | Sponsoring Access | SpoofedScholars | Thamar Reservoir  
    

----------

**Operational Scope**

APT35’s activities reveal a  **wide geopolitical footprint**, with a  **primary concentration in the Middle East and North Africa (MENA)**  region. The group strategically extends its reach to  **Europe, the Americas, and the Asia-Pacific**, conducting operations that align with Iran’s foreign policy and intelligence objectives.

**Primary target countries:**

Saudi Arabia | United Arab Emirates | Qatar | Israel | Kuwait | United States | United Kingdom | Germany | France | Canada | Australia | India | South Korea | Japan

![](https://blog-wp.darkatlas.io/wp-content/uploads/2025/10/image-2-1024x979.png "Click to enlarge")

----------

**Targeted Sectors**  
APT35 runs highly tailored campaigns that prioritize  **espionage, data exfiltration, and operational disruption**  against organizations whose work matters to Iran’s national strategy.

Key sectors repeatedly targeted by APT35 include:

-   **Government Agencies  **& Diplomatic Bodies**:**  
    Focused on  **foreign ministries, interior ministries, and other high-value state institutions**, particularly in  **Egypt, Saudi Arabia, and Western Europe**. These entities are often targeted to gather diplomatic intelligence and influence policy decisions.
-   **Energy & Critical Infrastructure**:  
    Targets  **major oil and energy corporations**, especially in  **Saudi Arabia**  and the  **United Arab Emirates**, aiming to undermine regional energy stability and collect strategic industrial data.
-   **Telecommunications:**  
    Compromises  **telecom providers in the Gulf region and Western Europe**  to obtain  **network access, intercept communications**, and facilitate secondary intrusions.
-   ****Defense & Aerospace Contractors****:  
    Pursues  **military and defense technology firms**  in the  **United States, United Kingdom, and Gulf nations**, focusing on sensitive data related to weapons development, logistics, and regional defense projects.
-   ****Media, Journalism & Influence Channels**:**  
    Targets  **news outlets, journalists, and media professionals**, leveraging  **phishing and impersonation campaigns**  to manipulate narratives and conduct information operations.
-   **Academia & Research Institutions**  
    Infiltrates  **universities, research centers, and think tanks**  with expertise in  **Middle Eastern geopolitics, nuclear policy, and defense research**, often for intelligence-gathering purposes.
-   **Non-Governmental Organizations (NGOs):**  
    Targets  **human rights and civil society organizations**  whose activities intersect with Iran’s strategic or ideological interests.
-   **Information Technology and Cybersecurity Firms:**  
    Attacks  **IT service providers and cybersecurity vendors**  to steal credentials, compromise supply chains, and gain indirect access to client environments.
-   **Financial Services:**  
    Exploits  **financial institutions and fintech platforms**  to  **evade sanctions, conduct reconnaissance**, or facilitate broader economic disruption.
-   **Legal Sector:**  
    Targets  **law firms and consultancy practices**  engaged in  **sanctions compliance, litigation, and international arbitration**, seeking insights into cases affecting Iranian interests.

----------

# Multi-Stage Attacks & Cross-Platform Espionage — Recent Activity (2023–2024)

**Overview**  
Between  **2023 and 2024**, APT35 markedly intensified its operations, adopting more sophisticated social-engineering tactics and multi-stage infection chains to compromise high-value targets. The group combined refined phishing lures with layered payload delivery (cloud hosted C2, password-protected archives, malicious LNKs, etc.) to increase stealth, persistence, and the ability to bypass modern defenses.

----------

## Key developments (2023–2024)

-   **Escalation of complexity:**  Attack flows moved from single-stage malware drops to multi-stage chains that leverage cloud infrastructure, intermediary droppers, and encrypted/archived payloads to frustrate detection and analysis.
-   **Cross-platform reach:**  APT35 expanded from Windows-centric tooling to implants that support macOS and mixed environments, enabling espionage across endpoints, servers, and cloud services.
-   **Targeting profile:**  The group prioritized  **foreign affairs ministries, think tanks, nuclear/security researchers, journalists, academics, and civil-society organizations**  — essentially actors with strategic value to Iranian state objectives.
-   **Operational OPSEC & evasion:**  Use of IPFS/cloud hosting, anti-analysis measures, custom droppers, and legitimate service abuse to hide C2 and frustrate attribution.

----------

## Notable malware, tools & capabilities

Period

Malware / Tool

Notable features & tactics

2023–2024

**BellaCiao / BellaCPP**

Custom Windows droppers; BellaCPP is a C++ successor with persistence, payload delivery capabilities and SSH-tunneling support for covert comms.

2023–2024

**Powerstar (aka CharmPower)**

PowerShell backdoor leveraging IPFS and cloud-hosted C2; supports screenshot capture, persistence, and anti-analysis techniques.

2023–2024

**GorjolEcho / NokNok**

PowerShell and macOS implants for cross-platform espionage and data exfiltration.

2022–2024

**Hyperscrape**

Email-harvesting tool designed to extract messages from compromised mailboxes for targeted intelligence collection.

----------

## Exploited vulnerabilities

APT35 consistently exploits high-severity, publicly disclosed vulnerabilities to gain initial access and persist in victim environments. Representative CVEs observed in associated activity include:

CVE

Common name

How APT35 used it

**CVE-2021-44228**

Log4Shell

Remote code execution against public-facing services; used for rapid initial access and follow-on deployment.

**CVE-2021-26855**

ProxyLogon

Exchange RCE used to install web shells and secure footholds on mail infrastructure.

**CVE-2021-34473**

ProxyShell (component)

Chained with other Exchange issues to enable lateral movement and maintain persistence.

**CVE-2021-34523**

ProxyShell (privilege escalation)

Used in privilege-escalation chains to deepen network compromise.

----------

## Tactics & Tradecraft Highlights

APT35 campaigns demonstrate  **methodical tradecraft**, combining social engineering with layered technical delivery to ensure long-term operational access.

-   **Multi-stage delivery:**  Lures → droppers (LNK, archives) → staged payloads → backdoors/C2.
-   **Legitimate infrastructure abuse:**  Cloud hosting, IPFS, and public services used to host or proxy C2 traffic.
-   **Credential harvesting & mailbox compromise:**  Focus on harvesting emails and credentials to scale reconnaissance and lateral access.
-   **Anti-analysis & persistence:**  Custom C++ implants, PowerShell obfuscation, and and multi-layer persistence mechanisms designed to resist detection and forensic analysis.

----------

## Operational impact

These enhanced capabilities enable APT35 to:

1.  Maintain  **covert, long-term access**  to sensitive networks.
2.  **Exfiltrate diplomatic, defense, and energy intelligence**  with minimal detection.
3.  Operate across  **Windows, macOS, and cloud ecosystems**  with reduced exposure risk.

----------

**Key actors (roles & tradecraft)**

APT35 — also known as  **Charming Kitten**  — operates through a  **network of skilled operators**, infrastructure managers, and social-engineering specialists tied to  **Iran-aligned cyber espionage**. Public reporting and judicial filings identify several individuals who have been linked to the group’s operational and hosting infrastructure, and who have been associated through social-media interactions, shared hosting resources, and alleged operational roles.

#### **Key Actors (Roles & Tradecraft)**  

-   **Behzad Mesri (alias: “Skote Vahshat”, “Mr. Smith”)**  
    Mesri is a long-standing actor linked to  **Iranian offensive cyber operations**, reportedly involved in the  **2017 HBO breach**  and several state-sponsored attacks. U.S. Department of Justice filings describe him as part of a broader ecosystem supporting  **IRGC-linked operations**.  
    

![](https://blog-wp.darkatlas.io/wp-content/uploads/2025/10/image-3.png "Click to enlarge")

  
  
**Mohammadamin Keshvari (aliases: “ArYaIeIrAn” / ArYaIeIrAn email handles shown in reporting)**  
Open-source reporting and vendor analysis have connected a persona using the handle  _ArYaIeIrAn_  to domain-management activity and to an individual identified as Mohammadamin Keshvari. That reporting links the persona to Mahanserver (an Iran-based web-hosting provider) and suggests a role managing malicious domains and infrastructure used in phishing and staging. These identifications are based on OSINT techniques (profile-picture correlation, domain registration/redirect patterns, and hosting relationships) and should be treated as vendor-level assessments.

**Mohammad Rasoul Akbari (alias: “ra3ou1”) — Mahanserver**  
Publicly available profiles and reporting identify Mohammad Rasoul Akbari as the founder/CEO of Mahanserver, an Iranian hosting provider that has been observed in vendor reporting as hosting domains and services used in Charming Kitten-attributed operations. Analysts have noted social-graph connections (mutual follows/friends) between Akbari and other alleged operators in open-source material; vendor reporting also references Mahanserver infrastructure as being operationally useful to the group. Public business profiles for Akbari corroborate his role with Mahanserver.

![](https://blog-wp.darkatlas.io/wp-content/uploads/2025/10/image-4-1024x518.png "Click to enlarge")

**Infrastructure notes (public reporting)**  
Researchers have observed Mahanserver-hosted domains and persiandns-style redirects associated with command-and-control, drop sites, and staging pages attributed to Charming Kitten activity. Some reporting geolocates that infrastructure to Tehran, Iran, based on public IP/hosting data and mapping services; as with all infrastructure ties, these observations are operational indicators that require continual validation because hosting and routing can change quickly.

----------

### Assessment of Key Actors

With  **medium confidence**, it is assessed that  **Behzad Mesri**,  **Mohammadamin Keshvari**, and  **Mohammad Rasoul Akbari**  serve as  **core members or critical enablers**  within  **APT35 (Charming Kitten)**. Collectively, they likely form part of the  **group’s operational backbone**, working alongside additional, unidentified operatives.  
Their demonstrated expertise in  **cyber intrusion, infrastructure administration, and social engineering**  strongly aligns with  **APT35’s established tradecraft**  and operational sophistication.

![](https://blog-wp.darkatlas.io/wp-content/uploads/2025/10/image-5.png "Click to enlarge")

----------

![](https://blog-wp.darkatlas.io/wp-content/uploads/2025/10/image-6.png "Click to enlarge")

----------

### Vulnerabilities, Attack, and Campaign History

#### **Charming Kitten Deploys New “NokNok” Malware**

APT35 has recently advanced its operational toolkit by introducing  **NokNok**, a newly observed malware variant specifically targeting  **macOS**  systems.  
Unlike previous campaigns that leveraged  **malicious Microsoft Word documents**, NokNok is  **delivered via LNK shortcut files**, marking a significant  **shift in TTPs**  (Tactics, Techniques, and Procedures).

This campaign is characterized by a  **highly refined social engineering strategy**, wherein threat actors  **impersonate U.S. nuclear experts**  and other credible figures to  **gain the trust of their targets**.  
Such impersonation techniques reinforce the group’s emphasis on  **strategic deception and human-targeted intrusion pathways**.

Analysts assess this evolution as indicative of APT35’s  **ongoing adaptability and technical advancement**, aligning with its broader mission of  **espionage and intelligence collection**  on behalf of the  **Islamic Revolutionary Guard Corps (IRGC)**.

![](https://blog-wp.darkatlas.io/wp-content/uploads/2025/10/image-7.png "Click to enlarge")

----------

# GorjolEcho Backdoor

**APT35 (Charming Kitten)**  delivers a  **multi-stage, cloud-hosted intrusion chain**, blending  **social engineering**  with  **legitimate-looking cloud services**  to quietly bypass defenses.

**Infection flow (summary):**

1.  Operators send a malicious link that hosts a Google Apps Script macro which immediately redirects the victim to a Dropbox URL.
2.  The Dropbox location serves a  **password-protected RAR**  archive. The archive contains a small malware dropper that leverages  **PowerShell**  and an  **LNK**  shortcut to stage the next stage from a cloud hosting provider.
3.  The staged downloader fetches and installs the final payload —  **GorjolEcho**, a remote backdoor capable of receiving and executing operator commands.
4.  As a deception measure, GorjolEcho opens a context-relevant PDF (e.g., a previously discussed document) on the victim’s system to reduce suspicion and delay incident discovery.

![](https://blog-wp.darkatlas.io/wp-content/uploads/2025/10/image-8.png "Click to enlarge")

----------

### macOS-targeted Lure — RUSI VPN App (refined)

**APT35 customizes each lure**  based on the target’s platform. For macOS users, they distribute a  **fake “RUSI VPN” installer**  — a ZIP file disguised as a legitimate app bundle.  
When executed, the bundle quietly  **drops a covert payload**  and sets up  **persistence under the guise of a VPN client**.

![](https://blog-wp.darkatlas.io/wp-content/uploads/2025/10/image-10.png "Click to enlarge")

**Attack characteristics (high-level, non-actionable)**

-   **Platform-aware lures**: Tailored macOS VPN themes boost victim trust.
-   **Disguised packaging**: Malware wrapped inside .app bundles mimicking real software.
-   **Trust manipulation**: Fake RUSI branding leverages credibility.
-   **Post-install stealth**: Background persistence and covert network beacons maintain access.

**Detection & defensive guidance (practical, non-actionable)**

-   **Gatekeeper & notarization checks:**  Enforce Gatekeeper policies and require Apple notarization/code-signature verification for all installed macOS apps. Alert on execution of unsigned or non-notarized  `.app`  bundles.
-   **Download source controls:**  Restrict downloads from unverified cloud or third-party sources. Mandate checksum validation or integrity verification for any app distributed outside official channels.
-   **Monitor persistence artefacts:**  Watch for creation of suspicious  `~/Library/LaunchAgents`,  `/Library/LaunchDaemons`, or other persistent plist entries following new app installs.
-   **Process & child-tree telemetry:**  Alert on newly installed app processes that spawn shells, install background agents, or open uncommon network connections soon after first-run.
-   **Network egress monitoring:**  Profile expected behavior for legitimate VPN clients; flag deviations such as unexpected remote C2-like endpoints, long-lived low-volume connections, or connections to short-lived domains/object storage.
-   **User education & packaging hygiene:**  Train users to validate vendor sources and to treat unsolicited VPN installers with suspicion; establish an approved-app distribution channel (MDM) for required remote-access tools.

![](https://blog-wp.darkatlas.io/wp-content/uploads/2025/10/image-9.png "Click to enlarge")

----------

![](https://blog-wp.darkatlas.io/wp-content/uploads/2025/10/image-11.png "Click to enlarge")

----------

![](https://blog-wp.darkatlas.io/wp-content/uploads/2025/10/image-12.png "Click to enlarge")

----------

### Mid-2025 Spear-Phishing Campaign — APT35 (Educated Manticore / Charming Kitten)

In  **mid-2025**, amid heightened  **Iran–Israel geopolitical tensions**,  **Iranian state-sponsored actors**  linked to  **APT35 (a.k.a. Educated Manticore / Charming Kitten)**  initiated a  **highly targeted spear-phishing campaign**  against  **Israeli journalists, cybersecurity professionals, and academics**.

The campaign demonstrated APT35’s adaptive tradecraft, sophisticated deception, and deep understanding of human trust mechanisms.

----------

#### **Attack Summary**

-   **Initial Approach:**  
    Adversaries posed as  **research assistants, analysts, or conference coordinators**, contacting victims through  **email and WhatsApp**.  
    Messages contained  **fake meeting invitations**,  **collaboration requests**, or  **inquiries for expert opinions**, all tailored to the target’s field of work.
-   **Delivery Vector:**  
    The attackers directed victims to  **phishing websites**  that  **mimicked Google services**, particularly  **Google Login**  and  **Google Meet**  pages.  
    These sites were meticulously cloned and often  **hosted on legitimate Google Sites infrastructure**, lending them additional authenticity.
-   **Credential Theft Mechanism:**  
    The phishing kit featured:
    -   **React-based web applications**  for realistic interactivity and responsiveness.
    -   **WebSockets**  for real-time data transmission between victim and attacker infrastructure.
    -   **Integrated keylogging and session relay**  capabilities, allowing immediate capture of  **credentials**  and  **two-factor authentication (2FA)**  codes.
    -   **Live relay of 2FA codes**, enabling attackers to log into accounts before token expiration.

----------

### Fake Personas, Malicious Content Pages, and Browser Exploitation.

APT35 routinely uses  **fabricated online personas and site content**  to build credibility, extend victim engagement, and create windows for technical exploitation.

![](https://blog-wp.darkatlas.io/wp-content/uploads/2025/10/image-13.png "Click to enlarge")

**Persona & social engineering tactics**

-   The group crafts convincing fake profiles (for example, a LinkedIn persona “Isabella Carey”) and shell news outlets to establish legitimacy. These personas and sites are used to  **initiate contact**, cultivate trust, and encourage victims to remain on pages longer than they otherwise would.
-   Common personas pose as  **students, journalists, or research assistants**  and are tailored to the target’s area of expertise—especially people researching Iran—so outreach appears contextually believable.
-   Attackers use multiple communication channels (email, LinkedIn, WhatsApp, social media) and often link to content hosted on  **reputable platforms**  (e.g., Google Sites) to increase perceived authenticity.

**Malicious site functionality**

-   The fake news pages frequently include links to attacker-controlled social accounts and interactive content designed to hold the visitor’s attention. Extended dwell time is an operational goal: it  **increases the chance of successful exploitation**  by client-side tooling.
-   Embedded in these pages, operators have deployed  **Browser Exploitation Framework (BeEF)**  modules or similar browser-based tooling. While BeEF is a legitimate penetration-testing framework, in this context it’s used to  **probe a visitor’s browser for vulnerabilities, run automated exploitation attempts, and gather reconnaissance**  while the user remains on the page.

![](https://blog-wp.darkatlas.io/wp-content/uploads/2025/10/image-14.png "Click to enlarge")

**Operational tradecraft**

-   Use of  **trusted hosting**  (Google Sites, content hosted on reputable platforms) and  **realistic site design**  makes manual inspection less likely and can reduce automated filtering.
-   Attackers chain social-engineering and client-side exploitation: social trust gets victims to the page → interactive content keeps them engaged → BeEF-like tooling probes and attempts exploitation.

**Detection & mitigation (high-level, non-actionable)**

-   Treat unsolicited contact that encourages visiting third-party sites—especially those on hosted or branded platforms—with heightened suspicion.
-   Monitor and alert on long-lived sessions where pages load third-party scripts or initiate WebSocket/long-polling connections not associated with known, legitimate services.
-   Apply browser hardening and enterprise controls: block or alert on the execution of suspicious in-page scripts, disable unnecessary features (e.g., legacy plugins), and require up-to-date browser versions with security patches.
-   Enforce strict phishing-resistant authentication and session protections to reduce the value of harvested credentials or session tokens.

![](https://blog-wp.darkatlas.io/wp-content/uploads/2025/10/image-16.png "Click to enlarge")

----------

**OPSEC Failure**

### Major Breach of APT35 (Charming Kitten) — Internal Leak Exposure

In what appears to be  **one of the most significant exposures of an Iranian state-sponsored cyber operation to date**, an  **anonymous whistleblower**  or  **rival actor**  has publicly released a cache of  **internal documents, employee data, and operational records**  belonging to  **APT35 (a.k.a. Charming Kitten / Educated Manticore)**  — a cyber-espionage group tied to Iran’s  **Islamic Revolutionary Guard Corps (IRGC)**.

![](https://blog-wp.darkatlas.io/wp-content/uploads/2025/10/image-17-1024x519.png "Click to enlarge")

----------

The leak, published on GitHub under the alias  **“KittenBusters,”**  exposes hundreds of internal files linked to Charming Kitten’s operations. These include  **attack reports, daily activity logs, internal communications, malware samples,**  and even  **photographs of personnel**  allegedly affiliated with the group. Among the disclosed details is the identification of  **Abbas Rahrovi (a.k.a. Abbas Hosseini)**, reportedly the  **leader of the operation**. The leaked data includes his  **Iranian national identification number [4270844116]**  and suggests he oversees Charming Kitten’s cyber activities through a  **network of front companies**  used to obscure state involvement and facilitate operational funding.

----------

What distinguishes  **Charming Kitten**  from other Iranian cyber actors is its  **patient and methodical tradecraft**. The group’s operators frequently invest  **weeks or even months**  cultivating trust with their targets through  **carefully crafted social engineering campaigns**. They often impersonate  **journalists, academic researchers, or conference organizers**, engaging in extended correspondence to establish credibility before delivering  **malicious links, weaponized documents, or phishing payloads**. This deliberate, human-centric approach reflects a  **strategic emphasis on persistence and psychological manipulation**, setting Charming Kitten apart from more opportunistic or technically focused Iranian threat groups.

![](https://blog-wp.darkatlas.io/wp-content/uploads/2025/10/image-18-1024x573.png "Click to enlarge")

----------

The leaked archive, meticulously organized into a hierarchical directory structure, exposes the  **day-to-day operations of a state-sponsored cyber unit**. The documents span multiple years, with filenames referencing the  **Persian calendar year 1403**—corresponding to  **2024 in the Gregorian calendar**—and earlier materials dating back to  **May 2022**. This suggests the leak covers  **at least two years of continuous operations**  by the Charming Kitten group.

A prominent folder titled  **“All_Proxy_Shell_Targets”**  contains subdirectories for  **Iran, South Korea, Kuwait, Turkey, Saudi Arabia, and Lebanon**, documenting exploitation activities against  **Microsoft Exchange servers**  through  **ProxyShell vulnerabilities**. This aligns with Charming Kitten’s established tactics of compromising  **email infrastructures**  to obtain  **persistent access to sensitive communications**.

Another directory, labeled  **“Attack Reports,”**  includes numerous  **Persian-language documents**  bearing the title  **“گزارش عملکرد ماهانه” (Monthly Performance Report)**. These reports, authored by operators identified as  **Majid, Mehyar, and Hosein**, describe routine assignments such as  **monitoring social media profiles, conducting OSINT collection, and maintaining phishing infrastructure**. In several cases, the files also record  **daily work hours**, providing rare insight into the  **bureaucratic and regimented nature of Iranian state-backed cyber operations**.

![](https://blog-wp.darkatlas.io/wp-content/uploads/2025/10/image-19-1024x690.png "Click to enlarge")

----------

Perhaps most striking is a folder containing employee photographs, with filenames in Persian that appear to include personal names. This level of exposure represents a severe and unprecedented operational security failure for an intelligence unit that has historically maintained strict secrecy. The inclusion of personal identifiers and visual records of personnel not only compromises individual operatives but also provides unique attribution opportunities for intelligence and law enforcement agencies worldwide. This kind of leak is rare in state-sponsored cyber operations and significantly erodes the group’s ability to operate covertly.

![](https://blog-wp.darkatlas.io/wp-content/uploads/2025/10/image-20-621x1024.png "Click to enlarge")

----------

According to the leak’s introductory documents,  **Charming Kitten has allocated considerable resources to tracking Iranians labeled as “regime opponents”**, both within the country and across the global diaspora. This  **persistent focus on dissidents, journalists, and activists abroad**  aligns with a broader Iranian strategy of  **integrating cyber operations with real-world surveillance and intimidation campaigns**.

**Human rights organizations**  have long reported that the Iranian government leverages a combination of  **digital espionage, coercion, and transnational repression**  to silence opposition voices. The leaked materials—detailing operational logs, target lists, and internal tasking orders—offer  **rare, primary-source evidence of the bureaucratic and military coordination**  underpinning these efforts. They illuminate how  **state-sponsored cyber units**  like Charming Kitten serve as extensions of Iran’s  **domestic intelligence apparatus**, blurring the line between cybersecurity operations and political repression.

![](https://blog-wp.darkatlas.io/wp-content/uploads/2025/10/image-21-963x1024.png "Click to enlarge")

----------

### **Conclusion**

The operations attributed to  **APT35 (Charming Kitten / Educated Manticore)**  reflect the  **strategic persistence, adaptability, and geopolitical intent**  that define Iran’s state-sponsored cyber ecosystem. By blending  **long-term social engineering**,  **custom malware development**, and the  **abuse of trusted cloud services**, the group continues to evolve its playbook—driven by goals of  **espionage, surveillance, and information dominance**  in alignment with Tehran’s regional ambitions.

The  **KittenBusters leak**  provides an  **unprecedented window**  into the inner mechanics of this threat actor—revealing not just its  **technical sophistication**, but also its  **organizational hierarchy, daily workflows, and direct links**  to the  **Islamic Revolutionary Guard Corps (IRGC)**. These insights underscore the  **bureaucratic precision of modern cyber warfare**, where offensive operations are managed with the  **discipline and structure**  of an intelligence agency.

Charming Kitten’s sustained focus on  **government institutions, energy infrastructure, defense contractors, media entities, academia, and diaspora communities**  illustrates a  **layered and persistent targeting strategy**—one that merges  **strategic espionage**  with  **domestic repression**. The fusion of  **digital espionage and psychological operations**  within Iran’s broader intelligence framework highlights the regime’s  **growing reliance on cyber power as an instrument of statecraft and control**.

Ultimately, APT35 embodies how  **cyber espionage has evolved into a core extension of national policy**—serving as a vehicle for  **regime preservation, regional influence, and intelligence gathering**. The exposure of its internal workings not only  **undermines operational secrecy**, but also provides the global cybersecurity community with  **rare insight into the evolution of Iranian cyber doctrine**—a doctrine that intricately weaves  **espionage, propaganda, and digital authoritarianism**  into a  **cohesive state strategy**.

----------

# MITRE ATT&CK

## Initial Access

Technique

Technique ID

Use

Spearphishing Attachment

T1566.001

Used malicious document lures in emails impersonating news outlets, universities, or HR departments (e.g., “Deutsche Welle”, “Jewish Journal”) to deliver malware (e.g., PupyRAT, PowerShell tools).

Spearphishing Link

T1566.002

Commonly used credential phishing pages disguised as Google, Yahoo, Outlook login portals.

Drive-by Compromise

T1189

Lured victims to fake websites mimicking trusted domains (e.g., spoofed ClearSky website).

Exploit Public-Facing Application

T1190

Used Log4Shell to gain initial access in some 2021–2022 campaigns.

## Credential Access

Technique

Technique ID

Use

Credential Phishing

T1566

Core technique in nearly all campaigns, harvesting email credentials through spoofed login pages.

Brute Force

T1110

Conducted password spraying to access targeted accounts.

Credentials from Password Stores

T1555

TA453 reportedly harvested browser-stored credentials and tokens.

## Discovery

Technique

Technique ID

Use

System Information Discovery

T1082

PowerShell-based implants like POWERSTAR gathered host metadata.

File and Directory Discovery

T1083

Malware modules enumerate directories for exfiltration targets.

Network Service Scanning

T1046

Recon of internal networks reported during ransomware-style attacks by COBALT MIRAGE.

## Persistence

Technique

Technique ID

Use

Web Shell

T1505.003

Planted ASPX web shells during exploit operations (Log4Shell, Exchange).

Valid Accounts

T1078

Maintained persistence using compromised accounts across M365 and VPN.

## Defense Evasion

Technique

Technique ID

Use

Obfuscated Files or Information

T1027

Used password-protected ZIPs to evade scanning during delivery.

Masquerading

T1036

Impersonated legitimate organizations and individuals (e.g., fake podcast invites, fake researchers).

## Command and Control

Technique

Technique ID

Use

Application Layer Protocol: Web Protocols

T1071.001

Used HTTPS for C2 over legitimate-looking domains.

Custom C2 Protocol

T1095

Educated Manticore campaign used custom backdoors and encrypted C2.

## Collection

Technique

Technique ID

Use

Email Collection

T1114

Collected inbox data and contact lists from targeted accounts.

Input Capture: Keylogging

T1056.001

Reported in use by POWERSTAR variants.

Screen Capture

T1113

POWERSTAR and other RATs included screenshot capabilities.

## Exfiltration

Technique

Technique ID

Use

Exfiltration Over Web Service

T1567

Exfiltrated stolen files to attacker-controlled cloud storage (Google Drive, OneDrive).

Exfiltration Over Web Service: To Cloud Storage

T1567.002

Continued use of RClone and similar tools reported.

## Impact

Technique

Technique ID

Use

Data Destruction

T1485

Cobalt Mirage (affiliated group) engaged in disk wipers in some ransomware-like operations.

Data Encrypted for Impact

T1486

Employed ransomware to pressure victims in “ransom-then-steal” operations.

Defacement

T1491

Less frequent, but fake news defacements have been documented in psychological ops.

## Known Tools

Tool Name

Tool Hash

MITRE ATT&CK ID

EmailDownloader.exe

35a485972282b7e0e8e3a7a9cbf86ad93856378fd96cc8e230be5099c4b89208

S0002

Pavilion.exe

00b5d45433391146ce98cd70a91bef08

S0194

PuTTY

19c0977fdbc221f7d6567fb268a4ef4cd2a759fcbc1039a82366978089f080d2

S0218

FUDDO~1.EXE

af5c01a7a3858bc3712ab69bc673cec4

S0154

er.exe

72071c6471e0dc8c1c23fc149c816f8f2fbf163e2de5debfbf741f178620e846

S0029

WEXTRACT.EXE.MUI

610fac8675cb9df3af83449ccdb814052a7f66c3

S0089

wuauclt.exe

b030729cbcbc045528fb13df8c57f1d2a385e176

S0357

systemnetwork.bin

e5ee874bd59bb2a6dec700686544e7914312abff166a7390b34f7cb29993267a

S0070

Sponsor

c4dbda41c726af9ba3d9224f2e38fc433d2b60f4a23512437adeae8ef8986c57

S0160

csext.exe

15121b7cbd15143fc0118e06ebe70b7dc1e239b21d865b2c750ed8a0f1f00ef2

S1047

## IOCs (Indicators of Compromise)

### File Hashes (SHA-256)

Hash

03d0e7ad4c12273a42e4c95d854408b98b0cf5ecf5f8c5ce05b24729b6f4e369

35a485972282b7e0e8e3a7a9cbf86ad93856378fd96cc8e230be5099c4b89208

5afc59cd2b39f988733eba427c8cf6e48bd2e9dc3d48a4db550655efe0dca798

6dc0600de00ba6574488472d5c48aa2a7b23a74ff1378d8aee6a93ea0ee7364f

767bd025c8e7d36f64dbd636ce0f29e873d1e3ca415d5ad49053a68918fe89f4

977f0053690684eb509da27d5eec2a560311c084a4a133191ef387e110e8b85f

ac8e59e8abeacf0885b451833726be3e8e2d9c88d21f27b16ebe00f00c1409e6

cd2ba296828660ecd07a36e8931b851dda0802069ed926b3161745aae9aa6daa

668ec78916bab79e707dc99fdecfa10f3c87ee36d4dee6e3502d1f5663a428a0

724d54971c0bba8ff32aeb6044d3b3fd571b13a4c19cada015ea4bcab30cae26

24a73efb6dcc798f1b8a08ccf3fa2263ff61587210fdec1f2b7641f05550fe3b

28332bdbfaeb8333dad5ada3c10819a1a015db9106d5e8a74beaaf03797511aa

e6f4ce982908108759536f5aff21fa6686b8ea8153fdd4cdd087cceff5f1748a

927289ddccbb1de98fe3f8af627296d0d7e9833c8f59e5e423fe283b6792da89

9dce6086c61c23420ac497f306debf32731decc5527231002dbb69523fad3369

6e842691116c188b823b7692181a428e9255af3516857b9f2eebdeca4638e96e

bc8f075c1b3fa54f1d9f4ac622258f3e8a484714521d89aa170246ce0470144

### IPv4 Addresses

Address

54.37.164.254

109.202.99.98

134.19.188.242

134.19.188.243

134.19.188.244

134.19.188.246

185.23.214.188

213.152.176.205

213.152.176.206

146.59.185.15

146.59.185.19

185.23.214.187

85.114.138.96

168.100.8.190

168.100.10.216

### Domains

Domain

linkedinz.me

listen-books.com

lukoil.in

mastergatevpn.com

microsoftcdn.co

microsoftdefender.info

microsoftedgesh.info

mideasthiring.com

office-shop.me

onedrivelive.me

onedriveupdate.net

online-audible.com

online-chess.live

outlookde.live

outlookdelivery.com

remgrogroup.com

saipem.org

sauditourismguide.com

savemoneytrick.com

sharepointnotify.com

sparrowsgroup.org

supportskype.com

talent-recruitment.org

talktalky.azurewebsites.net

thefreemovies.net

updateddns.ddns.net

updatedefender.net

updatedns.ddns.net

updateservices.co
