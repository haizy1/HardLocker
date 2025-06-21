# HardLocker
## Project Overview
The project focuses on evaluating the security limitations of AppLocker, a native Windows feature used for application whitelisting, and on developing an automated PowerShell based tool designed to detect and remediate known bypass techniques.
### General Context 
Application whitelisting is a key layer in endpoint protection strategies, particularly in Windows environments. AppLocker, Microsoft’s native application control feature, allows administrators to define policies that restrict the execution of unauthorized files based on parameters such as path, publisher, or file hash. Despite its potential, AppLocker is not immune to bypasses. Over the years, multiple bypass techniques have been discovered, often leveraging LOLBAS, misconfigured permissions, writable directories, PowerShell abuse, or alternate data streams. These methods highlight gaps in default configurations and expose how AppLocker can be circumvented by adversaries.
This project focuses on analyzing these bypasses in depth and developing remediation rules to block them. The ultimate objective is to enhance AppLocker’s effectiveness by
implementing custom hardened policies, and to support this process through the creation of an automated PowerShell-based tool capable of scanning, applying, and reverting AppLocker configurations.
### Problem Statement
Default AppLocker policies often leave gaps that can be exploited by attackers. Many organizations deploy AppLocker without adapting it to the evolving threat landscape or
known bypass vectors. As a result, security is often overestimated, and attackers can still achieve code execution using well-documented techniques.
This project addresses the lack of visibility and remediation mechanisms around these bypasses by proposing a systematic approach to detect, block, and prevent them.

### Proposed Solution
To address the limitations of AppLocker rules , this project introduces an automated PowerShell tool designed to strengthen application control on Windows. The tool was
developed after researching and understanding the most common and well-documented AppLocker bypass techniques.
Its main goal is to apply defensive rules that prevent these bypasses and help secure the system in a practical and adaptable way. The tool offers three predefined profiles(rules):
Basic Profile – Recommended for standard users, applying essential protections without disrupting usability.
Hardened Profile – A stricter setup designed for administrators or high-privilege environments, blocking a wider range of bypass techniques.
Custom Profile – Allows users to select specific rule sets based on their needs.
The tool also supports scanning for AppLocker weaknesses, as well as backup, rollback, and policy enforcement mode selection ,providing both flexibility and control over the
AppLocker configuration process.

### Existing Solutions
Several open-source tools are available to assist with AppLocker configuration and deployment, but most remain limited in scope. AaronLocker provides policy templates and
scripts to guide rule creation, but it lacks flexibility and does not adapt to specific attack scenarios. Applocker-Hardening automates the application of static policies, without offering any real analysis or bypass detection. AppLockerGen focuses on generating XML rules through a user-friendly interface but offers no support for hardening or automation. The following table provides a benchmark comparison of the existing tools based on their ability to manage, harden, and automate AppLocker configurations.
<p align="center">
  <img width="450" height="258" src="images/Capture d'écran 2025-06-21 154438.png">
</p>
These solutions are helpful in certain contexts, but none offer a complete framework that automates detection, hardening, rollback, and customized policy application in response to real-world AppLocker bypasses. This project aims to fill that gap by providing a tool that brings all these capabilities together in a single, adaptable solution.

### Known AppLocker Bypass Techniques Remediated by HardLocker
#### LOLBAS Abuse :
Living Off The Land Binaries, Scripts and Libraries refer to legitimate, pre-installed Windows utilities that can be repurposed by attackers to execute malicious payloads while avoiding detection. Since these tools are signed by Microsoft and often whitelisted by default, they provide an effective method for bypassing application control mechanisms such as AppLocker. Attackers frequently exploit binaries like mshta.exe, msbuild.exe, regsvr32.exe, and cmstp.exe to run unauthorized code without triggering security alerts. This technique allows adversaries to operate covertly using trusted system components.
I've tested [**InstallUtil.exe**](InstallUtil.exe.pdf) and [**MSBuild.exe**](Msbuild.exe.pdf) to reproduce them. I invite you to read those two files, as they explain the steps in detail. 
#### Writable Paths and Misconfiguration :
AppLocker enforces policies based on file locations, but its effectiveness can be undermined by improper directory permissions. Many paths, including %TEMP%, %APPDATA%,
and C:\Windows\Tasks\, are writable by non-privileged users. Attackers take advantage of these directories to drop and execute malicious files within otherwise trusted
locations. Without additional rules to explicitly block execution from these paths, even well-configured AppLocker environments can be bypassed. Securing these locations is
therefore a critical step in mitigating exploitation risks.
#### Alternate Data Streams (ADS) :
Alternate Data Streams (ADS) are a feature of the NTFS file system that allows data
to be stored in a hidden stream attached to a file. Attackers exploit ADS to hide malicious executables within seemingly innocuous files, allowing execution that can evade
AppLocker’s default rules. For instance, a payload might be written to file.txt:evil.exe and executed without being directly visible in file explorers. Since AppLocker does not natively inspect ADS, specific path rules must be configured to block these hidden streams effectively.
#### PowerShell v2 and Script Execution :
PowerShell Version 2 presents a significant security risk in modern environments due to its lack of support for key protections such as Constrained Language Mode and advanced
logging features. Attackers often target systems where PowerShell v2 is enabled, using it to execute malicious scripts without triggering AppLocker restrictions. Because AppLocker cannot effectively control script execution in this legacy version, organizations are advised to disable PowerShell v2 entirely and enforce script execution rules on modern versions with signed code requirements.
#### Reflective PE Injection (Fileless Execution) :
Reflective PE Injection is a technique used to load and execute portable executable (PE) files directly in memory without writing them to disk. This approach allows attackers to completely bypass AppLocker, which monitors disk-based execution. Tools like PowerSploit’s Invoke-ReflectivePEInjection script enable adversaries to store malicious binaries in memory and invoke them programmatically, leaving no artifacts behind. Since this method avoids traditional file-based triggers, it represents a powerful bypass against AppLocker and traditional antivirus mechanisms.
#### Office Add-ins and VSTO Exploitation :
Attackers can exploit Visual Studio Tools for Office (VSTO) add-ins to execute malicious code when opening applications like Word or Excel. These add-ins can run without
administrator privileges and are not blocked by AppLocker by default. This makes them a stealthy method for persistence and code execution within trusted programs.
#### DLL Hijacking :
DLL hijacking is a technique in which an attacker exploits the way a legitimate application loads dynamic link libraries (DLLs). Many Windows applications dynamically load DLLs from specific locations, often using relative paths. If the application does not explicitly specify a full path or validate the origin of the DLL, Windows will search for it in a predefined order , including directories that may be writable by users. An attacker can take advantage of this by placing a malicious DLL with the same name
as a legitimate one in a location that is searched before the correct directory. When the application is executed, it unknowingly loads the attacker’s malicious DLL instead of the intended one. This allows arbitrary code execution within the context of a trusted, often whitelisted, executable.
#### Exploitation of User-Writable System Files :
In some cases, AppLocker can be bypassed through exploitation of user-writable files located within trusted system directories. A notable example involves three files found
in C:\Windows\System32\AppLocker : AppCache.dat, AppCache.dat.LOG1, and AppCache.dat.LOG2. These files are writable by the first user who logs into the system after AppLocker has been deployed. Although they are not executables themselves, their write permissions can be abused as part of a broader evasion strategy, allowing an attacker
to plant or manipulate data in a location that is typically trusted by default AppLocker rules. This scenario highlights a subtle but impactful misconfiguration, where trusted paths intersect with insecure permissions.

Explore these bypasses in more detail in this [**document**](the_Generic_bypasses_and_the_famous_ones.pdf) where I explain the techniques and also provide suggestions on how to remediate them using AppLocker rules. 


### Implementation of the solution
Here, we present the practical realization of the HardLocker tool, designed to automate the hardening of Windows systems through AppLocker. The implementation is
based on a detailed analysis of known bypass techniques and common misconfigurations observed in enterprise environments.
<p align="center">
  <img width="400" height="258" src="images/Capture d'écran 2025-06-12 003855.png">
</p>

#### Design Choices and Testing Environment :
HardLocker was developed entirely in PowerShell to ensure seamless integration with native Windows systems, avoid external dependencies, and simplify administrative usage.
All testing and validation were carried out on a Windows 10 Professional virtual machine, a deliberate choice for both compatibility and realism. Windows 10 remains widely used in production environments and provides an ideal platform to study known AppLocker bypass techniques. Its balance of flexibility and legacy support made it preferable for experimentation and research purposes compared to Windows 11, which enforces stricter security policies that may hinder low-level testing.
#### HardLocker main features :
The main menu is the central point of interaction between the user and the HardLocker tool. It is designed to be simple and easy to navigate, using a clear text-based interface built with PowerShell.
<p align="center">
  <img width="400" height="258" src="images/Capture d'écran 2025-06-11 194800.png">
</p>

##### Profile Selection Module :
The tool offers three predefined profiles to match different levels of security:

<p align="center">
  <img width="400" height="258" src="images/Capture d'écran 2025-06-11 194950.png">
</p>

• **Basic**: For users who want to improve security without affecting normal usage. The rules in this profile are selected carefully to avoid blocking legitimate apps.
<p align="center">
  <img width="400" height="258" src="images/Capture d'écran 2025-06-11 195054.png">
</p>
As shown in the image above, after selecting the Basic profile and the enforcement mode, the tool automatically backs up the current policy, applies the selected rules,
refreshes the AppLocker interface, and redirects the user to the main menu to continue.
<p align="center">
  <img width="400" height="258" src="images/Capture d'écran 2025-06-11 195129.png">
</p>

• **Hardened** : Provides stronger protection, targeting more aggressive attack techniques. It is suitable for sensitive environments where maximum security is required. Applied the same way as the basic profile.
• **Custom** : Allows the user to select specific rules manually. This profile is ideal for experienced users who know their environment and want more control.

<p align="center">
  <img width="400" height="258" src="images/Capture d'écran 2025-06-11 195931.png">
</p>

With the Custom profile, the user selects specific rules from a list, then chooses the enforcement mode. The tool backs up the current policy, applies the selected rules, and saves them in a custom policy file.

<p align="center">
  <img width="400" height="258" src="images/Capture d'écran 2025-06-11 200058.png">
</p>
and the AppLocker interface is refreshed once the rules are applied.
<p align="center">
  <img width="400" height="258" src="images/Capture d'écran 2025-06-11 200132.png">
</p>
Technically, the rules for each profile are stored in XML format inside the script. When the user selects a profile, the corresponding XML is parsed and applied using built-in PowerShell cmdlets like Set-AppLockerPolicy. A unique ID is assigned to each rule to avoid conflicts or duplication.

##### Weakness Detection :
Before applying any profile, the tool offers a scan feature to detect potential security weaknesses.
<p align="center">
  <img width="400" height="258" src="images/Capture d'écran 2025-06-11 200316.png">
</p>
This scan checks several common issues, including:
• Absence of AppLocker rules in key categories (e.g., executable, script, DLL).
• Presence of known writable or risky paths.
• Existence of bypass opportunities (e.g., LOLBins that are not restricted).
The detection is done by querying the current AppLocker policy and comparing it with known patterns. The result is displayed in a readable format so the user can decide
whether to apply a full profile or customize their own.

##### Policy Exporting :
To give users more control, the tool includes a feature that allows exporting the current AppLocker policy. This is done using the Get-AppLockerPolicy cmdlet, which outputs
the policy in XML format.
<p align="center">
  <img width="400" height="258" src="images/Capture d'écran 2025-06-11 200337.png">
</p>
The exported file can be saved for backup, shared with other systems, or reviewed manually. This feature is useful for documentation, auditing, or reapplying policies in the future.
<p align="center">
  <img width="400" height="258" src="images/Capture d'écran 2025-06-11 200355.png">
</p>

##### Rollback Feature :
To avoid accidental misconfigurations, the tool automatically saves a backup of the current AppLocker policy before applying any changes. This backup can be restored later
using the rollback function.
<p align="center">
  <img width="400" height="258" src="images/Capture d'écran 2025-06-11 200549.png">
</p>
The rollback mechanism works by storing the exported policy file in a specific folder and reimporting it when the user selects the rollback option. This provides a safety net and allows users to experiment with profiles without risk.

##### Log Viewer :
Every action taken by the tool is logged for transparency and troubleshooting. Logs are stored in a local file that records the date, selected options, applied rules, scan results,and any errors.
<p align="center">
  <img width="400" height="258" src="images/Capture d'écran 2025-06-11 201915.png">
</p>
This feature helps users understand what changes were made, especially in environments where multiple policies might be tested. Logs are also useful during audits or when
debugging unexpected behavior.

##### Post-Deployment Blocking Test :
Once the hardened rules were applied using the HardLocker tool, the effectiveness of the configuration was confirmed by triggering a blocked execution. For demonstration purposes, the execution of INSTALLUTIL.EXE was attempted and was immediately blocked by AppLocker, as expected. 
Two validations were captured :
**AppLocker Event Log (Event ID 8004) :**
The Windows Event Viewer showed that the binary InstallUtil.exe was prevented from running under the AppLocker EXE and DLL policy.
<p align="center">
  <img width="400" height="258" src="images/Capture d'écran 2025-06-15 120945.png">
</p>


**System Notification** :
A system-level popup confirmed that the application was blocked by the system administrator, reinforcing that the rule was correctly enforced.
<p align="center">
  <img width="400" height="258" src="images/Capture d'écran 2025-06-15 120831.png">
</p>
These results confirm that the AppLocker hardening profile was successfully applied, and unauthorized applications were effectively restricted as designed.

### Conclusion :
The tool was conceived as a bridge between offensive knowledge and defensive solutions ,using the logic of how attacks are conducted to proactively block them. This dual vision allowed us to reinforce not only our technical skills in Windows internals and PowerShell automation, but also to explore how security tools can be made scalable, auditable, and usable in real environments.


Finally, I invite you to read my full [**report**](Rapport_PFE_LMPS-final-versionn.pdf), where I provide a detailed analysis of the bypass techniques and how HardLocker addresses them.
