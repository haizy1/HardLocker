# HardLocker
## Project Overview
The project focuses on evaluating the security limitations of AppLocker, a native Windows feature used for application whitelisting, and on developing an automated PowerShell based tool designed to detect and remediate known bypass techniques.
## General Context 
Application whitelisting is a key layer in endpoint protection strategies, particularly in Windows environments. AppLocker, Microsoft’s native application control feature, allows administrators to define policies that restrict the execution of unauthorized files based on parameters such as path, publisher, or file hash. Despite its potential, AppLocker is not immune to bypasses. Over the years, multiple bypass techniques have been discovered, often leveraging LOLBAS, misconfigured permissions, writable directories, PowerShell abuse, or alternate data streams. These methods highlight gaps in default configurations and expose how AppLocker can be circumvented by adversaries.
This project focuses on analyzing these bypasses in depth and developing remediation rules to block them. The ultimate objective is to enhance AppLocker’s effectiveness by
implementing custom hardened policies, and to support this process through the creation of an automated PowerShell-based tool capable of scanning, applying, and reverting AppLocker configurations.
### Problem Statement
Default AppLocker policies often leave gaps that can be exploited by attackers. Many organizations deploy AppLocker without adapting it to the evolving threat landscape or
known bypass vectors. As a result, security is often overestimated, and attackers can still achieve code execution using well-documented techniques.
This project addresses the lack of visibility and remediation mechanisms around these bypasses by proposing a systematic approach to detect, block, and prevent them.

### Proposed Solution
To address the limitations of AppLocker rules , this project introduces an automated PowerShell tool designed to strengthen application control on Windows. The tool was
developed after researching and understanding the most common and well-documented AppLocker bypass techniques.
Its main goal is to apply defensive rules that prevent these bypasses and help secure the system in a practical and adaptable way. The tool offers three predefined profiles(rules):
Basic Profile – Recommended for standard users, applying essential protections without disrupting usability.
Hardened Profile – A stricter setup designed for administrators or high-privilege environments, blocking a wider range of bypass techniques.
Custom Profile – Allows users to select specific rule sets based on their needs.
The tool also supports scanning for AppLocker weaknesses, as well as backup, rollback, and policy enforcement mode selection ,providing both flexibility and control over the
AppLocker configuration process.

### Existing Solutions
Several open-source tools are available to assist with AppLocker configuration and deployment, but most remain limited in scope. AaronLocker provides policy templates and
scripts to guide rule creation, but it lacks flexibility and does not adapt to specific attack scenarios. Applocker-Hardening automates the application of static policies, without offering any real analysis or bypass detection. AppLockerGen focuses on generating XML rules through a user-friendly interface but offers no support for hardening or automation. The following table provides a benchmark comparison of the existing tools based on their ability to manage, harden, and automate AppLocker configurations.
<p align="center">
  <img width="375" height="258" src="images/logo.png">
</p>
