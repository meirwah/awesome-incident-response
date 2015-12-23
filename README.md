# awesome-incident-response
A curated list of tools and resources for security incident response, aimed to help security analysts and [DFIR](http://www.acronymfinder.com/Digital-Forensics%2c-Incident-Response-(DFIR).html) teams.

[![Awesome](https://cdn.rawgit.com/sindresorhus/awesome/d7305f38d29fed78fa85652e3a63e154dd8e8829/media/badge.svg)](https://github.com/sindresorhus/awesome)

- [Disk Image Creation Tools](#disk-image-creation-tools)
- [Memory Analysis Tools](#memory-analysis-tools)
- [Memory Imaging Tools](#memory-imaging-tools)
- [Process Dump Tools](#process-dump-tools)
- [Timeline tools](#timeline-tools)
- [All in one tools](#all-in-one-tools)
- [Incident Management](#incident-management)
- [Windows Evidence Collection](#windows-evidence-collection)
- [OSX Evidence Collection](#osx-evidence-collection)
- [Sandboxing/reversing tools](#sandboxingreversing-tools)
- [Linux Distributions](#linux-distributions)
- [Other tools](#other-tools)
- [Videos](#videos)
- [Books](#books)
- [Communities](#communities)

## IR tools Collection

### Disk Image Creation Tools

* [GetData Forensic Imager](http://www.forensicimager.com/) - GetData Forensic Imager is a Windows based program that will acquire, convert, or verify a forensic image in one of the following common forensic file formats
* [Guymager](http://guymager.sourceforge.net) - Guymager is a free forensic imager for media acquisition on Linux
* [AccessData FTK Imager](http://accessdata.com/product-download/?/support/adownloads#FTKImager) - AccessData FTK Imager is a forensics tool whose main purpose is to preview recoverable data from a disk of any kind. FTK Imager can also acquire live memory and paging file on 32bit and 64bit systems

### Memory Analysis Tools
* [Volatility](https://github.com/volatilityfoundation/volatility) - An advanced memory forensics framework
* [Evolve](https://github.com/JamesHabben/evolve) - Web interface for the Volatility Memory Forensics Framework
* [WindowsSCOPE](http://www.windowsscope.com/index.php?page=shop.product_details&flypage=flypage.tpl&product_id=35&category_id=3&option=com_virtuemart) - another memory forensics and reverse engineering tool used for analyzing volatile memory. It is basically used for reverse engineering of malwares. It provides the capability of analyzing the Windows kernel, drivers, DLLs, virtual and physical memory
* [Responder PRO](http://www.countertack.com/responder-pro) - Responder PRO is the industry standard physical memory and automated malware analysis solution
* [KnTList](http://www.gmgsystemsinc.com/knttools/) - Computer memory analysis tools
* [Rekall](http://www.rekall-forensic.com/) - Open source tool (and library) for the extraction of digital artifacts from volatile memory (RAM) samples
* [Memoryze](https://www.fireeye.com/services/freeware/memoryze.html) - Memoryze by Mandiant is a free memory forensic software that helps incident responders find evil in live memory. Memoryze can acquire and/or analyze memory images, and on live systems, can include the paging file in its analysis.
* [Memoryze for Mac](https://www.fireeye.com/services/freeware/memoryze-for-the-mac.html) - Memoryze for Mac is Memoryze but then for Macs. A lower number of features, however.


### Memory Imaging Tools
* [OSForensics](http://www.osforensics.com/) - OSForensics can acquire live memory on 32bit and 64bit systems. A dump of an individual process’s memory space or physical memory dump can be done
* [Belkasoft Live RAM Capturer](http://belkasoft.com/ram-capturer) - A tiny free forensic tool to reliably extract the entire content of the computer’s volatile memory – even if protected by an active anti-debugging or anti-dumping system

### Process Dump Tools
* [PMDump](http://ntsecurity.nu/toolbox/pmdump/) - PMDump is a tool that lets you dump the memory contents of a process to a file without stopping the process
* [Microsoft User Mode Process Dumper](http://www.microsoft.com/en-us/download/details.aspx?id=4060) - The User Mode Process Dumper (userdump) dumps any running Win32 processes memory image on the fly

### Timeline tools
* [Plaso](https://github.com/log2timeline/plaso) -  a Python-based backend engine for the tool log2timeline
* [Timesketch](https://github.com/google/timesketch) -open source tool for collaborative forensic timeline analysis
* [Highlighter](https://www.fireeye.com/services/freeware/highlighter.html) - Free Tool available from Fire/Mandiant that will depict log/text file that can highlight areas on the graphic, that corresponded to a key word or phrase. Good for time lining an infection and what was done post compromise.

### All in one Tools
* [X-Ways Forensics](http://www.x-ways.net/forensics/) - X-Ways is a forensics tool for Disk cloning and imaging. It can be used to find deleted files and disk analysis
* [The Sleuth Kit & Autopsy](http://www.sleuthkit.org) - The Sleuth Kit is a Unix and Windows based tool which helps in forensic analysis of computers. It comes with various tools which helps in digital forensics. These tools help in analyzing disk images, performing in-depth analysis of file systems, and various other things
* [Open Computer Forensics Architecture](http://sourceforge.net/projects/ocfa/) - Open Computer Forensics Architecture (OCFA) is another popular distributed open-source computer forensics framework. This framework was built on Linux platform and uses postgreSQL database for storing data
* [Digital Forensics Framework](http://www.arxsys.fr/discover/) - DFF is an Open Source computer forensics platform built on top of a dedicated Application Programming Interface (API). DFF proposes an alternative to the aging digital forensics solutions used today. Designed for simple use and automation, the DFF interface guides the user through the main steps of a digital investigation so it can be used by both professional and non-expert to quickly and easily conduct a digital investigations and perform incident response
* [Osquery](https://osquery.io/) - with osquery you can easily ask questions about your Linux and OSX infrastructure. Whether your goal is intrusion detection, infrastructure reliability, or compliance, osquery gives you the ability to empower and inform a broad set of organizations within your company. Queries in the *incident-response pack* help you detect and respond to breaches.
* [MozDef](https://github.com/jeffbryner/MozDef) - The Mozilla Defense Platform (MozDef) seeks to automate the security incident handling process and facilitate the real-time activities of incident handlers.
* [GRR Rapid Response](https://github.com/google/grr) - GRR Rapid Response is an incident response framework focused on remote live forensics. It consists of a python agent (client) that is installed on target systems, and a python server infrastructure that can manage and talk to the agent.
* [MIG](http://mig.mozilla.org/) - Mozilla Investigator (MIG) is a platform to perform investigative surgery on remote endpoints. It enables investigators to obtain information from large numbers of systems in parallel, thus accelerating investigation of incidents and day-to-day operations security.
* [FIDO](https://github.com/Netflix/Fido) - Fully Integrated Defense Operation (FIDO) by Netflix is an orchestration layer used to automate the incident response process by evaluating, assessing and responding to malware. FIDO’s primary purpose is to handle the heavy manual effort needed to evaluate threats coming from today's security stack and the large number of alerts generated by them.
* [Redline](https://www.fireeye.com/services/freeware/redline.html) - provides host investigative capabilities to users to find signs of malicious activity through memory and file analysis, and the development of a threat assessment profile.
* [Envdb](https://github.com/mephux/envdb) - Envdb turns your production, dev, cloud, etc environments into a database cluster you can search using osquery as the foundation. It wraps the osquery process with a (cluster) node agent that can communicate back to a central location.

### Incident Management
* [FIR](https://github.com/certsocietegenerale/FIR/) - Fast Incident Response (FIR) is an cybersecurity incident management platform designed with agility and speed in mind. It allows for easy creation, tracking, and reporting of cybersecurity incidents and is useful for CSIRTs, CERTs and SOCs alike.
* [SCOT](http://getscot.sandia.gov/) - Sandia Cyber Omni Tracker (SCOT) is an Incident Response collaboration and knowledge capture tool focused on flexibility and ease of use. Our goal is to add value to the incident response process without burdening the user.
* [RTIR](https://www.bestpractical.com/rtir/) - Request Tracker for Incident Response (RTIR) is the premier open source incident handling system targeted for computer security teams. We worked with over a dozen CERT and CSIRT teams around the world to help you handle the ever-increasing volume of incident reports. RTIR builds on all the features of Request Tracker.
* [threat_note](https://github.com/defpoint/threat_note) - A lightweight investigation notebook that allows security researchers the ability to register and retrieve indicators related to their research.

### Windows Evidence Collection
* [FECT](https://github.com/jipegit/FECT) - Fast Evidence Collector Toolkit (FECT) is a light incident response toolkit to collect evidences on a suspicious Windows computer. Basically it is intended to be used by non-tech savvy people working with a journeyman Incident Handler.
* [PSRecon](https://github.com/gfoss/PSRecon/) - PSRecon gathers data from a remote Windows host using PowerShell (v2 or later), organizes the data into folders, hashes all extracted data, hashes PowerShell and various system properties, and sends the data off to the security team. The data can be pushed to a share, sent over email, or retained locally.
* [FastIR Collector](https://github.com/SekoiaLab/Fastir_Collector) - FastIR Collector is a tool that collects different artefacts on live Windows systems and records the results in csv files. With the analyses of these artefacts, an early compromise can be detected.
* [AChoir](https://github.com/OMENScan/AChoir) - Achoir is a framework/scripting tool to standardize and simplify the process of scripting live acquisition utilities for Windows.
* [RegRipper](https://code.google.com/p/regripper/wiki/RegRipper) - Regripper is an open source tool, written in Perl, for extracting/parsing information (keys, values, data) from the Registry and presenting it for analysis.
* [IOC Finder](https://www.fireeye.com/services/freeware/ioc-finder.html) - IOC Finder is a free tool from Mandiant for collecting host system data and reporting the presence of Indicators of Compromise (IOCs). Supports for Windows only.
* [Crowd Response](http://www.crowdstrike.com/community-tools/) - Crowd Response by CrowdStrike is a lightweight Windows console application designed to aid in the gathering of system information for incident response and security engagements. It features numerous modules and output formats.
* [LOKI](https://github.com/Neo23x0/Loki) - Loki is a free IR scanner for scanning endpoint with yara rules and other indicators(IOCs).
* [TRIAGE-IR](https://code.google.com/p/triage-ir/) - Triage-IR is a IR collector for Windows.


### OSX Evidence Collection
* [OSX Auditor](https://github.com/jipegit/OSXAuditor) - OSX Auditor is a free Mac OS X computer forensics tool
* [OSX Collector](https://github.com/yelp/osxcollector) - An OSX Auditor offshoot for live response

### Sandboxing/reversing tools
* [Cuckoo](https://github.com/cuckoobox) - Open Source Highly configurable sandboxing tool
* [Cuckoo-modified](https://github.com/spender-sandbox/cuckoo-modified) - Heavily modified Cuckoo fork developed by community
* [Mastiff](https://github.com/KoreLogicSecurity/mastiff) - MASTIFF is a static analysis framework that automates the process of extracting key characteristics from a number of different file formats.
* [Viper](https://github.com/viper-framework/viper) - Viper is a python based binary analysis and management framework, that works well with Cuckoo and YARA.
* [Virustotal](https://www.virustotal.com) - Virustotal, a subsidiary of Google, is a free online service that analyzes files and URLs enabling the identification of viruses, worms, trojans and other kinds of malicious content detected by antivirus engines and website scanners
* [Malwr](https://malwr.com) - Malwr is a free online malware analysis service and community, which is powered by the Cuckoo Sandbox
* [Hybrid-Analysis](https://www.hybrid-analysis.com/) - Hybrid-Analysis is a free powerful online sandbox by Payload Security

### Linux Distributions
* [Security Onion](https://github.com/Security-Onion-Solutions/security-onion) - Security Onion is a special Linux distro aimed at network security monitoring featuring advanced analysis tools.
* [SIFT Workstation](http://digital-forensics.sans.org/community/downloads) - The SANS Investigative Forensic Toolkit (SIFT) Workstation demonstrates that advanced incident response capabilities and deep dive digital forensic techniques to intrusions can be accomplished using cutting-edge open-source tools that are freely available and frequently updated.
* [CAINE](http://www.caine-live.net/index.html) - The Computer Aided Investigative Environment (CAINE) contains numerous tools that help investigators during their analysis, including forensic evidence collection.
* [DEFT](http://www.deftlinux.net/) - The Digital Evidence & Forensics Toolkit (DEFT) is a Linux distribution made for computer forensic evidence collection. It comes bundled with the Digital Advanced Response Toolkit (DART) for Windows. A light version of DEFT, called DEFT Zero, is also available, which is focused primarily on forensically sound evidence collection.

### Other Tools
* [Hindsight](https://github.com/obsidianforensics/hindsight) - Internet history forensics for Google Chrome/Chromium
* [Kansa](https://github.com/davehull/Kansa/) - Kansa is a modular incident response framework in Powershell.
* [Stalk](https://www.percona.com/doc/percona-toolkit/2.2/pt-stalk.html) - Collect forensic data about MySQL when problems occur.
* [DNS Miner](http://dnsminer.net/) - DNS Miner is a semi-automatic incident response and threat intelligence tool for small, over worked security teams. Specific incident reponse features include a DNS sinkhole and historical analysis of DNS traffic against newly arriving data, e.g. suspicious domain lists.
* [traceroute-circl](https://github.com/CIRCL/traceroute-circl) - traceroute-circl is an extended traceroute to support the activities of CSIRT (or CERT) operators. Usually CSIRT team have to handle incidents based on IP addresses received. Created by Computer Emergency Responce Center Luxembourg.
* [Live Response Collection](https://www.brimorlabs.com/tools/) - The Live Response collection by BriMor Labs is an automated tool that collects volatile data from Windows, OSX, and *nix based operating systems.

### Videos
* [Demisto IR video resources](https://www.demisto.com/category/videos/) - Video Resources for Incident Response and Forensics Tools
* [The Future of Incident Response](https://www.youtube.com/watch?v=bDcx4UNpKNc) - Presented by Bruce Schneier at OWASP AppSecUSA 2015.

### Books
 * [The Practice of Network Security Monitoring: Understanding Incident Detection and Response](http://www.amazon.com/gp/product/1593275099) - Richard Bejtlich's book on IR

### Communities
 * [Slack DFIR channel](https://dfircommunity.slack.com) - Slack DFIR Communitiy channel - [Signup here](https://rishi28.typeform.com/to/sTbTI8)
 * [Sans DFIR mailing list](https://lists.sans.org/mailman/listinfo/dfir) - Mailing list by SANS for DFIR
