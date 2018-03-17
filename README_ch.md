# 应急响应大合集
用于安全事件响应的工具与资源的列表，旨在帮助安全分析师与 [DFIR](http://www.acronymfinder.com/Digital-Forensics%2c-Incident-Response-(DFIR).html) 团队。

[![Awesome](https://cdn.rawgit.com/sindresorhus/awesome/d7305f38d29fed78fa85652e3a63e154dd8e8829/media/badge.svg)](https://github.com/sindresorhus/awesome)

## 目录

- [工具集](#工具集)
- [书籍](#书籍)
- [社区](#社区)
- [磁盘镜像创建工具](#磁盘镜像创建工具)
- [证据收集](#证据收集)
- [事件管理](#事件管理)
- [Linux 发行版](#Linux发行版)
- [Linux 证据收集](#Linux证据收集)
- [日志分析工具](#日志分析工具)
- [内存分析工具](#内存分析工具)
- [内存镜像工具](#内存镜像工具)
- [OSX 证据收集](#osx证据收集)
- [其它清单](#其它清单)
- [其他工具](#其他工具)
- [Playbooks](#playbooks)
- [进程 Dump 工具](#进程Dump工具)
- [沙盒 / 逆向工具](#沙盒/逆向工具)
- [时间线工具](#时间线工具)
- [视频](#视频)
- [Windows 证据收集](#Windows证据收集)

## IR 工具收集

### 工具集

* [Belkasoft Evidence Center](https://belkasoft.com/ec) -  该工具包可以快速从多个数据源提取电子证据，包括硬盘、硬盘镜像、内存转储、iOS、黑莓与安卓系统备份、UFED、JTAG 与 chip-off 转储。
* [CimSweep](https://github.com/PowerShellMafia/CimSweep) - CimSweep 是一套基于 CIM/WMI 的工具，提供在所有版本的 Windows 上执行远程事件响应和追踪。
* [CIRTkit](https://github.com/byt3smith/CIRTKit) - CIRTKit 不仅是一个工具集合，更是一个框架，统筹事件响应与取证调查的进程。
* [Cyber Triage](http://www.cybertriage.com) - Cyber Triage 远程收集分析终端数据，以帮助确定计算机是否被入侵。其专注易用性与自动化，采用无代理的部署方法使公司在没有重大基础设施及取证专家团队的情况下做出响应。其分析结果用于决定该终端是否应该被擦除或者进行进一步调查。
* [Digital Forensics Framework](http://www.arxsys.fr/discover/) - DFF 是一个建立在专用 API 之上的开源计算机取证平台，DFF 提出了一种替代目前老旧的数字取证解决方案。其设计简单、更加易于自动化。DFF 接口可以帮助用户进行数字调查取证的主要步骤，专业与非专业人员都可以快速的进行数字取证并执行事件响应。
* [Doorman](https://github.com/mwielgoszewski/doorman) - Doorman 是一个 osquery 的管理平台，可以远程管理节点的 osquery 配置。它利用 osquery 的 TLS 配置\记录器\分布式读写等优势仅以最小开销和侵入性为管理员提供一组设备的管理可见性。
* [Envdb](https://github.com/mephux/envdb) - Envdb 将你的生产\开发\云等环境变成数据库集群，你可以使用 osquery 作为基础搜索。它将 osquery 的查询进程和一个agent打包在一起向一个集中位置发送。
* [Falcon Orchestrator](https://github.com/CrowdStrike/falcon-orchestrator) - Falcon Orchestrator 是由 CrowdStrike 提供的一个基于 Windows 可扩展的应用程序，提供工作流自动化、案例管理与安全应急响应等功能。
* [GRR Rapid Response](https://github.com/google/grr) - GRR Rapid Response 是一个用来远程现场实时取证的应急响应框架，其带有一个python客户端安装在目标系统以及一个可以管理客户端的 Python 编写的服务器。
* [Kolide Fleet](https://kolide.com/fleet) - Kolide Fleet 是一个为安全专家定制的先进的主机监控平台。通过利用Facebook经过实战检验的 osquery 项目，Kolide 能够快速回答复杂问题。
* [Limacharlie](https://github.com/refractionpoint/limacharlie) - 一个终端安全平台，它本身是一个小项目的集合，并提供了一个跨操作系统的低级环境，你可以管理并推送附加功能进入内存给程序扩展功能。
* [MIG](http://mig.mozilla.org/) - Mozilla Investigator (MIG) 是一个在远程终端执行调查的平台，它可以在大量系统中并行获取数据，从而加速事故调查与日常业务安全
* [MozDef](https://github.com/mozilla/MozDef) - Mozilla Defense Platform (MozDef) 旨在帮助安全事件处理自动化，并促进事件的实时处理。
* [nightHawk](https://github.com/biggiesmallsAG/nightHawkResponse) - nightHawk Response Platform 是一个以 ElasticSearch 为后台的异步取证数据呈现的应用程序，设计与 Redline 配合调查。
* [Open Computer Forensics Architecture](http://sourceforge.net/projects/ocfa/) - Open Computer Forensics Architecture (OCFA) 是另一个分布式开源计算机取证框架，这个框架建立在 Linux 平台上，并使用 postgreSQL 数据库来存储数据。
* [Osquery](https://osquery.io/) - osquery 可以找到 Linux 与 OSX 基础设施的问题,无论你是要入侵检测、基础架构可靠性检查或者合规性检查，osquery 都能够帮助你提高公司内部的安全组织能力, *incident-response pack* 可以帮助你进行检测\响应活动。
* [Redline](https://www.fireeye.com/services/freeware/redline.html) - 为用户提供主机调查工具，通过内存与文件分析来找到恶意行为的活动迹象，包括对威胁评估配置文件的开发
* [The Sleuth Kit & Autopsy](http://www.sleuthkit.org) - Sleuth Kit 是基于 Unix 和 Windows 的工具，可以帮助计算机取证分析，其中包含各种协助取证的工具，比如分析磁盘镜像、文件系统深度分析等
* [TheHive](https://thehive-project.org/) - TheHive 是一个可扩展的三合一开源解决方案，旨在让 SOC、CSIRT、CERT 或其他任何信息安全从业人员快速地进行安全事件调查。
* [X-Ways Forensics](http://www.x-ways.net/forensics/) - X-Ways 是一个用于磁盘克隆、镜像的工具，可以查找已经删除的文件并进行磁盘分析。
* [Zentral](https://github.com/zentralopensource/zentral) - 与 osquery 强大的端点清单保护能力相结合，通知与行动都灵活的框架，可以快速对 OS X 与 Linux 客户机上的更改做出识别与响应。

### 书籍

* [Dfir intro](https://medium.com/@sroberts/introduction-to-dfir-d35d5de4c180/)) - 作者:Scott J. Roberts
* [The Practice of Network Security Monitoring: Understanding Incident Detection and Response](http://www.amazon.com/gp/product/1593275099) - 作者:Richard Bejtlich

### 社区

* [augmentd](https://augmentd.co/) - 这是一家社区驱动的网站，上面提供了一个可通过不同的常用安全工具部署执行的搜索清单
* [Sans DFIR mailing list](https://lists.sans.org/mailman/listinfo/dfir) - Mailing list by SANS for DFIR
* [Slack DFIR channel](https://dfircommunity.slack.com) - Slack DFIR Communitiy channel - [Signup here](https://rishi28.typeform.com/to/sTbTI8)

### 磁盘镜像创建工具

* [AccessData FTK Imager](http://accessdata.com/product-download/?/support/adownloads#FTKImager) - AccessData FTK Imager 是一个从任何类型的磁盘中预览可恢复数据的取证工具，FTK Imager 可以在 32\64 位系统上实时采集内存与页面文件。
* [Bitscout](https://github.com/vitaly-kamluk/bitscout) - Vitaly Kamluk 开发的 Bitscout 可以帮助你定制一个完全可信的 LiveCD/LiveUSB 镜像以供远程数字取证使用（或者你需要的其它任务）。它对系统所有者透明且可被监控，同时可用于法庭质证、可定制且紧凑。 
* [GetData Forensic Imager](http://www.forensicimager.com/) - GetData Forensic Imager 是一个基于 Windows 程序，将常见的镜像文件格式进行获取\转换\验证取证
* [Guymager](http://guymager.sourceforge.net) - Guymager 是一个用于 Linux 上媒体采集的免费镜像取证器。
* [Magnet ACQUIRE](https://www.magnetforensics.com/magnet-acquire/) - Magnet Forensics 开发的 ACQUIRE 可以在不同类型的磁盘上执行取证,包括 Windows\Linux\OS X 与移动操作系统。

### 证据收集

* [bulk_extractor](https://github.com/simsong/bulk_extractor) - bulk_extractor 是一个计算机取证工具，可以扫描磁盘镜像、文件、文件目录，并在不解析文件系统或文件系统结构的情况下提取有用的信息，由于其忽略了文件系统结构，程序在速度和深入程度上都相比其它工具有了很大的提高。
* [Cold Disk Quick Response](https://github.com/rough007/CDQR) - 使用精简的解析器列表来快速分析取证镜像文件(dd, E01, .vmdk, etc)并输出报告。
* [ir-rescue](https://github.com/diogo-fernan/ir-rescue) - *ir-rescue* 是一个 Windows 批处理脚本与一个 Unix Bash 脚本,用于在事件响应期在主机全面收集证据。
* [Live Response Collection](https://www.brimorlabs.com/tools/) - BriMor 开发的 Live Response collection 是一个用于从 Windows、OSX、*nix 等操作系统中收集易失性数据的自动化工具。

### 事件管理

* [Cyphon](https://www.cyphon.io/) - Cyphon 通过一个单一的平台来组织一系列相关联的工作消除了事件管理的开销。它对事件进行收集、处理、分类。
* [Demisto](https://www.demisto.com/product/) - Demisto 免费的社区版提供全事件生命周期的管理，事件披露报告，团队任务分配与协作，以及众多增强自动化的系统集成（如 Active Directory, PagerDuty, Jira 等）。
* [FIR](https://github.com/certsocietegenerale/FIR/) - Fast Incident Response (FIR) 是一个网络安全事件管理平台，在设计时考虑了敏捷性与速度。其可以轻松创建、跟踪、报告网络安全应急事件并用于 CSIRT、CERT 与 SOC 等人员。
* [RTIR](https://www.bestpractical.com/rtir/) - Request Tracker for Incident Response (RTIR) 对于安全团队来说是首要的开源事件处理系统,其与世界各地的十多个 CERT 与 CSIRT 合作，帮助处理不断增加的事件报告，RTIR 包含 Request Tracker 的全部功能。
* [SCOT](http://getscot.sandia.gov/) - Sandia Cyber Omni Tracker (SCOT) 是一个应急响应协作与知识获取工具，为事件响应的过程在不给用户带来负担的情况下增加价值。
* [threat_note](https://github.com/defpoint/threat_note) - 一个轻量级的调查笔记，允许安全研究人员注册、检索他们需要的 IOC 数据。

### Linux 发行版

* [ADIA](https://forensics.cert.org/#ADIA) - Appliance for Digital Investigation and Analysis (ADIA) 是一个基于 VMware 的应用程序，用于进行数字取证。其完全由公开软件构建，包含的工具有 Autopsy\Sleuth Kit\Digital Forensics Framework\log2timeline\Xplico\Wireshark。大多数系统维护使用 Webmin。它为中小规模的数字取证设计，可在 Linux、Windows 及 Mac OS 下使用。
* [CAINE](http://www.caine-live.net/index.html) - Computer Aided Investigative Environment (CAINE) 包含许多帮助调查人员进行分析的工具，包括取证工具。
* [CCF-VM](https://github.com/rough007/CCF-VM) - CyLR CDQR Forensics Virtual Machine (CCF-VM): 一款多合一的解决方案，能够解析收集的数据，将它转化得易于使用內建的常见搜索，也可并行搜索一个或多个主机。
* [DEFT](http://www.deftlinux.net/) - Digital Evidence & Forensics Toolkit (DEFT) 是一个用于计算机取证的 Linux 发行版，它与 Windows 上的 Digital Advanced Response Toolkit (DART) 捆绑在一起。DEFT 的轻量版被成为 DEFT Zero，主要关注可用于法庭质证的取证环节。
* [NST - Network Security Toolkit](https://sourceforge.net/projects/nst/files/latest/download?source=files) - 包括大量的优秀开源网络安全应用程序的 Linux 发行版
* [PALADIN](https://sumuri.com/software/paladin/) - PALADIN 是一个附带许多开源取证工具的改 Linux 发行版，用于以可被法庭质证的方式执行取证任务
* [Security Onion](https://github.com/Security-Onion-Solutions/security-onion) - Security Onion 是一个特殊的 Linux 发行版，旨在利用高级的分析工具进行网络安全监控
* [SIFT Workstation](http://digital-forensics.sans.org/community/downloads) - SANS Investigative Forensic Toolkit (SIFT) 使用前沿的优秀开源工具以实现高级事件响应与入侵深度数字取证，这些功能免费提供并且经常更新。

### Linux 证据收集

* [FastIR Collector Linux](https://github.com/SekoiaLab/Fastir_Collector_Linux) - FastIR 在 Linux 系统上收集不同的信息并将结果存入 CSV 文件

### 日志分析工具

* [Lorg](https://github.com/jensvoid/lorg) - 一个用 HTTPD 日志进行高级安全分析与取证的工具

### 内存分析工具

* [Evolve](https://github.com/JamesHabben/evolve) - Volatility 内存取证框架的 Web 界面
* [inVtero.net](https://github.com/ShaneK2/inVtero.net) - 支持 hypervisor 的 Windows x64 高级内存分析
* [KnTList](http://www.gmgsystemsinc.com/knttools/) - 计算机内存分析工具
* [LiME](https://github.com/504ensicsLabs/LiME) - LiME 是 Loadable Kernel Module (LKM)，可以从 Linux 以及基于 Linux 的设备采集易失性内存数据。
* [Memoryze](https://www.fireeye.com/services/freeware/memoryze.html) - 由 Mandiant 开发的 Memoryze 是一个免费的内存取证软件，可以帮助应急响应人员在内存中定位恶意部位, Memoryze 也可以分析内存镜像或者在正在运行的系统上把页面文件加入它的分析。
* [Memoryze for Mac](https://www.fireeye.com/services/freeware/memoryze-for-the-mac.html) - Memoryze for Mac 是 Memoryze 但仅限于 Mac,且功能较少。
* [Rekall](http://www.rekall-forensic.com/) - 用于从 RAM 中提取样本的开源工具
* [Responder PRO](http://www.countertack.com/responder-pro) - Responder PRO 是一个工业级的物理内存及自动化恶意软件分析解决方案
* [Volatility](https://github.com/volatilityfoundation/volatility) - 高级内存取证框架
* [VolatilityBot](https://github.com/mkorman90/VolatilityBot) - VolatilityBot 是一个自动化工具，帮助研究员减少在二进制程序提取解析阶段的手动任务，或者帮助研究人员进行内存分析调查的第一步
* [VolDiff](https://github.com/aim4r/VolDiff) - 基于 Volatility 的 恶意软件足迹分析
* [WindowsSCOPE](http://www.windowsscope.com/index.php?page=shop.product_details&flypage=flypage.tpl&product_id=35&category_id=3&option=com_virtuemart) - 一个用来分析易失性内存的取证与逆向工程工具，被用于对恶意软件进行逆向分析，提供了分析 Windows 内核\驱动程序\DLL\虚拟与物理内存的功能。

### 内存镜像工具

* [Belkasoft Live RAM Capturer](http://belkasoft.com/ram-capturer) - 轻量级取证工具,即使有反调试\反转储的系统保护下也可以方便地提取全部易失性内存的内容。
* [Linux Memory Grabber](https://github.com/halpomeranz/lmg/) - 用于 dump Linux 内存并创建 Volatility 配置文件的脚本。
* [Magnet RAM Capture](https://www.magnetforensics.com/free-tool-magnet-ram-capture/) - Magnet RAM Capture 是一个免费的镜像工具，可以捕获可疑计算机中的物理内存，支持最新版的 Windows。
* [OSForensics](http://www.osforensics.com/) - OSForensics 可以获取 32/64 位系统的实时内存，可以将每个独立进程的内存空间 dump 下来。

### OSX 证据收集

* [Knockknock](https://github.com/synack/knockknock) - 显示那些在 OSX 上被设置为自动执行的那些脚本、命令、程序等。
* [mac_apt - macOS Artifact Parsing Tool](https://github.com/ydkhatri/mac_apt) - 基于插件的取证框架，可以对正在运行的系统、硬盘镜像或者单个文件。
* [OSX Auditor](https://github.com/jipegit/OSXAuditor) - OSX Auditor 是一个面向 Mac OS X 的免费计算机取证工具。
* [OSX Collector](https://github.com/yelp/osxcollector) - OSX Auditor 的实时响应版。

### 其它清单

* [List of various Security APIs](https://github.com/deralexxx/security-apis) - 一个包括了在安全领域使用的公开 JSON API 的汇总清单.

### 其他工具

* [Cortex](https://thehive-project.org) - Cortex 可以通过 Web 界面逐个或批量对 IP 地址\邮件地址\URL\域名\文件哈希的分析,还可以使用 REST API 来自动执行这些操作
* [Crits](https://crits.github.io/) - 一个将分析引擎与网络威胁数据库相结合且带有 Web 界面的工具
* [domfind](https://github.com/diogo-fernan/domfind) - *domfind* 一个用 Python 编写的 DNS 爬虫，它可以找到在不同顶级域名下面的相同域名.
* [DumpsterFire](https://github.com/TryCatchHCF/DumpsterFire) - DumsterFire 工具集是一个模块化的、基于菜单的、跨平台的工具，它可以创建可重复的、可延时的、分布式的安全事件，可以很轻松地给攻防演练中的蓝方创建定制的事件链和传感器/告警的对应关系。红方可以创建诱骗的事件、分散注意力的事以及鱼饵来支撑、扩展他们的行动。
* [Fenrir](https://github.com/Neo23x0/Fenrir) - Fenrir 是一个简单的 IOC 扫描器,可以在纯 bash 中扫描任意 Linux/Unix/OSX  系统,由 THOR 与 LOKI 的开发者创作
* [Fileintel](https://github.com/keithjjones/fileintel) - 为每个文件哈希值提供情报
* [HELK](https://github.com/Cyb3rWard0g/HELK) - 威胁捕捉
* [Hindsight](https://github.com/obsidianforensics/hindsight) - 针对 Google Chrome/Chromium 中浏览历史的数字取证
* [Hostintel](https://github.com/keithjjones/hostintel) - 为每个主机提供情报
* [imagemounter](https://github.com/ralphje/imagemounter) - 命令行工具及 Python 包，可以简单地 mount/unmount 数字取证的硬盘镜像
* [Kansa](https://github.com/davehull/Kansa/) - Kansa 是一个 PowerShell 的模块化应急响应框架
* [rastrea2r](https://github.com/aboutsecurity/rastrea2r) - 使用 YARA 在 Windows、Linux 与 OS X 上扫描硬盘或内存
* [RaQet](https://raqet.github.io/) - RaQet 是一个非常规的远程采集与分类工具，允许对那些为取证构建的操作系统进行远端计算机的遴选
* [Stalk](https://www.percona.com/doc/percona-toolkit/2.2/pt-stalk.html) - 收集关于 MySQL 的取证数据
* [SearchGiant](https://github.com/jadacyrus/searchgiant_cli) - 从云服务中获取取证数据的命令行程序
* [Stenographer](https://github.com/google/stenographer) - Stenographer 是一个数据包捕获解决方案，旨在快速将全部数据包转储到磁盘中，然后提供对这些数据包的快速访问。它存储尽可能多的历史记录并且管理磁盘的使用情况，在大小达到设定的上限时删除记录，非常适合在事件发生前与发生中捕获流量，而不是显式存储所有流量。
* [sqhunter](https://github.com/0x4d31/sqhunter) - 一个基于 osquery 和 Salt Open (SaltStack) 的威胁捕捉工具，它无需 osquery 的 tls 插件就能发出临时的或者分布式的查询。 sqhunter 也可以查询开放的 sockets，并将它们与威胁情报进行比对。
* [traceroute-circl](https://github.com/CIRCL/traceroute-circl) - 由 Computer Emergency Responce Center Luxembourg 开发的 traceroute-circl 是一个增强型的 traceroute 来帮助 CSIRT\CERT 的工作人员，通常 CSIRT 团队必须根据收到的 IP 地址处理事件
* [X-Ray 2.0](https://www.raymond.cc/blog/xray/) - 一个用来向反病毒厂商提供样本的 Windows 实用工具(几乎不再维护)


### Playbooks

* [Demisto Playbooks Collection](https://www.demisto.com/category/playbooks/) - Playbook 集锦
* [IRM](https://github.com/certsocietegenerale/IRM) - CERT Societe Generale 开发的事件响应方法论
* [IR Workflow Gallery](https://www.incidentresponse.com/playbooks/) - 不同的通用事件响应工作流程,例如恶意软件爆发、数据窃取、未经授权的访问等，每个工作流程都有七个步骤:准备、检测、分析、遏制、根除、恢复、事后处理。
* [PagerDuty Incident Response Documentation](https://response.pagerduty.com/) - 描述 PagerDuty 应急响应过程的文档，不仅提供了关于事件准备的信息，还提供了在此前与之后要做什么工作，源在 [GitHub](https://github.com/PagerDuty/incident-response-docs) 上。

### 进程 Dump 工具

* [Microsoft User Mode Process Dumper](http://www.microsoft.com/en-us/download/details.aspx?id=4060) - 用户模式下的进程 dump 工具，可以 dump 任意正在运行的 Win32 进程内存映像
* [PMDump](http://www.ntsecurity.nu/toolbox/pmdump/) - PMDump 是一个可以在不停止进程的情况下将进程的内存内容 dump 到文件中的工具

### 沙盒／逆向工具

* [Cuckoo](https://github.com/cuckoobox) - 开源沙盒工具，高度可定制化
* [Cuckoo-modified](https://github.com/spender-sandbox/cuckoo-modified) - 社区基于 Cuckoo 的大修版
* [Cuckoo-modified-api](https://github.com/keithjjones/cuckoo-modified-api) - 一个用来控制 Cuckoo 沙盒设置的 Python 库
* [Hybrid-Analysis](https://www.hybrid-analysis.com/) - Hybrid-Analysis 是一个由 Payload Security 提供的免费在线沙盒
* [Malwr](https://malwr.com) - Malwr 是由 Cuckoo 沙盒提供支持的一个免费在线恶意软件分析服务
* [Mastiff](https://github.com/KoreLogicSecurity/mastiff) - MASTIFF 是一个静态分析框架，可以自动化的从多种文件格式中提取关键特征。
* [Metadefender Cloud](https://www.metadefender.com) - Metadefender 是一个免费的威胁情报平台，提供多点扫描、数据清理以及对文件的脆弱性分析
* [Viper](https://github.com/viper-framework/viper) - Viper 是一个基于 Python 的二进制程序分析及管理框架，支持 Cuckoo 与 YARA
* [Virustotal](https://www.virustotal.com) - Virustotal, Google 的子公司，一个免费在线分析文件/URL的厂商，可以分析病毒\蠕虫\木马以及其他类型被反病毒引擎或网站扫描器识别的恶意内容
* [Visualize_Logs](https://github.com/keithjjones/visualize_logs) - Cuckoo、Procmon等日志的开源可视化库


### 时间线工具

* [Highlighter](https://www.fireeye.com/services/freeware/highlighter.html) - Fire/Mandiant 开发的免费工具，来分析日志/文本文件，可以对某些关键字或短语进行高亮显示，有助于时间线的整理
* [Morgue](https://github.com/etsy/morgue) - 一个 Etsy 开发的 PHP Web 应用，可用于管理事后处理
* [Plaso](https://github.com/log2timeline/plaso) -  一个基于 Python 用于 log2timeline 的后端引擎
* [Timesketch](https://github.com/google/timesketch) - 用于协作取证时间线分析的开源工具


### 视频

* [Demisto IR video resources](https://www.demisto.com/category/videos/) - 应急响应与取证分析的视频资源
* [The Future of Incident Response](https://www.youtube.com/watch?v=bDcx4UNpKNc) - Bruce Schneier 在 OWASP AppSecUSA 2015 上的分享

### Windows 证据收集

* [AChoir](https://github.com/OMENScan/AChoir) - Achoir 是一个将对 Windows 的实时采集工具脚本化变得更标准与简单的框架
* [Binaryforay](http://binaryforay.blogspot.co.il/p/software.html) - 一个 Windows 取证的免费工具列表 (http://binaryforay.blogspot.co.il/)
* [Crowd Response](http://www.crowdstrike.com/community-tools/) - 由 CrowdStrike 开发的 Crowd Response 是一个轻量级 Windows 终端应用,旨在收集用于应急响应与安全操作的系统信息，其包含许多模块与输出格式。
* [FastIR Collector](https://github.com/SekoiaLab/Fastir_Collector) - FastIR Collector 在 Windows 系统中实时收集各种信息并将结果记录在 CSV 文件中，通过对这些信息的分析，我们可以发现早期的入侵痕迹
* [FECT](https://github.com/jipegit/FECT) - Fast Evidence Collector Toolkit (FECT) 是一个轻量级的应急响应工具集，用于在可疑的 Windows 计算机上取证，它可以让非技术调查人员更专业的进行应急处理。
* [Fibratus](https://github.com/rabbitstack/fibratus) - 探索与跟踪 Windows 内核的工具。
* [IOC Finder](https://www.fireeye.com/services/freeware/ioc-finder.html) - IOC Finder 是由 Mandiant 开发的免费工具，用来收集主机数据并报告存在危险的 IOC，仅支持 Windows。
* [Fidelis ThreatScanner](https://www.fidelissecurity.com/resources/fidelis-threatscanner) - Fidelis ThreatScanner 是一个由 Fidelis Cybersecurity 开发的免费工具，使用 OpenIOC 和 YARA 来报告终端设备的安全状态，ThreatScanner 衡量系统的运行状态后会出具匹配情况的报告，仅限 Windows。
* [LOKI](https://github.com/Neo23x0/Loki) - Loki 是一个使用 YARA 与其他 IOC 对终端进行扫描的免费 IR 扫描器
* [Panorama](https://github.com/AlmCo/Panorama) - Windows 系统运行时的快速事件概览
* [PowerForensics](https://github.com/Invoke-IR/PowerForensics) - PowerShell 开发的实时硬盘取证框架
* [PSRecon](https://github.com/gfoss/PSRecon/) - PSRecon 使用 PowerShell 在远程 Windows 主机上提取/整理数据，并将数据发送到安全团队，数据可以通过邮件来传送数据或者在本地留存
* [RegRipper](https://code.google.com/p/regripper/wiki/RegRipper) - Regripper 是用 Perl 编写的开源工具，可以从注册表中提取/解析数据(键\值\数据)提供分析
* [TRIAGE-IR](https://code.google.com/p/triage-ir/) - Triage-IR 是一个 Windows 下的 IR 收集工具