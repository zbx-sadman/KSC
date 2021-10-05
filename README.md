[![PS-Check](https://github.com/atao/KSC/actions/workflows/blank.yml/badge.svg)](https://github.com/atao/KSC/actions/workflows/blank.yml)
## KSC Miner 
This is a little Powershell script help to fetch metric's values from Kaspersky Security Center (KSC).

Actual release 0.99

Tested on:
- Production mode: Windows Server 2008 R2 SP1, Powershell 2, Kaspersky Security Center 10 SP2
- Production mode:	Windows Server 2019 Standard, Powershell 5.1, Kaspersky Security Center 12.2.0.4376
 
Supported objects:

- _Server_  - KSC server;
- _Host_    - Managed server / workstation;
- _License_ - License data.

Virtual keys for 'Host' object are:
- _Unassigned_ - Host(s) contained in "Unassigned" group;
- _Status.{OK | Critical | Warning | Any }_ - Host(s) extended status: Any, OK, Critical, Warning;
- _RTPState.{Unknown | Stopped | Suspended | Starting | Running | Failure}_ - Realtime protection on host is Unknown/Stopped/Suspended/etc;
- _NotInstalledAVApplication_ - Anti-virus application is not installed on host;
- _NotRunningAVApplication_ - Anti-virus application is installed on host but not running;
- _NotRunningRTP_ - Anti-virus application is installed but real-time protection on host is not running;
- _TooMuchVirusesDetected_ - Number of viruses detected  on host is too much;
- _TooOldAVBases_ - Anti-virus bases on host were updated too long ago;
- _FullScanPerformedTooLongAgo_ - Full scan for viruses performed too long ago;
- _AgentIsInactiveTooLong_ - Network agent is inactive too long;
- _AVBasesAgeLess1Hr_ - Anti-virus bases were updated in last hour;
- _AVBasesAgeIs24Hrs_ - Anti-virus bases were updated between an 1..24 hour ago;
- _AVBasesAgeIs1-3Days_ - Anti-virus bases were updated between an 1..3 days ago;
- _AVBasesAgeIs3-7Days_ - Anti-virus bases were updated between an 3..7 days ago;
- _AVBasesAgeMoreThan7Days_ - Anti-virus bases were updated more than 7 days ago.

Virtual keys for 'License' object are:
- _TimeLeftToLicenseExpire_ - Time left to end of license (in seconds);
- _LicenseExpired_ - "License is expired" flag.

Virtual keys for 'Server' object are:
- _Build_ - Administration Server build number;
- _VersionId_ - ID of Administration Server version;
- _SAASBlocked_ - SAAS mode is turned off due to expired/absent/blacklisted license, boolean.

Actions
- _Discovery_ - Make Zabbix's LLD JSON;
- _Get_       - Get metric from collection item;
- _Sum_       - Sum metrics of collection items;
- _Count_     - Count collection items.


### How to use standalone

    # Make Zabbix's LLD JSON for Licenses on Kaspersky Security Center Server
    powershell.exe -NoProfile -ExecutionPolicy "RemoteSigned" -File "ksc.ps1" -Action "Discovery" -ObjectType "License"

    # Get number of Hosts which have Critical State 
    ... "ksc.ps1" -Action "Count" -ObjectType "Host" -Key "Status.Critical" -consoleCP CP866

    # Get expiration date of license with "1C1C-000423-1323DEA0" serial number
    ... "ksc.ps1" -Action "Get" -ObjectType "License" -Key "KLLIC_LIMIT_DATE" -Id "1C1C-000423-1323DEA0"



### How to use with Zabbix
1. Just include [zbx_ksc.conf](https://github.com/zbx-sadman/ksc/tree/master/Zabbix_Templates/zbx_ksc.conf) to Zabbix Agent config;
2. Put _ksc.ps1_ to _C:\zabbix\scripts\_ dir;
3. Set Zabbix Agent's / Server's _Timeout_ to more that 3 sec (may be 10 or 30);
4. Import [template](https://github.com/zbx-sadman/HASP/tree/master/Zabbix_Templates) to Zabbix Server;
5. Watch to Zabbix's Latest Data.

**Note**
Do not try import Zabbix v2.4 template to Zabbix _pre_ v2.4. You need to edit .xml file and make some changes at discovery_rule - filter tags area and change _#_ to _<>_ in trigger expressions. I will try to make template to old Zabbix.

**Note**
It is possible that you will need to provide the script with the credentials of user from the _KLAdmins_ group to connect to the server. Refer to _Username_ / _Userpass_ / _UserDomain_ options.

**Note**
All available options are described in head of the script file.

### Hints
- To see keys, run script without **-Key** option: 
  _... "ksc.ps1" -Action "Get" -Object "**ObjectType**"_  
- For debug in standalone mode use _-defaultConsoleWidth_ option to leave console default width while run script and
   _-Verbose_ to get additional processing information;
- If you get Zabbix's "Should be JSON" - try to increase the number value in CONSOLE_WIDTH constant variable inside _ksc.ps1_. 
  Powershell use console width to format output JSON-lines and can break its. 

**Beware** frequent requests to PowerShell script eat CPU and increase Load. To avoid it - don't use small update intervals with Zabbix's Data Items and disable unused.
