<#                                          
    .SYNOPSIS  
        Return Kaspersky Security Center Server metric values, sum & count selected objects, make LLD-JSON for Zabbix

    .DESCRIPTION
        Return Kaspersky Security Center Server metric values, sum & count selected objects, make LLD-JSON for Zabbix

    .NOTES  
        Version: 0.9
        Name: KSC Miner
        Author: zbx.sadman@gmail.com
        DateCreated: 05SEP2017
        Testing environment: Windows Server 2008R2 SP1, Powershell 2.0, Kaspersky Security Center 10

    .LINK  
        https://github.com/zbx-sadman

    .PARAMETER Action
        What need to do with collection or its item:
            Discovery - Make Zabbix's LLD JSON;
            Get       - Get metric from collection item;
            Sum       - Sum metrics of collection items;
            Count     - Count collection items.

    .PARAMETER ObjectType
        Define rule to make collection:
            Server    - KSC server;
            Host      - Managed server / workstation (IKlAkHosts class instance);
            License   - License data (IKlAkLicense class instance);

    .PARAMETER Key
        Define "path" to collection item's metric 
   
        Virtual keys for 'Host' object are:
            Unassigned - Host(s) contained in "Unassigned" group;
            Status.{OK | Critical | Warning | Any } - Host(s) extended status: Any, OK, Critical, Warning;
            RTPState.{Unknown | Stopped | Suspended | Starting | Running | Failure} - Realtime protection on host is Unknown/Stopped/Suspended/etc;
            NotInstalledAVApplication - Anti-virus application is not installed on host;
            NotRunningAVApplication – Anti-virus application is installed but not running on host;
            NotRunningRTP -  Anti-virus application is installed but real-time protection is not running on host;
            TooMuchVirusesDetected - Number of viruses detected is too much on host;
            TooOldAVBases - Anti-virus bases were updated too long ago on host;

        Virtual keys for 'License' object are:
            TimeLeftToLicenseExpire - Time left to end of license (in seconds)
            LicenseExpired - "License is expired" flag;

        Virtual keys for 'Server' object are:
            Build - Administration Server build number;
            VersionId - ID of Administration Server version;
            SAASBlocked - SAAS mode is turned off due to expired/absent/blacklisted license, boolean;

    .PARAMETER ID
        Used to select only one item from collection. 

    .PARAMETER ServerAddress
        Administration KSC Server address in <host>:<port> format, for example, "localhost:13000"

    .PARAMETER Username
        User name which used to KSC access. Must be true if "UseSSL" is specified. Security context of calling user is used if "User" is not specified. 

    .PARAMETER Userpass
        User password.

    .PARAMETER UserDomain
        User domain.

    .PARAMETER ErrorCode
        What must be returned if any process error will be reached

    .PARAMETER ConsoleCP
        Codepage of Windows console. Need to properly convert output to UTF-8

    .PARAMETER DefaultConsoleWidth
        Say to leave default console width and not grow its to $CONSOLE_WIDTH

    .PARAMETER Verbose
        Enable verbose messages

    .EXAMPLE 
        powershell.exe -NoProfile -ExecutionPolicy "RemoteSigned" -File "ksc.ps1" -Action "Discovery" -ObjectType "License"

        Description
        -----------  
        Make Zabbix's LLD JSON for Licenses on Kaspersky Security Center Server

    .EXAMPLE 
        ... "ksc.ps1" -Action "Count" -ObjectType "Host" -Key "Status.Critical" -consoleCP CP866

        Description
        -----------  
        Get number of Hosts which have Critical State 

    .EXAMPLE 
        ... "ksc.ps1" -Action "Get" -ObjectType "License" -Key "KLLIC_LIMIT_DATE" -Id "1C1C-000423-1323DEA0"

        Description
        -----------  
        Get expiration date of license with "1C1C-000423-1323DEA0" serial number

#>

Param (
   [Parameter(Mandatory = $False)] 
   [ValidateSet('Discovery', 'Get', 'Count', 'Sum')]
   [String]$Action,
   [String]$ServerAddress,
   [String]$Username,
   [String]$Userpass,
   [String]$UserDomain,
   [Parameter(Mandatory = $False)]
   [ValidateSet('Server', 'Host', "License")]
   [Alias('Object')]
   [String]$ObjectType,
   [Parameter(Mandatory = $False)]
   [String]$Key,
   [Parameter(Mandatory = $False)]
   [String]$Id,
   [Parameter(Mandatory = $False)]
   [String]$ErrorCode,
   [Parameter(Mandatory = $False)]
   [String]$ConsoleCP,
   [Parameter(Mandatory = $False)]
   [Switch]$DefaultConsoleWidth
);

# Set US locale to properly formatting float numbers while converting to string
[System.Threading.Thread]::CurrentThread.CurrentCulture = "en-US"

# Width of console to stop breaking JSON lines
Set-Variable -Option Constant -Name "CONSOLE_WIDTH" -Value 512

Add-Type -TypeDefinition "public enum HostStatus { Any, OK, Critical, Warning, Unassigned}";
Add-Type -TypeDefinition "public enum RTPState   { Unknown, Stopped, Suspended, Starting, Running, RunningMaxProtection, RunningMaxSpeed, RunningRecomendedSettings, RunningCustomSettings, Failure}";

####################################################################################################################################
#
#                                                  Function block
#    
####################################################################################################################################
#
#  Select object with Property that equal Value if its given or with Any Property in another case
#
Function PropertyEqualOrAny {
   Param (
      [Parameter(ValueFromPipeline = $True)] 
      [PSObject]$InputObject,
      [PSObject]$Property,
      [PSObject]$Value
   );
   Process {
      # Do something with all objects (non-pipelined input case)  
      ForEach ($Object in $InputObject) { 
         # IsNullorEmpty used because !$Value give a erong result with $Value = 0 (True).
         # But 0 may be right ID  
         If (($Object.$Property -Eq $Value) -Or ([string]::IsNullorEmpty($Value))) { $Object }
      }
   } 
}

#
#  Prepare string to using with Zabbix 
#
Function PrepareTo-Zabbix {
   Param (
      [Parameter(ValueFromPipeline = $True)] 
      [PSObject]$InputObject,
      [String]$ErrorCode,
      [Switch]$NoEscape,
      [Switch]$JSONCompatible
   );
   Begin {
      # Add here more symbols to escaping if you need
      $EscapedSymbols = @('\', '"');
      $UnixEpoch = Get-Date -Date "01/01/1970";
   }
   Process {
      # Do something with all objects (non-pipelined input case)  
      ForEach ($Object in $InputObject) { 
         If ($Null -Eq $Object) {
           # Put empty string or $ErrorCode to output  
           If ($ErrorCode) { $ErrorCode } Else { "" }
           Continue;
         }
         # Need add doublequote around string for other objects when JSON compatible output requested?
         $DoQuote = $False;
         Switch (($Object.GetType()).FullName) {
            'System.Boolean'  { $Object = [int]$Object; }
            'System.DateTime' { $Object = (New-TimeSpan -Start $UnixEpoch -End $Object).TotalSeconds; }
            Default           { $DoQuote = $True; }
         }
         # Normalize String object
         $Object = $( If ($JSONCompatible) { $Object.ToString().Trim() } else { Out-String -InputObject (Format-List -InputObject $Object -Property *) });
         
         If (!$NoEscape) { 
            ForEach ($Symbol in $EscapedSymbols) { 
               $Object = $Object.Replace($Symbol, "\$Symbol");
            }
         }

         # Doublequote object if adherence to JSON standart requested
         If ($JSONCompatible -And $DoQuote) { 
            "`"$Object`"";
         } else {
            $Object;
         }
      }
   }
}

#
#  Convert incoming object's content to UTF-8
#
Function ConvertTo-Encoding ([String]$From, [String]$To){  
   Begin   {  
      $encFrom = [System.Text.Encoding]::GetEncoding($from)  
      $encTo = [System.Text.Encoding]::GetEncoding($to)  
   }  
   Process {  
      $bytes = $encTo.GetBytes($_)  
      $bytes = [System.Text.Encoding]::Convert($encFrom, $encTo, $bytes)  
      $encTo.GetString($bytes)  
   }  
}

#
#  Make & return JSON, due PoSh 2.0 haven't Covert-ToJSON
#
Function Make-JSON {
   Param (
      [Parameter(ValueFromPipeline = $True)] 
      [PSObject]$InputObject, 
      [array]$ObjectProperties, 
      [Switch]$Pretty
   ); 
   Begin   {
      [String]$Result = "";
      # Pretty json contain spaces, tabs and new-lines
      If ($Pretty) { $CRLF = "`n"; $Tab = "    "; $Space = " "; } Else { $CRLF = $Tab = $Space = ""; }
      # Init JSON-string $InObject
      $Result += "{$CRLF$Space`"data`":[$CRLF";
      # Take each Item from $InObject, get Properties that equal $ObjectProperties items and make JSON from its
      $itFirstObject = $True;
   } 
   Process {
      # Do something with all objects (non-pipelined input case)  
      ForEach ($Object in $InputObject) {
         # Skip object when its $Null
         If ($Null -Eq $Object) { Continue; }

         If (-Not $itFirstObject) { $Result += ",$CRLF"; }
         $itFirstObject=$False;
         $Result += "$Tab$Tab{$Space"; 
         $itFirstProperty = $True;
         # Process properties. No comma printed after last item
         ForEach ($Property in $ObjectProperties) {
            If (-Not $itFirstProperty) { $Result += ",$Space" }
            $itFirstProperty = $False;
            $Result += "`"{#$Property}`":$Space$(PrepareTo-Zabbix -InputObject $Object.$Property -JSONCompatible)";
         }
         # No comma printed after last string
         $Result += "$Space}";
      }
   }
   End {
      # Finalize and return JSON
      "$Result$CRLF$Tab]$CRLF}";
   }
}

#
#  Return value of object's metric defined by key-chain from $Keys Array
#
Function Get-Metric { 
   Param (
      [Parameter(ValueFromPipeline = $True)] 
      [PSObject]$InputObject, 
      [Array]$Keys
   ); 
   Process {
      # Do something with all objects (non-pipelined input case)  
      ForEach ($Object in $InputObject) { 
        If ($Null -Eq $Object) { Continue; }
        # Expand all metrics related to keys contained in array step by step
        ForEach ($Key in $Keys) {              
           If ($Key) {
              $Object = Select-Object -InputObject $Object -ExpandProperty $Key -ErrorAction SilentlyContinue;
              If ($Error) { Break; }
           }
        }
        $Object;
      }
   }
}

#
#  Exit with specified ErrorCode or Warning message
#
Function Exit-WithMessage { 
   Param (
      [Parameter(Mandatory = $True, ValueFromPipeline = $True)] 
      [String]$Message, 
      [String]$ErrorCode 
   ); 
   If ($ErrorCode) { 
      $ErrorCode;
   } Else {
      Write-Warning ($Message);
   }
   Exit;
}

####################################################################################################################################
#
#                                                 Main code block
#    
####################################################################################################################################
#$VerbosePreference = "continue";
#$defaultConsoleWidth = $True;

# split key to subkeys
$Keys = $Key.Split(".");

If ([string]::IsNullorEmpty($AdmServerLocation)) { $AdmServerLocation = "localhost:13000"; }
Write-Verbose "$(Get-Date) Connecting to Kaspersky Security Center on $AdmServerLocation";

# Connecting to Administration Server of KSC 
$SrvConnectionProps = New-Object -COMObject "klakaut.KlAkParams";
$SrvConnectionProps.Add("Address", $AdmServerLocation);
$SrvConnectionProps.Add("UseSSL", $true);

if (-Not [string]::IsNullorEmpty($Username))   { $SrvConnectionProps.Add('User'       , $Username);   }
if (-Not [string]::IsNullorEmpty($Userpass))   { $SrvConnectionProps.Add('Password'   , $Userpass);   }
if (-Not [string]::IsNullorEmpty($UserDomain)) { $SrvConnectionProps.Add('UserDomain' , $UserDomain); }

$AdmServer = New-Object -COMObject "klakaut.KlAkProxy";

Try {
    $AdmServer.Connect($SrvConnectionProps);
} Catch {
    Exit-WithMessage -Message "Connection Error" -ErrorCode $ErrorCode; 
}

Write-Verbose "$(Get-Date) Connected successfully. Kaspersky Security Center build is $($AdmServer.Build)";
Write-Verbose "$(Get-Date) Prepare to fetch data for object type: '$ObjectType'";

# Temporary variables
$Fileds2Return = New-Object -COMObject "klakaut.KlAkCollection";
$Fileds2Order  = New-Object -COMObject "klakaut.KlAkCollection"; 
$KLCollection = @();
$IDFilterProperty = "";

# Make PS-Object collection from the KSC
$Objects = @();

$NeedToConvertData = $True;
# Prepare fields and perform request(s) to KSC COM-object to get some data
Switch ($ObjectType) {
   'Server' {
      $NeedToConvertData = $False;
      $Objects = New-Object PSObject -Property @{"Build" = $AdmServer.Build; 
                                                 "VersionId" = $AdmServer.VersionId; 
                                                 "IsAlive" = $AdmServer.GetProp("IsAlive");
                                                 "SAASBlocked" = $AdmServer.GetProp("KLADMSRV_SAAS_BLOCKED");
                                               };
    }

   # Fetch Hosts info
   'Host' {
      $KLHosts = New-Object -COMObject "klakaut.KlAkHosts";
      $KLHosts.AdmServer = $AdmServer;

      # Make 'pFields2Return' structure from array of attrib's names
      $FieldNames = ("KLHST_WKS_STATUS_ID", "KLHST_WKS_ID", "KLHST_WKS_DN", "KLHST_WKS_GROUPID", "KLHST_WKS_VIRUS_COUNT", "KLHST_WKS_DNSNAME", "KLHST_WKS_STATUS_MASK");
      $FieldNames | % {$Fileds2Return.SetSize($FieldNames.Count); $i = 0} {$Fileds2Return.SetAt($i, $_); $i++; }

      Switch ($Keys[0]) { 
        'Unassigned' {
            $StrFilter = "KLHST_WKS_FROM_UNASSIGNED = `"True`"";
        }
        'Status' { 
            # Make query only if $Value is valid
            if ($Keys[1] ) {                  
               $StrFilter = 'KLHST_WKS_STATUS_ID ="' + $(
                     Switch ($Keys[1]) { 
                       'OK'       { "0" }
                       'Critical' { "1" }
                       'Warning'  { "2" }
                       'Any'      { "*" }
                     } 
               ) +'"';
            } Else { Exit-WithMessage -Message "Unknown Subkey" -ErrorCode $ErrorCode; }
        }

        'RTPState' { 
            # Make query only if $Value is valid
            if ($Keys[1] -As [RTPState]) {
               $Fileds2Return.SetAt(0, "KLHST_WKS_RTP_STATE");
               # Convert 'RTPState' string representation to integer
               $StrFilter = "KLHST_WKS_RTP_STATE = $([int32] ($Keys[1] -As [RTPState]))";
               Write-Host $StrFilter;
            } Else { 
              Exit-WithMessage -Message "Unknown Subkey '$($Keys[1])'" -ErrorCode $ErrorCode; }
         }

        'NotRunningRTP' { 
            # Bit 1 – Anti-virus application is installed but real-time protection is not running 
            $StrFilter = "KLHST_WKS_STATUS_MASK_1 <> 0";
        }

        'NotRunningAVApplication' { 
            # Bit 2 – Anti-virus application is installed but not running 
            $StrFilter = "KLHST_WKS_STATUS_MASK_2 <> 0";
        }

        'TooMuchVirusesDetected' { 
            # Bit 3 – Number of viruses detected is too much 
            $StrFilter = "KLHST_WKS_STATUS_MASK_3 <> 0";
        }

        'NotInstalledAVApplication' { 
            # Bit 5 – Anti-virus application is not installed 
            $StrFilter = "KLHST_WKS_STATUS_MASK_5 <> 0";
        }

        'TooOldAVBases' { 
            # Bit 7 – Anti-virus bases were updated too long ago 
            $StrFilter = "KLHST_WKS_STATUS_MASK_7 <> 0";
        }

         Default {
            $StrFilter = $(If ($Id) { "KLHST_WKS_ID = $Id" } Else { "KLHST_WKS_DN = `"*`"" } );
         }

      } # Switch ($Keys[0])
      $KLCollection = $KLHosts.FindHosts($StrFilter, $Fileds2Return, $Fileds2Order);
      $IDFilterProperty = "KLHST_WKS_ID";
  }
  # Fetch Licenses info
  'License' {
      $KLLicenses = New-Object -COMObject "klakaut.KlAkLicense";
      $Options = New-Object -COMObject "klakaut.KlAkParams";
      $KLLicenses.AdmServer = $AdmServer;

      # Make 'pFields2Return' structure from array of attrib's names
      $FieldNames = ("KLLIC_APP_ID", "KLLIC_PROD_SUITE_ID", "KLLIC_CREATION_DATE", "KLLIC_LIMIT_DATE", "KLLIC_SERIAL", "KLLIC_PROD_NAME", "KLLIC_KEY_TYPE", "KLLIC_MAJ_VER", "KLLIC_LICENSE_PERIOD", "KLLIC_LIC_COUNT", "KLLICSRV_KEY_INSTALLED", "KLLIC_LICINFO", "KLLIC_SUPPORT_INFO", "KLLIC_CUSTOMER_INFO");     
      $FieldNames | % {$Fileds2Return.SetSize($FieldNames.Count); $i = 0} {$Fileds2Return.SetAt($i, $_); $i++; }
      $KLCollection=$KLLicenses.EnumKeys($Fileds2Return, $Fileds2Order, $Options);
      $IDFilterProperty = "KLLIC_SERIAL";
  }
} # switch ($Object)

If ($NeedToConvertData) {
   # Make PS-Object collection from the COM-object data
   ForEach ($KLCollectionItem in $KLCollection) {
      $Object = New-Object PSObject;
      ForEach ($Filed2Return in $Fileds2Return) {
         Add-Member -InputObject $Object -MemberType 'NoteProperty' -Name $Filed2Return -Value $KLCollectionItem.Item($Filed2Return);
      }
      $Objects +=$Object;
   }
}

# Diconnect from KSC
$AdmServer.Disconnect();

$Objects = PropertyEqualOrAny -InputObject $Objects -Property $IDFilterProperty -Value $Id;

# PS-Object collection post-processing
Switch ($ObjectType) {
  'License' { 
      $Objects | % { $NowTime = Get-Date;
         Add-Member -InputObject $_ -MemberType 'NoteProperty' -Name "TimeLeftToLicenseExpire" -Value $([Int32] $($_.KLLIC_LIMIT_DATE - $NowTime).TotalSeconds);
         Add-Member -InputObject $_ -MemberType 'NoteProperty' -Name "LicenseExpired" -Value $(If ($(Get-Date) -ge $_.KLLIC_LIMIT_DATE) { "1" } Else { "0" }) 
      }     
    }
}

#$Objects | ft *
#exit;
Write-Verbose "$(Get-Date) Collection created, begin processing its with action: '$Action'";

# if no object in collection: 1) JSON must be empty; 2) 'Get' must be able to return ErrorCode
Switch ($Action) {
   'Discovery' {
      # Discovery given object, make json for zabbix
      Switch ($ObjectType) {
        'License' { $ObjectProperties = @("KLLIC_SERIAL", "KLLIC_KEY_TYPE", "KLLICSRV_KEY_INSTALLED", "KLLIC_LIC_COUNT", "KLLIC_LIMIT_DATE", "LicenseExpired"); }
        'Host' { $ObjectProperties = @("KLHST_WKS_ID", "KLHST_WKS_DN", "KLHST_WKS_GROUPID", "KLHST_WKS_DNSNAME"); }
      }
      Write-Verbose "$(Get-Date) Generating LLD JSON";
      $Result = Make-JSON -InputObject $Objects -ObjectProperties $ObjectProperties -Pretty;
   }
   'Get' {
      # Get metrics or metric list
      Write-Verbose "$(Get-Date) Getting metric related to key: '$Key'";
      $Result = PrepareTo-Zabbix -InputObject (Get-Metric -InputObject $Objects -Keys $Keys) -ErrorCode $ErrorCode;
   }
   # Get-Metric can return an array of objects. In this case need to take each item and add its to $r
   'Sum' {
      Write-Verbose "$(Get-Date) Sum objects";  
      $Result = $( 
         If ($Objects) { 
            $Result = 0;
            ForEach ($Object in $Objects) {
               $Mtr = Get-Metric -InputObject $Object -Keys $Keys;
               Write-Host $Mtr;
               $Result += $Mtr;
            }
            $Result
         } Else { 0 } 
      ); 
   }
   'Count' { 
      Write-Verbose "$(Get-Date) Counting objects";  
      $Count = 0;
      # ++ must be faster that .Count, due don't enumerate object list
      ForEach ($Object in $Objects) { $Count++; }
      $Result = $Count;
   }
}


# Convert string to UTF-8 if need (For Zabbix LLD-JSON with Cyrillic chars for example)
if ($consoleCP) { 
   Write-Verbose "$(Get-Date) Converting output data to UTF-8";
   $Result = $Result | ConvertTo-Encoding -From $consoleCP -To UTF-8; 
}

# Break lines on console output fix - buffer format to 255 chars width lines 
if (!$defaultConsoleWidth) { 
   Write-Verbose "$(Get-Date) Changing console width to $CONSOLE_WIDTH";
   mode con cols=$CONSOLE_WIDTH; 
}

Write-Verbose "$(Get-Date) Finishing";

$Result;
