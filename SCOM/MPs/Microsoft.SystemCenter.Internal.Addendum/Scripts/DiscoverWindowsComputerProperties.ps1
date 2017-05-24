#-------------------------------------------------------------------------------
# DiscoverWindowsComputerProperties.ps1
#
# Script discovers the extended properties from AD/WMI given the 
#  DNS name of the computer.
#  Fixes added by Morten Lerudjordet
#-------------------------------------------------------------------------------
param(
    $SourceType, 
    $SourceId, 
    $ManagedEntityId, 
    $ComputerIdentity, 
    [String]$LogLevelText = "CommandLine"
)

    $strDNSComputerName     = $ComputerIdentity
    $strNetBIOSDomain       = $null 
    $strNetBIOSComputerName = $null
    $strDomainDNsName       = $null
    $strForestDnsName       = $null
    $strSite                = $null
    $strComputerOU          = $null
    $strIPAddresses         = $null
    $strLogicalProcessors   = $null
    $strPhysicalProcessors  = $null
    $strHostServerName      = $null
    $strVirtualMachineName  = $null

#==================================================================================
# Func:		LogEvent
# Purpose:	Logs an informational event to the Operations Manager event log
#
#==================================================================================
function LogEvent
{
Param(
    [Int]$EventNr,
    [Int]$EventType,
    [String]$LogMessage
)

$LogMessage = "`n" + $LogMessage
if($EventType -le $LogLevel)
{
    Switch($EventType)
    {
        1 {
            if($LogLevelText -eq "CommandLine") 
            {
                # Run from command line and log to screen
                Write-Verbose -Message $LogMessage
            }
            else
            {
                # Error
                $oAPI.LogScriptEvent($SCRIPT_NAME,$EventNr,1,$LogMessage)	
            }

        }
        2 {
            if($LogLevelText -eq "CommandLine") 
            {
                # Run from command line and log to screen
                Write-Verbose -Message $LogMessage
            }
            else
            {
                # Warning
                $oAPI.LogScriptEvent($SCRIPT_NAME,$EventNr,2,$LogMessage)	
            }

        }
        4 {
            if($LogLevelText -eq "CommandLine") 
            {
                # Run from command line and log to screen
                Write-Verbose -Message $LogMessage
            }
            else
            {
                # Information
                $oAPI.LogScriptEvent($SCRIPT_NAME,$EventNr,0,$LogMessage)
            }
    
        }
        5 {
            if($LogLevelText -eq "CommandLine") 
            {
                # Run from command line and log to screen
                Write-Verbose -Message $LogMessage
            }
            else
            {
                # Debug
                $oAPI.LogScriptEvent($SCRIPT_NAME,$EventNr,0,$LogMessage)
            }
    
        }	
    }
}
}

#--------------------------------------------------------------
# Tests for NULL or Empty
#--------------------------------------------------------------
function IsNullOrEmpty
{
Param(
    [string]$str
)
  return (($null -eq $str) -or (0 -eq $str.length))
}

#-----------------------------------------------------------
# Returns the forest for the domain
#-----------------------------------------------------------
function ForestFromDomainDNS
{
Param(
    [string]$strDNSDomain
)
    $strForestDNS = $null
    try
    {
        $query = "LDAP://$strDNSDomain/RootDSE"
        $objRootDSE = [System.DirectoryServices.DirectoryEntry]([ADSI]$query)
        $strForestDN = $objRootDSE.Get("rootdomainNamingContext")
        
        # We got the DN (DC=corp,DC=microsoft,DC=com), translate to DNS (corp.microsoft.com)
        $arrParseDN = $strForestDN.split(",")
        for ($i = 0; $i -lt $arrParseDN.length; $i++)
        {
            $arrParseDC = $arrParseDN[$i].split("=")
            if ($null -eq $strForestDNS)
            {
                $strForestDNS = $arrParseDC[1]
            }
            else
            {
                $strForestDNS = $strForestDNS + "." + $arrParseDC[1]
            }
        }
    }
    catch
    {
       LogEvent -EventNr $EventId -EventType $EVENT_ERROR -LogMessage "Error retrieving forest domain name.`n$($_.Exception.Message)"
    }
    return $strForestDNS
}

#-----------------------------------------------------------
# Returns the NetBIOS domain name
#-----------------------------------------------------------
function NetBIOSDomain
{
    $query = "Select DomainName from Win32_NTDomain"

    try
    {
        $ntDomain = Get-CimInstance -Namespace "root\cimv2" -Query $query -ErrorAction Stop
    }
    catch
    {
        try
        {
            $ntDomain = Get-WmiObject "root\cimv2" -Namespace -Query $query -ErrorAction Stop   
        }
        catch 
        {
            LogEvent -EventNr $EventId -EventType $EVENT_ERROR -LogMessage "Error retrieving netbios domain name info.`n$($_.Exception.Message)`n$($_.InvocationInfo.PositionMessage)"
        }
        
    }

    return $ntDomain.DomainName
}

#-------------------------------------------------------------
# Gets the IP addresses for the given computer name
#-------------------------------------------------------------
function GetIPAddresses
{
    $strIPs =""
    # get connected network adapters
    try
    {    
        $Adapters = Get-CimInstance -Classname Win32_NetworkAdapter -Filter 'netConnectionStatus = 2' -ErrorAction Stop | Select-Object -Property Index            
    }
    catch
    {
        try
        {
            $Adapters = Get-WmiObject -Class Win32_NetworkAdapter -Filter "netConnectionStatus = 2" -ErrorAction Stop | Select-Object -Property Index
        }
        catch
        {
            LogEvent -EventNr $EventId -EventType $EVENT_ERROR -LogMessage "Error retrieving NIC info.`n$($_.Exception.Message)`n$($_.InvocationInfo.PositionMessage)"
        }    
    }
    # IP address from connected network adapters

    ForEach ($Adapter in $Adapters)
    {            
        try
        {    
            $Config = Get-CimInstance -Classname Win32_NetworkAdapterConfiguration -Filter "Index = $($Adapter.Index)" -ErrorAction Stop               
        }
        catch
        {
            try
            {
                $Config = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "Index = $($Adapter.Index)" -ErrorAction Stop
            }
            catch 
            {
                LogEvent -EventNr $EventId -EventType $EVENT_ERROR -LogMessage "Error retrieving NIC config for adapter: $($Adapter.Name).`nError details: $($_.Exception.Message)`n$($_.InvocationInfo.PositionMessage)"
            }
            
        }
        if($Config)
        {
            $IPValue = $Config.IPAddress
            if ($null -ne $IPValue)
            {
                $arrIPs = $IPValue

                for ($i =0; $i -lt $arrIPs.length; $i++)
                {
                    $strIP = $arrIPs[$i];
                    if ($null -ne $strIP)
                    {
                        if (($null -eq $strIPs)  -or ($strIPs -eq ""))
                        {
                            $strIPs = $strIP
                        }
                        else
                        {
                            $matchIP = $strIPs.IndexOf($strIP);                        
                            if($matchIP -eq -1)
                            {
                                $strIPs = $strIPs + ", " + $strIP
                            }
                        }
                    }
                }
            }
        }
    } 
    if(($strIPs -ne "") -and ($strIPs -ne $null))
    {
        return $strIPs
    }
    else
    {
        LogEvent -EventNr $EventId -EventType $EVENT_WARNING -LogMessage "No connected network adapter with IP addresses found on this machine"
    }
}

#-----------------------------------------------------------
# Get the site name from the Computer DNS
#-----------------------------------------------------------
function GetSiteFromComputerDNS
{
Param(
    [string]$strComputerDNS
)
    $strSiteName = $null

    try
    {
        $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $strComputerDNS)
        $regKey = $reg.OpenSubKey("System\\CurrentControlSet\\Services\\Netlogon\\Parameters")
        $strSiteName = $regKey.GetValue("SiteName")

        #If SiteName override is $null or empty, try DynamicSiteName
        if(IsNullOrEmpty $strSiteName)
        {
          $strSiteName = $regKey.GetValue("DynamicSiteName")
        }
    }
    catch
    {
         LogEvent -EventNr $EventId -EventType $EVENT_ERROR -LogMessage "Error retrieving site name.`n$($_.Exception.Message)`n$($_.InvocationInfo.PositionMessage)"
    }

    return $strSiteName
   
}

#-----------------------------------------------------------
# Adds the property to the instance if the value is non-$null
#-----------------------------------------------------------
function AddClassProperty
{
Param(
    $oInstance, 
    [string]$strProperty, 
    [string]$strValue
)
    if ($null -ne $strValue) {
        $oInstance.AddProperty($strProperty, $strValue)
    }
}

#---------------------------------------------------------------------------
# Main
#---------------------------------------------------------------------------
#Define local event constants
$SCRIPT_NAME    = 'DiscoverWindowsComputerProperties.ps1'
$EVENT_ERROR 	= 1
$EVENT_WARNING 	= 2
$EVENT_INFO     = 4
$EVENT_DEBUG    = 5
$EventId        = 100


# Alternate way to write to eventlog for SCOM
Write-EventLog -EventId $EventId -LogName 'Operations Manager' -Source 'Health Service Script' -EntryType Information -Message "$($SCRIPT_NAME): Executing with loglevel: $LogLevelText" -ErrorAction SilentlyContinue
$Time = [System.Diagnostics.Stopwatch]::StartNew()

Switch($LogLevelText)
{
    'Error' {
        $LogLevel = 1
    }
    'Warning' {
        $LogLevel = 2
    }
    'Information' {
        $LogLevel = 4
    }
    'Debug' {
        $LogLevel = 5
    }
    'CommandLine' {
        $VerbosePreference="Continue"
        $LogLevel = 6
    }
    Default {
        $LogLevel = 1
    }
}

# Need to retrieve these properties
$oAPI = new-object -comobject "MOM.ScriptAPI"

LogEvent -EventNr $EventId -EventType $EVENT_INFO -LogMessage "Starting script. Running as: $(whoami)"
$oDiscovery = $oAPI.CreateDiscoveryData($SourceType, $SourceId, $ManagedEntityId);
# Get the virtual machine information
$reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $strDNSComputerName)
$regKey = $reg.OpenSubKey("SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters")
$strHostServerName = $regKey.GetValue("HostName")

# Will only discover if VM is running on Hyper-V
$reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $strDNSComputerName)
$regKey = $reg.OpenSubKey("SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters")
$strVirtualMachineName = $regKey.GetValue("VirtualMachineName")

try
{    
    # Get the computer from the system
    $objComputer = $null
    $colSettings = $null

    try
    {	
        $query = "Select Domain, Name, NumberOfLogicalProcessors, NumberOfProcessors, PartOfDomain from Win32_ComputerSystem"
        $objComputer = Get-CimInstance -Namespace "root\cimv2" -Query $query -ErrorAction Stop
    }
    catch
    {
        try
        {
			Import-Module -Name cimcmdlets -ErrorAction Stop
            $objComputer = Get-CimInstance -Namespace "root\cimv2" -Query $query -ErrorAction Stop
        }
        catch
        {
            try
            {
                $objComputer = Get-WmiObject -Namespace "root\cimv2" -Query $query -ErrorAction Stop
            }
            catch
            {
                LogEvent -EventNr $EventId -EventType $EVENT_ERROR -LogMessage "Error retrieveing computer system info from WMI.`n$($_.Exception.Message)`n$($_.InvocationInfo.PositionMessage)"
            }    
                
        }
    }
    $strDomainDNSName = $objComputer.Domain
    # if retrieved from WMI use as netbiosname
    If($objComputer.Name)
    {
        $strNetBIOSComputerName = $objComputer.Name
    }
    # create netbios name from machine name input
    else
    {
        $strNetBIOSComputerName = $strDNSComputerName.split(".")[0]
    }
    $strLogicalProcessors = $objComputer.NumberOfLogicalProcessors
    $strPhysicalProcessors = $objComputer.NumberOfProcessors
    if ($null -eq $strLogicalProcessors)
    {
        $strLogicalProcessors = $objComputer.NumberOfProcessors
        $strPhysicalProcessors = $null
    }

    # Get the domain information. If computer is part of domain
    if($objComputer.PartOfDomain -eq $True) 
    {
        # Get netbios domain name
        $strNetBIOSDomain = NetBIOSDomain
        # Get forest name
        $strForestDnsName = ForestFromDomainDNS $strDomainDNSName
        # Get the site name
        $strSite = GetSiteFromComputerDNS $strDNSComputerName

        $Computer = $Null
        $ADSISearcher = New-Object System.DirectoryServices.DirectorySearcher
        $ADSISearcher.Filter = '(&(dnshostname=' + $strDNSComputerName + ')(name=' + $strNetBIOSComputerName + ')(objectClass=computer))'
        $ADSISearcher.SearchScope = 'Subtree'
        $Computer = $ADSISearcher.FindOne()

        if( !($Computer -eq $Null) )
        {  
            if($Computer.Properties.Item('distinguishedName') -notlike "*OU=*") 
            {
                $strComputerOU = $($Computer.Properties.Item('distinguishedName')).Substring($($Computer.Properties.Item('distinguishedName')).LastIndexOf('CN='))
            }
            else
            {
                $strComputerOU = $($Computer.Properties.Item('distinguishedName')).Substring($($Computer.Properties.Item('distinguishedName')).IndexOf('OU='))
            }            
        }
        else 
        {
            LogEvent -EventNr $EventId -EventType $EVENT_WARNING -LogMessage "Failed to find matching computer object in Active Directory for $strDNSComputerName"
        }
    }

    # Adapter IP addresses
    $strIPAddresses = GetIPAddresses

    # Set date for last script run
    $strLastInventoryDate = Get-Date

    LogEvent -EventNr $EventId -EventType $EVENT_DEBUG -LogMessage  "NetBIOS Computer Name:    $strNetBIOSComputerName"
    LogEvent -EventNr $EventId -EventType $EVENT_DEBUG -LogMessage  "NetBIOS Domain Name:      $strNetBIOSDomain"
    LogEvent -EventNr $EventId -EventType $EVENT_DEBUG -LogMessage  "Forest DNS Name:          $strForestDnsName"
    LogEvent -EventNr $EventId -EventType $EVENT_DEBUG -LogMessage  "Domain DNS Name:          $strDomainDNsName"
    LogEvent -EventNr $EventId -EventType $EVENT_DEBUG -LogMessage  "AD Site:                  $strSite"
    LogEvent -EventNr $EventId -EventType $EVENT_DEBUG -LogMessage  "OU:                       $strComputerOU"
    LogEvent -EventNr $EventId -EventType $EVENT_DEBUG -LogMessage  "IP Addresses:             $strIPAddresses"
    LogEvent -EventNr $EventId -EventType $EVENT_DEBUG -LogMessage  "Logical Processors:       $strLogicalProcessors"
    LogEvent -EventNr $EventId -EventType $EVENT_DEBUG -LogMessage  "Physical Processors:      $strPhysicalProcessors"
    LogEvent -EventNr $EventId -EventType $EVENT_DEBUG -LogMessage  "Host Server Name:         $strHostServerName"
    LogEvent -EventNr $EventId -EventType $EVENT_DEBUG -LogMessage  "Virtual Machine Name:     $strVirtualMachineName"
    LogEvent -EventNr $EventId -EventType $EVENT_DEBUG -LogMessage  "Last Inventory Date:      $($strLastInventoryDate.ToString())"

    $oInstance = $oDiscovery.CreateClassInstance("$MPElement[Name='Windows!Microsoft.Windows.Computer']$")
    AddClassProperty $oInstance "$MPElement[Name='Windows!Microsoft.Windows.Computer']/PrincipalName$" $ComputerIdentity
    AddClassProperty $oInstance "$MPElement[Name='Windows!Microsoft.Windows.Computer']/NetbiosComputerName$" $strNetBIOSComputerName
    AddClassProperty $oInstance "$MPElement[Name='Windows!Microsoft.Windows.Computer']/NetbiosDomainName$" $strNetBIOSDomain
    AddClassProperty $oInstance "$MPElement[Name='Windows!Microsoft.Windows.Computer']/ForestDnsName$" $strForestDnsName
    AddClassProperty $oInstance "$MPElement[Name='Windows!Microsoft.Windows.Computer']/DomainDnsName$" $strDomainDNsName
    AddClassProperty $oInstance "$MPElement[Name='Windows!Microsoft.Windows.Computer']/ActiveDirectorySite$" $strSite
    AddClassProperty $oInstance "$MPElement[Name='Windows!Microsoft.Windows.Computer']/OrganizationalUnit$" $strComputerOU
    AddClassProperty $oInstance "$MPElement[Name='Windows!Microsoft.Windows.Computer']/IPAddress$" $strIPAddresses
    AddClassProperty $oInstance "$MPElement[Name='Windows!Microsoft.Windows.Computer']/LogicalProcessors$" $strLogicalProcessors
    AddClassProperty $oInstance "$MPElement[Name='Windows!Microsoft.Windows.Computer']/PhysicalProcessors$" $strPhysicalProcessors
    AddClassProperty $oInstance "$MPElement[Name='Windows!Microsoft.Windows.Computer']/HostServerName$" $strHostServerName
    AddClassProperty $oInstance "$MPElement[Name='Windows!Microsoft.Windows.Computer']/VirtualMachineName$" $strVirtualMachineName
    AddClassProperty $oInstance "$MPElement[Name='Windows!Microsoft.Windows.Computer']/LastInventoryDate$" $strLastInventoryDate

    $oDiscovery.AddInstance($oInstance)
}
catch 
{
    LogEvent -EventNr $EventId -EventType $EVENT_ERROR -LogMessage "Error running script.`n$($_.Exception.Message)`n$($_.InvocationInfo.PositionMessage)"
}
finally 
{
    if($LogLevelText -eq "CommandLine") 
    {
        $oAPI.Return($oDiscovery)
    }
    else 
    {
        $oDiscovery
    }    
    $Time.Stop()
    LogEvent -EventNr $EventId -EventType $EVENT_INFO -LogMessage "Script has completed.`nRun Time: $($Time.Elapsed.TotalSeconds) second(s)"
}
