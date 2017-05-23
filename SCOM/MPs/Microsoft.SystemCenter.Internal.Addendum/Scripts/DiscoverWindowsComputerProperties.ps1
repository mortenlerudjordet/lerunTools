#-------------------------------------------------------------------------------
# DiscoverWindowsComputerProperties.ps1
#
# Script discovers the extended properties from AD/WMI given the 
#  DNS name of the computer.
#  Fixes added by Morten Lerudjordet
#-------------------------------------------------------------------------------

param($SourceType, $SourceId, $ManagedEntityId, $ComputerIdentity, [String]$LogLevelText)

    $strDNSComputerName     = $ComputerIdentity
    $strNetBIOSDomain       = $null 
    $strNetBIOSComputerName = $null
    $strNetBIOSHostName     = $null
    $strDomainDNsName       = $null
    $strForestDnsName       = $null
    $strSite                = $null
    $strComputerOU          = $null
    $strIPAddresses         = $null
    $strLogicalProcessors   = $null
    $strPhysicalProcessors  = $null
    $strHostServerName      = $null
    $strVirtualMachineName  = $null

$strDomainDN = $null;
$WIN_OS_2012_Ver = "6.2"

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
			# Error
			$oAPI.LogScriptEvent($SCRIPT_NAME,$EventNr,1,$LogMessage)	
		}
		2 {
			# Warning
			$oAPI.LogScriptEvent($SCRIPT_NAME,$EventNr,2,$LogMessage)	
		}
		4 {
			# Information
			$oAPI.LogScriptEvent($SCRIPT_NAME,$EventNr,0,$LogMessage)	
		}
		5 {
			# Debug
			$oAPI.LogScriptEvent($SCRIPT_NAME,$EventNr,0,$LogMessage)	
		}		
	}
}
}

#Checks if the OS Version is more than 6.2 i.e. Server 2012
function CheckByOSCurrentVersion($strComputerDNS) #As Boolean
{ 
    $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $strComputerDNS)
    $regKey = $reg.OpenSubKey("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion")
    $strCurrentOSVer = $regKey.GetValue("CurrentVersion")
    if($strCurrentOSVer -ge $WIN_OS_2012_Ver)
	{	
		return $true
	}
    return $false
}

#--------------------------------------------------------------
# Tests for NULL or Empty
#--------------------------------------------------------------
function IsNullOrEmpty($str)
{
  return (($null -eq $str) -or (0 -eq $str.length))
}


#-----------------------------------------------------------
# Returns the DN domain name from DNS
#-----------------------------------------------------------
function DNDomainFromDNS($strDomainDNsName)
{
    # Determine DN domain name from RootDSE object.
    $query = "LDAP://$strDomainDNsName/RootDSE"
    $objRootDSE = [System.DirectoryServices.DirectoryEntry]([ADSI]$query)
    return $objRootDSE.Get("defaultNamingContext")
}


#-----------------------------------------------------------
# Returns the forest for the domain
#-----------------------------------------------------------
function ForestFromDomainDNS($strDNSDomain)
{
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
       LogEvent -EventNr $EventId -EventType $EVENT_ERROR -LogMessage "Error retrieving domain name.`n$($_.Exception.Message)"
    }
    return $strForestDNS
}

#-----------------------------------------------------------
# Returns the NetBIOS domain name from the DNS domain name
#-----------------------------------------------------------
function NetBIOSDomainFromDN($strNetBIOSComputerName)
{
    if($Is_OS_More_Than_2012)
	{
		try
		{
			$DnsObject = Get-CimInstance -Classname Win32_ComputerSystem -ErrorAction Stop
		}
		catch
		{
			LogEvent -EventNr $EventId -EventType $EVENT_ERROR -LogMessage "Error retrieving OS info.`n$($_.Exception.Message)`n$($_.InvocationInfo.PositionMessage)"
		}
    }
	else
	{
      $DnsObject = Get-WmiObject -Class Win32_ComputerSystem
    }
    return $DnsObject.Domain
}


#-------------------------------------------------------------
# Gets the IP addresses for the given computer name
#-------------------------------------------------------------
function GetIPAddresses($strNetBIOSComputerName)
{
    $strIPs =""
    if($Is_OS_More_Than_2012)
	{
		try
		{
			$arrItems = Get-CimInstance -Classname Win32_NetworkAdapterConfiguration -ErrorAction Stop
		}
		catch
		{
			LogEvent -EventNr $EventId -EventType $EVENT_ERROR -LogMessage "Error retrieving NIC info.`n$($_.Exception.Message)`n$($_.InvocationInfo.PositionMessage)"
		}
    }
	else
    {
      $arrItems = Get-WmiObject -Class Win32_NetworkAdapterConfiguration
    }
    foreach($arrItem in $arrItems)
    {
        $IPValue = $arrItem.IPAddress
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
    if(($strIPs -ne "") -and ($strIPs -ne $null))
    {
        return $strIPs
    }
	else
	{
		# Alternate way of getting IP addresses
		$ipItems = Get-NetIPAddress
		foreach($ipItem in $ipItems)
		{
			$ip = $ipItem.IPAddress
			if(($ip -ne "::1") -and ($ip -ne "127.0.0.1"))
			{
				if (($null -eq $strIPs) -or ($strIPs -eq ""))
				{
					$strIPs = $ip
				}
				else
				{
					$strIPs = $strIPs + ', ' +$ip
				}
			}
		}
		return $strIPs
	}
}

#-----------------------------------------------------------
# Get the site name from the Computer DNS
#-----------------------------------------------------------
function GetSiteFromComputerDNS($strComputerDNS)
{
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
         LogEvent -EventNr $EventId -EventType $EVENT_ERROR -LogMessage "Error retrieving site name.`n$($_.Exception.Message)"
    }

    return $strSiteName
    
}

#-----------------------------------------------------------
# Adds the property to the instance if the value is non-$null
#-----------------------------------------------------------
function AddClassProperty($oInstance, $strProperty, $strValue)
{
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

try 
{

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
		Default {
			$LogLevel = 1
		}
	}

	$Is_OS_More_Than_2012 = CheckByOSCurrentVersion $strDNSComputerName
	# Need to retrieve these properties
	$oAPI = new-object -comobject "MOM.ScriptAPI"

	LogEvent -EventNr $EventId -EventType $EVENT_INFO -LogMessage "Starting script. Running as: $(whoami)"
	$oDiscovery = $oAPI.CreateDiscoveryData($SourceType, $SourceId, $ManagedEntityId);
	# Get the virtual machine information
	try
	{
		$reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $strDNSComputerName)
		$regKey = $reg.OpenSubKey("SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters")
		$strHostServerName = $regKey.GetValue("HostName")
	}
	catch
	{
		LogEvent -EventNr $EventId -EventType $EVENT_INFO  -LogMessage "Could not retrieving hostname from registry.`n$($_.Exception.Message)"
	}
	try
	{
		$reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $strDNSComputerName)
		$regKey = $reg.OpenSubKey("SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters")
		$strVirtualMachineName = $regKey.GetValue("VirtualMachineName")
	}
	catch
	{
		LogEvent -EventNr $EventId -EventType $EVENT_INFO -LogMessage "Could not retrieving virtual machine name from registry.`n$($_.Exception.Message)"
	}
	# Attempt to do things the 'right' way
	try
	{
    
		$E_CLUSTER_RESOURCE_NOT_FOUND = -2146823281

		# Get the computer from the system
		$astrSplit = ""
		$objComputer = $null
		$colSettings = $null
		$astrSplit = $strDNSComputerName.split(".")
		$strNetBIOSComputerName = $astrSplit[0]

		try
		{	
			$query = "Select Domain, Name, NumberOfLogicalProcessors, NumberOfProcessors from Win32_ComputerSystem WHERE Name = ""$strNetBIOSComputerName"""
			if($Is_OS_More_Than_2012)
			{   
				try
				{
					if(! (Get-Module -Name cimcmdlets -ErrorAction SilentlyContinue) )
					{
						# Stop if one cannot use Get-CimInstance CMDlet
						Import-Module -Name cimcmdlets -ErrorAction Stop
					}					
					$objComputer = Get-CimInstance -Namespace "root\cimv2" -Query $query -ErrorAction Stop
				}
				catch
				{
					LogEvent -EventNr $EventId -EventType $EVENT_ERROR -LogMessage "Error retrieveing OS data from WMI.`n$($_.Exception.Message)`n$($_.InvocationInfo.PositionMessage)"
				}
			}
			else
			{
				$objComputer = Get-WmiObject -Namespace "root\cimv2" -Query $query -ErrorAction Stop
			}
        
			$strDomainDNsName = $objComputer.Domain
			$strNetBIOSHostName = $objComputer.Name
			$strLogicalProcessors = $objComputer.NumberOfLogicalProcessors
			$strPhysicalProcessors = $objComputer.NumberOfProcessors
			if ($null -eq $strLogicalProcessors)
			{
			  $strLogicalProcessors = $objComputer.NumberOfProcessors
			  $strPhysicalProcessors = $null
			}
		}
		catch
		{
			$e = $_.Exception.Message
			$message = $_.Exception.Message
			LogEvent -EventNr $EventId -EventType $EVENT_ERROR -LogMessage $message
			if ($e -ne $E_CLUSTER_RESOURCE_NOT_FOUND)
			{
				throw $e;
			}
			$query = "Select Domain, Name, NumberOfLogicalProcessors, NumberOfProcessors from Win32_ComputerSystem"
			if($Is_OS_More_Than_2012)
			{
				try
				{
					$colSettings = Get-CimInstance -Namespace "root\cimv2" -Query $query -ErrorAction Stop
				}
				catch
				{
					LogEvent -EventNr $EventId -EventType $EVENT_ERROR -LogMessage "Error retrieveing logical processors.`n$($_.Exception.Message)`n$($_.InvocationInfo.PositionMessage)"
				}
			}
			else
			{
			  $colSettings = Get-WmiObject -Namespace "root\cimv2" -Query $query -ErrorAction Stop
			}
			$objComputer = $colSettings.item()
			$strDomainDNsName = $objComputer.Domain
			$strNetBIOSHostName = $objComputer.Name
			$strLogicalProcessors = $objComputer.NumberOfLogicalProcessors
			$strPhysicalProcessors = $objComputer.NumberOfProcessors
			if ($null -eq $strLogicalProcessors)
			{
			  $strLogicalProcessors = $objComputer.NumberOfProcessors
			  $strPhysicalProcessors = $null
			}
		}
    
		try
		{
		  # Get the domain data. If computer is in a workgroup, it will catch exception.
		  $strDomainDN = DNDomainFromDNS $strDomainDNsName
		}
		catch
		{
		  Write-Verbose -Message "Domain Data Exception caught for " + $strDomainDNsName
		  LogEvent -EventNr $EventId -EventType $EVENT_ERROR -LogMessage "Domain Data Exception caught for " + $strDomainDNsName
		}
    
		if ($strDomainDN -ne $null)
		{
		  $strNetBIOSDomain = NetBIOSDomainFromDN $strNetBIOSComputerName
		}
    
		$strIPAddresses = GetIPAddresses $strNetBIOSComputerName

		$ADSISearcher = New-Object System.DirectoryServices.DirectorySearcher
		$ADSISearcher.Filter = '(&(dnshostname=' + $strDNSComputerName + ')(name=' + $strNetBIOSComputerName + ')(objectClass=computer))'
		$ADSISearcher.SearchScope = 'Subtree'
		$Computer = $ADSISearcher.FindOne()
		$strComputerOU = $($Computer.Properties.Item('distinguishedName')).Substring($($Computer.Properties.Item('distinguishedName')).IndexOf('OU='))
	}

	# Unable to contact the machine, (mis)use the DNS name
	catch
	{
	  $e = $_.Exception.Message
	  $message = "Exception retrieving properties '" + $e + "', using failsafe method" # Do nothing
	  LogEvent -EventNr $EventId -EventType $EVENT_ERROR -LogMessage $message
	  Write-Verbose -Message $message
	}

	if((IsNullOrEmpty $strNetBIOSComputerName) -or (IsNullOrEmpty $strNetBIOSDomain))
	{
		# Try to parse the DNS name of the system
		$arrNameSplit       = $strDNSComputerName.split(".")
		if (IsNullOrEmpty $strNetBIOSComputerName -and ($arrNameSplit.length -gt 0))
		{
		  $strNetBIOSComputerName = $arrNameSplit[0]
		}
		if ((IsNullOrEmpty $strNetBIOSDomain) -and ($arrNameSplit.length -gt 1))
		{
		  $strNetBIOSDomain = $arrNameSplit[1]
		}
    
		# If there is no DNS name (no '.') then this is a workgroup, so use the domain name from WMI as NetBIOS Domain
		if ((IsNullOrEmpty $strNetBIOSDomain)  -and (-not (IsNullOrEmpty $strDomainDnsName)))
		{
		  $strNetBIOSDomain = $strDomainDNsName;
		}
	}

	if (IsNullOrEmpty $strDomainDnsName)
	{
		for($i = 1; $i -lt $arrNameSplit.length; $i++)
		{
			if (-not (IsNullOrEmpty $strDomainDnsName))
			{
				$strDomainDNsName = $strDomainDNsName + "."
				$strDomainDNsName = $strDomainDNsName + $arrNameSplit[$i]
			}
			else
			{
				$strDomainDNsName = $arrNameSplit[$i]
			}
		}
	}


	# Get the forest if we have the Domain DNS name
	if((IsNullOrEmpty $strForestDnsName) -and (-not (IsNullOrEmpty $strDomainDNsName)))
	{
		$strForestDnsName = ForestFromDomainDNS $strDomainDNsName
	}

	# Get the site name
	if (IsNullOrEmpty $strSite)
	{
		$strSite = GetSiteFromComputerDNS $strDNSComputerName
	}

	Write-Verbose -Message "NetBIOS Computer Name:    $strNetBIOSComputerName"
	Write-Verbose -Message "NetBIOS Domain Name:      $strNetBIOSDomain"
	Write-Verbose -Message "Forest DNS Name:          $strForestDnsName"
	Write-Verbose -Message "Domain DNS Name:          $strDomainDNsName"
	Write-Verbose -Message "AD Site:                  $strSite"
	Write-Verbose -Message "OU:                       $strComputerOU"
	Write-Verbose -Message "IP Addresses:             $strIPAddresses"
	Write-Verbose -Message "Logical Processors:       $strLogicalProcessors"
	Write-Verbose -Message "Physical Processors:      $strPhysicalProcessors"
	Write-Verbose -Message "Host Server Name:         $strHostServerName"
	Write-Verbose -Message "Virtual Machine Name:     $strVirtualMachineName"

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

	$oDiscovery.AddInstance($oInstance)
	$oDiscovery
}
Catch 
{
	LogEvent -EventNr $EventId -EventType $EVENT_ERROR -LogMessage "Error running script.`n$($_.Exception.Message)`n$($_.InvocationInfo.PositionMessage)"
	LogEvent -EventNr $EventId -EventType $EVENT_DEBUG  `
	-LogMessage "Debug:`n$($_.InvocationInfo.MyCommand.Name)`n$($_.ErrorDetails.Message)`n$($_.InvocationInfo.PositionMessage)`n$($_.CategoryInfo.ToString())`n$($_.FullyQualifiedErrorId)"
}
Finally 
{
	$Time.Stop()
	LogEvent -EventNr $EventId -EventType $EVENT_INFO -LogMessage "Script has completed.`nRun Time: $($Time.Elapsed.TotalSeconds) second(s)"
}
