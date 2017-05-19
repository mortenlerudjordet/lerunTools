Param($SourceType, $SourceId, $ManagedEntityId, $ComputerIdentity, $NetworkName)


#OS version for Win 2012
$WIN_OS_2012_Ver = "6.2"
$OSRegistryKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\"
# Hardcoded
$LogLevelText = "Information"

#******************************************************************************
#   FUNCTION:       CheckMinOSVer
#   DESCRIPTION:    Returns True if the Registry Key for CurrentVersion
#                   is equal or Higher than the Minimum OS Versions Number.
#   PARAMETER:      DblMinVer Minimum Version Number to use
#   RETURNS:        Boolean: True, if build is greater or equal than the given number
#******************************************************************************
function CheckByOSCurrentVersion() #As Boolean
{ 
    $strCurrentOSVer = Get-ItemProperty $OSRegistryKey
    $strCurrentOSVer = $strCurrentOSVer.CurrentVersion
    if($strCurrentOSVer -ge $WIN_OS_2012_Ver)
	{	
		return $true;
	}
    return $false;
}

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
			$api.LogScriptEvent($SCRIPT_NAME,$EventNr,1,$LogMessage)	
		}
		2 {
			# Warning
			$api.LogScriptEvent($SCRIPT_NAME,$EventNr,2,$LogMessage)	
		}
		4 {
			# Information
			$api.LogScriptEvent($SCRIPT_NAME,$EventNr,0,$LogMessage)	
		}
		5 {
			# Debug
			$api.LogScriptEvent($SCRIPT_NAME,$EventNr,0,$LogMessage)	
		}		
	}
}
}

#---------------------------------------------------------------------------
# Main
#---------------------------------------------------------------------------
#Define local event constants
$SCRIPT_NAME    = 'DiscoverWindowsOSProperties.ps1'
$EVENT_ERROR 	= 1
$EVENT_WARNING 	= 2
$EVENT_INFO     = 4
$EVENT_DEBUG    = 5
$EventId        = 102

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

try 
{
	$api = new-object -comObject "MOM.ScriptAPI"
	$properties = "Version","Caption","BuildNumber","CSDVersion","ServicePackMajorVersion","ServicePackMinorVersion","SerialNumber","InstallDate","WindowsDirectory","TotalVisibleMemorySize"
	$isHigherThanWin08 = CheckByOSCurrentVersion
	if($isHigherThanWin08 -eq $true)
	{
	  try{
		$items = Get-CimInstance -Namespace "root\cimv2" -Class "Win32_OperatingSystem" -Property $properties -ErrorAction stop
	  }catch{
		import-module cimcmdlets
		$items = Get-CimInstance -Namespace "root\cimv2" -Class "Win32_OperatingSystem" -Property $properties
	  }
	}
	else
	{
	  $items = Get-WMIObject -Namespace "root\cimv2" -Class "Win32_OperatingSystem" -Property $properties
	}

	if($items -ne $null)
	{
		$discoveryData = $api.CreateDiscoveryData(0, $SourceId, $ManagedEntityId)
		$windowsOS = $discoveryData.CreateClassInstance("$MPElement[Name='Windows!Microsoft.Windows.OperatingSystem']$")
		$windowsOS.AddProperty("$MPElement[Name='Windows!Microsoft.Windows.Computer']/PrincipalName$", $ComputerIdentity)

		foreach ($item in $items)
		{
			if($item -ne $null)
			{
				if($item.Version -ne $null)
				{
					$windowsOS.AddProperty("$MPElement[Name='Windows!Microsoft.Windows.OperatingSystem']/OSVersion$", $item.Version)
				}
			  else
				{
					$windowsOS.AddProperty("$MPElement[Name='Windows!Microsoft.Windows.OperatingSystem']/OSVersion$", "")
				}
          
				if($item.Caption -ne $null)
				{
					$windowsOS.AddProperty("$MPElement[Name='Windows!Microsoft.Windows.OperatingSystem']/OSVersionDisplayName$", $item.Caption)
					$windowsOS.AddProperty("$MPElement[Name='System!System.Entity']/DisplayName$", $item.Caption)
				}
			  else
				{
					$windowsOS.AddProperty("$MPElement[Name='Windows!Microsoft.Windows.OperatingSystem']/OSVersionDisplayName$", "")
					$windowsOS.AddProperty("$MPElement[Name='System!System.Entity']/DisplayName$", "")
				}
          
				if($item.BuildNumber -ne $null)
				{
					$windowsOS.AddProperty("$MPElement[Name='Windows!Microsoft.Windows.OperatingSystem']/BuildNumber$", $item.BuildNumber)
				}
			  else
				{
					$windowsOS.AddProperty("$MPElement[Name='Windows!Microsoft.Windows.OperatingSystem']/BuildNumber$", "")
				}
          
				if($item.CSDVersion -ne $null)
				{
					$windowsOS.AddProperty("$MPElement[Name='Windows!Microsoft.Windows.OperatingSystem']/CSDVersion$", $item.CSDVersion)
				}
			  else
				{
					$windowsOS.AddProperty("$MPElement[Name='Windows!Microsoft.Windows.OperatingSystem']/CSDVersion$", "")
				}
          
				if($item.ServicePackMajorVersion -ne $null)
				{
					$windowsOS.AddProperty("$MPElement[Name='Windows!Microsoft.Windows.OperatingSystem']/ServicePackVersion$", $($item.ServicePackMajorVersion.ToString() + "." + $item.ServicePackMinorVersion.ToString()))
				}
			  else
				{
					$windowsOS.AddProperty("$MPElement[Name='Windows!Microsoft.Windows.OperatingSystem']/ServicePackVersion$", "")
				}
          
				if($item.SerialNumber -ne $null)
				{
					$windowsOS.AddProperty("$MPElement[Name='Windows!Microsoft.Windows.OperatingSystem']/SerialNumber$", $item.SerialNumber)
				}
			  else
				{
					$windowsOS.AddProperty("$MPElement[Name='Windows!Microsoft.Windows.OperatingSystem']/SerialNumber$", "")
				}
          
				if($item.InstallDate -ne $null)
				{
					$dateTime = $item.InstallDate.ToString().Split(" ")
					$windowsOS.AddProperty("$MPElement[Name='Windows!Microsoft.Windows.OperatingSystem']/InstallDate$", $($dateTime[0] + " " + $dateTime[1]))
				}
			  else
				{
					$windowsOS.AddProperty("$MPElement[Name='Windows!Microsoft.Windows.OperatingSystem']/InstallDate$", "")
				}
          
				if($item.WindowsDirectory -ne $null)
				{
					$windowsOS.AddProperty("$MPElement[Name='Windows!Microsoft.Windows.OperatingSystem']/SystemDrive$", $item.WindowsDirectory.substring(0,2))
					$windowsOS.AddProperty("$MPElement[Name='Windows!Microsoft.Windows.OperatingSystem']/WindowsDirectory$", $item.WindowsDirectory)
				}
			  else
				{
					$windowsOS.AddProperty("$MPElement[Name='Windows!Microsoft.Windows.OperatingSystem']/SystemDrive$", "")
					$windowsOS.AddProperty("$MPElement[Name='Windows!Microsoft.Windows.OperatingSystem']/WindowsDirectory$", "")
				}
          
				if($item.TotalVisibleMemorySize -ne $null)
				{
					$windowsOS.AddProperty("$MPElement[Name='Windows!Microsoft.Windows.OperatingSystem']/PhysicalMemory$", $item.TotalVisibleMemorySize)
				}
			  else
				{
					$windowsOS.AddProperty("$MPElement[Name='Windows!Microsoft.Windows.OperatingSystem']/PhysicalMemory$", "")
				}
			}
		}

		$discoveryData.AddInstance($windowsOS)
		$discoveryData
	}
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
	LogEvent -EventNr $EventId -EventType $EVENT_INFO -LogMessage "Script Finished`nRun Time: $($Time.Elapsed.TotalSeconds) second(s)"
}