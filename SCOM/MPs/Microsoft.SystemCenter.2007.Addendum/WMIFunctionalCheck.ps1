#Copyright (c) Microsoft Corporation. All rights reserved.
# Addendum by: Morten Lerudjordet
#*************************************************************************
# $ScriptName:  "WMIFunctionalCheck" $
#
# Purpose:      This script runs a WMI functional check.
#
# $File:        WMIFunctionalCheck.ps1 $
#*************************************************************************
Param(
	[String]$ComputerName,
	[String]$LogLevelText
)

#OS version for Win 2012
$WIN_OS_2012_Ver = "6.2"
$OSRegistryKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\"

#******************************************************************************
#   FUNCTION:       CheckMinOSVer
#   DESCRIPTION:    Returns True if the Registry Key for CurrentVersion
#                   is equal or Higher than the Minimum OS Versions Number.
#   PARAMETER:      DblMinVer Minimum Version Number to use
#   RETURNS:        Boolean: True, if build is greater or equal than the given number
#******************************************************************************
function CheckByOSCurrentVersion #As Boolean
{
    $strCurrentOSVer = Get-ItemProperty $OSRegistryKey
    $strCurrentOSVer = $strCurrentOSVer.CurrentVersion
    if($strCurrentOSVer -ge $WIN_OS_2012_Ver)
	{
		return $true
	}
    return $false
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
	$SCOMapi.LogScriptEvent($SCRIPT_NAME,$EventNr,$EventType,$LogMessage)
  }
}

#---------------------------------------------------------------------------
# Retrieves the script output.
#---------------------------------------------------------------------------
function ReturnResponse
{
Param(
	[Bool]$ErrorFlag,
	[String]$Message
)

    if($ErrorFlag -eq $true)
    {
        $propertyBag.AddValue("Status", "FAIL")
        $propertyBag.AddValue("ErrorMessage", $Message)
        LogEvent -EventNr $EventId -EventType $EVENT_ERROR -LogMessage $Message
    }
    else
    {
        $propertyBag.AddValue("Status", "OK")
        LogEvent -EventNr $EventId -EventType $EVENT_INFO -LogMessage $Message
    }

    $propertyBag
}


#---------------------------------------------------------------------------
# Execute a WMI Query.
#---------------------------------------------------------------------------
function ExecuteWMIQuery
{
Param(
	[String]$targetComputer,
	[String]$BaseClass,
	[String]$Query,
	[String]$PropertyName
)

if($isHigherThanWin08 -eq $true)
{
    try{
		# Check if CIM methods are loaded
        if(! (Get-Module -Name cimcmdlets -ErrorAction SilentlyContinue) )
        {
		    # Stop if one cannot use Get-CimInstance CMDlet
            Import-Module -Name cimcmdlets -ErrorAction Stop
	    }
        LogEvent -EventNr $EventId -EventType $EVENT_INFO -LogMessage "Trying to connect through WinRM using computer name:  $targetComputer to get data from WMI"
        $wbemObjectSet = Get-CimInstance -ComputerName $targetComputer -Namespace $("root\" + $BaseClass) -Query $Query -ErrorAction SilentlyContinue -ErrorVariable wbemError

        if($wbemError) {
            $error.Clear()
            # Log Error as Info in eventlog
            LogEvent -EventNr $EventId -EventType $EVENT_INFO -LogMessage $wbemError
            $wbemError = $Null
            # Get netbios name from FQDN
            $targetComputerNetbios = $targetComputer.split(".")[0]
            LogEvent -EventNr $EventId -EventType $EVENT_INFO -LogMessage "Trying to connect through WinRM using computer name:  $targetComputerNetbios to get data from WMI"
            # Try to use netbios computer name instead of FQDN/DNS
            $wbemObjectSet = Get-CimInstance -ComputerName $targetComputerNetbios -Namespace $("root\" + $BaseClass) -Query $Query -ErrorAction SilentlyContinue -ErrorVariable wbemError

            if($wbemError) {
                $error.Clear()
                # Log Error as Info in eventlog
                LogEvent -EventNr $EventId -EventType $EVENT_INFO -LogMessage $wbemError
                $wbemError = $Null
                LogEvent -EventNr $EventId -EventType $EVENT_INFO -LogMessage "Using COM to get WMI data instead of WinRM"
                # Use COM instead if all WinRM connection attempts fail
                $wbemObjectSet = Get-CimInstance -Namespace $("root\" + $BaseClass) -Query $Query -ErrorAction Continue
            }
        }
	}
    catch{
        # Log unhandeled execption
        LogEvent -EventNr $EventId -EventType $EVENT_ERROR -LogMessage $_.Exception.Message
    }
}
else
{
    $wbemObjectSet = Get-WMIObject -Namespace $("root\" + $BaseClass) -ComputerName $targetComputer -Query $Query
}
foreach($objItem in $wbemObjectSet)
{
    $temp = $objItem.$PropertyName
}
return $temp
}


#---------------------------------------------------------------------------
# Gets WMI Status.
#---------------------------------------------------------------------------
function GetWMIStatus
{
Param(
	[String]$ComputerName
)


    $status = ExecuteWMIQuery -targetComputer $ComputerName -BaseClass "cimv2" -Query "select Status from win32_operatingsystem" -PropertyName "Status"

    if($status -eq "OK")
    {
        return "OK"
    }
    else
    {
        return "FAIL"
    }
}
#---------------------------------------------------------------------------
# Main
#---------------------------------------------------------------------------

#Define local event constants
$SCRIPT_NAME    = 'WMIFunctionalCheck.ps1'
$EVENT_ERROR 	= 1
$EVENT_WARNING 	= 2
$EVENT_INFO     = 4
$EventId        = 150

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
    Default {
        $LogLevel = 1
    }
}

# Alternate way to write to eventlog for SCOM
Write-EventLog -EventId $EventId -LogName 'Operations Manager' -Source 'Health Service Script' -EntryType Information -Message "$SCRIPT_NAME loglevel is set to: $LogLevelText translated to number: $LogLevel" -ErrorAction SilentlyContinue

#Check the OS version
$isHigherThanWin08 = CheckByOSCurrentVersion

#Create PropertyBag object
$SCOMapi = new-object -comObject "MOM.ScriptAPI"
LogEvent -EventNr $EventId -EventType $EVENT_INFO -LogMessage "Script has started, loglevel is set to: $LogLevelText"

$propertyBag = $SCOMapi.CreatePropertyBag()

$error.Clear()

#Set variables
LogEvent -EventNr $EventId -EventType $EVENT_INFO -LogMessage "Retrieving WMI Status"
$strWMIStatus = GetWMIStatus -ComputerName $ComputerName
LogEvent -EventNr $EventId -EventType $EVENT_INFO -LogMessage "WMI Status: $strWMIStatus"
if($error.Count -ne 0)
{
    $strMessageToUse = "Script WMIFunctionalCheck executed with Errors.`nError Details: " + $error[0]
    ReturnResponse -ErrorFlag $true -Message $strMessageToUse
}
else
{
    $strMessageToUse = "Script WMIFunctionalCheck executed Successfully"
    ReturnResponse -ErrorFlag $false -Message $strMessageToUse
}
LogEvent -EventNr $EventId -EventType $EVENT_INFO -LogMessage "Script Finished"
