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
	Switch($EventType)
	{
		1 {
			# Error
			$SCOMapi.LogScriptEvent($SCRIPT_NAME,$EventNr,1,$LogMessage)	
		}
		2 {
			# Warning
			$SCOMapi.LogScriptEvent($SCRIPT_NAME,$EventNr,2,$LogMessage)	
		}
		4 {
			# Information
			$SCOMapi.LogScriptEvent($SCRIPT_NAME,$EventNr,0,$LogMessage)	
		}
		5 {
			# Debug
			$SCOMapi.LogScriptEvent($SCRIPT_NAME,$EventNr,0,$LogMessage)	
		}		
	}
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
        LogEvent -EventNr $EventId -EventType $EVENT_DEBUG -LogMessage $Message
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
            LogEvent -EventNr $EventId -EventType $EVENT_DEBUG -LogMessage "Using COM to get WMI data"
            # Use COM instead if all WinRM connection attempts fail
            $wbemObjectSet = Get-CimInstance -Namespace $("root\$($BaseClass)") -Query $Query -ErrorAction Stop
	}
    catch{
        # Log unhandeled execption
        LogEvent -EventNr $EventId -EventType $EVENT_ERROR -LogMessage "Failed to get wmi data.`n$($_.Exception.Message)`n$($_.InvocationInfo.PositionMessage)"
    }
}
else
{
    $wbemObjectSet = Get-WMIObject -Namespace $("root\" + $BaseClass) -Query $Query
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

$Time = [System.Diagnostics.Stopwatch]::StartNew()

#Define local event constants
$SCRIPT_NAME    = 'WMIFunctionalCheck.ps1'
$EVENT_ERROR 	= 1
$EVENT_WARNING 	= 2
$EVENT_INFO     = 4
$EVENT_DEBUG    = 5
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
	'Debug' {
        $LogLevel = 5
    }
    Default {
        $LogLevel = 1
    }
}

# Alternate way to write to eventlog for SCOM
Write-EventLog -EventId $EventId -LogName 'Operations Manager' -Source 'Health Service Script' -EntryType Information -Message "$($SCRIPT_NAME): Executing with loglevel: $LogLevelText" -ErrorAction SilentlyContinue

Try
{
	#Check the OS version
	$isHigherThanWin08 = CheckByOSCurrentVersion

	#Create PropertyBag object
	$SCOMapi = new-object -comObject "MOM.ScriptAPI"
	LogEvent -EventNr $EventId -EventType $EVENT_INFO -LogMessage "Time started: $((Get-Date).ToString("HH:mm:ss"))"

	$propertyBag = $SCOMapi.CreatePropertyBag()

	$error.Clear()

	#Set variables
	LogEvent -EventNr $EventId -EventType $EVENT_DEBUG -LogMessage "Retrieving WMI Status"
	$strWMIStatus = GetWMIStatus -ComputerName $ComputerName
	LogEvent -EventNr $EventId -EventType $EVENT_DEBUG -LogMessage "WMI Status: $strWMIStatus"
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
}
Catch
{	
	LogEvent -EventNr $EventId -EventType $EVENT_ERROR -LogMessage "Error running script.`n$($_.Exception.Message)`n$($_.InvocationInfo.PositionMessage)"
	LogEvent -EventNr $EventId -EventType $EVENT_DEBUG   `
	-LogMessage "Debug:`n$($_.InvocationInfo.MyCommand.Name)`n$($_.ErrorDetails.Message)`n$($_.InvocationInfo.PositionMessage)`n$($_.CategoryInfo.ToString())`n$($_.FullyQualifiedErrorId)"
}
Finally
{
	$Time.Stop()
	LogEvent -EventNr $EventId -EventType $EVENT_INFO -LogMessage "Script Finished`nRun Time: $($Time.Elapsed.TotalSeconds) second(s)"
}