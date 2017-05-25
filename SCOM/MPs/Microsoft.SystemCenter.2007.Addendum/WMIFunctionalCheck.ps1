#Copyright (c) Microsoft Corporation. All rights reserved.
#
#*************************************************************************
# $ScriptName:  "WMIFunctionalCheck" $
#
# Purpose:      This script runs a WMI functional check.
#
# $File:        WMIFunctionalCheck.ps1 $
#*************************************************************************
Param(
    [String]$LogLevelText = "CommandLine"
)

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

if($LogLevelText -ne "CommandLine") 
{
    $LogMessage = "`n" + $LogMessage
}

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
                $SCOMapi.LogScriptEvent($SCRIPT_NAME,$EventNr,1,$LogMessage)	
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
                $SCOMapi.LogScriptEvent($SCRIPT_NAME,$EventNr,2,$LogMessage)	
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
                $SCOMapi.LogScriptEvent($SCRIPT_NAME,$EventNr,0,$LogMessage)
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
                $SCOMapi.LogScriptEvent($SCRIPT_NAME,$EventNr,0,$LogMessage)
            }
    
        }	
    }
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
    'CommandLine' {
        $VerbosePreference="Continue"
        $LogLevel = 6
    }
    Default {
        $LogLevel = 1
    }
}

# Alternate way to write to eventlog for SCOM
Write-EventLog -EventId $EventId -LogName 'Operations Manager' -Source 'Health Service Script' -EntryType Information -Message "$($SCRIPT_NAME): Executing with loglevel: $LogLevelText" -ErrorAction SilentlyContinue

try
{

    #Create PropertyBag object
    $SCOMapi = new-object -comObject "MOM.ScriptAPI"
    LogEvent -EventNr $EventId -EventType $EVENT_INFO -LogMessage "Starting script. Running as: $(whoami)"

    $propertyBag = $SCOMapi.CreatePropertyBag()

    $strBaseClass="cimv2"
    $strQuery="select Status from win32_operatingsystem"
    try
    {
        try
        {
            LogEvent -EventNr $EventId -EventType $EVENT_DEBUG -LogMessage "Retrieveing WMI data using Get-CimInstance"
            $wbemObjectSet = Get-CimInstance -Namespace $("root\$($strBaseClass)") -Query $strQuery -ErrorAction Stop
        }
        catch
        {
            try
            {
                LogEvent -EventNr $EventId -EventType $EVENT_DEBUG -LogMessage "Trying to import cimcmdlets"
                Import-Module -Name cimcmdlets -ErrorAction Stop
                $wbemObjectSet = Get-CimInstance -Namespace $("root\$($strBaseClass)") -Query $strQuery -ErrorAction Stop
            }
            catch
            {
                LogEvent -EventNr $EventId -EventType $EVENT_DEBUG -LogMessage "Falling back to use alternate metod to retrieve WMI data using Get-WMIObject"
                $wbemObjectSet = Get-WMIObject -Namespace $("root\$($strBaseClass)") -Query $strQuery -ErrorAction Stop
            }
        }
    }
    catch{
        # execute outer catch
        Write-Error -Message "Failed to get wmi data.`n$($_.Exception.Message)`n$($_.InvocationInfo.PositionMessage)" -ErrorAction Stop
    }
}
catch
{	
    $propertyBag.AddValue("Status", "FAIL")
    $Message = "Script WMIFunctionalCheck executed with Errors.`nError Details: $($_.Exception.Message)"
    $propertyBag.AddValue("ErrorMessage", $Message)
    LogEvent -EventNr $EventId -EventType $EVENT_ERROR -LogMessage "Script WMIFunctionalCheck executed with Errors.`nError Details:`n$($_.Exception.Message)"
}
finally
{
    if($wbemObjectSet.Status -eq "OK")
    {
        $propertyBag.AddValue("Status", "OK")
        $Message = "Script WMIFunctionalCheck executed Successfully"
        LogEvent -EventNr $EventId -EventType $EVENT_INFO -LogMessage $Message
    }
    
    if($LogLevelText -eq "CommandLine") 
    {
        $SCOMapi.Return($propertyBag)
    }
    else 
    {
        $propertyBag
    }
    
    $Time.Stop()
    LogEvent -EventNr $EventId -EventType $EVENT_INFO -LogMessage "Script done.`nRun Time: $([string]::Format('{0:N}',$Time.Elapsed.TotalSeconds)) second(s)"
}