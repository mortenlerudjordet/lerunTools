Param(
    [string]$ComputerName,
    [string]$ConfigForRun,
    [int]$ProcessIterationCount,
    [String]$LogLevelText = "CommandLine"
)
#Process Arguments:
# 0 - ComputerIdentity
# 1 - RunAsDiagnostic
# 2 - ProcessIterationCount

# For testing discovery manually in PowerShell console (not ISE):
# $ComputerName = 'servername.domainname.domain'
# ProcessIterationCount = 3
# Output diagnostics $ConfigForRun = "true" (string)

#Event log variables
$SCRIPT_EVENT_ID     = 3000
$CN_SCOM_SUCCESS     = 0
$CN_SCOM_ERROR       = 1
$CN_SCOM_WARNING     = 2
$CN_SCOM_INFORMATION = 4
$CN_SCOM_DEBUG       = 5
$SCRIPT_NAME		 = "SCOMPercentageCPUTimeCounter.ps1"

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


function GetProcessorTime
{
Param(
    $procId
)

$N1 = 0
$D1 = 0
$N2 = 0
$D2 = 0
$Nd = 0
$Dd = 0
    $PercentProcessorTime   = 0
    $query = "Select Name,PercentProcessorTime,TimeStamp_Sys100NS from Win32_PerfRawData_PerfProc_Process where IDProcess = ""$procId"""

    try
    {
        # Use COM instead if all WinRM connection attempts fail
        $objService1 = Get-CimInstance -Namespace "root\cimv2" -Query $query -ErrorAction Stop
    }
    catch
    {
        try
        {
            $objService1 = Get-WMIObject -Namespace "root\cimv2" -Query $query -ErrorAction Stop
        }
        catch
        {
            # Log unhandeled execption
            LogEvent -EventNr $SCRIPT_EVENT_ID -EventType $CN_SCOM_ERROR -LogMessage "Could not retrive performance data through WMI.`n$($_.Exception.Message)`n$($_.InvocationInfo.PositionMessage)"
        }

    }

    ForEach($objInstance1 in $objService1)
    {
        $N1 = $objInstance1.PercentProcessorTime
        $D1 = $objInstance1.TimeStamp_Sys100NS
    }

   Start-Sleep 1

    try
    {
        LogEvent -EventNr $SCRIPT_EVENT_ID -EventType $CN_SCOM_DEBUG -LogMessage "Using COM to get WMI 2nd round of raw performance data"
        # Use COM instead if all WinRM connection attempts fail
        $objService2 = Get-CimInstance -Namespace "root\cimv2" -Query $query -ErrorAction Stop
    }
    catch
    {
        try
        {
            $objService2 = Get-WMIObject -Namespace "root\cimv2" -Query $query -ErrorAction Stop
        }
        catch
        {
            # Log unhandeled execption
            LogEvent -EventNr $SCRIPT_EVENT_ID -EventType $CN_SCOM_ERROR -LogMessage "Could not retrive second round of performance data.`n$($_.Exception.Message)`n$($_.InvocationInfo.PositionMessage)"
        }

    }
    ForEach($objInstance2 in $objService2)
    {
        $N2 = $objInstance2.PercentProcessorTime
        $D2 = $objInstance2.TimeStamp_Sys100NS
    }

    $Nd = $N2-$N1
    LogEvent -EventNr $SCRIPT_EVENT_ID -EventType $CN_SCOM_DEBUG -LogMessage "Difference for precent processor time: $Nd"
    $Dd = $D2-$D1
    LogEvent -EventNr $SCRIPT_EVENT_ID -EventType $CN_SCOM_DEBUG -LogMessage "Difference for timestamp: $Dd"
    # stop divide by zero
    if($Dd -eq 0)
    {
        # Set to zero so not to get unhandled exception
        $PercentProcessorTime = 0
    }
    else
    {
        $PercentProcessorTime = $($($Nd/$Dd) * 100)
    }
    return $PercentProcessorTime

}

#---------------------------------------------------------------------------
# Main
#---------------------------------------------------------------------------
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

# Alternate way to write to eventlog for SCOM
Write-EventLog -EventId $SCRIPT_EVENT_ID -LogName 'Operations Manager' -Source 'Health Service Script' -EntryType Information -Message "$($SCRIPT_NAME): Executing with loglevel: $LogLevelText" -ErrorAction SilentlyContinue


Try
{
    #Create PropertyBag object
    $oAPI = new-object -comObject "MOM.ScriptAPI"

    # $ConfigForRun is string even if defined as bool in probe
    if($ConfigForRun -eq "true")
    {
        $Diagnostic = $True
    }
    else
    {
        $Diagnostic = $False
    }

    LogEvent -EventNr $SCRIPT_EVENT_ID -EventType $CN_SCOM_INFORMATION -LogMessage "Starting script. Running as: $(whoami)`nDiagnostic mode: $Diagnostic"

    $oPropertyBag = $oAPI.CreatePropertyBag()

    #Set the retry attempts for WMI and other counters
    $retryAttempts = 2
    $dataCount = 0

    #Get WMI object
    $finalPercentProcessorTime = 0
    $procCount = 0
    $checker = $null

    try{

        LogEvent -EventNr $SCRIPT_EVENT_ID -EventType $CN_SCOM_DEBUG -LogMessage "Using COM to get WMI data"
        # Use COM instead if all WinRM connection attempts fail
        $checker = Get-CimInstance -Namespace "root\cimv2" -Class "Win32_Process" -ErrorAction Stop
    }
    catch
    {
        try
        {
            # Check if CIM methods are loaded
            Import-Module -Name cimcmdlets -ErrorAction Stop
            $checker = Get-CimInstance -Namespace "root\cimv2" -Class "Win32_Process" -ErrorAction Stop
        }
        catch
        {
            try
            {
                $checker = Get-WMIObject -Namespace "root\cimv2" -Class "Win32_Process" -ErrorAction Stop
            }
            catch
            {
                # Log unhandeled execption
                LogEvent -EventNr $SCRIPT_EVENT_ID -EventType $CN_SCOM_ERROR -LogMessage "Could not retrive data through WMI.`n$($_.Exception.Message)`n$($_.InvocationInfo.PositionMessage)"
            }
        }
    }

    if($checker -ne $null)
    {
        LogEvent -EventNr $SCRIPT_EVENT_ID -EventType $CN_SCOM_DEBUG -LogMessage "WMI check successful"
        for($counter=0;$counter -lt $retryAttempts;$counter++)
        {
            # Get the number of cores in the system
            try
            {
                LogEvent -EventNr $SCRIPT_EVENT_ID -EventType $CN_SCOM_DEBUG -LogMessage "Using COM to get number of CPU cores data"
                # Use COM to get WMI data
                $processorList = Get-CimInstance -Namespace "root\cimv2" -Query "SELECT NumberOfCores FROM Win32_Processor" -ErrorAction Stop
            }
            catch
            {
                try
                {
                    $processorList = Get-WMIObject -Namespace "root\cimv2" -Query "SELECT NumberOfCores FROM Win32_Processor" -ErrorAction Stop
                }
                catch
                {
                    LogEvent -EventNr $SCRIPT_EVENT_ID -EventType $CN_SCOM_ERROR -LogMessage "Could not retrive number of CPUs.`n$($_.Exception.Message)`n$($_.InvocationInfo.PositionMessage)"
                }

            }
            if($processorList -ne $null)
            {
                LogEvent -EventNr $SCRIPT_EVENT_ID -EventType $CN_SCOM_DEBUG -LogMessage "WMI query successful.`nNumber of cores found: $($processorList.NumberOfCores)"
                foreach($processor in $processorList)
                {
                    $procCount = $procCount + $processor.NumberOfCores
                }
                break
            }
        }
        if($procCount -lt 1)
        {
            $procCount = 1
        }

        #Set the variables for detailed analysis
        $min = 32767
        $max = 0
        $sampleCount = 0
        $totalCount = 0
        $procTime = 0

        #Process id of current script is $pid

        # Get the total processor time count ProcessIterationCount number of times, to get the average
        for($loopCounter=0; $loopCounter -lt $ProcessIterationCount; $loopCounter++)
        {
            $agentProcIDs = New-Object 'System.Collections.Generic.List[Int]'
            # Step 1: Get all SCOM Processes
            for($counter=0; $counter -lt $retryAttempts; $counter++)
            {

                try
                {
                    LogEvent -EventNr $SCRIPT_EVENT_ID -EventType $CN_SCOM_DEBUG -LogMessage "Using COM to get ProcessId, ParentProcessId data"
                    # Use COM
                    $processes = Get-CimInstance -Namespace "root\cimv2" -Query 'SELECT ProcessId,ParentProcessId,Name FROM Win32_Process' -ErrorAction Stop

                }
                catch
                {
                    try
                    {
                        $processes = Get-WMIObject -Namespace "root\cimv2" -Query 'SELECT ProcessId,ParentProcessId,Name FROM Win32_Process' -ErrorAction stop
                    }
                    catch
                    {
                        LogEvent -EventNr $SCRIPT_EVENT_ID -EventType $CN_SCOM_ERROR -LogMessage "Could not retrive processes.`n$($_.Exception.Message)`n$($_.InvocationInfo.PositionMessage)"
                    }

                }

                if($processes -ne $null)
                {
                    LogEvent -EventNr $SCRIPT_EVENT_ID -EventType $CN_SCOM_DEBUG -LogMessage "Number of active processes found: $($processes.Count).`nStarting search for the ones related to HealthService"
                    # Step 2: Get the Health Service and Monitoring Host objects
                    foreach($process in $processes)
                    {
                        if(($process -ne $null) -and ($process.GetType().Name -ne "Nothing"))
                        {
                            if(($process.Name.Equals("HealthService.exe") -Or $process.Name.Equals("MonitoringHost.exe")) -And (-Not($agentProcIDs.contains($process.ProcessId))))
                            {
                                $Null = $agentProcIDs.Add($process.ProcessId)
                            }
                        }
                    }

                    # Step 3: Get all the child processes
                    $childFound = $true
                    # While a new child is found, re-iterate the list to find its child
                    Do
                    {
                        $childFound = $false
                        foreach($process in $processes)
                        {
                            if(($process -ne $null) -and ($process.GetType().Name -ne "Nothing"))
                            {
                                # If parent process is in the agentProcIDs list but the process itself is not, its a new child

                                # Filter out myself
                                if($process.ProcessId -ne $pid)
                                {
                                    if($agentProcIDs.contains($process.ParentProcessId) -And (-Not($agentProcIDs.contains($process.ProcessId))))
                                    {
                                        $Null = $agentProcIDs.Add($process.ProcessId)
                                        $childFound = $true
                                    }
                                }
                            }
                        }
                    }
                    While($childFound -eq $true)

                    # Step 4: Get the total cpu percentage used for all the SCOM processes

                    $totalPercentProcessorTime = 0

                    # Only iterate through processes hosted by SCOM agent
                    foreach($processID in $agentProcIDs)
                    {

                            $x = $(GetProcessorTime -ProcID $processID)
                            $totalPercentProcessorTime = $totalPercentProcessorTime + $x
                            if($Diagnostic-eq $true)
                            {
                                $procTime = $(GetProcessorTime -ProcID $processID)
                                $sampleCount = $sampleCount + 1
                                $procTime = [double]$procTime
                                $totalCount = $totalCount + $procTime

                                # Check for min value
                                if($procTime -lt $min)
                                {
                                    $min = $procTime
                                }
                                # Check for max value
                                if($procTime -gt $max)
                                {
                                    $max = $procTime
                                }
                            }
                    }

                    # Add the total percentage time to the final percentage time for averaging in the end
                    $finalPercentProcessorTime = $finalPercentProcessorTime + $totalPercentProcessorTime
                    $dataCount = $dataCount + 1
                    break
                }
            }

            # Delaying each iteration by 3 seconds
            Start-Sleep 3
        }
        # Add the detailed analysis to the property bag
        if($Diagnostic -eq $true)
        {
            $oPropertyBag.AddValue("SamplesTaken", $ProcessIterationCount)
            $oPropertyBag.AddValue("Average", [double]($totalCount/$sampleCount))
            $oPropertyBag.AddValue("Maximum", $max)
            $oPropertyBag.AddValue("Minimum", $min)
        }
        # Calculate the final percentage processor time for all the SCOM processes
        if($dataCount -lt 1)
        {
            $dataCount = 1
        }
        $finalPercentProcessorTime = ($finalPercentProcessorTime/$dataCount)/$procCount
    }

    if($Diagnostic -eq $false)
    {
        $oPropertyBag.AddValue("SCOMpercentageCPUTime", $finalPercentProcessorTime)
    }
}
Catch
{
    LogEvent -EventNr $SCRIPT_EVENT_ID -EventType $CN_SCOM_ERROR -LogMessage "Error running script.`n$($_.Exception.Message)`n$($_.InvocationInfo.PositionMessage)"
}
Finally
{
    if($LogLevelText -eq "CommandLine")
    {
        $oAPI.Return($oPropertyBag)
    }
    else
    {
        $oPropertyBag
    }

    $Time.Stop()
    LogEvent -EventNr $SCRIPT_EVENT_ID -EventType $CN_SCOM_INFORMATION -LogMessage "Script done.`nRun Time: $([string]::Format('{0:N}',$Time.Elapsed.TotalSeconds)) second(s)"
}
