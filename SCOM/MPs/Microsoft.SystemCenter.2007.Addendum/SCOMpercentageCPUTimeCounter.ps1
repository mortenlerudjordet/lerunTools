Param(
	[string]$ComputerName,
	[string]$ConfigForRun,
	[int]$ProcessIterationCount,
	[String]$LogLevelText
)
#Process Arguments:
# 0 - ComputerIdentity
# 1 - RunAsDiagnostic
# 2 - ProcessIterationCount

#Event log variables
$SCRIPT_EVENT_ID     = 3000
$CN_SCOM_SUCCESS     = 0
$CN_SCOM_ERROR       = 1
$CN_SCOM_WARNING     = 2
$CN_SCOM_INFORMATION = 4
$SCRIPT_NAME		 = "SCOMPercentageCPUTimeCounter.ps1"

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
	$oAPI.LogScriptEvent($SCRIPT_NAME,$EventNr,$EventType,$LogMessage)
  }
}


function GetProcessorTime ($procId, $ComputerName)
{

$N1 = 0
$D1 = 0
$N2 = 0
$D2 = 0
$Nd = 0
$Dd = 0
$PercentProcessorTime   = 0
    $query = "Select * from Win32_PerfRawData_PerfProc_Process where IDProcess = ""$procId"""
    if($isHigherThanWin08 -eq $true)
    {
        LogEvent -EventNr $SCRIPT_EVENT_ID -EventType $CN_SCOM_INFORMATION -LogMessage "Trying to connect through WinRM using computer name:  $ComputerName to get raw performance data from WMI"
		$objService1 = Get-CimInstance -Namespace "root\cimv2" -ComputerName $ComputerName -Query $query -ErrorAction SilentlyContinue -ErrorVariable wbemError

        if($wbemError) {
            # Log Error as Info in eventlog
            LogEvent -EventNr $SCRIPT_EVENT_ID -EventType $CN_SCOM_INFORMATION -LogMessage $wbemError
            $wbemError = $Null
            # Get netbios name from FQDN
            $ComputerNameNetbios = $ComputerName.split(".")[0]
            LogEvent -EventNr $SCRIPT_EVENT_ID -EventType $CN_SCOM_INFORMATION -LogMessage "Trying to connect through WinRM using computer name:  $ComputerNameNetbios to get raw performance data from WMI"
            # Try to use netbios computer name instead of FQDN/DNS
			$objService1 = Get-CimInstance -ComputerName $ComputerNameNetbios -Namespace "root\cimv2" -Query $query -ErrorAction SilentlyContinue -ErrorVariable wbemError

            if($wbemError) {
                # Log Error as Info in eventlog
                LogEvent -EventNr $SCRIPT_EVENT_ID -EventType $CN_SCOM_INFORMATION -LogMessage $wbemError
                $wbemError = $Null
                LogEvent -EventNr $SCRIPT_EVENT_ID -EventType $CN_SCOM_INFORMATION -LogMessage "Using COM to get WMI raw performance data instead of WinRM"
                # Use COM instead if all WinRM connection attempts fail
				$objService1 = Get-CimInstance -Namespace "root\cimv2" -Query $query -ErrorAction Stop
            }
		}
    }
	else{
        $objService1 = Get-WMIObject -Namespace "root\cimv2" -ComputerName $ComputerName -Query $query
    }
    ForEach($objInstance1 in $objService1)
{
        $N1 = $objInstance1.PercentProcessorTime
        $D1 = $objInstance1.TimeStamp_Sys100NS
 }

  Start-Sleep 1
   if($isHigherThanWin08 -eq $true)
    {
        LogEvent -EventNr $SCRIPT_EVENT_ID -EventType $CN_SCOM_INFORMATION -LogMessage "Trying to connect through WinRM using computer name:  $ComputerName to get 2nd round of raw performance data from WMI"
		$objService2 = Get-CimInstance -Namespace "root\cimv2" -ComputerName $ComputerName -Query $query -ErrorAction SilentlyContinue -ErrorVariable wbemError

        if($wbemError) {
            # Log Error as Info in eventlog
            LogEvent -EventNr $SCRIPT_EVENT_ID -EventType $CN_SCOM_INFORMATION -LogMessage $wbemError
            $wbemError = $Null
            # Get netbios name from FQDN
            $ComputerNameNetbios = $ComputerName.split(".")[0]
            LogEvent -EventNr $SCRIPT_EVENT_ID -EventType $CN_SCOM_INFORMATION -LogMessage "Trying to connect through WinRM using computer name:  $ComputerNameNetbios to get 2nd round of raw performance data from WMI"
            # Try to use netbios computer name instead of FQDN/DNS
			$objService2 = Get-CimInstance -ComputerName $ComputerNameNetbios -Namespace "root\cimv2" -Query $query -ErrorAction SilentlyContinue -ErrorVariable wbemError

            if($wbemError) {
                # Log Error as Info in eventlog
                LogEvent -EventNr $SCRIPT_EVENT_ID -EventType $CN_SCOM_INFORMATION -LogMessage $wbemError
                $wbemError = $Null
                LogEvent -EventNr $SCRIPT_EVENT_ID -EventType $CN_SCOM_INFORMATION -LogMessage "Using COM to get WMI 2nd round of raw performance data instead of WinRM"
                # Use COM instead if all WinRM connection attempts fail
				$objService2 = Get-CimInstance -Namespace "root\cimv2" -Query $query -ErrorAction Stop
            }
		}
    }
	else{
        $objService2 = Get-WMIObject -Namespace "root\cimv2" -ComputerName $ComputerName -Query $query
    }
    ForEach($objInstance2 in $objService2)
	{
        $N2 = $objInstance2.PercentProcessorTime
        $D2 = $objInstance2.TimeStamp_Sys100NS
	}

    $Nd = $N2-$N1
    $Dd = $D2-$D1
    $PercentProcessorTime = $($($Nd/$Dd) * 100)
   return $PercentProcessorTime

}

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
Write-EventLog -EventId $SCRIPT_EVENT_ID -LogName 'Operations Manager' -Source 'Health Service Script' -EntryType Information -Message "$($SCRIPT_NAME): loglevel is set to: $LogLevelText" -ErrorAction SilentlyContinue

#Check the OS version
$isHigherThanWin08 = CheckByOSCurrentVersion

#Create PropertyBag object
$oAPI = new-object -comObject "MOM.ScriptAPI"
LogEvent -EventNr $SCRIPT_EVENT_ID -EventType $CN_SCOM_INFORMATION -LogMessage "SCOM script API created"

$oPropertyBag = $oAPI.CreatePropertyBag()

#Set the retry attempts for WMI and other counters
$retryAttempts = 2
$dataCount = 0

#Get WMI object
$finalPercentProcessorTime = 0
$procCount = 0
$checker = $null
if($isHigherThanWin08 -eq $true)
{
	try{
		# Check if CIM methods are loaded
        if(! (Get-Module -Name cimcmdlets -ErrorAction SilentlyContinue) )
        {
		    # Stop if one cannot use Get-CimInstance CMDlet
            Import-Module -Name cimcmdlets -ErrorAction Stop
	    }
		LogEvent -EventNr $SCRIPT_EVENT_ID -EventType $CN_SCOM_INFORMATION -LogMessage "Trying to connect through WinRM using computer name:  $ComputerName to get data from WMI"
		$checker = Get-CimInstance -ComputerName $ComputerName -Namespace "root\cimv2" -Class "Win32_Process" -ErrorAction SilentlyContinue -ErrorVariable wbemError

        if($wbemError) {
            # Log Error as Info in eventlog
            LogEvent -EventNr $SCRIPT_EVENT_ID -EventType $CN_SCOM_INFORMATION -LogMessage $wbemError
            $wbemError = $Null
            # Get netbios name from FQDN
            $ComputerNameNetbios = $ComputerName.split(".")[0]
            LogEvent -EventNr $SCRIPT_EVENT_ID -EventType $CN_SCOM_INFORMATION -LogMessage "Trying to connect through WinRM using computer name:  $ComputerNameNetbios to get data from WMI"
            # Try to use netbios computer name instead of FQDN/DNS
			$checker = Get-CimInstance -ComputerName $ComputerNameNetbios -Namespace "root\cimv2" -Class "Win32_Process" -ErrorAction SilentlyContinue -ErrorVariable wbemError

            if($wbemError) {
                # Log Error as Info in eventlog
                LogEvent -EventNr $SCRIPT_EVENT_ID -EventType $CN_SCOM_INFORMATION -LogMessage $wbemError
                $wbemError = $Null
                LogEvent -EventNr $SCRIPT_EVENT_ID -EventType $CN_SCOM_INFORMATION -LogMessage "Using COM to get WMI data instead of WinRM"
                # Use COM instead if all WinRM connection attempts fail
				$checker = Get-CimInstance -Namespace "root\cimv2" -Class "Win32_Process" -ErrorAction SilentlyContinue -ErrorVariable wbemError
            }
		}

	}
	catch
    {
		# Log unhandeled execption
		LogEvent -EventNr $SCRIPT_EVENT_ID -EventType $CN_SCOM_ERROR -LogMessage $_.Exception.Message
	}
}
else
{
    $checker = Get-WMIObject -Namespace "root\cimv2" -ComputerName $ComputerName -Class "Win32_Process"
}

if($checker -ne $null)
{
    LogEvent -EventNr $SCRIPT_EVENT_ID -EventType $CN_SCOM_INFORMATION -LogMessage "WMI check successful"
    for($counter=0;$counter -lt $retryAttempts;$counter++)
    {
        # Get the number of cores in the system
        if($isHigherThanWin08 -eq $true)
        {
            $processorList = Get-CimInstance -Namespace "root\cimv2" -ComputerName $ComputerName -Query "SELECT NumberOfCores FROM Win32_Processor" -ErrorAction SilentlyContinue -ErrorVariable wbemError

			if($wbemError) {
				# Log Error as Info in eventlog
				LogEvent -EventNr $SCRIPT_EVENT_ID -EventType $CN_SCOM_INFORMATION -LogMessage $wbemError
				$wbemError = $Null
				# Get netbios name from FQDN
				$ComputerNameNetbios = $ComputerName.split(".")[0]
				LogEvent -EventNr $SCRIPT_EVENT_ID -EventType $CN_SCOM_INFORMATION -LogMessage "Trying to connect through WinRM using computer name:  $ComputerNameNetbios to get get number of CPU cores data from WMI"
				# Try to use netbios computer name instead of FQDN/DNS
				$processorList = Get-CimInstance -ComputerName $ComputerNameNetbios -Namespace "root\cimv2" -Query "SELECT NumberOfCores FROM Win32_Processor" -ErrorAction SilentlyContinue -ErrorVariable wbemError

				if($wbemError) {
					# Log Error as Info in eventlog
					LogEvent -EventNr $SCRIPT_EVENT_ID -EventType $CN_SCOM_INFORMATION -LogMessage $wbemError
					$wbemError = $Null
					LogEvent -EventNr $SCRIPT_EVENT_ID -EventType $CN_SCOM_INFORMATION -LogMessage "Using COM to get number of CPU cores data instead of WinRM"
					# Use COM instead if all WinRM connection attempts fail
					$processorList = Get-CimInstance -Namespace "root\cimv2" -Query "SELECT NumberOfCores FROM Win32_Processor" -ErrorAction Stop
				}
			}
        }
        else
        {
            $processorList = Get-WMIObject -Namespace "root\cimv2" -ComputerName $ComputerName -Query "SELECT NumberOfCores FROM Win32_Processor" -ErrorAction stop
        }
        if($processorList -ne $null)
        {
            LogEvent -EventNr $SCRIPT_EVENT_ID -EventType $CN_SCOM_INFORMATION -LogMessage "WMI query successful.`nNumber of cores found: $($processorList.NumberOfCores)"
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
        $agentProcIDs = "|"
        # Step 1: Get all SCOM Processes
        for($counter=0; $counter -lt $retryAttempts; $counter++)
        {
            if($isHigherThanWin08 -eq $true)
            {
                $processes = Get-CimInstance -Namespace "root\cimv2" -ComputerName $ComputerName -Query 'SELECT ProcessId,ParentProcessId,Name FROM Win32_Process' -ErrorAction SilentlyContinue -ErrorVariable wbemError

				if($wbemError) {
					# Log Error as Info in eventlog
					LogEvent -EventNr $SCRIPT_EVENT_ID -EventType $CN_SCOM_INFORMATION -LogMessage $wbemError
					$wbemError = $Null
					# Get netbios name from FQDN
					$ComputerNameNetbios = $ComputerName.split(".")[0]
					LogEvent -EventNr $SCRIPT_EVENT_ID -EventType $CN_SCOM_INFORMATION -LogMessage "Trying to connect through WinRM using computer name:  $ComputerNameNetbios to get get ProcessId, ParentProcessId data from WMI"
					# Try to use netbios computer name instead of FQDN/DNS
					$processes = Get-CimInstance -ComputerName $ComputerNameNetbios -Namespace "root\cimv2" -Query 'SELECT ProcessId,ParentProcessId,Name FROM Win32_Process' -ErrorAction SilentlyContinue -ErrorVariable wbemError

					if($wbemError) {
						# Log Error as Info in eventlog
						LogEvent -EventNr $SCRIPT_EVENT_ID -EventType $CN_SCOM_INFORMATION -LogMessage $wbemError
						$wbemError = $Null
						LogEvent -EventNr $SCRIPT_EVENT_ID -EventType $CN_SCOM_INFORMATION -LogMessage "Using COM to get ProcessId, ParentProcessId data instead of WinRM"
						# Use COM instead if all WinRM connection attempts fail
						$processes = Get-CimInstance -Namespace "root\cimv2" -Query 'SELECT ProcessId,ParentProcessId,Name FROM Win32_Process' -ErrorAction Stop
					}
				}
            }
            else
            {
                $processes = Get-WMIObject -Namespace "root\cimv2" -ComputerName $ComputerName -Query 'SELECT ProcessId,ParentProcessId,Name FROM Win32_Process' -ErrorAction stop
            }
            if($processes -ne $null)
            {
                LogEvent -EventNr $SCRIPT_EVENT_ID -EventType $CN_SCOM_INFORMATION -LogMessage "Number of active processes found: $($processes.Count).`nStarting search for the ones related to HealthService"
                # Step 2: Get the Health Service and Monitoring Host objects
                foreach($process in $processes)
                {
                    if(($process -ne $null) -and ($process.GetType().Name -ne "Nothing"))
                    {
                        if(($process.Name.contains("HealthService") -Or $process.Name.contains("MonitoringHost")) -And (-Not($agentProcIDs.contains($("|" + $process.ProcessId + "|")))))
                        {
                            $agentProcIDs = $($agentProcIDs + $process.ProcessId + "|")
                        }
                    }
                }

                # Step 3: Get all the child processes
                $childFound = $true
                # While a new child is found, re-iterate the list to find its child
                DO
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
                                if($agentProcIDs.contains($("|" + $process.ParentProcessId + "|")) -And (-Not($agentProcIDs.contains($("|" + $process.ProcessId + "|")))))
                                {
                                    $agentProcIDs = $($agentProcIDs + $process.ProcessId + "|")
                                    $childFound = $true
                                }
                            }
                        }
                    }
                }
                While($childFound -eq $true)

                # Step 4: Get the total cpu percentage used for all the SCOM processes
                if($isHigherThanWin08 -eq $true)
                {
                    LogEvent -EventNr $SCRIPT_EVENT_ID -EventType $CN_SCOM_INFORMATION -LogMessage "Getting the total cpu percentage used for all the SCOM processes"
                    $wmiService =  Get-CimInstance -Namespace "root\cimv2" -ComputerName $ComputerName -Class "Win32_PerfFormattedData_PerfProc_Process" -ErrorAction SilentlyContinue -ErrorVariable wbemError

					if($wbemError) {
						# Log Error as Info in eventlog
						LogEvent -EventNr $SCRIPT_EVENT_ID -EventType $CN_SCOM_INFORMATION -LogMessage $wbemError
						$wbemError = $Null
						# Get netbios name from FQDN
						$ComputerNameNetbios = $ComputerName.split(".")[0]
						LogEvent -EventNr $SCRIPT_EVENT_ID -EventType $CN_SCOM_INFORMATION -LogMessage "Trying to connect through WinRM using computer name:  $ComputerNameNetbios to get get performance counter data from WMI"
						# Try to use netbios computer name instead of FQDN/DNS
						$wmiService = Get-CimInstance -ComputerName $ComputerNameNetbios -Namespace "root\cimv2" -Class "Win32_PerfFormattedData_PerfProc_Process" -ErrorAction SilentlyContinue -ErrorVariable wbemError

						if($wbemError) {
							# Log Error as Info in eventlog
							LogEvent -EventNr $SCRIPT_EVENT_ID -EventType $CN_SCOM_INFORMATION -LogMessage $wbemError
							$wbemError = $Null
							LogEvent -EventNr $SCRIPT_EVENT_ID -EventType $CN_SCOM_INFORMATION -LogMessage "Using COM to get performance counter data instead of WinRM"
							# Use COM instead if all WinRM connection attempts fail
							$wmiService = Get-CimInstance -Namespace "root\cimv2" -Class "Win32_PerfFormattedData_PerfProc_Process" -ErrorAction Stop
						}
					}
                }
                else
                {
                    $wmiService =  Get-WMIObject -Namespace "root\cimv2" -ComputerName $ComputerName -Class "Win32_PerfFormattedData_PerfProc_Process"
                }
                $totalPercentProcessorTime = 0


                # Iterate each process to add the percent processor time to the to
                foreach($process in $wmiService)
                {
                    if($agentProcIDs.Contains($("|" + $process.IDProcess + "|")))
                    {
                        $x = $(GetProcessorTime $process.IDProcess $ComputerName)
                        $totalPercentProcessorTime = $totalPercentProcessorTime + $x
                        if($ConfigForRun -eq $true)
                        {
                            $procTime = $(GetProcessorTime $process.IDProcess $ComputerName)
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
    if($ConfigForRun -eq $true)
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
else
{
    LogEvent -EventNr $SCRIPT_EVENT_ID -EventType $CN_SCOM_ERROR -LogMessage "Failed to retrieve status data through WMI. `nError: $wbemError"
    $wbemError = $Null
}
if($ConfigForRun -eq $false)
{
    $oPropertyBag.AddValue("SCOMpercentageCPUTime", $finalPercentProcessorTime)
}
$oPropertyBag
LogEvent -EventNr $SCRIPT_EVENT_ID -EventType $CN_SCOM_INFORMATION -LogMessage "Script Finished"
