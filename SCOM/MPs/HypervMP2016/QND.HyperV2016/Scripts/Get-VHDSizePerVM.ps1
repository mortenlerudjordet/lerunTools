#TO SHOW VERBOSE MESSAGES SET $VerbosePreference="continue"
#SET ErrorLevel to 5 so show discovery info

#*************************************************************************
# Script Name - Get-VHDSizePerVM.ps1
# Author	  -  - Tao Yang (based on Get-VHDStats.ps1 from Progel spa)
# Version  - 1.0 24.09.2007
# Purpose     - 
#               
# Assumptions - 
#				
#               
# Parameters  - TraceLevel
#             - ComputerName
#				- SourceId
#				- ManagedEntityId
# Command Line - .\test.ps1 4 "serverName" '{1860E0EB-8C21-41DA-9F35-2FE9343CCF36}' '{1860E0EB-8C21-41DA-9F35-2FE9343CCF36}'
# If discovery must be added the followinf parameters
#				SourceId ($ MPElement $ )
#				ManagedEntityId ($ Target/Id $)
#
# Output properties
#
# Status
#
# Version History
#	  1.0 21.02.2015 DG First Release
#     
#
# (c) Copyright 2015, Progel spa, All Rights Reserved
# Proprietary and confidential to Progel srl              
#
#*************************************************************************


# Get the named parameters
param([int]$traceLevel=$(throw 'must have a value'))

	[Threading.Thread]::CurrentThread.CurrentCulture = "en-US"        
	[Threading.Thread]::CurrentThread.CurrentUICulture = "en-US"
	
#Constants used for event logging
$SCRIPT_NAME			= "Get-VHDSizePerVM.ps1"
$SCRIPT_ARGS = 1
$SCRIPT_STARTED			= 831
$PROPERTYBAG_CREATED	= 832
$SCRIPT_ENDED			= 835
$SCRIPT_VERSION = "1.0"

#region Constants
#Trace Level Costants
$TRACE_NONE 	= 0
$TRACE_ERROR 	= 1
$TRACE_WARNING = 2
$TRACE_INFO 	= 3
$TRACE_VERBOSE = 4
$TRACE_DEBUG = 5

#Event Type Constants
$EVENT_TYPE_SUCCESS      = 0
$EVENT_TYPE_ERROR        = 1
$EVENT_TYPE_WARNING      = 2
$EVENT_TYPE_INFORMATION  = 4
$EVENT_TYPE_AUDITSUCCESS = 8
$EVENT_TYPE_AUDITFAILURE = 16

#Standard Event IDs
$FAILURE_EVENT_ID = 4000		#errore generico nello script
$SUCCESS_EVENT_ID = 1101
$START_EVENT_ID = 1102
$STOP_EVENT_ID = 1103

#TypedPropertyBag
$AlertDataType = 0
$EventDataType	= 2
$PerformanceDataType = 2
$StateDataType       = 3
#endregion

#region Helper Functions
function Log-Params
{
	param($Invocation)
	$line=''
	foreach($key in $Invocation.BoundParameters.Keys) {$line += "$key=$($Invocation.BoundParameters[$key])  "}
	Log-Event $START_EVENT_ID $EVENT_TYPE_INFORMATION  ("Starting script. Invocation Name:$($Invocation.InvocationName)`n Parameters`n $line") $TRACE_INFO
}


function Log-Event
{
	param($eventID, $eventType, $msg, $level)
	
	Write-Verbose ("Logging event. " + $SCRIPT_NAME + " EventID: " + $eventID + " eventType: " + $eventType + " Version:" + $SCRIPT_VERSION + " --> " + $msg)
	if($level -le $P_TraceLevel)
	{
		Write-Host ("Logging event. " + $SCRIPT_NAME + " EventID: " + $eventID + " eventType: " + $eventType + " Version:" + $SCRIPT_VERSION + " --> " + $msg)
		$g_API.LogScriptEvent($SCRIPT_NAME,$eventID,$eventType, ($msg + "`n" + "Version :" + $SCRIPT_VERSION))
	}
}

Function Throw-EmptyDiscovery
{
	param($SourceId, $ManagedEntityId)

	$oDiscoveryData = $g_API.CreateDiscoveryData(0, $SourceId, $ManagedEntityId)
	Log-Event $FAILURE_EVENT_ID $EVENT_TYPE_WARNING "Exiting with empty discovery data" $TRACE_INFO
	$oDiscoveryData
	If($traceLevel -eq $TRACE_DEBUG)
	{
		#just for debug proposes when launched from command line does nothing when run inside OpsMgr Agent
		$g_API.Return($oDiscoveryData)
	}
}

Function Throw-KeepDiscoveryInfo
{
param($SourceId, $ManagedEntityId)
	$oDiscoveryData = $g_API.CreateDiscoveryData(0,$SourceId,$ManagedEntityId)
	#Instead of Snapshot discovery, submit Incremental discovery data
	$oDiscoveryData.IsSnapshot = $false
	Log-Event $FAILURE_EVENT_ID $EVENT_TYPE_WARNING "Exiting with null non snapshot discovery data" $TRACE_INFO
	$oDiscoveryData    
	If($traceLevel -eq $TRACE_DEBUG)
	{
		#just for debug proposes when launched from command line does nothing when run inside OpsMgr Agent	
		$g_API.Return($oDiscoveryData)
	}
}
#endregion

Function NullIsZero
{
	param($value)
	if(! $value) {return 0}
	return $value
}

$Time = [System.Diagnostics.Stopwatch]::StartNew()

#Start by setting up API object.
	$P_TraceLevel = $TRACE_VERBOSE
	$g_Api = New-Object -comObject 'MOM.ScriptAPI'
	#$g_RegistryStatePath = "HKLM\" + $g_API.GetScriptStateKeyPath($SCRIPT_NAME)
	
	$P_TraceLevel = $traceLevel
	Log-Params $MyInvocation

try
{
	if (!(get-Module -Name Hyper-v)) {Import-Module Hyper-v}


	if (!(get-command -Module Hyper-V -Name Get-VM -ErrorAction SilentlyContinue)) {
		Log-Event $START_EVENT_ID $EVENT_TYPE_WARNING ("Get-VM Commandlet doesn't exist.") $TRACE_WARNING
		Exit 1;
	}

	#$vms = @(gwmi Msvm_ComputerSystem -namespace "root\virtualization\v2" | where {$_.ReplicationMode -ne 0 -and $_.ReplicationMode -ne $null})
	$vms=Get-VM
	foreach($vm in $vms) {
		try {
			$HardDrives = $vm.HardDrives
			$VHDs = Get-VHD -VMId $vm.VMId -ErrorAction SilentlyContinue
			$TotalCurrentSize = 0
			$TotalMaxSize = 0
			$TotalMinSize = 0
			foreach($hd in $HardDrives) {
				$vhd = $VHDs | where {$_.Path -ieq $hd.Path}
				
				if($vhd) {
					$TotalCurrentSize = $TotalCurrentSize + $vhd.FileSize
					$TotalMaxSize = $TotalMaxSize + $vhd.Size
					$TotalMinSize = $TotalMinSize + $vhd.MinimumSize
					$minSizeGB = [math]::Round((NullIsZero ($vhd.MinimumSize/1GB)),2)					
				}
			}
				$TotalCurrentSizeGB = [math]::Round((NullIsZero ($TotalCurrentSize/1GB)),2)
				$TotalMaxSizeGB = [math]::Round((NullIsZero ($TotalMaxSize/1GB)),2)
				$TotalMinSizeGB = [math]::Round((NullIsZero ($TotalMinSize/1GB)),2)
				$bag = $g_api.CreatePropertyBag()
				$bag.AddValue('VMId',$VM.VMId.ToString())
				$bag.AddValue('VMName',$VM.VMName)
				$bag.AddValue('CurrentSizeGB', $TotalCurrentSizeGB)
				$bag.AddValue('MaxSizeGB',$TotalMaxSizeGB)
				$bag.AddValue('MinSizeGB',$TotalMinSizeGB)				
				$bag
			Log-Event $START_EVENT_ID $EVENT_TYPE_INFO ("$($vm.Name) has been processed") $TRACE_VERBOSE
		}
		Catch [Exception] {
			Log-Event $START_EVENT_ID $EVENT_TYPE_WARNING ("$($vm.Name) error getting disk info $($Error[0].Exception)") $TRACE_WARNING
		}
	}

	Log-Event $STOP_EVENT_ID $EVENT_TYPE_SUCCESS ("has completed successfully in " + ((Get-Date)- ($dtstart)).TotalSeconds + " seconds.") $TRACE_INFO
}
Catch [Exception] {
	Log-Event $FAILURE_EVENT_ID $EVENT_TYPE_WARNING ("Main " + $($Error[0].Exception)) $TRACE_WARNING	
	write-Verbose $("TRAPPED: " + $_.Exception.GetType().FullName); 
	Write-Verbose $("TRAPPED: " + $_.Exception.Message); 
}
Finally {
	$Time.Stop()
	Log-Event $STOP_EVENT_ID $EVENT_TYPE_SUCCESS "Script Finished`nRun Time: $($Time.Elapsed.TotalSeconds) second(s)" $TRACE_INFO
}
