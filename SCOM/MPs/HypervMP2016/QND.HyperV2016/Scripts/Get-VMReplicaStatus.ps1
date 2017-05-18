﻿#TO SHOW VERBOSE MESSAGES SET $VerbosePreference="continue"
#SET ErrorLevel to 5 so show discovery info

#*************************************************************************
# Script Name - Get-VMReplicaStatus.ps1
# Author	  -  - Progel spa
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
param([int]$traceLevel=$(throw 'must have a value'),
	[string]$VMGuid)

	[Threading.Thread]::CurrentThread.CurrentCulture = "en-US"        
	[Threading.Thread]::CurrentThread.CurrentUICulture = "en-US"
	
#Constants used for event logging
$SCRIPT_NAME			= "Get-VMReplicaStatus.ps1"
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

	if ($VMGuid -ine 'ignore') {	#here we're in atask targeted at a specific VM
		$vm = Get-VM | where {$_.VMId -ieq $VMGuid}
		if ($vm) {
			$replica = Get-VMReplication -VM $vm
			Write-Host "$($vm.Name) Replication mode: $($vm.ReplicationMode.ToString())"
			Write-Host "Replication Health: $($replica.ReplicationHealth.ToString()) State: $($replica.ReplicationState.ToString())"
			Write-Host "Last replication: $($replica.LastReplicationTime)"
			Write-Host "Replica state dump: "
			$replica | fl *
			Write-Host "Replica measure dump: "
			Mesaure-VMReplica -VM $vm | fl *
		}
		else {
			Write-Host "VM with Guid $VMGuid not found on host!"
		}
		exit;
	}

	$vms = @(gwmi Msvm_ComputerSystem -namespace "root\virtualization\v2" | where {$_.ReplicationMode -ne 0 -and $_.ReplicationMode -ne $null})
	foreach($vm in $vms) {
		$VMId = $vm.Name
		$LastReplicationTime=[System.Management.ManagementDateTimeConverter]::ToDateTime($vm.LastReplicationTime) 
		$VMReplicationMode=$vm.ReplicationMode
		$VMReplicationHealthCode=$vm.ReplicationHealth
		$VMReplicationStateCode=$vm.ReplicationState

	#need to use Msvm_ReplicationRelationship
	$VMReplicationState= switch ($VMReplicationStateCode)
	{
		0 {'Disabled'}
		1 {'Ready for replication'}
		2 {'Waiting to complete initial replication'}
		3 {'Replicating'}
		4 {'Synced replication complete'}
		5 {'Recovered'}
		6 {'Committed'}
		7 {'Suspended'}
		8 {'Critical'}
		9 {'Waiting to start resynchronization'}
		10 {'Resynchronizing'}
		11 {'Resynchronization suspended'}
		12 {'Failover in progress'}
		13 {'Failback in progress'}
		14 {'Failback complete'}
		default {'Unknown'};
	}
		
		$VMReplicationHealth= switch ($VMReplicationHealthCode) {
			0 {'Disabled'}
			1 {'OK'}	
			2 {'Warning'}
			3 {'Critical'}
			default {'Unknown'}
		}

		$replicaAgeHours = ([DateTime]::Now - $LastReplicationTime).TotalHours
		$bag = $g_api.CreatePropertyBag()
		$bag.AddValue('VMId',$VMId)
		$bag.AddValue('ReplicationMode', $VMReplicationMode) #to be used in filters, we just monitor primary replica side ==1
		$bag.AddValue('ReplicationHealthCode',$VMReplicationHealthCode)
		$bag.AddValue('ReplicationHealth',$VMReplicationHealth)
		$bag.AddValue('ReplicationStateCode',$VMReplicationStateCode)
		$bag.AddValue('ReplicationState',$VMReplicationState)
		$bag.AddValue('ReplicaAgeHours',$replicaAgeHours)
		$bag

	$message="$($vm.Name) Replica State is: $($vmreplicationstatecode) Replica Health Is: $($vmreplicationhealthcode). Replica Age is: $replicaAgeHours"
		Log-Event $START_EVENT_ID $EVENT_TYPE_INFO ("$($vm.VMName) has been processed `n $message") $TRACE_DEBUG
	}

	#Debug the pèowershll module has issues in both caching (results doesn't change between iterations and values returned so we're not going to use POSH
	$vms = Get-VM | where {$_.ReplicationMode.Value__ -ne 0}	#use the enum codes instead of labels 0 = 'None'
	$vms=$null #debug not using POSH
	foreach($vm in $vms) {
		$replica = Get-VMReplication -VM $vm
		$VMId = $vm.VMId.ToString()
		$LastReplicationTime=$replica.LastReplicationTime
		$VMReplicationMode=$vm.ReplicationMode.value__
		$VMReplicationHealthCode=$replica.ReplicationHealth.Value__
		$VMReplicationStateCode=$replica.ReplicationState.Value__
		$VMReplicationState=$replica.ReplicationState.ToString()
		$VMRepliactionHealth=$replica.ReplicationHealth.ToString()	
		$message="$($vm.Name) Replica State is: $($vmreplicationstatecode) Replica Health Is: $($vmreplicationhealthcode). Replica Age is: $replicaAgeHours"
		Log-Event $START_EVENT_ID $EVENT_TYPE_INFO ("$($vm.VMName) has been processed `n $message") $TRACE_DEBUG

	}

	Log-Event $STOP_EVENT_ID $EVENT_TYPE_SUCCESS ("has completed successfully in " + ((Get-Date)- ($dtstart)).TotalSeconds + " seconds.") $TRACE_INFO
}
Catch [Exception] {
	Log-Event $FAILURE_EVENT_ID $EVENT_TYPE_WARNING ("Main " + $Error) $TRACE_WARNING	
	write-Verbose $("TRAPPED: " + $_.Exception.GetType().FullName); 
	Write-Verbose $("TRAPPED: " + $_.Exception.Message); 
}
Finally {
	$Time.Stop()
	Log-Event $STOP_EVENT_ID $EVENT_TYPE_SUCCESS "Script Finished`nRun Time: $($Time.Elapsed.TotalSeconds) second(s)" $TRACE_INFO
}

