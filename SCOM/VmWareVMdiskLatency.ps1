#region Parameters
# Set sample interval Last 3 hours UTC
$aggregationInterval = 3
$TopN = 30
$PerfCounterName = "diskLatency"
$RuleDisplayName = "VMGUEST.Collect.diskLatency"

$avg_stat = @{}
$dataObjects = @()
#endregion Parameters
#region Functions
function RecalculateMinMaxForAvgStatItem {
param($name,$value)
    $avg_stat[$name]["min"] = ($avg_stat[$name]["min"], $value | Measure-Object -Min).Minimum
    $avg_stat[$name]["max"] = ($avg_stat[$name]["max"], $value | Measure-Object -Max).Maximum
}

function CreateStatistics {
param($value)
    $stat = $ScriptContext.CreateInstance("xsd://Microsoft.SystemCenter.Visualization.Library!Microsoft.SystemCenter.Visualization.DataProvider/PerformanceDataStatistics")
    if ($value -ne $null) {
        $stat["AverageValue"] = [double]$value
        $stat["Value"] = [double]$value
    }
    $stat
}

# Initialize Stat Item:
function InitAvgStatItem {
param($name)
    if($avg_stat[$name] -eq $null) {
        $avg_stat[$name] = @{}
        $avg_stat[$name]["min"] = 0
        $avg_stat[$name]["max"] = [Int32]::MinValue
    }
}

function AddColumnValue {
param($dataObject,$name,$value)

    $v = $value

    InitAvgStatItem $name
    if ($v -ne $null) {
        $dataObject[$name] = CreateStatistics($v)
        RecalculateMinMaxForAvgStatItem $name $v
    }
    else
    {
        $dataObject[$name] = $null
    }
}

function PadCounter {
PARAM([string]$Counter)
    switch ($Counter.length)
    {
            1 {Return [string]"0000$Counter"}
            2 {Return [string]"000$Counter"}
            3 {Return [string]"00$Counter"}
            4 {Return [string]"0$Counter"}
            5 {Return [string]"$Counter"}
    }
}

#endregion Functions

#region Main
$Class = Get-SCOMClass -Name Veeam.Virt.Extensions.VMware.VMGUEST
$Instances = Get-SCOMClassInstance -class $Class

foreach ($Instance in $Instances) {
    $dataObject = $ScriptContext.CreateFromObject($Instance, "Id=Id,State=HealthState", $null)
    $dataObject["Name"]= $Instance.DisplayName
    $dataObject["DataStore"]=$Instance.'[Veeam.Virt.Extensions.VMware.VMGUEST].usesDatastores'.Value
    $dataObject["Cluster"]=$Instance.'[Veeam.Virt.Extensions.VMware.VMGUEST].clusterName'.Value
    $dataObject["Path"]= $Instance.Path

    if ($dataObject -ne $null)  {
        $dt = New-TimeSpan -hour $aggregationInterval
        $nowlocal = Get-Date

        #Convert local time to UTC time
        $now = $nowlocal.ToUniversalTime()
        $from = $now.Subtract($dt)

        $perfRules = $Instance.GetMonitoringPerformanceData()
        foreach ($perfRule in $perfRules) {
            if($perfRule.CounterName -eq $PerfCounterName -and $perfRule.RuleDisplayName -eq $RuleDisplayName)   {
                $data = $perfRule.GetValues($from, $now) | ForEach-Object { $_.SampleValue } | Measure-Object -Average
                AddColumnValue $dataObject $perfRule.CounterName $data.Average
            }
        }
        $dataObjects += $dataObject
    }
}

# Sorts array of hashtables on perf counter defined in PerfCounterName on the averagevalue parameter and selects topN of these
# Use Descending parameter to sort from highest to lowest perf value
$ProcessedObjects = $dataObjects | Sort-Object  {$_[$PerfCounterName]["AverageValue"]} -Descending #| Select-Object -First $TopN

$sortIndex = 0
foreach ($dataObject in $ProcessedObjects)
{
    foreach ($metric in $avg_stat.Keys)
    {
        $stat = $avg_stat[$metric]
        $dataObject[$metric]["MinimumValue"] = [double]$stat["min"]

        if ($stat["max"] -ne [Int32]::MinValue)
        {
            $dataObject[$metric]["MaximumValue"] = [double]$stat["max"]
        }
        else
        {
            $dataObject[$metric]["MaximumValue"] = [double]0
        }
    }
    # Fix how objects are displayed and sorted in the dashboard, must use state as this is used as default sort column for widget
    # Use ID if Powershell Widget, or State if using Sample Blue bar Widget
    #$dataObject["Id"] = [string](PadCounter -Counter $sortIndex)
    $dataObject["State"] = [string](PadCounter -Counter $sortIndex)

    $ScriptContext.ReturnCollection.Add($dataObject)
    # Increment counter
    $sortIndex++
}
#endregion Main
