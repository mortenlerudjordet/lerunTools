# Set sample interval Last 3 hours UTC
$aggregationInterval = 3
$TopN = 10
$PerfCounterName = "Send Queue Size"
$RuleDisplayName = "Collect Health Service Management Group\Send Queue Size"

$class = get-scomclass -Name Microsoft.SystemCenter.Agent
$Agents = Get-SCOMClassInstance -class $class

$avg_stat = @{}
$dataObjects = @()

#///////// Functions Section ///////////////////// START

function RecalculateMinMaxForAvgStatItem {
    param($name, $value)
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
param($dataObject, $name, $value)

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

function SortID {
PARAM([string]$strID)
switch ($strID.length)
{
        1 {Return "0000$strID"}
        2 {Return "000$strID"}
        3 {Return "00$strID"}
        4 {Return "0$strID"}
        5 {Return "$strID"}
}
}

#///////// Functions Section ///////////////////// END

#///////// Main Section ///////////////////// START

foreach ($Agent in $Agents) {
    # View is sorted based on what parameter is set as ID, this must also be unique or it will get stripped out
    $dataObject = $ScriptContext.CreateFromObject($Agent, "Id=Id,State=HealthState", $null)
    $dataObject["Name"]= $Agent.DisplayName
    $dataObject["Patch Level"]=$Agent.'[Microsoft.SystemCenter.HealthService].PatchList'.Value
    $dataObject["Path"]= $Agent.Path

    if ($dataObject -ne $null)  {
        $dt = New-TimeSpan -hour $aggregationInterval
        $nowlocal = Get-Date

        #Convert local time to UTC time
        $now = $nowlocal.ToUniversalTime()
        $from = $now.Subtract($dt)

        $perfRules = $Agent.GetMonitoringPerformanceData()
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
$ProcessedObjects = $dataObjects | Sort-Object  {$_[$PerfCounterName]["AverageValue"]} -Descending | Select-Object -First $TopN

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
    # Fix how objects are displayed and sorted in the dashboard, must use state as this is used as default sort column in dashboard
    $dataObject["State"] = [string]$sortIndex

    $ScriptContext.ReturnCollection.Add($dataObject)
    # Increment counter
    $sortIndex++
}
#///////// Main Section ///////////////////// END