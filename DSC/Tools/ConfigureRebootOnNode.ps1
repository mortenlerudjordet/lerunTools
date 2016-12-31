Configuration ConfigureRebootOnNode
{
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $NodeName
    )

    Node $NodeName
    {
        LocalConfigurationManager
        {
            RebootNodeIfNeeded = $false
        }
    }
}

Write-Host "Creating mofs"
ConfigureRebootOnNode -NodeName "node01.lerun.info" -OutputPath .\rebootMofs

Write-Host "Starting CimSession"
$pass = ConvertTo-SecureString "NetsurfeR" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential ("!Installer", $pass)
$cim = New-CimSession -ComputerName fabfiberserver -Credential $cred

Write-Host "Writing config"
Set-DscLocalConfigurationManager -CimSession $cim -Path .\rebootMofs -Verbose

# read the config settings back to confirm
Get-DscLocalConfigurationManager -CimSession $cim