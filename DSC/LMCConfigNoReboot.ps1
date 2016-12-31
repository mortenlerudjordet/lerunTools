[DSCLocalConfigurationManager()]
Configuration LCMConfigNoReboot {
Node $AllNodes.NodeName
    {
        # Set LCM to reboot if needed
        Settings
        {
            DebugMode = 'ForceModuleImport'
            RebootNodeIfNeeded = $false
            ActionAfterReboot = 'ContinueConfiguration'
            RefreshMode = "PUSH"
            # This will only apply the configuration once, change to ApplyAndMonitor or ApplyAndAutoCorrect for config monitoring and auto change
            ConfigurationMode = "ApplyOnly"
        }
    }

}

$ConfigurationData = @{
    AllNodes = @(
        @{
            NodeName   = 'node01.domain.com'
        }
    )
}
LCMConfigNoReboot -ConfigurationData $ConfigurationData
Set-DscLocalConfigurationManager -Path .\LCMConfigNoReboot -Verbose