#requires -Version 5
# SCOM 2016
$SecurePassword = ConvertTo-SecureString -String "Pass@word1" -AsPlainText -Force
$InstallerServiceAccount = New-Object System.Management.Automation.PSCredential ("domain\!Installer", $SecurePassword)
$SecurePassword = ConvertTo-SecureString -String "Pass@word1" -AsPlainText -Force
$SystemCenter2016VirtualMachineManagerServiceAccount = New-Object System.Management.Automation.PSCredential ("CONTOSO\!vmm", $SecurePassword)



$ConfigurationData = @{
    AllNodes = @(
        @{
            NodeName = "*"
            PSDscAllowPlainTextPassword                         = $true
            PSDscAllowDomainUser                                = $true
            SourcePath                                          = "\\SQL01\Software"
            SourceFolder                                        = "\SystemCenter2016\VirtualMachineManager"
            WindowsServerSource                                 = "\WindowsServer2012R2"
            SQLServer2012NativeClient                           = ""
            SQLServer2014ManagementToolsPath                    = ""
            SQLServer2012CommandLineUtilities                   = ""
            InstallerServiceAccount                             = $InstallerServiceAccount
            AdminAccount                                        = "domain\VMMAdmins"
            SystemCenter2016VirtualMachineManagerServiceAccount = $SystemCenter2016VirtualMachineManagerServiceAccount
            SystemCenter2016ProductKey                          = ""
            CreateVMMDB                                         = 1
            SqlServer                                           = "SQL01.domain.info"
            SqlInstance                                         = "MSSQLSERVER"
            SqlDatabase                                         = "OperationsManager"
            CreateNewLibraryShare                               = 1
            LibraryShareName                                    = ""
            LibrarySharePath                                    = ""
            IndigoTcpPort                                       = 8100
            IndigoHTTPSPort                                     = 8101
            IndigoNETTCPPort                                    = 8102
            IndigoHTTPPort                                      = 8103
            WSManTcpPort                                        = 5985
            BitsTcpPort                                         = 443
        }
        @{
            NodeName = "node02.domain.info"
            Roles = @(
                "System Center 2016 Machine Manager Management Server"
            )
        }
    )
}

Configuration VMM
{
    #Import-DscResource -Module xSQLServer
    Import-DscResource -Module xSCVMM

    # Set role and instance variables
    $Roles = $AllNodes.Roles | Sort-Object -Unique
    foreach($Role in $Roles)
    {
        $Servers = @($AllNodes.Where{$_.Roles | Where-Object {$_ -eq $Role}}.NodeName)
        Set-Variable -Name ($Role.Replace(" ","").Replace(".","") + "s") -Value $Servers
        if($Servers.Count -eq 1)
        {
            Set-Variable -Name ($Role.Replace(" ","").Replace(".","")) -Value $Servers[0]
            if(
                $Role.Contains("Database") -or
                $Role.Contains("Datawarehouse") -or
                $Role.Contains("Reporting") -or
                $Role.Contains("Analysis") -or
                $Role.Contains("Integration")
            )
            {
                $Instance = $AllNodes.Where{$_.NodeName -eq $Servers[0]}.SQLServers.Where{$_.Roles | Where-Object {$_ -eq $Role}}.InstanceName
                Set-Variable -Name ($Role.Replace(" ","").Replace(".","").Replace("Server","Instance")) -Value $Instance
            }
        }
    }

    Node $AllNodes.NodeName
    {

        # Install .NET Framework 3.5 on SQL nodes
        if(
            ($SystemCenter2016VirtualMachineManagerDatabaseServer -eq $Node.NodeName) -or
            ($SQLServer2014ManagementTools | Where-Object {$_ -eq $Node.NodeName})
        )
        {
            if($Node.WindowsServerSource)
            {
                $WindowsServerSource = (Join-Path -Path $Node.WindowsServerSource -ChildPath "\sources\sxs")
            }
            else
            {
                $WindowsServerSource = "\WindowsServer2012R2\sources\sxs"
            }

            WindowsFeature "NET-Framework-Core"
            {
                Ensure = "Present"
                Name = "NET-Framework-Core"
                Source = $Node.SourcePath + $WindowsServerSource
            }
        }
<#
        # Install SQL Instances
        if(
            ($SystemCenter2016VirtualMachineManagerDatabaseServer -eq $Node.NodeName)
        )
        {
            foreach($SQLServer in $Node.SQLServers)
            {
                $SQLInstanceName = $SQLServer.InstanceName

                $Features = ""
                if(
                    (
                        ($SystemCenter2016VirtualMachineManagerDatabaseServer -eq $Node.NodeName) -and
                        ($SystemCenter2016VirtualMachineManagerDatabaseInstance -eq $SQLInstanceName)
                    )
                )
                {
                    $Features += "SQLENGINE"
                }
                $Features = $Features.Trim(",")

                if($Features -ne "")
                {
                    xSqlServerSetup ($Node.NodeName + $SQLInstanceName)
                    {
                        DependsOn = "[WindowsFeature]NET-Framework-Core"
                        SourcePath = $Node.SourcePath
                        SourceFolder = "SQLServer2014.en"
                        SetupCredential = $Node.InstallerServiceAccount
                        InstanceName = $SQLInstanceName
                        Features = $Features
                        SQLSysAdminAccounts = $Node.AdminAccount
                    }

                    xSqlServerFirewall ($Node.NodeName + $SQLInstanceName)
                    {
                        DependsOn = ("[xSqlServerSetup]" + $Node.NodeName + $SQLInstanceName)
                        SourcePath = $Node.SourcePath
                        SourceFolder = "SQLServer2014.en"
                        InstanceName = $SQLInstanceName
                        Features = $Features
                    }
                }
            }
        }

        # Install SQL Management Tools
        if($SQLServer2014ManagementTools | Where-Object {$_ -eq $Node.NodeName})
        {
            xSqlServerSetup "SQLMT"
            {
                DependsOn = "[WindowsFeature]NET-Framework-Core"
                SourcePath = $Node.SourcePath
                SourceFolder = $Node.SQLServer2014ManagementToolsPath
                SetupCredential = $Node.InstallerServiceAccount
                InstanceName = "NULL"
                Features = "SSMS,ADV_SSMS"
            }
        }
#>
        # Install prerequisites on Management Servers
        if(
            ($SystemCenter2016VirtualMachineManagerManagementServers | Where-Object {$_ -eq $Node.NodeName})
        )
        {
            if($Node.SQLServer2012NativeClient)
            {
                $SQLServer2012NativeClient = (Join-Path -Path $Node.SQLServer2012NativeClient -ChildPath "SQLNCli.msi")
            }
            else
            {
                $SQLServer2012NativeClient = "\Prerequisites\SQL2012NC\SQLNCli.msi"
            }
            Package "SQLServer2012NativeClient"
            {
                Ensure = "Present"
                Name = "Microsoft SQL Server 2012 Native Client "
                ProductId = ""
                Path = (Join-Path -Path $Node.SourcePath -ChildPath $SQLServer2012NativeClient)
                Arguments = "IACCEPTSQLNCLILICENSETERMS=YES ALLUSERS=2"
                Credential = $Node.InstallerServiceAccount
            }

            if($Node.SQLServer2012CommandLineUtilities)
            {
                $SQLServer2012CommandLineUtilities = (Join-Path -Path $Node.SQLServer2012CommandLineUtilities -ChildPath "SQLCmdLnUtils.msi")
            }
            else
            {
                $SQLServer2012CommandLineUtilities = "\Prerequisites\SQL2012CLU\SQLCmdLnUtils.msi"
            }
            Package "SQLServer2012CommandLineUtilities"
            {
                Ensure = "Present"
                Name = "Microsoft SQL Server 2012 Command Line Utilities "
                ProductId = ""
                Path = (Join-Path -Path $Node.SourcePath -ChildPath $SQLServer2012CommandLineUtilities)
                Arguments = "ALLUSERS=2"
                Credential = $Node.InstallerServiceAccount
            }

            if($Node.WindowsDeploymentTools81)
            {
                $WindowsDeploymentTools81 = (Join-Path -Path $Node.WindowsDeploymentTools81 -ChildPath "adksetup.exe")
            }
            else
            {
                $WindowsDeploymentTools81 = "\Prerequisites\ADK81\adksetup.exe"
            }
            Package "WindowsDeploymentTools81"
            {
                Ensure = "Present"
                Name = "Windows Deployment Tools"
                ProductId = ""
                Path = (Join-Path -Path $Node.SourcePath -ChildPath $WindowsDeploymentTools81)
                Arguments = "/quiet /features OptionId.DeploymentTools"
                Credential = $Node.InstallerServiceAccount
            }

            if($Node.WindowsPreinstallationEnvironment81)
            {
                $WindowsPreinstallationEnvironment81 = (Join-Path -Path $Node.WindowsPreinstallationEnvironment81 -ChildPath "adksetup.exe")
            }
            else
            {
                $WindowsPreinstallationEnvironment81 = "\Prerequisites\ADK81\adksetup.exe"
            }
            Package "WindowsPreinstallationEnvironment81"
            {
                Ensure = "Present"
                Name = "Windows PE x86 x64"
                ProductId = ""
                Path = (Join-Path -Path $Node.SourcePath -ChildPath $WindowsPreinstallationEnvironment81)
                Arguments = "/quiet /features OptionId.WindowsPreinstallationEnvironment"
                Credential = $Node.InstallerServiceAccount
            }
        }

        # Add service accounts to admins on Management Servers
        if($SystemCenter2016VirtualMachineManagerManagementServers | Where-Object {$_ -eq $Node.NodeName})
        {
            Group "Administrators"
            {
                GroupName = "Administrators"
                MembersToInclude = @(
                    $Node.SystemCenter2012VirtualMachineManagerServiceAccount.UserName
                )
                Credential = $Node.InstallerServiceAccount
                PsDscRunAsCredential = $Node.InstallerServiceAccount
            }
        }

        # Install first Management Server
        if ($SystemCenter2016VirtualMachineManagerManagementServers[0] -eq $Node.NodeName)
        {
            # Create DependsOn for first Management Server
            $DependsOn = @(
                "[Package]SQLServer2012NativeClient",
                "[Package]SQLServer2012CommandLineUtilities",
                "[Package]WindowsDeploymentTools81",
                "[Package]WindowsPreinstallationEnvironment81",
                "[Group]Administrators"
            )

            # Wait for VMM SQL Server
            if ($SystemCenter2016VirtualMachineManagerManagementServers[0] -eq $SystemCenter2016VirtualMachineManagerDatabaseServer)
            {
                $DependsOn += @(("[xSqlServerFirewall]" + $SystemCenter2016VirtualMachineManagerDatabaseServer + $SystemCenter2016VirtualMachineManagerDatabaseInstance))
            }
            else
            {
                WaitForAll "VMMDB"
                {
                    NodeName = $SystemCenter2016VirtualMachineManagerDatabaseServer
                    ResourceName = ("[xSqlServerFirewall]" + $SystemCenter2016VirtualMachineManagerDatabaseServer + $SystemCenter2016VirtualMachineManagerDatabaseInstance)
                    PsDscRunAsCredential = $Node.InstallerServiceAccount
                    RetryCount = 720
                    RetryIntervalSec = 5
                }
                $DependsOn += @("[WaitForAll]VMMDB")
            }

            # Install first Management Server
            xSCVMMManagementServerSetup "VMMMS"
            {
                DependsOn = $DependsOn
                Ensure = "Present"
                SourcePath = $Node.SourcePath
                SourceFolder =  $Node.SourceFolder
                SetupCredential = $Node.InstallerServiceAccount
                ProductKey = $Node.SystemCenter2016ProductKey
                vmmService = $Node.SystemCenter2016VirtualMachineManagerServiceAccount
                SqlMachineName = $Node.SqlServer
                SqlInstanceName = $Node.SqlInstance
                SqlDatabaseName = $Node.SqlDatabase
                CreateNewSqlDatabase = $Node.CreateVMMDB
                CreateNewLibraryShare = $Node.CreateNewLibraryShare
                LibraryShareName = $Node.LibraryShareName
                LibrarySharePath = $Node.LibrarySharePath
                IndigoTcpPort = $Node.IndigoTcpPort
                IndigoHTTPSPort = $Node.IndigoHTTPSPort
                IndigoNETTCPPort = $Node.IndigoNETTCPPort
                IndigoHTTPPort = $Node.IndigoHTTPPort
                WSManTcpPort = $Node.WSManTcpPort
                BitsTcpPort = $Node.BitsTcpPort

            }
        }

        # Install Consoles
        if($SystemCenter2016VirtualMachineManagerConsoles | Where-Object {$_ -eq $Node.NodeName})
        {
            xSCVMMConsoleSetup "VMMC"
            {
                Ensure = "Present"
                SourcePath = $Node.SourcePath
                SourceFolder = $Node.SourceFolder
                SetupCredential = $Node.InstallerServiceAccount
            }
        }
    }
}
foreach($Node in $ConfigurationData.AllNodes)
{
    if($Node.NodeName -ne "*")
    {
        Start-Process -FilePath "robocopy.exe" -ArgumentList ("`"C:\Program Files\WindowsPowerShell\Modules`" `"\\" + $Node.NodeName + "\c$\Program Files\WindowsPowerShell\Modules`" /e /purge /xf") -NoNewWindow -Wait
    }
}

VMM -ConfigurationData $ConfigurationData
Set-DscLocalConfigurationManager -Path .\VMM -Verbose
Start-DscConfiguration -Path .\VMM -Verbose -Wait -Force