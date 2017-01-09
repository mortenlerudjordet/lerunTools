#requires -Version 5
# SPF 2016
$SecurePassword = ConvertTo-SecureString -String "********" -AsPlainText -Force
$InstallerServiceAccount = New-Object System.Management.Automation.PSCredential ("domain\!Installer", $SecurePassword)
$SecurePassword = ConvertTo-SecureString -String "********" -AsPlainText -Force
$SPFServiceAccount = New-Object System.Management.Automation.PSCredential ("domain\!spf", $SecurePassword)
$SecurePassword = ConvertTo-SecureString -String "********" -AsPlainText -Force
$SCVMMServiceAccount = New-Object System.Management.Automation.PSCredential ("domain\!spf", $SecurePassword)
$SecurePassword = ConvertTo-SecureString -String "********" -AsPlainText -Force
$SPFAdminServiceAccount = New-Object System.Management.Automation.PSCredential ("domain\!spf", $SecurePassword)
$SecurePassword = ConvertTo-SecureString -String "********" -AsPlainText -Force
$SPFProviderServiceAccount = New-Object System.Management.Automation.PSCredential ("domain\!spf", $SecurePassword)
$SecurePassword = ConvertTo-SecureString -String "********" -AsPlainText -Force
$SPFUsageServiceAccount = New-Object System.Management.Automation.PSCredential ("domain\!spf", $SecurePassword)

$ConfigurationData = @{
    AllNodes = @(
        @{
            NodeName = "*"
            PSDscAllowPlainTextPassword = $true
            PSDscAllowDomainUser = $true
            SourcePath = "\\SQL01\Software"
            SourceFolder = "\SystemCenter2016\Orchestrator"
            SCVMMSourcePath = "\SystemCenter2016\VirtualMachineManager"
            InstallerServiceAccount = $InstallerServiceAccount
            SPFServiceAccount = $SPFServiceAccount
            SCVMM = $SCVMMServiceAccount
            SCAdmin = $SPFAdminServiceAccount
            SCProvider = $SPFProviderServiceAccount
            SCUsage = $SPFUsageServiceAccount
            VMMSecurityGroupUsers = "domain\ladmin;domain\VMMAdmins"
            AdminSecurityGroupUsers = "domain\ladmin;domain\SPFAdmins"
            ProviderSecurityGroupUsers = "domain\ladmin;domain\ProviderAdmins"
            UsageSecurityGroupUsers = "domain\ladmin;domain\UsageAdmins"
            DatabaseServer = "SQL01.domain.info"
            DatabaseName =  "SCSPFDB"
            DatabasePortNumber = "1433"
            WebSitePortNumber = "443"
            SCVMMConsolePort = "8100"
            SpecifyCertificate = $True
            CertificateName = "SPF"
        }
        @{
            NodeName = "Node01.domain.info"
            Roles = @("System Center 2016 Service Provider Foundation Server")
        }
    )
}

Configuration SPF
{
    Import-DscResource -Module xSQLServer
    Import-DscResource -Module xSCVMM
    Import-DscResource -Module xSCSPF
    Import-DscResource -ModuleName PSDesiredStateConfiguration

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

        # Install .NET 3.5 Framework
        if(
            ($SystemCenter2016ServiceProviderFoundationDatabaseServer -eq $Node.NodeName) -or
            ($SQLServer2012ManagementTools | Where-Object {$_ -eq $Node.NodeName})
        )
        {
            WindowsFeature "NET-Framework-Core"
            {
                Ensure = "Present"
                Name = "NET-Framework-Core"
                Source = $Node.SourcePath + "\WindowsServer2012R2\sources\sxs"
            }
        }

        # Install IIS on Web Service servers
        if(
            ($SystemCenter2016ServiceProviderFoundationServers  | Where-Object {$_ -eq $Node.NodeName})
        )
        {
            WindowsFeature "Web-WebServer"
            {
                Ensure = "Present"
                Name = "Web-WebServer"
            }

            WindowsFeature "Web-Basic-Auth"
            {
                Ensure = "Present"
                Name = "Web-Basic-Auth"
            }

            WindowsFeature "Web-Windows-Auth"
            {
                Ensure = "Present"
                Name = "Web-Windows-Auth"
            }

            WindowsFeature "Web-Asp-Net45"
            {
                Ensure = "Present"
                Name = "Web-Asp-Net45"
            }

            WindowsFeature "NET-WCF-HTTP-Activation45"
            {
                Ensure = "Present"
                Name = "NET-WCF-HTTP-Activation45"
            }

            WindowsFeature "ManagementOData"
            {
                Ensure = "Present"
                Name = "ManagementOData"
            }

            WindowsFeature "Web-Request-Monitor"
            {
                Ensure = "Present"
                Name = "Web-Request-Monitor"
            }

            WindowsFeature "Web-Http-Tracing"
            {
                Ensure = "Present"
                Name = "Web-Http-Tracing"
            }

            WindowsFeature "Web-Scripting-Tools"
            {
                Ensure = "Present"
                Name = "Web-Scripting-Tools"
            }
            WindowsFeature IISCOnsole
            {
                Ensure = "Present"
                Name = "Web-Mgmt-Console"
                DependsOn = "[WindowsFeature]Web-WebServer"
            }
        }
        <#
        # Install SQL Instances
        if(
            ($SystemCenter2016ServiceProviderFoundationDatabaseServer -eq $Node.NodeName)
        )
        {
            foreach($SQLServer in $Node.SQLServers)
            {
                $SQLInstanceName = $SQLServer.InstanceName

                $Features = ""
                if(
                    (
                        ($SystemCenter2016ServiceProviderFoundationDatabaseServer -eq $Node.NodeName) -and
                        ($SystemCenter2016ServiceProviderFoundationDatabaseInstance -eq $SQLInstanceName)
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
                        SourceFolder = $Node.SQLSourceFolder
                        SetupCredential = $Node.InstallerServiceAccount
                        InstanceName = $SQLInstanceName
                        Features = $Features
                        SQLSysAdminAccounts = $Node.SQLSysAdminAccounts
                    }

                    xSqlServerFirewall ($Node.NodeName + $SQLInstanceName)
                    {
                        DependsOn = ("[xSqlServerSetup]" + $Node.NodeName + $SQLInstanceName)
                        SourcePath = $Node.SourcePath
                        InstanceName = $SQLInstanceName
                        Features = $Features
                    }
                }
            }
        }
        #>
        # Install SQL Management Tools
        if($SQLServer2012ManagementTools | Where-Object {$_ -eq $Node.NodeName})
        {
            xSqlServerSetup "SQLMT"
            {
                DependsOn = "[WindowsFeature]NET-Framework-Core"
                SourcePath = $Node.SourcePath
                SetupCredential = $Node.InstallerServiceAccount
                InstanceName = "NULL"
                Features = "SSMS,ADV_SSMS"
            }
        }

        # Install SPF prerequisites
        if($SystemCenter2016ServiceProviderFoundationServers | Where-Object {$_ -eq $Node.NodeName})
        {
            if($Node.ASPNETMVC4)
            {
                $ASPNETMVC4 = (Join-Path -Path $Node.ASPNETMVC4 -ChildPath "AspNetMVC4Setup.exe")
            }
            else
            {
                $ASPNETMVC4 = "\Prerequisites\ASPNETMVC4\AspNetMVC4Setup.exe"
            }
            Package "ASPNETMVC4"
            {
                Ensure = "Present"
                Name = "Microsoft ASP.NET MVC 4 Runtime"
                ProductId = ""
                Path = (Join-Path -Path $Node.SourcePath -ChildPath $ASPNETMVC4)
                Arguments = "/q"
                PsDscRunAsCredential = $Node.InstallerServiceAccount
            }

            if($Node.WCFDataServices50)
            {
                $WCFDataServices50 = (Join-Path -Path $Node.WCFDataServices50 -ChildPath "WCFDataServices.exe")
            }
            else
            {
                $WCFDataServices50 = "\Prerequisites\WCF50\WCFDataServices.exe"
            }
            Package "WCFDataServices50"
            {
                Ensure = "Present"
                Name = "WCF Data Services 5.0 (for OData v3) Primary Components"
                ProductId = ""
                Path = (Join-Path -Path $Node.SourcePath -ChildPath $WCFDataServices50)
                Arguments = "/q"
                PsDscRunAsCredential = $Node.InstallerServiceAccount
            }

            xSCVMMConsoleSetup "VMMC"
            {
                Ensure = "Present"
                SourcePath = $Node.SourcePath
                SourceFolder = $Node.SCVMMSourcePath
                SetupCredential = $Node.InstallerServiceAccount
                IndigoTcpPort = $Node.SCVMMConsolePort
            }
        }

        # Create DependsOn for SPF Server
        $DependsOn = @(
            "[Package]ASPNETMVC4",
            "[Package]WCFDataServices50",
            "[xSCVMMConsoleSetup]VMMC"
        )

        # Install first Server
        if ($SystemCenter2016ServiceProviderFoundationServers[0] -eq $Node.NodeName)
        {
            <#
            # Wait for  SQL Server
            if ($SystemCenter2016ServiceProviderFoundationServers[0] -eq $SystemCenter2016ServiceProviderFoundationDatabaseServer)
            {
                $DependsOn += @(("[xSqlServerFirewall]" + $SystemCenter2016ServiceProviderFoundationDatabaseServer + $SystemCenter2016ServiceProviderFoundationDatabaseInstance))
            }
            else
            {
                WaitForAll "SPFDB"
                {
                    NodeName = $SystemCenter2016ServiceProviderFoundationDatabaseServer
                    ResourceName = ("[xSqlServerFirewall]" + $SystemCenter2016ServiceProviderFoundationDatabaseServer + $SystemCenter2016ServiceProviderFoundationDatabaseInstance)
                    PsDscRunAsCredential = $Node.InstallerServiceAccount
                    RetryCount = 720
                    RetryIntervalSec = 5
                }
                $DependsOn += @("[WaitForAll]SPFDB")
            }
            #>
            # Install first Web Service Server
            xSCSPFServerSetup "SPF"
            {
                DependsOn = $DependsOn
                Ensure = "Present"
                SourcePath = $Node.SourcePath
                SourceFolder = $Node.SourceFolder
                SetupCredential = $Node.InstallerServiceAccount
                DatabaseServer = $Node.DatabaseServer
                DatabaseName = $Node.DatabaseName
                DatabasePortNumber = $Node.DatabasePortNumber
                SCVMM = $Node.SCVMM
                SCAdmin = $Node.SCAdmin
                SCProvider = $Node.SCProvider
                SCUsage = $Node.SCUsage
                VMMSecurityGroupUsers = $Node.VMMSecurityGroupUsers
                AdminSecurityGroupUsers = $Node.AdminSecurityGroupUsers
                ProviderSecurityGroupUsers = $Node.ProviderSecurityGroupUsers
                UsageSecurityGroupUsers = $Node.UsageSecurityGroupUsers
                SpecifyCertificate = $Node.SpecifyCertificate
                CertificateName = $Node.CertificateName
                WebSitePortNumber = $Node.WebSitePortNumber

            }
        }

        # Wait for first server
        if(
            ($SystemCenter2016ServiceProviderFoundationServers | Where-Object {$_ -eq $Node.NodeName}) -and
            (!($SystemCenter2016ServiceProviderFoundationServers[0] -eq $Node.NodeName))
        )
        {
            WaitForAll "SPF"
            {
                NodeName = $SystemCenter2016ServiceProviderFoundationServers[0]
                ResourceName = "[xSCSPFServerSetup]SPF"
                RetryIntervalSec = 5
                RetryCount = 720
                PsDscRunAsCredential = $Node.InstallerServiceAccount
            }
            $DependsOn += @("[WaitForAll]SPF")
        }

        # Install additional servers
        if(
            ($SystemCenter2016ServiceProviderFoundationServers | Where-Object {$_ -eq $Node.NodeName}) -and
            (!($SystemCenter2016ServiceProviderFoundationServers[0] -eq $Node.NodeName))
        )
        {
            xSCSPFServerSetup "SPF"
            {
                DependsOn = $DependsOn
                Ensure = "Present"
                SourcePath = $Node.SourcePath
                SourceFolder = $Node.SourceFolder
                SetupCredential = $Node.InstallerServiceAccount
                DatabaseServer = $Node.DatabaseServer
                DatabaseName = $Node.DatabaseName
                DatabasePortNumber = $Node.DatabasePortNumber
                SCVMM = $Node.SCVMM
                SCAdmin = $Node.SCAdmin
                SCProvider = $Node.SCProvider
                SCUsage = $Node.SCUsage
                VMMSecurityGroupUsers = $Node.VMMSecurityGroupUsers
                AdminSecurityGroupUsers = $Node.AdminSecurityGroupUsers
                ProviderSecurityGroupUsers = $Node.ProviderSecurityGroupUsers
                UsageSecurityGroupUsers = $Node.UsageSecurityGroupUsers
                SpecifyCertificate = $Node.SpecifyCertificate
                CertificateName = $Node.CertificateName
                WebSitePortNumber = $Node.WebSitePortNumber
            }
        }
    }
}

# Copies all modules from the source server to the nodes targeted
foreach($Node in $ConfigurationData.AllNodes)
{
    if($Node.NodeName -ne "*")
    {
        Start-Process -FilePath "robocopy.exe" -ArgumentList ("`"C:\Program Files\WindowsPowerShell\Modules`" `"\\" + $Node.NodeName + "\c$\Program Files\WindowsPowerShell\Modules`" /e /purge /xf") -NoNewWindow -Wait
    }
}
Write-Host "Creating MOFs" -ForegroundColor Yellow
SPF -ConfigurationData $ConfigurationData
Write-Host "Running Config" -ForegroundColor Yellow
Start-DscConfiguration -Path .\SPF -Verbose -Wait -Force