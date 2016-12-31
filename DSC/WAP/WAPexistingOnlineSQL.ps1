#requires -Version 5
<#
Reqs :
    DNS records must be created before running scripts
    WMF 5.0 must be installed on all machines, even SQL
#>
$SecurePassword = ConvertTo-SecureString -String "********" -AsPlainText -Force
$InstallerServiceAccount = New-Object System.Management.Automation.PSCredential ("domain\!Installer", $SecurePassword)
$SecurePassword = ConvertTo-SecureString -String "********" -AsPlainText -Force
$SQLsaAccount = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ('sa', $SecurePassword)
# Passphrase needs to be at least 8 character long, and contain least one non-alphanumeric (+,%,!,etc).
$SecurePassword = ConvertTo-SecureString -String "********+" -AsPlainText -Force
$WAPpassphrase = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ('notrequired', $SecurePassword)
$SecurePassword = ConvertTo-SecureString -String "********" -AsPlainText -Force
$PFXPassword = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ('notrequired',$SecurePassword)
#$SecurePassword = ConvertTo-SecureString -String '********' -AsPlainText -Force
#$SQLServiceAccount = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ('SRV_MSSQL',$SecurePassword)

$ConfigurationData = @{
    AllNodes = @(
        @{
            NodeName                        = '*'
            PSDscAllowPlainTextPassword     = $true
            PSDscAllowDomainUser            = $true
            #SQLSourcePath                   = '\\SQL01\Software'
            #SQLSourceFolder                 = 'SQLServer2014'
            #SQLSysAdminAccounts             = '.\MSSQL_Administrators'
            SQLServer                       = "SQL01.domain.info"
            SQLInstance                     = "MSSQLSERVER"
            SourcePath                      = '\\SQL01.domain.info\Software'
            WAPSourceFolder                 = "\WAP2013"
            WindowsServer2012R2Source       = "\WindowsServer2012R2"
            InstallerServiceAccount         = $InstallerServiceAccount
            SAPassword                      = $SQLsaAccount
            AzurePackAdministratorsGroup    = 'domain\WAP_Administrators'
            WAPackPassphrase                =  $WAPpassphrase
            AzurePackTenantSiteFQDN         = 'portal.domain.info'
            AzurePackAdminSiteFQDN          = 'wapadmin.domain.info'
            AzurePackAuthSiteFQDN           = 'auth.domain.info'
            AzurePackWindowsAuthSiteFQDN    = 'adminauth.domain.info'
            AzurePackTenantAPIFQDN          = 'wapapi.domain.info'
            AzurePackAdminAPIFQDN           = 'wapadminapi.domain.info'
            AzurePackTenantPublicAPIFQDN    = 'pubapi.domain.info'
            AzurePackSQLServerExtensionFQDN = 'wapsql.domain.info'
            AzurePackMySQLExtensionFQDN     = 'wapmysql.domain.info'
            AzurePackAdminAPIPort           = 30004
            AzurePackTenantAPIPort          = 30005
            AzurePackTenantPublicAPIPort    = 30006
            AzurePackMarketplacePort        = 30018
            AzurePackMonitoringPort         = 30020
            AzurePackUsageServicePort       = 30022
            AzurePackSQLServerExtensionPort = 30010
            AzurePackMySQLExtensionPort     = 30012
            AzurePackAuthSitePort           = 30071
            AzurePackWindowsAuthSitePort    = 30072
            AzurePackTenantSitePort         = 443
            AzurePackAdminSitePort          = 443
            WAPCertificatelocation          = '\\SQL01\Software\WAP2013\Prerequisites\WAP.pfx'
            WAPCertificateThumbprint        = 'B9EBEF5A8E67B6BB335806E92A8680359CDF5E0F'
            WAPCertificatepassword          = $PFXPassword

        }
        # This is minimum configuration for server with only Admin portal
        # TODO: make forced dependency logic
        @{
            NodeName   = 'node01.domain.info'
            Roles      = @(
                'Windows Azure Pack 2013 Tenant API Server',
                'Windows Azure Pack 2013 Admin API Server',
                'Windows Azure Pack 2013 Admin Site Server',
                'Windows Azure Pack 2013 Admin Authentication Site Server'
            )
        }
        @{
            NodeName   = 'node02.domain.info'
            Roles      = @(
                'Windows Azure Pack 2013 Tenant API Server',
                'Windows Azure Pack 2013 Tenant Public API Server',
                'Windows Azure Pack 2013 Tenant Site Server',
                'Windows Azure Pack 2013 Tenant Authentication Site Server'
            )
        }
    )
}


Configuration WindowsAzurePack
{
    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName xSQLServer
    Import-DscResource -ModuleName xCredSSP
    Import-DscResource -ModuleName xWebAdministration
    Import-DscResource -ModuleName xCertificate
    Import-DscResource -ModuleName xAzurePack
    Import-DSCResource -Module xSystemSecurity -Name xIEEsc

    # Set role and instance variables
    $Roles = $AllNodes.Roles | Sort-Object -Unique
    foreach($Role in $Roles)
    {
        $Servers = @($AllNodes.Where{
                $_.Roles | Where-Object -FilterScript {
                    $_ -eq $Role
                }
        }.NodeName)
        Set-Variable -Name ($Role.Replace(' ','').Replace('.','') + 's') -Value $Servers
        if($Servers.Count -eq 1)
        {
            Set-Variable -Name ($Role.Replace(' ','').Replace('.','')) -Value $Servers[0]
            if(
                $Role.Contains('Database') -or
                $Role.Contains('Datawarehouse') -or
                $Role.Contains('Reporting') -or
                $Role.Contains('Analysis') -or
                $Role.Contains('Integration')
            )
            {
                $Instance = $AllNodes.Where{
                    $_.NodeName -eq $Servers[0]
                }.SQLServers.Where{
                    $_.Roles | Where-Object -FilterScript {
                        $_ -eq $Role
                    }
                }.InstanceName
                Set-Variable -Name ($Role.Replace(' ','').Replace('.','').Replace('Server','Instance')) -Value $Instance
            }
        }
    }

    Node $AllNodes.NodeName
    {
       # Disable for IE Enhanced Security
       xIEEsc DisableIEEsc
        {
            IsEnabled = $false
            UserRole = "Administrators"
        }
        <#
        # Enable CredSSP
        # Do NOT use if WinRM is set by GPO, will cause boot loop
        if(
            ($WindowsAzurePack2013AdminAPIServers | Where-Object -FilterScript {
                    $_ -eq $Node.NodeName
            }) -or
            ($WindowsAzurePack2013TenantAPIServers | Where-Object -FilterScript {
                    $_ -eq $Node.NodeName
            }) -or
            ($WindowsAzurePack2013TenantPublicAPIServers | Where-Object -FilterScript {
                    $_ -eq $Node.NodeName
            }) -or
            ($WindowsAzurePack2013SQLServerExtensionServers | Where-Object -FilterScript {
                    $_ -eq $Node.NodeName
            }) -or
            ($WindowsAzurePack2013MySQLExtensionServers | Where-Object -FilterScript {
                    $_ -eq $Node.NodeName
            }) -or
            ($WindowsAzurePack2013AdminSiteServers | Where-Object -FilterScript {
                    $_ -eq $Node.NodeName
            }) -or
            ($WindowsAzurePack2013AdminAuthenticationServers | Where-Object -FilterScript {
                    $_ -eq $Node.NodeName
            }) -or
            ($WindowsAzurePack2013TenantSiteServers | Where-Object -FilterScript {
                    $_ -eq $Node.NodeName
            }) -or
            ($WindowsAzurePack2013TenantAuthenticationSiteServers | Where-Object -FilterScript {
                    $_ -eq $Node.NodeName
            })
        )
        {
            xCredSSP 'Server'
            {
                Ensure = 'Present'
                Role = 'Server'
            }

            xCredSSP 'Client'
            {
                Ensure = 'Present'
                Role = 'Client'
                DelegateComputers = $Node.NodeName
            }
        }
        #>
        # Install .NET Frameworks
        if(
            ($WindowsAzurePack2013DatabaseServer -eq $Node.NodeName) -or
            ($WindowsAzurePack2013AdminAPIServers | Where-Object -FilterScript {
                    $_ -eq $Node.NodeName
            }) -or
            ($WindowsAzurePack2013TenantAPIServers | Where-Object -FilterScript {
                    $_ -eq $Node.NodeName
            }) -or
            ($WindowsAzurePack2013TenantPublicAPIServers | Where-Object -FilterScript {
                    $_ -eq $Node.NodeName
            }) -or
            ($WindowsAzurePack2013SQLServerExtensionServers | Where-Object -FilterScript {
                    $_ -eq $Node.NodeName
            }) -or
            ($WindowsAzurePack2013MySQLExtensionServers | Where-Object -FilterScript {
                    $_ -eq $Node.NodeName
            }) -or
            ($WindowsAzurePack2013AdminSiteServers | Where-Object -FilterScript {
                    $_ -eq $Node.NodeName
            }) -or
            ($WindowsAzurePack2013AdminAuthenticationServers | Where-Object -FilterScript {
                    $_ -eq $Node.NodeName
            }) -or
            ($WindowsAzurePack2013TenantSiteServers | Where-Object -FilterScript {
                    $_ -eq $Node.NodeName
            }) -or
            ($WindowsAzurePack2013TenantAuthenticationSiteServers | Where-Object -FilterScript {
                    $_ -eq $Node.NodeName
            }) -or
            ($SQLServer2014ManagementTools | Where-Object -FilterScript {
                    $_ -eq $Node.NodeName
            })
        )
        {
            if($Node.WindowsServer2012R2Source)
            {
                $WindowsServer2012R2Source = (Join-Path -Path $Node.WindowsServer2012R2Source -ChildPath "\sources\sxs")
            }
            else
            {
                $WindowsServer2012R2Source = "\WindowsServer2012R2\sources\sxs"
            }
            WindowsFeature "NET-Framework-Core"
            {
                Ensure = "Present" # To uninstall the role, set Ensure to "Absent"
                Name = "NET-Framework-Core"
                Source = $Node.SourcePath + $WindowsServer2012R2Source
                DependsOn = "[WindowsFeature]NET-Framework-Features"
            }
            WindowsFeature "NET-Framework-Features"
            {
                Ensure = "Present" # To uninstall the role, set Ensure to "Absent"
                Name = "NET-Framework-Features"
                Source = $Node.SourcePath + $WindowsServer2012R2Source
            }
            WindowsFeature "NET-Framework-45-Features"
            {
                Ensure = "Present" # To uninstall the role, set Ensure to "Absent"
                Name = "NET-Framework-45-Features"
            }
            WindowsFeature "NET-Framework-45-Core"
            {
                Ensure = "Present" # To uninstall the role, set Ensure to "Absent"
                Name = "NET-Framework-45-Core"
                DependsOn = "[WindowsFeature]NET-Framework-45-Features"
            }
        }

        # Install IIS
        if(
            ($WindowsAzurePack2013AdminAPIServers | Where-Object -FilterScript {
                    $_ -eq $Node.NodeName
            }) -or
            ($WindowsAzurePack2013TenantAPIServers | Where-Object -FilterScript {
                    $_ -eq $Node.NodeName
            }) -or
            ($WindowsAzurePack2013TenantPublicAPIServers | Where-Object -FilterScript {
                    $_ -eq $Node.NodeName
            }) -or
            ($WindowsAzurePack2013SQLServerExtensionServers | Where-Object -FilterScript {
                    $_ -eq $Node.NodeName
            }) -or
            ($WindowsAzurePack2013MySQLExtensionServers | Where-Object -FilterScript {
                    $_ -eq $Node.NodeName
            }) -or
            ($WindowsAzurePack2013AdminSiteServers | Where-Object -FilterScript {
                    $_ -eq $Node.NodeName
            }) -or
            ($WindowsAzurePack2013AdminAuthenticationServers | Where-Object -FilterScript {
                    $_ -eq $Node.NodeName
            }) -or
            ($WindowsAzurePack2013TenantSiteServers | Where-Object -FilterScript {
                    $_ -eq $Node.NodeName
            }) -or
            ($WindowsAzurePack2013TenantAuthenticationSiteServers | Where-Object -FilterScript {
                    $_ -eq $Node.NodeName
            })
        )
        {
            WindowsFeature 'Web-WebServer'
            {
                Ensure = 'Present'
                Name = 'Web-WebServer'
            }

            WindowsFeature 'Web-Default-Doc'
            {
                Ensure = 'Present'
                Name = 'Web-Default-Doc'
                DependsOn = "[WindowsFeature]Web-WebServer"
            }

            WindowsFeature 'Web-Static-Content'
            {
                Ensure = 'Present'
                Name = 'Web-Static-Content'
                DependsOn = "[WindowsFeature]Web-WebServer"
            }

            WindowsFeature 'Web-Stat-Compression'
            {
                Ensure = 'Present'
                Name = 'Web-Stat-Compression'
                DependsOn = "[WindowsFeature]Web-WebServer"
            }

            WindowsFeature 'Web-Filtering'
            {
                Ensure = 'Present'
                Name = 'Web-Filtering'
                DependsOn = "[WindowsFeature]Web-WebServer"
            }

            WindowsFeature 'Web-Dyn-Compression'
            {
                Ensure = 'Present'
                Name = 'Web-Dyn-Compression'
                DependsOn = "[WindowsFeature]Web-WebServer"
            }

            WindowsFeature 'Web-Windows-Auth'
            {
                Ensure = 'Present'
                Name = 'Web-Windows-Auth'
                DependsOn = "[WindowsFeature]Web-WebServer"
            }

            WindowsFeature 'NET-Framework-45-ASPNET'
            {
                Ensure = 'Present'
                Name = 'NET-Framework-45-ASPNET'
                DependsOn = "[WindowsFeature]NET-Framework-45-Features"
            }

            WindowsFeature 'Web-Net-Ext45'
            {
                Ensure = 'Present'
                Name = 'Web-Net-Ext45'
            }

            WindowsFeature 'Web-ISAPI-Ext'
            {
                Ensure = 'Present'
                Name = 'Web-ISAPI-Ext'
            }

            WindowsFeature 'Web-ISAPI-Filter'
            {
                Ensure = 'Present'
                Name = 'Web-ISAPI-Filter'
                DependsOn = "[WindowsFeature]Web-WebServer"
            }

            WindowsFeature 'Web-Asp-Net45'
            {
                Ensure = 'Present'
                Name = 'Web-Asp-Net45'
            }

            WindowsFeature 'Web-Metabase'
            {
                Ensure = 'Present'
                Name = 'Web-Metabase'
                DependsOn = "[WindowsFeature]Web-WebServer"
            }

            WindowsFeature 'PowerShell'
            {
                Ensure = 'Present'
                Name = 'PowerShell'
            }

            WindowsFeature 'PowerShell-V2'
            {
                Ensure = 'Present'
                Name = 'PowerShell-V2'
            }

            WindowsFeature 'WAS-Process-Model'
            {
                Ensure = 'Present'
                Name = 'WAS-Process-Model'
            }

            WindowsFeature 'WAS-NET-Environment'
            {
                Ensure = 'Present'
                Name = 'WAS-NET-Environment'
            }
            WindowsFeature 'WAS-Config-APIs'
            {
                Ensure = 'Present'
                Name = 'WAS-Config-APIs'
            }

        }
        if(
            ($WindowsAzurePack2013AdminSiteServers | Where-Object -FilterScript {
                    $_ -eq $Node.NodeName
            }) -or
            ($WindowsAzurePack2013AdminAuthenticationServers | Where-Object -FilterScript {
                    $_ -eq $Node.NodeName
            }) -or
            ($WindowsAzurePack2013TenantSiteServers | Where-Object -FilterScript {
                    $_ -eq $Node.NodeName
            }) -or
            ($WindowsAzurePack2013TenantAuthenticationSiteServers | Where-Object -FilterScript {
                    $_ -eq $Node.NodeName
            })
        )
        {
            WindowsFeature 'Web-Mgmt-Console'
            {
                Ensure = "Present"
                Name = "Web-Mgmt-Console"
                DependsOn = "[WindowsFeature]Web-WebServer"
            }
        }
        if(
            ($WindowsAzurePack2013TenantSiteServers | Where-Object -FilterScript {
                    $_ -eq $Node.NodeName
            })
        )
        {
            WindowsFeature 'Web-Basic-Auth'
            {
                Ensure = 'Present'
                Name = 'Web-Basic-Auth'
            }
        }
        <#
        # Install SQL Instances
        if(
            ($WindowsAzurePack2013DatabaseServer -eq $Node.NodeName)
        )
        {
            foreach($SQLServer in $Node.SQLServers)
            {
                $SQLInstanceName = $SQLServer.InstanceName

                $Features = ""
                if(
                    (
                        ($WindowsAzurePack2013DatabaseServer -eq $Node.NodeName) -and
                        ($WindowsAzurePack2013DatabaseInstance -eq $SQLInstanceName)
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
        # Install ASP.NET Web Pages 2 and ASP.NET MVC 4
        if(
            ($WindowsAzurePack2013AdminAPIServers | Where-Object -FilterScript {
                    $_ -eq $Node.NodeName
            }) -or
            ($WindowsAzurePack2013TenantAPIServers | Where-Object -FilterScript {
                    $_ -eq $Node.NodeName
            }) -or
            ($WindowsAzurePack2013TenantPublicAPIServers | Where-Object -FilterScript {
                    $_ -eq $Node.NodeName
            }) -or
            ($WindowsAzurePack2013SQLServerExtensionServers | Where-Object -FilterScript {
                    $_ -eq $Node.NodeName
            }) -or
            ($WindowsAzurePack2013MySQLExtensionServers | Where-Object -FilterScript {
                    $_ -eq $Node.NodeName
            }) -or
            ($WindowsAzurePack2013AdminSiteServers | Where-Object -FilterScript {
                    $_ -eq $Node.NodeName
            }) -or
            ($WindowsAzurePack2013AdminAuthenticationServers | Where-Object -FilterScript {
                    $_ -eq $Node.NodeName
            }) -or
            ($WindowsAzurePack2013TenantSiteServers | Where-Object -FilterScript {
                    $_ -eq $Node.NodeName
            }) -or
            ($WindowsAzurePack2013TenantAuthenticationSiteServers | Where-Object -FilterScript {
                    $_ -eq $Node.NodeName
            })
        )
        {
            # Install ASP.NET Web Pages 2
            # Create ASPNETWebPages2 under ConfigurationData to set custom path for this prereq
            if($Node.ASPNETWebPages2)
            {
                $ASPNETWebPages2 = (Join-Path -Path $Node.ASPNETWebPages2 -ChildPath "AspNetWebPages2Setup.exe")
            }
            else
            {
                $ASPNETWebPages2 = "\Prerequisites\ASPNETWebPages2\AspNetWebPages2Setup.exe"
            }

            Package 'ASPNETWebPages2'
            {
                Ensure = 'Present'
                Name = 'Microsoft ASP.NET Web Pages 2 Runtime'
                ProductId = ''
                Path = (Join-Path -Path $Node.SourcePath -ChildPath $ASPNETWebPages2)
                Arguments = '/q'
                Credential = $Node.InstallerServiceAccount
            }

            # Install ASP.NET MVC 4
            # Create ASPNETMVC4 under ConfigurationData to set custom path for this prereq
            if($Node.ASPNETMVC4)
            {
                $ASPNETMVC4 = (Join-Path -Path $Node.ASPNETMVC4 -ChildPath "AspNetMVC4Setup.exe")
            }
            else
            {
                $ASPNETMVC4 = "\Prerequisites\ASPNETMVC4\AspNetMVC4Setup.exe"
            }
            Package 'ASPNETMVC4'
            {
                Ensure = 'Present'
                Name = 'Microsoft ASP.NET MVC 4 Runtime'
                ProductId = ''
                Path = (Join-Path -Path $Node.SourcePath -ChildPath $ASPNETMVC4)
                Arguments = '/q'
                Credential = $Node.InstallerServiceAccount
            }
        }

        # Install MySQL Connector Net 6.5.4
        # Create MySQLConnectorNet699 under ConfigurationData to set custom path for this prereq
        if(
            ($WindowsAzurePack2013MySQLExtensionServers | Where-Object -FilterScript {
                    $_ -eq $Node.NodeName
            })
        )
        {
            # Install MySQL Connector Net 6.9.9
            # Create MySQLConnectorNet699 under ConfigurationData to set custom path for this prereq
            if($Node.MySQLConnectorNet699)
            {
                $MySQLConnectorNet699 = (Join-Path -Path $Node.MySQLConnectorNet699 -ChildPath "mysql-connector-net-6.9.9.msi")
            }
            else
            {
                $MySQLConnectorNet699 = "\Prerequisites\MySQLConnectorNet699\mysql-connector-net-6.9.9.msi"
            }

            Package 'MySQLConnectorNet699'
            {
                Ensure = 'Present'
                Name = 'MySQL Connector Net 6.9.9'
                ProductId = ''
                Path = (Join-Path -Path $Node.SourcePath -ChildPath $MySQLConnectorNet699)
                Arguments = 'ALLUSERS=2'
                Credential = $Node.InstallerServiceAccount
            }
        }

        # Install URL Rewrite 2
        # Create URLRewrite2 under ConfigurationData to set custom path for this prereq
        if(
            ($WindowsAzurePack2013AdminSiteServers | Where-Object -FilterScript {
                    $_ -eq $Node.NodeName
            }) -or
            ($WindowsAzurePack2013AdminAuthenticationServers | Where-Object -FilterScript {
                    $_ -eq $Node.NodeName
            }) -or
            ($WindowsAzurePack2013TenantSiteServers | Where-Object -FilterScript {
                    $_ -eq $Node.NodeName
            }) -or
            ($WindowsAzurePack2013TenantAuthenticationSiteServers | Where-Object -FilterScript {
                    $_ -eq $Node.NodeName
            })
        )
        {
            # Install URL Rewrite 2
            # Create URLRewrite2 under ConfigurationData to set custom path for this prereq
            if($Node.URLRewrite2)
            {
                $URLRewrite2 = (Join-Path -Path $Node.URLRewrite2 -ChildPath "rewrite_amd64_en-US.msi")
            }
            else
            {
                $URLRewrite2 = "\Prerequisites\URLRewrite2\rewrite_amd64_en-US.msi"
            }
            Package 'URLRewrite2'
            {
                Ensure = 'Present'
                Name = 'IIS URL Rewrite Module 2'
                ProductId = ''
                Path = (Join-Path -Path $Node.SourcePath -ChildPath $URLRewrite2)
                Arguments = 'ALLUSERS=2'
                Credential = $Node.InstallerServiceAccount
            }
        }

        # Install and initialize Azure Pack Admin API
        if(
            ($WindowsAzurePack2013AdminAPIServers | Where-Object -FilterScript {
                    $_ -eq $Node.NodeName
            })
        )
        {
            xAzurePackSetup 'AdminAPIInstall'
            {
                Role = 'Admin API'
                Action = 'Install'
                SourcePath = $Node.SourcePath
                SourceFolder = $Node.WAPSourceFolder
                SetupCredential = $Node.InstallerServiceAccount
                Passphrase = $Node.WAPackPassphrase
            }

            $DependsOn = @()

            if(
                ($WindowsAzurePack2013AdminAPIServers[0] -eq $Node.NodeName)
            )
            {
                # Assumes SQL is online
                <#
                # Wait for Azure Pack Database Server
                if ($WindowsAzurePack2013AdminAPIServers[0] -eq $WindowsAzurePack2013DatabaseServer)
                {
                    $DependsOn = @(('[cSqlServerFirewall]' + $WindowsAzurePack2013DatabaseServer + $WindowsAzurePack2013DatabaseInstance))
                }
                else
                {
                    WaitForAll 'WAPDB'
                    {
                        NodeName = $WindowsAzurePack2013DatabaseServer
                        ResourceName = ('[cSqlServerFirewall]' + $WindowsAzurePack2013DatabaseServer + $WindowsAzurePack2013DatabaseInstance)
                        PsDscRunAsCredential = $Node.InstallerServiceAccount
                        RetryCount = 720
                        RetryIntervalSec = 20
                    }
                    $DependsOn = @('[WaitForAll]WAPDB')
                }
                #>
                $DependsOn += @(
                    '[xAzurePackSetup]AdminAPIInstall'
                )

                xAzurePackSetup 'AdminAPIInitialize'
                {
                    DependsOn = $DependsOn
                    Role = 'Admin API'
                    Action = 'Initialize'
                    dbUser = $Node.SAPassword
                    SourcePath = $Node.SourcePath
                    SourceFolder = $Node.WAPSourceFolder
                    SetupCredential = $Node.InstallerServiceAccount
                    Passphrase = $Node.WAPackPassphrase
                    SQLServer = $Node.SQLServer
                    SQLInstance = $Node.SQLInstance
                }

                if($Node.AzurePackAdminAPIFQDN)
                {
                    if ($Node.AzurePackAdminAPIPort)
                    {
                        $AzurePackAdminAPIPort = $Node.AzurePackAdminAPIPort
                    }
                    else
                    {
                        $AzurePackAdminAPIPort = 30004
                    }

                    xAzurePackDatabaseSetting 'AntaresGeoMasterUri'
                    {
                        DependsOn = '[xAzurePackSetup]AdminAPIInitialize'
                        Namespace = 'AdminSite'
                        Name = 'Microsoft.Azure.Portal.Configuration.AppManagementConfiguration.AntaresGeoMasterUri'
                        Value = ('https://' + $Node.AzurePackAdminAPIFQDN + ':' + $AzurePackAdminAPIPort + '/services/webspaces/')
                        AzurePackAdminCredential = $Node.InstallerServiceAccount
                        SQLServer = $Node.SQLServer
                        SQLInstance = $Node.SQLInstance
                        dbUser = $Node.SAPassword
                    }

                    xAzurePackDatabaseSetting 'RdfeAdminManagementServiceUri'
                    {
                        DependsOn = '[xAzurePackSetup]AdminAPIInitialize'
                        Namespace = 'AdminSite'
                        Name = 'Microsoft.Azure.Portal.Configuration.AppManagementConfiguration.RdfeAdminManagementServiceUri'
                        Value = ('https://' + $Node.AzurePackAdminAPIFQDN + ':' + $AzurePackAdminAPIPort + '/')
                        AzurePackAdminCredential = $Node.InstallerServiceAccount
                        SQLServer = $Node.SQLServer
                        SQLInstance = $Node.SQLInstance
                        dbUser = $Node.SAPassword
                    }

                    xAzurePackDatabaseSetting 'RdfeAdminUri'
                    {
                        DependsOn = '[xAzurePackSetup]AdminAPIInitialize'
                        Namespace = 'AdminSite'
                        Name = 'Microsoft.Azure.Portal.Configuration.OnPremPortalConfiguration.RdfeAdminUri'
                        Value = ('https://' + $Node.AzurePackAdminAPIFQDN + ':' + $AzurePackAdminAPIPort + '/')
                        AzurePackAdminCredential = $Node.InstallerServiceAccount
                        SQLServer = $Node.SQLServer
                        SQLInstance = $Node.SQLInstance
                        dbUser = $Node.SAPassword
                    }

                    xAzurePackDatabaseSetting 'RdfeProvisioningUri'
                    {
                        DependsOn = '[xAzurePackSetup]AdminAPIInitialize'
                        Namespace = 'AdminSite'
                        Name = 'Microsoft.Azure.Portal.Configuration.OnPremPortalConfiguration.RdfeProvisioningUri'
                        Value = ('https://' + $Node.AzurePackAdminAPIFQDN + ':' + $AzurePackAdminAPIPort + '/')
                        AzurePackAdminCredential = $Node.InstallerServiceAccount
                        SQLServer = $Node.SQLServer
                        SQLInstance = $Node.SQLInstance
                        dbUser = $Node.SAPassword
                    }
                }
            }
            else
            {
                WaitForAll 'AdminAPIInitialize'
                {
                    NodeName = $WindowsAzurePack2013AdminAPIServers[0]
                    ResourceName = '[xAzurePackSetup]AdminAPIInitialize'
                    PsDscRunAsCredential = $Node.InstallerServiceAccount
                    RetryCount = 720
                    RetryIntervalSec = 20
                }

                xAzurePackSetup 'AdminAPIInitialize'
                {
                    DependsOn = @(
                        '[xAzurePackSetup]AdminAPIInstall',
                        '[WaitForAll]AdminAPIInitialize'
                    )
                    Role = 'Admin API'
                    Action = 'Initialize'
                    dbUser = $Node.SAPassword
                    SourcePath = $Node.SourcePath
                    SourceFolder = $Node.WAPSourceFolder
                    SetupCredential = $Node.InstallerServiceAccount
                    Passphrase = $Node.WAPackPassphrase
                    SQLServer = $Node.SQLServer
                    SQLInstance = $Node.SQLInstance
                }
            }

            if($Node.AzurePackAdministratorsGroup)
            {
                xAzurePackAdmin 'WAPAdministrators'
                {
                    DependsOn = '[xAzurePackSetup]AdminAPIInitialize'
                    Principal = $Node.AzurePackAdministratorsGroup
                    AzurePackAdminCredential = $Node.InstallerServiceAccount
                    SQLServer = $Node.SQLServer
                    SQLInstance = $Node.SQLInstance
                    dbUser = $Node.SAPassword
                }
            }

        }

        # Install and initialize Azure Pack Tenant API
        if(
            ($WindowsAzurePack2013TenantAPIServers | Where-Object -FilterScript {
                    $_ -eq $Node.NodeName
            })
        )
        {
            xAzurePackSetup 'TenantAPIInstall'
            {
                Role = 'Tenant API'
                Action = 'Install'
                SourcePath = $Node.SourcePath
                SourceFolder = $Node.WAPSourceFolder
                SetupCredential = $Node.InstallerServiceAccount
                Passphrase = $Node.WAPackPassphrase
            }

            $DependsOn = @()

            if(
                ($WindowsAzurePack2013TenantAPIServers[0] -eq $Node.NodeName)
            )
            {
                # Wait for Admin API
                if ($WindowsAzurePack2013TenantAPIServers[0] -eq $WindowsAzurePack2013AdminAPIServers[0])
                {
                    $DependsOn = @('[xAzurePackSetup]AdminAPIInitialize')
                }
                else
                {
                    WaitForAll 'AdminAPI'
                    {
                        NodeName = $WindowsAzurePack2013AdminAPIServers[0]
                        ResourceName = ('[xAzurePackSetup]AdminAPIInitialize')
                        PsDscRunAsCredential = $Node.InstallerServiceAccount
                        RetryCount = 720
                        RetryIntervalSec = 20
                    }
                    $DependsOn = @('[WaitForAll]AdminAPI')
                }

                $DependsOn += @(
                    '[xAzurePackSetup]TenantAPIInstall'
                )

                xAzurePackSetup 'TenantAPIInitialize'
                {
                    DependsOn = $DependsOn
                    Role = 'Tenant API'
                    Action = 'Initialize'
                    dbUser = $Node.SAPassword
                    SourcePath = $Node.SourcePath
                    SourceFolder = $Node.WAPSourceFolder
                    SetupCredential = $Node.InstallerServiceAccount
                    Passphrase = $Node.WAPackPassphrase
                    SQLServer = $Node.SQLServer
                    SQLInstance = $Node.SQLInstance
                }

                if($Node.AzurePackTenantAPIFQDN)
                {
                    if ($Node.AzurePackTenantAPIPort)
                    {
                        $AzurePackTenantAPIPort = $Node.AzurePackTenantAPIPort
                    }
                    else
                    {
                        $AzurePackTenantAPIPort = 30005
                    }

                    xAzurePackDatabaseSetting 'AdminSite-RdfeUnifiedManagementServiceUri'
                    {
                        DependsOn = '[xAzurePackSetup]TenantAPIInitialize'
                        Namespace = 'AdminSite'
                        Name = 'Microsoft.Azure.Portal.Configuration.AppManagementConfiguration.RdfeUnifiedManagementServiceUri'
                        Value = ('https://' + $Node.AzurePackTenantAPIFQDN + ':' + $AzurePackTenantAPIPort + '/')
                        AzurePackAdminCredential = $Node.InstallerServiceAccount
                        SQLServer = $Node.SQLServer
                        SQLInstance = $Node.SQLInstance
                        dbUser = $Node.SAPassword
                    }

                    xAzurePackDatabaseSetting 'TenantSite-RdfeUnifiedManagementServiceUri'
                    {
                        DependsOn = '[xAzurePackSetup]TenantAPIInitialize'
                        Namespace = 'TenantSite'
                        Name = 'Microsoft.Azure.Portal.Configuration.AppManagementConfiguration.RdfeUnifiedManagementServiceUri'
                        Value = ('https://' + $Node.AzurePackTenantAPIFQDN + ':' + $AzurePackTenantAPIPort + '/')
                        AzurePackAdminCredential = $Node.InstallerServiceAccount
                        SQLServer = $Node.SQLServer
                        SQLInstance = $Node.SQLInstance
                        dbUser = $Node.SAPassword
                    }
                }
            }
            else
            {
                WaitForAll 'TenantAPIInitialize'
                {
                    NodeName = $WindowsAzurePack2013TenantAPIServers[0]
                    ResourceName = '[xAzurePackSetup]TenantAPIInitialize'
                    PsDscRunAsCredential = $Node.InstallerServiceAccount
                    RetryCount = 720
                    RetryIntervalSec = 20
                }

                xAzurePackSetup 'TenantAPIInitialize'
                {
                    DependsOn = @(
                        '[xAzurePackSetup]TenantAPIInstall',
                        '[WaitForAll]TenantAPIInitialize'
                    )
                    Role = 'Tenant API'
                    Action = 'Initialize'
                    dbUser = $Node.SAPassword
                    SourcePath = $Node.SourcePath
                    SourceFolder = $Node.WAPSourceFolder
                    SetupCredential = $Node.InstallerServiceAccount
                    Passphrase = $Node.WAPackPassphrase
                    SQLServer = $Node.SQLServer
                    SQLInstance = $Node.SQLInstance
                }
            }
        }

        # Install and initialize Azure Pack Tenant Public API
        if(
            ($WindowsAzurePack2013TenantPublicAPIServers | Where-Object -FilterScript {
                    $_ -eq $Node.NodeName
            })
        )
        {
            xAzurePackSetup 'TenantPublicAPIInstall'
            {
                Role = 'Tenant Public API'
                Action = 'Install'
                SourcePath = $Node.SourcePath
                SourceFolder = $Node.WAPSourceFolder
                SetupCredential = $Node.InstallerServiceAccount
                Passphrase = $Node.WAPackPassphrase
            }

            $DependsOn = @()

            if(
                ($WindowsAzurePack2013TenantPublicAPIServers[0] -eq $Node.NodeName)
            )
            {
                # Wait for Tenant API
                if ($WindowsAzurePack2013TenantPublicAPIServers[0] -eq $WindowsAzurePack2013TenantAPIServers[0])
                {
                    $DependsOn = @('[xAzurePackSetup]TenantAPIInitialize')
                }
                else
                {
                    WaitForAll 'TenantAPI'
                    {
                        NodeName = $WindowsAzurePack2013TenantAPIServers[0]
                        ResourceName = ('[xAzurePackSetup]TenantAPIInitialize')
                        PsDscRunAsCredential = $Node.InstallerServiceAccount
                        RetryCount = 720
                        RetryIntervalSec = 20
                    }
                    $DependsOn = @('[WaitForAll]TenantAPI')
                }

                $DependsOn += @(
                    '[xAzurePackSetup]TenantPublicAPIInstall'
                )

                xAzurePackSetup 'TenantPublicAPIInitialize'
                {
                    DependsOn = $DependsOn
                    Role = 'Tenant Public API'
                    Action = 'Initialize'
                    dbUser = $Node.SAPassword
                    SourcePath = $Node.SourcePath
                    SourceFolder = $Node.WAPSourceFolder
                    SetupCredential = $Node.InstallerServiceAccount
                    Passphrase = $Node.WAPackPassphrase
                    SQLServer = $Node.SQLServer
                    SQLInstance = $Node.SQLInstance
                }

                if($Node.AzurePackTenantPublicAPIFQDN)
                {
                    if ($Node.AzurePackTenantPublicAPIPort)
                    {
                        $AzurePackTenantPublicAPIPort = $Node.AzurePackTenantPublicAPIPort
                    }
                    else
                    {
                        $AzurePackTenantPublicAPIPort = 30006
                    }

                    xAzurePackDatabaseSetting 'PublicRdfeProvisioningUri'
                    {
                        DependsOn = '[xAzurePackSetup]TenantPublicAPIInitialize'
                        Namespace = 'TenantSite'
                        Name = 'Microsoft.WindowsAzure.Server.Configuration.TenantPortalConfiguration.PublicRdfeProvisioningUri'
                        Value = ('https://' + $Node.AzurePackTenantPublicAPIFQDN + ':' + $AzurePackTenantPublicAPIPort + '/')
                        AzurePackAdminCredential = $Node.InstallerServiceAccount
                        SQLServer = $Node.SQLServer
                        SQLInstance = $Node.SQLInstance
                        dbUser = $Node.SAPassword
                    }
                }
            }
            else
            {
                WaitForAll 'TenantPublicAPIInitialize'
                {
                    NodeName = $WindowsAzurePack2013TenantPublicAPIServers[0]
                    ResourceName = '[xAzurePackSetup]TenantPublicAPIInitialize'
                    PsDscRunAsCredential = $Node.InstallerServiceAccount
                    RetryCount = 720
                    RetryIntervalSec = 20
                }

                xAzurePackSetup 'TenantPublicAPIInitialize'
                {
                    DependsOn = @(
                        '[xAzurePackSetup]TenantPublicAPIInstall',
                        '[WaitForAll]TenantPublicAPIInitialize'
                    )
                    Role = 'Tenant Public API'
                    Action = 'Initialize'
                    dbUser = $Node.SAPassword
                    SourcePath = $Node.SourcePath
                    SourceFolder = $Node.WAPSourceFolder
                    SetupCredential = $Node.InstallerServiceAccount
                    Passphrase = $Node.WAPackPassphrase
                    SQLServer = $Node.SQLServer
                    SQLInstance = $Node.SQLInstance
                }
            }
        }

        # Install and initialize Azure Pack SQL Server Extension
        if(
            ($WindowsAzurePack2013SQLServerExtensionServers | Where-Object -FilterScript {
                    $_ -eq $Node.NodeName
            })
        )
        {
            xAzurePackSetup 'SQLServerExtensionInstall'
            {
                Role = 'SQL Server Extension'
                Action = 'Install'
                SourcePath = $Node.SourcePath
                SourceFolder = $Node.WAPSourceFolder
                SetupCredential = $Node.InstallerServiceAccount
                Passphrase = $Node.WAPackPassphrase
            }

            $DependsOn = @()

            if(
                ($WindowsAzurePack2013SQLServerExtensionServers[0] -eq $Node.NodeName)
            )
            {
                # Wait for Admin API
                if ($WindowsAzurePack2013SQLServerExtensionServers[0] -eq $WindowsAzurePack2013AdminAPIServers[0])
                {
                    $DependsOn = @('[xAzurePackSetup]AdminAPIInitialize')
                }
                else
                {
                    WaitForAll 'AdminAPI'
                    {
                        NodeName = $WindowsAzurePack2013AdminAPIServers[0]
                        ResourceName = ('[xAzurePackSetup]AdminAPIInitialize')
                        PsDscRunAsCredential = $Node.InstallerServiceAccount
                        RetryCount = 720
                        RetryIntervalSec = 20
                    }
                    $DependsOn = @('[WaitForAll]AdminAPI')
                }

                $DependsOn += @(
                    '[xAzurePackSetup]SQLServerExtensionInstall'
                )

                xAzurePackSetup 'SQLServerExtensionInitialize'
                {
                    DependsOn = $DependsOn
                    Role = 'SQL Server Extension'
                    Action = 'Initialize'
                    dbUser = $Node.SAPassword
                    SourcePath = $Node.SourcePath
                    SourceFolder = $Node.WAPSourceFolder
                    SetupCredential = $Node.InstallerServiceAccount
                    Passphrase = $Node.WAPackPassphrase
                    SQLServer = $Node.SQLServer
                    SQLInstance = $Node.SQLInstance
                }
            }
            else
            {
                WaitForAll 'SQLServerExtensionInitialize'
                {
                    NodeName = $WindowsAzurePack2013SQLServerExtensionServers[0]
                    ResourceName = '[xAzurePackSetup]SQLServerExtensionInitialize'
                    PsDscRunAsCredential = $Node.InstallerServiceAccount
                    RetryCount = 720
                    RetryIntervalSec = 20
                }

                xAzurePackSetup 'SQLServerExtensionInitialize'
                {
                    DependsOn = @(
                        '[xAzurePackSetup]SQLServerExtensionInstall',
                        '[WaitForAll]SQLServerExtensionInitialize'
                    )
                    Role = 'SQL Server Extension'
                    Action = 'Initialize'
                    dbUser = $Node.SAPassword
                    SourcePath = $Node.SourcePath
                    SourceFolder = $Node.WAPSourceFolder
                    SetupCredential = $Node.InstallerServiceAccount
                    Passphrase = $Node.WAPackPassphrase
                    SQLServer = $Node.SQLServer
                    SQLInstance = $Node.SQLInstance
                }
            }
        }

        # Install and initialize Azure Pack MySQL Extension
        if(
            ($WindowsAzurePack2013MySQLExtensionServers | Where-Object -FilterScript {
                    $_ -eq $Node.NodeName
            })
        )
        {
            xAzurePackSetup 'MySQLExtensionInstall'
            {
                Role = 'MySQL Extension'
                Action = 'Install'
                SourcePath = $Node.SourcePath
                SourceFolder = $Node.WAPSourceFolder
                SetupCredential = $Node.InstallerServiceAccount
                Passphrase = $Node.WAPackPassphrase
            }

            $DependsOn = @()

            if(
                ($WindowsAzurePack2013MySQLExtensionServers[0] -eq $Node.NodeName)
            )
            {
                # Wait for Admin API
                if ($WindowsAzurePack2013MySQLExtensionServers[0] -eq $WindowsAzurePack2013AdminAPIServers[0])
                {
                    $DependsOn = @('[xAzurePackSetup]AdminAPIInitialize')
                }
                else
                {
                    WaitForAll 'AdminAPI'
                    {
                        NodeName = $WindowsAzurePack2013AdminAPIServers[0]
                        ResourceName = ('[xAzurePackSetup]AdminAPIInitialize')
                        PsDscRunAsCredential = $Node.InstallerServiceAccount
                        RetryCount = 720
                        RetryIntervalSec = 20
                    }
                    $DependsOn = @('[WaitForAll]AdminAPI')
                }

                $DependsOn += @(
                    '[xAzurePackSetup]MySQLExtensionInstall'
                )

                xAzurePackSetup 'MySQLExtensionInitialize'
                {
                    DependsOn = $DependsOn
                    Role = 'MySQL Extension'
                    Action = 'Initialize'
                    dbUser = $Node.SAPassword
                    SourcePath = $Node.SourcePath
                    SourceFolder = $Node.WAPSourceFolder
                    SetupCredential = $Node.InstallerServiceAccount
                    Passphrase = $Node.WAPackPassphrase
                    SQLServer = $Node.SQLServer
                    SQLInstance = $Node.SQLInstance
                }
            }
            else
            {
                WaitForAll 'MySQLExtensionInitialize'
                {
                    NodeName = $WindowsAzurePack2013MySQLExtensionServers[0]
                    ResourceName = '[xAzurePackSetup]MySQLExtensionInitialize'
                    PsDscRunAsCredential = $Node.InstallerServiceAccount
                    RetryCount = 720
                    RetryIntervalSec = 20
                }

                xAzurePackSetup 'MySQLExtensionInitialize'
                {
                    DependsOn = @(
                        '[xAzurePackSetup]MySQLExtensionInstall',
                        '[WaitForAll]MySQLExtensionInitialize'
                    )
                    Role = 'MySQL Extension'
                    Action = 'Initialize'
                    dbUser = $Node.SAPassword
                    SourcePath = $Node.SourcePath
                    SourceFolder = $Node.WAPSourceFolder
                    SetupCredential = $Node.InstallerServiceAccount
                    Passphrase = $Node.WAPackPassphrase
                    SQLServer = $Node.SQLServer
                    SQLInstance = $Node.SQLInstance
                }
            }
        }

        # Install and initialize Azure Pack Admin Site
        if(
            ($WindowsAzurePack2013AdminSiteServers | Where-Object -FilterScript {
                    $_ -eq $Node.NodeName
            })
        )
        {
            xAzurePackSetup 'AdminSiteInstall'
            {
                Role = 'Admin Site'
                Action = 'Install'
                SourcePath = $Node.SourcePath
                SourceFolder = $Node.WAPSourceFolder
                SetupCredential = $Node.InstallerServiceAccount
                Passphrase = $Node.WAPackPassphrase
            }

            $DependsOn = @()

            if(
                ($WindowsAzurePack2013AdminSiteServers[0] -eq $Node.NodeName)
            )
            {
                # Wait for Admin API
                if ($WindowsAzurePack2013AdminSiteServers[0] -eq $WindowsAzurePack2013AdminAPIServers[0])
                {
                    $DependsOn = @('[xAzurePackSetup]AdminAPIInitialize')
                }
                else
                {
                    WaitForAll 'AdminAPI'
                    {
                        NodeName = $WindowsAzurePack2013AdminAPIServers[0]
                        ResourceName = ('[xAzurePackSetup]AdminAPIInitialize')
                        PsDscRunAsCredential = $Node.InstallerServiceAccount
                        RetryCount = 720
                        RetryIntervalSec = 20
                    }
                    $DependsOn = @('[WaitForAll]AdminAPI')
                }

                $DependsOn += @(
                    '[xAzurePackSetup]AdminSiteInstall'
                )

                xAzurePackSetup 'AdminSiteInitialize'
                {
                    DependsOn = $DependsOn
                    Role = 'Admin Site'
                    Action = 'Initialize'
                    dbUser = $Node.SAPassword
                    SourcePath = $Node.SourcePath
                    SourceFolder = $Node.WAPSourceFolder
                    SetupCredential = $Node.InstallerServiceAccount
                    Passphrase = $Node.WAPackPassphrase
                    SQLServer = $Node.SQLServer
                    SQLInstance = $Node.SQLInstance
                }

                if($Node.AzurePackAdminSiteFQDN)
                {
                    xPfxImport 'AdminSite'
                    {
                        DependsOn = '[xAzurePackSetup]AdminSiteInitialize'
                        Ensure = 'Present'
                        Path = $Node.WAPCertificatelocation
                        Thumbprint = $Node.WAPCertificateThumbprint
                        Credential = $Node.WAPCertificatepassword
                        Store = 'My'
                        Location = 'LocalMachine'
                        PsDscRunAsCredential = $Node.InstallerServiceAccount
                    }

                    xWebsite 'AdminSite'
                    {
                        DependsOn = '[xAzurePackSetup]AdminSiteInitialize'
                        Name = 'MgmtSvc-AdminSite'
                        Ensure = 'Present'
                        State = 'Started'
                        PhysicalPath = 'C:\inetpub\MgmtSvc-AdminSite'
                        BindingInfo = @(
                                            @(MSFT_xWebBindingInformation
                                                {
                                                    Protocol = 'HTTPS'
                                                    Port = $Node.AzurePackAdminSitePort
                                                    HostName = $Node.AzurePackAdminSiteFQDN
                                                    CertificateThumbprint = $Node.WAPCertificateThumbprint
                                                    CertificateStoreName = 'My'
                                                }
                                            )
                                        )
                    }

                    xAzurePackFQDN 'AdminSite'
                    {
                        DependsOn = '[xAzurePackSetup]AdminSiteInitialize'
                        Namespace = 'AdminSite'
                        FullyQualifiedDomainName = $Node.AzurePackAdminSiteFQDN
                        Port = $Node.AzurePackAdminSitePort
                        AzurePackAdminCredential = $Node.InstallerServiceAccount
                        SQLServer = $Node.SQLServer
                        SQLInstance = $Node.SQLInstance
                        dbUser = $Node.SAPassword
                    }

                    xAzurePackIdentityProvider 'AdminSite'
                    {
                        DependsOn = '[xAzurePackSetup]AdminSiteInitialize'
                        Target = 'Windows'
                        FullyQualifiedDomainName = $Node.AzurePackAdminSiteFQDN
                        Port = $Node.AzurePackAdminSitePort
                        AzurePackAdminCredential = $Node.InstallerServiceAccount
                        SQLServer = $Node.SQLServer
                        SQLInstance = $Node.SQLInstance
                        dbUser = $Node.SAPassword
                    }
                }
            }
            else
            {
                WaitForAll 'AdminSiteInitialize'
                {
                    NodeName = $WindowsAzurePack2013AdminSiteServers[0]
                    ResourceName = '[xAzurePackSetup]AdminSiteInitialize'
                    PsDscRunAsCredential = $Node.InstallerServiceAccount
                    RetryCount = 720
                    RetryIntervalSec = 20
                }

                xAzurePackSetup 'AdminSiteInitialize'
                {
                    DependsOn = @(
                        '[xAzurePackSetup]AdminSiteInstall',
                        '[WaitForAll]AdminSiteInitialize'
                    )
                    Role = 'Admin Site'
                    Action = 'Initialize'
                    dbUser = $Node.SAPassword
                    SourcePath = $Node.SourcePath
                    SourceFolder = $Node.WAPSourceFolder
                    SetupCredential = $Node.InstallerServiceAccount
                    Passphrase = $Node.WAPackPassphrase
                    SQLServer = $Node.SQLServer
                    SQLInstance = $Node.SQLInstance
                }
            }
        }

        # Install and initialize Azure Pack Admin Authentication Site
        if(
            ($WindowsAzurePack2013AdminAuthenticationSiteServers | Where-Object -FilterScript {
                    $_ -eq $Node.NodeName
            })
        )
        {
            xAzurePackSetup 'AdminAuthenticationSiteInstall'
            {
                Role = 'Admin Authentication Site'
                Action = 'Install'
                SourcePath = $Node.SourcePath
                SourceFolder = $Node.WAPSourceFolder
                SetupCredential = $Node.InstallerServiceAccount
                Passphrase = $Node.WAPackPassphrase
            }

            $DependsOn = @()

            if(
                ($WindowsAzurePack2013AdminAuthenticationSiteServers[0] -eq $Node.NodeName)
            )
            {
                # Wait for Admin API
                if ($WindowsAzurePack2013AdminAuthenticationSiteServers[0] -eq $WindowsAzurePack2013AdminAPIServers[0])
                {
                    $DependsOn = @('[xAzurePackSetup]AdminAPIInitialize')
                }
                else
                {
                    if ($WindowsAzurePack2013AdminAuthenticationSiteServers[0] -eq $WindowsAzurePack2013AdminSiteServers[0])
                    {
                        $DependsOn = @('[xAzurePackSetup]AdminSiteInitialize')
                    }
                    else
                    {
                        WaitForAll 'AdminAPI'
                        {
                            NodeName = $WindowsAzurePack2013AdminAPIServers[0]
                            ResourceName = ('[xAzurePackSetup]AdminAPIInitialize')
                            PsDscRunAsCredential = $Node.InstallerServiceAccount
                            RetryCount = 720
                            RetryIntervalSec = 20
                        }
                        $DependsOn = @('[WaitForAll]AdminAPI')
                    }


                }

                $DependsOn += @(
                    '[xAzurePackSetup]AdminAuthenticationSiteInstall'
                )

                xAzurePackSetup 'AdminAuthenticationSiteInitialize'
                {
                    DependsOn = $DependsOn
                    Role = 'Admin Authentication Site'
                    Action = 'Initialize'
                    dbUser = $Node.SAPassword
                    SourcePath = $Node.SourcePath
                    SourceFolder = $Node.WAPSourceFolder
                    SetupCredential = $Node.InstallerServiceAccount
                    Passphrase = $Node.WAPackPassphrase
                    SQLServer = $Node.SQLServer
                    SQLInstance = $Node.SQLInstance
                    PsDscRunAsCredential = $Node.InstallerServiceAccount

                }

                if($Node.AzurePackWindowsAuthSiteFQDN)
                {
                    if ($WindowsAzurePack2013AdminSiteServers[0] -ne $WindowsAzurePack2013AdminAuthenticationSiteServers[0])
                    {
                        xPfxImport 'AdminAuthenticationSite'
                        {
                            DependsOn = '[xAzurePackSetup]AdminAuthenticationSiteInitialize'
                            Ensure = 'Present'
                            Path = $Node.WAPCertificatelocation
                            Thumbprint = $Node.WAPCertificateThumbprint
                            Credential = $Node.WAPCertificatepassword
                            Store = 'My'
                            Location = 'LocalMachine'
                            PsDscRunAsCredential = $Node.InstallerServiceAccount
                        }
                    }

                    xWebsite 'AdminAuthenticationSite'
                    {
                        DependsOn = '[xAzurePackSetup]AdminAuthenticationSiteInitialize'
                        Name = 'MgmtSvc-WindowsAuthSite'
                        Ensure = 'Present'
                        State = 'Started'
                        PhysicalPath = 'C:\inetpub\MgmtSvc-WindowsAuthSite'
                        BindingInfo = @(
                                            @(MSFT_xWebBindingInformation
                                                {
                                                    Protocol = 'HTTPS'
                                                    Port = $Node.AzurePackWindowsAuthSitePort
                                                    HostName = $Node.AzurePackWindowsAuthSiteFQDN
                                                    CertificateThumbprint = $Node.WAPCertificateThumbprint
                                                    CertificateStoreName = 'My'
                                                }
                                            )
                                        )
                    }

                    xAzurePackFQDN 'AdminAuthenticationSite'
                    {
                        DependsOn = '[xAzurePackSetup]AdminAuthenticationSiteInitialize'
                        Namespace = 'WindowsAuthSite'
                        Port = $Node.AzurePackWindowsAuthSitePort
                        FullyQualifiedDomainName = $Node.AzurePackWindowsAuthSiteFQDN
                        AzurePackAdminCredential = $Node.InstallerServiceAccount
                        SQLServer = $Node.SQLServer
                        SQLInstance = $Node.SQLInstance
                        dbUser = $Node.SAPassword
                    }

                    xAzurePackRelyingParty 'AdminAuthenticationSite'
                    {
                        DependsOn = '[xAzurePackSetup]AdminAuthenticationSiteInitialize'
                        Target = 'Admin'
                        FullyQualifiedDomainName = $Node.AzurePackWindowsAuthSiteFQDN
                        AzurePackAdminCredential = $Node.InstallerServiceAccount
                        SQLServer = $Node.SQLServer
                        SQLInstance = $Node.SQLInstance
                        dbUser = $Node.SAPassword
                    }
                }
            }
            else
            {
                WaitForAll 'AdminAuthenticationSiteInitialize'
                {
                    NodeName = $WindowsAzurePack2013AdminAuthenticationSiteServers[0]
                    ResourceName = '[xAzurePackSetup]AdminAuthenticationSiteInitialize'
                    PsDscRunAsCredential = $Node.InstallerServiceAccount
                    RetryCount = 720
                    RetryIntervalSec = 20
                }

                xAzurePackSetup 'AdminAuthenticationSiteInitialize'
                {
                    DependsOn = @(
                        '[xAzurePackSetup]AdminAuthenticationSiteInstall',
                        '[WaitForAll]AdminAuthenticationSiteInitialize'
                    )
                    Role = 'Admin Authentication Site'
                    Action = 'Initialize'
                    dbUser = $Node.SAPassword
                    SourcePath = $Node.SourcePath
                    SourceFolder = $Node.WAPSourceFolder
                    SetupCredential = $Node.InstallerServiceAccount
                    Passphrase = $Node.WAPackPassphrase
                    SQLServer = $Node.SQLServer
                    SQLInstance = $Node.SQLInstance
                    PsDscRunAsCredential = $Node.InstallerServiceAccount
                }
            }
        }

        # Install and initialize Azure Pack Tenant Site
        if(
            ($WindowsAzurePack2013TenantSiteServers | Where-Object -FilterScript {
                    $_ -eq $Node.NodeName
            })
        )
        {
            xAzurePackSetup 'TenantSiteInstall'
            {
                Role = 'Tenant Site'
                Action = 'Install'
                SourcePath = $Node.SourcePath
                SourceFolder = $Node.WAPSourceFolder
                SetupCredential = $Node.InstallerServiceAccount
                Passphrase = $Node.WAPackPassphrase
            }

            $DependsOn = @()

            if(
                ($WindowsAzurePack2013TenantSiteServers[0] -eq $Node.NodeName)
            )
            {
                # Wait for Tenant Public API
                if ($WindowsAzurePack2013TenantSiteServers[0] -eq $WindowsAzurePack2013TenantPublicAPIServers[0])
                {
                    $DependsOn = @('[xAzurePackSetup]TenantPublicAPIInitialize')
                }
                else
                {
                    WaitForAll 'AdminAPI'
                    {
                        NodeName = $WindowsAzurePack2013TenantPublicAPIServers[0]
                        ResourceName = ('[xAzurePackSetup]TenantPublicAPIInitialize')
                        PsDscRunAsCredential = $Node.InstallerServiceAccount
                        RetryCount = 720
                        RetryIntervalSec = 20
                    }
                    $DependsOn = @('[WaitForAll]AdminAPI')
                }

                $DependsOn += @(
                    '[xAzurePackSetup]TenantSiteInstall'
                )

                xAzurePackSetup 'TenantSiteInitialize'
                {
                    DependsOn = $DependsOn
                    Role = 'Tenant Site'
                    Action = 'Initialize'
                    dbUser = $Node.SAPassword
                    SourcePath = $Node.SourcePath
                    SourceFolder = $Node.WAPSourceFolder
                    SetupCredential = $Node.InstallerServiceAccount
                    Passphrase = $Node.WAPackPassphrase
                    SQLServer = $Node.SQLServer
                    SQLInstance = $Node.SQLInstance
                }

                if($Node.AzurePackTenantSiteFQDN)
                {
                    xPfxImport 'TenantSite'
                    {
                        DependsOn = '[xAzurePackSetup]TenantSiteInitialize'
                        Ensure = 'Present'
                        Path = $Node.WAPCertificatelocation
                        Thumbprint = $Node.WAPCertificateThumbprint
                        Credential = $Node.WAPCertificatepassword
                        Store = 'My'
                        Location = 'LocalMachine'
                        PsDscRunAsCredential = $Node.InstallerServiceAccount
                    }

                    xWebsite 'TenantSite'
                    {
                        DependsOn = '[xAzurePackSetup]TenantSiteInitialize'
                        Name = 'MgmtSvc-TenantSite'
                        Ensure = 'Present'
                        State = 'Started'
                        PhysicalPath = 'C:\inetpub\MgmtSvc-TenantSite'
                        BindingInfo = @(
                                            @(MSFT_xWebBindingInformation
                                                {
                                                    Protocol = 'HTTPS'
                                                    Port = $Node.AzurePackTenantSitePort
                                                    HostName = $Node.AzurePackTenantSiteFQDN
                                                    CertificateThumbprint = $Node.WAPCertificateThumbprint
                                                    CertificateStoreName = 'My'
                                                }
                                            )
                                        )
                    }

                    xAzurePackFQDN 'TenantSite'
                    {
                        DependsOn = '[xAzurePackSetup]TenantSiteInitialize'
                        Namespace = 'TenantSite'
                        FullyQualifiedDomainName = $Node.AzurePackTenantSiteFQDN
                        Port = $Node.AzurePackTenantSitePort
                        AzurePackAdminCredential = $Node.InstallerServiceAccount
                        SQLServer = $Node.SQLServer
                        SQLInstance = $Node.SQLInstance
                        dbUser = $Node.SAPassword
                    }

                    xAzurePackIdentityProvider 'TenantSite'
                    {
                        DependsOn = '[xAzurePackSetup]TenantSiteInitialize'
                        Target = 'Membership'
                        FullyQualifiedDomainName = $Node.AzurePackTenantSiteFQDN
                        Port = $Node.AzurePackTenantSitePort
                        AzurePackAdminCredential = $Node.InstallerServiceAccount
                        SQLServer = $Node.SQLServer
                        SQLInstance = $Node.SQLInstance
                        dbUser = $Node.SAPassword
                    }
                }
            }
            else
            {
                WaitForAll 'TenantSiteInitialize'
                {
                    NodeName = $WindowsAzurePack2013TenantSiteServers[0]
                    ResourceName = '[xAzurePackSetup]TenantSiteInitialize'
                    PsDscRunAsCredential = $Node.InstallerServiceAccount
                    RetryCount = 720
                    RetryIntervalSec = 20
                }

                xAzurePackSetup 'TenantSiteInitialize'
                {
                    DependsOn = @(
                        '[xAzurePackSetup]TenantSiteInstall',
                        '[WaitForAll]TenantSiteInitialize'
                    )
                    Role = 'Tenant Site'
                    Action = 'Initialize'
                    dbUser = $Node.SAPassword
                    SourcePath = $Node.SourcePath
                    SourceFolder = $Node.WAPSourceFolder
                    SetupCredential = $Node.InstallerServiceAccount
                    Passphrase = $Node.WAPackPassphrase
                    SQLServer = $Node.SQLServer
                    SQLInstance = $Node.SQLInstance
                }
            }
        }

        # Install and initialize Azure Pack Tenant Authentication Site
        if(
            ($WindowsAzurePack2013TenantAuthenticationSiteServers | Where-Object -FilterScript {
                    $_ -eq $Node.NodeName
            })
        )
        {
            xAzurePackSetup 'TenantAuthenticationSiteInstall'
            {
                Role = 'Tenant Authentication Site'
                Action = 'Install'
                SourcePath = $Node.SourcePath
                SourceFolder = $Node.WAPSourceFolder
                SetupCredential = $Node.InstallerServiceAccount
                Passphrase = $Node.WAPackPassphrase
            }

            $DependsOn = @()

            if(
                ($WindowsAzurePack2013TenantAuthenticationSiteServers[0] -eq $Node.NodeName)
            )
            {
                # Wait for Tenant Public API
                if ($WindowsAzurePack2013TenantAuthenticationSiteServers[0] -eq $WindowsAzurePack2013TenantPublicAPIServers[0])
                {
                    $DependsOn = @('[xAzurePackSetup]TenantPublicAPIInitialize')
                }
                else
                {
                    WaitForAll 'AdminAPI'
                    {
                        NodeName = $WindowsAzurePack2013TenantPublicAPIServers[0]
                        ResourceName = ('[xAzurePackSetup]TenantPublicAPIInitialize')
                        PsDscRunAsCredential = $Node.InstallerServiceAccount
                        RetryCount = 720
                        RetryIntervalSec = 20
                    }
                    $DependsOn = @('[WaitForAll]AdminAPI')
                }

                $DependsOn += @(
                    '[xAzurePackSetup]TenantAuthenticationSiteInstall'
                )

                xAzurePackSetup 'TenantAuthenticationSiteInitialize'
                {
                    DependsOn = $DependsOn
                    Role = 'Tenant Authentication Site'
                    Action = 'Initialize'
                    dbUser = $Node.SAPassword
                    SourcePath = $Node.SourcePath
                    SourceFolder = $Node.WAPSourceFolder
                    SetupCredential = $Node.InstallerServiceAccount
                    Passphrase = $Node.WAPackPassphrase
                    SQLServer = $Node.SQLServer
                    SQLInstance = $Node.SQLInstance
                }

                if($Node.AzurePackAuthSiteFQDN)
                {
                    if ($WindowsAzurePack2013TenantAuthenticationSiteServers[0] -ne $WindowsAzurePack2013TenantSiteServers[0])
                    {
                        xPfxImport 'TenantAuthenticationSite'
                        {
                            DependsOn = '[xAzurePackSetup]TenantAuthenticationSiteInitialize'
                            Ensure = 'Present'
                            Path = $Node.WAPCertificatelocation
                            Thumbprint = $Node.WAPCertificateThumbprint
                            Credential = $Node.WAPCertificatepassword
                            Store = 'My'
                            Location = 'LocalMachine'
                            PsDscRunAsCredential = $Node.InstallerServiceAccount
                        }
                    }

                    xWebsite 'TenantAuthenticationSite'
                    {
                        DependsOn = '[xAzurePackSetup]TenantAuthenticationSiteInitialize'
                        Name = 'MgmtSvc-AuthSite'
                        Ensure = 'Present'
                        State = 'Started'
                        PhysicalPath = 'C:\inetpub\MgmtSvc-AuthSite'
                        BindingInfo = @(
                                            @(MSFT_xWebBindingInformation
                                                {
                                                    Protocol = 'HTTPS'
                                                    Port = $Node.AzurePackAuthSitePort
                                                    HostName = $Node.AzurePackAuthSiteFQDN
                                                    CertificateThumbprint = $Node.WAPCertificateThumbprint
                                                    CertificateStoreName = 'My'
                                                }
                                            )
                                        )
                    }

                    xAzurePackFQDN 'TenantAuthenticationSite'
                    {
                        DependsOn = '[xAzurePackSetup]TenantAuthenticationSiteInitialize'
                        Namespace = 'AuthSite'
                        Port = $Node.AzurePackAuthSitePort
                        FullyQualifiedDomainName = $Node.AzurePackAuthSiteFQDN
                        AzurePackAdminCredential = $Node.InstallerServiceAccount
                        SQLServer = $Node.SQLServer
                        SQLInstance = $Node.SQLInstance
                        dbUser = $Node.SAPassword
                    }

                    xAzurePackRelyingParty 'TenantAuthenticationSite'
                    {
                        DependsOn = '[xAzurePackSetup]TenantAuthenticationSiteInitialize'
                        Target = 'Tenant'
                        FullyQualifiedDomainName = $Node.AzurePackAuthSiteFQDN
                        AzurePackAdminCredential = $Node.InstallerServiceAccount
                        SQLServer = $Node.SQLServer
                        SQLInstance = $Node.SQLInstance
                        dbUser = $Node.SAPassword
                    }
                }
            }
            else
            {
                WaitForAll 'TenantAuthenticationSiteInitialize'
                {
                    NodeName = $WindowsAzurePack2013TenantAuthenticationSiteServers[0]
                    ResourceName = '[xAzurePackSetup]TenantAuthenticationSiteInitialize'
                    PsDscRunAsCredential = $Node.InstallerServiceAccount
                    RetryCount = 720
                    RetryIntervalSec = 20
                }

                xAzurePackSetup 'TenantAuthenticationSiteInitialize'
                {
                    DependsOn = @(
                        '[cAzurePackSetup]TenantAuthenticationSiteInstall',
                        '[WaitForAll]TenantAuthenticationSiteInitialize'
                    )
                    Role = 'Tenant Authentication Site'
                    Action = 'Initialize'
                    dbUser = $Node.SAPassword
                    SourcePath = $Node.SourcePath
                    SourceFolder = $Node.WAPSourceFolder
                    SetupCredential = $Node.InstallerServiceAccount
                    Passphrase = $Node.WAPackPassphrase
                    SQLServer = $Node.SQLServer
                    SQLInstance = $Node.SQLInstance
                }
            }
        }

    }
}
<#
# Copies all modules from the source server to the nodes targeted
foreach($Node in $ConfigurationData.AllNodes)
{
    if($Node.NodeName -ne "*")
    {
        Start-Process -FilePath "robocopy.exe" -ArgumentList ("`"C:\Program Files\WindowsPowerShell\Modules`" `"\\" + $Node.NodeName + "\c$\Program Files\WindowsPowerShell\Modules`" /e /purge /xf") -NoNewWindow -Wait
    }
}
#>
Write-Host "Creating MOFs" -ForegroundColor Yellow
WindowsAzurePack -ConfigurationData $ConfigurationData
Write-Host "Running Config" -ForegroundColor Yellow
Start-DscConfiguration -Path .\WindowsAzurePack -Verbose -Wait -Force