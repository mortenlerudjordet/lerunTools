<#
.SYNOPSIS
Validate and import certificates for SCOM agent authentication

.DESCRIPTION
Default execution checks the currently configured SCOM Agent certificate to determine if it is valid.

This is designed to work with the certificates already in the local store as well as PFX files.  It can also be use to automate configuration of the SCOM agents from within SCCM.

.PARAMETER InstallBestFitFromLocalStore
Iterates throught the certificates on the machine and configures the valid certificate with the longest remaining lifetime as the certification certificate for the SCOM agent.
.  Can not be used with -SerialNumber, -Path, or -Remove.

.PARAMETER SerialNumber
Check the configuration of the certificate specified by the serial number passed.  Can not be used with -InstallFromLocalStore, -Path, or -Remove.

.PARAMETER CheckCurrentCert
Query the certificate currently in use by SCOM and interrogate the certificate to make sure it is valid.

.PARAMETER EnableDiagnostics
This script ALWAYS validates the certificate before it does anything.  This just enables human readable output so the reader knows why the certificate is or is not valid.  When this is false (default) it also exits out at the first failed test, thus is a little faster.

.PARAMETER ValidateCertOnly
(Passive Mode) This will run the script and validate the certificates but will not make any changes to the system.

.PARAMETER SuppressHealthServiceRestart
By default the script will restart the health service so that it reads the certificate value from the registry.  This suppresses the automatic restart

.PARAMETER Path
Instead of reading from the local certificate store, supply a certificate file to act on.  Can not be used with -InstallFromLocalStore, -SerialNumber, or -Remove.

For other scenarios, this is the input or output path for the file.

.PARAMETER Password
This is the password for the PFX file you want to validate.  If you don't specify the password here, the script will prompt.

.PARAMETER Remove
Remove existing SCOM Agent certificate configuration.  This ignores all other settings and leaves the certificate on the machine.

.PARAMETER CreateCertificateRequest
For environments that do not use autoenrollment this allows for automatic creation of the certificate request file.  Must be used with -Path for the output location of the request.

.PARAMETER KeyLength
Allows user to specify the key length for the certificate request.  Default is 2048.  Available values are 1024, 2048, 4096, 8192, or 16384.

.PARAMETER SubmitToOnlineAuthority
Provide the name of the certificate authority.  This should be in the format of "<ServerName>\<Certificate Authority Name>"

.PARAMETER UseCertificateTemplate
Enter the name of the certificate template to use for Enterprise CAs.  This defaults to OperationsManagerCert, as per the guidance in the technet article.  The name is irrelevent so long as the template is configured properly.

.EXAMPLE


.NOTES
When running against the local certificate store, this script should be run under administrative context otherwise not all data will be returned accurately.

.LINK
http://blogs.technet.com/b/ken_brumfield/archive/2014/01/06/momcertimport-is-it-all-it-s-cracked-up-to-be.aspx

.LINK
http://blogs.technet.com/b/momteam/archive/2013/09/17/troubleshooting-opsmgr-2007-and-opsmgr-2012-certificate-issues-with-powershell.aspx

.LINK
http://technet.microsoft.com/en-us/library/dd362553.aspx
#>

#[CmdletBinding(DefaultParameterSetName="CheckCurrentConfig")]
[CmdletBinding(DefaultParameterSetName="CheckCurrentConfig")]

Param
(
    [Parameter(Mandatory=$False, ParameterSetName="InstallBestFitFromLocalStore")][switch][bool]$InstallBestFitFromLocalStore
    , [Parameter(Mandatory=$True, ParameterSetName="InstallBestFitFromSerialNumber")][string]$SerialNumber = $null
    , [Parameter(Mandatory=$True, ParameterSetName="CreateCertificateRequest")][switch][bool]$CreateCertificateRequest
    , [Parameter(Mandatory=$True, ParameterSetName="CreateCertificateRequest")][ValidateSet(1024, 2048, 4096, 8192, 16384)][int]$KeyLength
    , [Parameter(Mandatory=$True, ParameterSetName="InstallFromPFX")]
        [Parameter(Mandatory=$False, ParameterSetName="CreateCertificateRequest")][string]$Path = $null
    , [Parameter(Mandatory=$True, ParameterSetName="InstallFromPFX")][System.Security.SecureString]$Password = $null
    , [Parameter(Mandatory=$False, ParameterSetName="CreateCertificateRequest")]
        [Parameter(Mandatory=$True, ParameterSetName="GetCertificateResponse")][string]$SubmitToOnlineAuthority
    , [Parameter(Mandatory=$False, ParameterSetName="CreateCertificateRequest")][string]$UseCertificateTemplate
    , [Parameter(Mandatory=$True, ParameterSetName="GetCertificateResponse")][int]$RequestId
    , [Parameter(Mandatory=$True, ParameterSetName="Remove")][switch][bool]$Remove
    , [Parameter(Mandatory=$False, ParameterSetName="InstallBestFitFromLocalStore")]
        [Parameter(Mandatory=$False, ParameterSetName="InstallBestFitFromSerialNumber")]
        [Parameter(Mandatory=$False, ParameterSetName="InstallFromPFX")][switch][bool]$EnableDiagnostics
    , [Parameter(Mandatory=$False, ParameterSetName="InstallBestFitFromLocalStore")]
        [Parameter(Mandatory=$False, ParameterSetName="InstallBestFitFromSerialNumber")]
        [Parameter(Mandatory=$False, ParameterSetName="InstallFromPFX")][switch][bool]$ValidateCertOnly
    , [Parameter(Mandatory=$False, ParameterSetName="InstallBestFitFromLocalStore")]
        [Parameter(Mandatory=$False, ParameterSetName="InstallBestFitFromSerialNumber")]
        [Parameter(Mandatory=$False, ParameterSetName="InstallFromPFX")]
        [Parameter(Mandatory=$False, ParameterSetName="Remove")][switch][bool]$SuppressHealthServiceRestart
)

Set-StrictMode -Version 2

#region constants
    #X509CertificateEnrollmentContext enum
    Set-Variable X509CertificateEnrollmentContext_ContextNone -Option Constant -Value 0
    Set-Variable X509CertificateEnrollmentContext_ContextUser -Option Constant -Visibility Private -Value 0x1
    Set-Variable X509CertificateEnrollmentContext_ContextMachine -Option Constant -Visibility Private -Value 0x2
    Set-Variable X509CertificateEnrollmentContext_ContextAdministratorForceMachine -Visibility Private -Option Constant -Value 0x3
    #end X509CertificateEnrollmentContext ICertRequest3 ReturnCodes

    #EncodingType enum
    #http://msdn.microsoft.com/en-us/library/windows/desktop/aa374936(v=vs.85).aspx
    Set-Variable EncodingType_XCN_CRYPT_STRING_BASE64HEADER -Option Constant -Value 0
    Set-Variable EncodingType_XCN_CRYPT_STRING_BASE64 -Option Constant -Value 0x1
    Set-Variable EncodingType_XCN_CRYPT_STRING_BINARY -Option Constant -Value 0X2
    Set-Variable EncodingType_XCN_CRYPT_STRING_BASE64REQUESTHEADER -Option Constant -Value 0x3
    Set-Variable EncodingType_XCN_CRYPT_STRING_HEX -Option Constant -Value 0x4
    Set-Variable EncodingType_XCN_CRYPT_STRING_HEXASCII -Option Constant -Value 0x5
    Set-Variable EncodingType_XCN_CRYPT_STRING_BASE64_ANY -Option Constant -Value 0x6
    Set-Variable EncodingType_XCN_CRYPT_STRING_ANY -Option Constant -Value 0x7
    Set-Variable EncodingType_XCN_CRYPT_STRING_HEX_ANY -Option Constant -Value 0x8
    Set-Variable EncodingType_XCN_CRYPT_STRING_BASE64X509CRLHEADER -Option Constant -Value 0x9
    Set-Variable EncodingType_XCN_CRYPT_STRING_HEXADDR -Option Constant -Value 0xa
    Set-Variable EncodingType_XCN_CRYPT_STRING_HEXASCIIADDR -Option Constant -Value 0xb
    Set-Variable EncodingType_XCN_CRYPT_STRING_HEXRAW -Option Constant -Value 0xc
    Set-Variable EncodingType_XCN_CRYPT_STRING_NOCRLF -Option Constant -Value 0x40000000
    Set-Variable EncodingType_XCN_CRYPT_STRING_NOCR -Option Constant -Value 0x80000000
    #End EncodingType

    #ICertRequest3 ReturnCodes
    #http://msdn.microsoft.com/en-us/library/windows/desktop/aa385054(v=vs.85).aspx
    Set-Variable CR_DISP_INCOMPLETE -Option Constant -Value 0 # Request did not complete
    Set-Variable CR_DISP_ERROR -Option Constant -Value 0x1 # Request failed
    Set-Variable CR_DISP_DENIED -Option Constant -Value 0x2 #Request denied
    Set-Variable CR_DISP_ISSUED -Option Constant -Value 0x3 #Certificate issued
    Set-Variable CR_DISP_ISSUED_OUT_OF_BAND -Option Constant -Value 0x4 #Certificate issued separately
    Set-Variable CR_DISP_UNDER_SUBMISSION -Option Constant -Value 0x5 #Request taken under submission
    Set-Variable CR_DISP_REVOKED -Option Constant -Value 0x6 #Request taken under submission
    #end 
#endregion

Function isUserAdministrator
{
    [OutputType([bool])]
    Param()

    if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
        [Security.Principal.WindowsBuiltInRole] "Administrator"))
    {
        return $False
    }

    return $True
}

#region Test-Certificate
Function isSubjectNameValid
{
    [OutputType([bool])]
    Param
    (
        [Parameter(Mandatory=$False
            , ValueFromPipeLine=$True
            , ValueFromPipelineByPropertyName=$True)][System.Security.Cryptography.X509Certificates.X500DistinguishedName]$SubjectName
    )

    $sysinfo = Get-WmiObject -Class Win32_ComputerSystem
    $fqdn = “{0}.{1}” -f $sysinfo.Name, $sysinfo.Domain

    # Check if server is in domain or workgroup
    If($sysinfo.PartOfDomain) {
        $expectedSubjectName = "CN=" + $fqdn.Replace(".","\.") + '(,.*)?$'
        $isValid = ($SubjectName.Name -match $expectedSubjectName)
    }
    Else {
        $expectedSubjectName = "CN=" + $sysinfo.Name
        $isValid = ($SubjectName.Name -match $expectedSubjectName)
    }
    
    if (!($isValid) -and ($EnableDiagnostics))
    {
        Write-Host "Test:  Certificate Subject Name Failed" -BackgroundColor Red -ForegroundColor Black 
        If($sysinfo.PartOfDomain) {
            Write-Host "`tThe SubjectName of this cert does not match the FQDN of this machine." 
            Write-Host "`tActual - $($SubjectName.Name)" 
            Write-Host "`tExpected (case insensitive)- CN=$fqdn as this server is part of a domain"
        }
        Else {
            Write-Host "`tThe SubjectName of this cert does not match the netbios name of this machine." 
            Write-Host "`tActual - $($SubjectName.Name)" 
            Write-Host "`tExpected (case insensitive)- CN=$($sysinfo.Name) as this server is part of a workgroup"
        }

    }
    elseif ($EnableDiagnostics)
    {
        Write-Host "Test:  Certificate Subject Name Passed" -BackgroundColor Green -ForegroundColor Black
    }
    return $isValid
}

Function isPrivateKeyValid
{
    [OutputType([bool])]
    Param
    (
        [Parameter(Mandatory=$True
            , ValueFromPipeLine=$True
            , ValueFromPipelineByPropertyName=$True)][System.Security.Cryptography.X509Certificates.X509Certificate2]$cert
    )

    if (!(isUserAdministrator) -and [string]::IsNullOrEmpty($Path))
    {
        Write-Host "Test:  Private Key Warning" -BackgroundColor Yellow -ForegroundColor Black 
        Write-Host "`tWarning:  This process is not running under administrative context!" -BackgroundColor Black -ForegroundColor Yellow
        Write-Host "`tPrivate key information can not be tested!" -BackgroundColor Black -ForegroundColor Yellow
        return $False
    }

    if (!($cert.HasPrivateKey) -and ($EnableDiagnostics))
    {
        Write-Host "Test:  Private Key Failed" -BackgroundColor Red -ForegroundColor Black 
        Write-Host "`tThis certificate does not have a private key." 
        Write-Host "`tVerify that proper steps were taken when installing this cert." 
    }
    elseif (!($cert.PrivateKey.CspKeyContainerInfo.MachineKeyStore) -and ($EnableDiagnostics))
    {
        Write-Host "Test:  Private Key Failed" -BackgroundColor Red -ForegroundColor Black 
        Write-Host "`tThis certificate's private key is not issued to a machine account." 
        Write-Host "`tOne possible cause of this is that the certificate" 
        Write-Host "`twas issued to a user account rather than the machine," 
        Write-Host "`tthen copy/pasted from the Current User store to the Local" 
        Write-Host "`tMachine store.  A full export/import is required to switch" 
        Write-Host "`tbetween these stores."
    }
    elseif ($EnableDiagnostics)
    {
        Write-Host "Test:  Private Key Passed" -BackgroundColor Green -ForegroundColor Black
    }

    return (($cert.HasPrivateKey) -and ($cert.PrivateKey.CspKeyContainerInfo.MachineKeyStore))
}

Function isNotExpired
{
    [OutputType([bool])]
    Param
    (
        [Parameter(Mandatory=$True
            , ValueFromPipeLine=$True
            , ValueFromPipelineByPropertyName=$True)][System.Security.Cryptography.X509Certificates.X509Certificate2]$cert
    )

    $isValid = (($cert.NotBefore -le [DateTime]::Now) -or ($cert.NotAfter -gt [DateTime]::Now))

    if (!$isValid -and $EnableDiagnostics)
    {
        Write-Host "Test:  Expiration Failed" -BackgroundColor Red -ForegroundColor Black 
        Write-Host "`tThis certificate is not currently valid." 
        Write-Host "`tIt will be valid between $($cert.NotBefore) and $($cert.NotAfter)" 
    }
    elseif ($EnableDiagnostics)
    {
        Write-Host "Test:  Expiration Passed" -BackgroundColor Green -ForegroundColor Black
    }

    return $isValid
}

Function areCorrectExtensionsInCertificate
{
    [OutputType([bool])]
    Param
    (
        [Parameter(Mandatory=$False
            , ValueFromPipeLine=$True)][System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension] $enhancedKeyUsageExtension
    )

    if ($enhancedKeyUsageExtension -eq $null)
    {
        if ($EnableDiagnostics)
        {
            Write-Host "Test:  Enhanced Key Usage Extension Failed" -BackgroundColor Red -ForegroundColor Black 
            Write-Host "`tNo enhanced key usage extension found." 
        }
        return $False
    }
    elseif ($enhancedKeyUsageExtension.EnhancedKeyUsages -eq $null)
    {
        if ($EnableDiagnostics)
        {
            Write-Host "Test:  Enhanced Key Usage Extension Failed" -BackgroundColor Red -ForegroundColor Black 
            Write-Host "`tNo enhanced key usages found." 
        }
        return $False
    }

    $containsServerAuth = $containsClientAuth = $False
    foreach($enhancedKeyUsage in $enhancedKeyUsageExtension.EnhancedKeyUsages)
    {
        if ($enhancedKeyUsage.Value -eq "1.3.6.1.5.5.7.3.1") {$containsServerAuth = $True}
        if ($enhancedKeyUsage.Value -eq "1.3.6.1.5.5.7.3.2") {$containsClientAuth = $True}
    }

    if ((!$containsServerAuth) -or (!$containsClientAuth)) 
    {
        if ($EnableDiagnostics)
        {
            Write-Host "Test:  Enhanced Key Usage Extension Failed" -BackgroundColor Red -ForegroundColor Black 
            Write-Host "`tEnhanced key usage extension does not meet requirements." 
            Write-Host "`tRequired EKUs are 1.3.6.1.5.5.7.3.1 and 1.3.6.1.5.5.7.3.2" 
            Write-Host "`tEKUs found on this cert are:" 
            $enhancedKeyUsageExtension.EnhancedKeyUsages |%{Write-Host "`t$($_.Value)" }
        }
        return $False
    }
    elseif ($EnableDiagnostics)
    {
        Write-Host "Test:  Enhanced Key Usage Extension Passed" -BackgroundColor Green -ForegroundColor Black
    }

    return ($containsServerAuth -and $containsClientAuth)
}

Function isKeyUsageSetCorrectly
{
    [OutputType([bool])]
    Param
    (
        [Parameter(Mandatory=$True
            , ValueFromPipeLine=$True)][System.Security.Cryptography.X509Certificates.X509KeyUsageExtension] $KeyUsageExtension
    )

    #there is a divergence between the technet and the troubleshooting scripts regarding the KeyUsage value
    #      0xA0 vs. 0xF0
    #From the reference (0xA0): https://blogs.technet.com/b/momteam/archive/2013/09/17/troubleshooting-opsmgr-2007-and-opsmgr-2012-certificate-issues-with-powershell.aspx
    #Technet reference here states a different value (0xF0):  http://technet.microsoft.com/en-us/library/dd362553.aspx
    #Also changed this to use the enumeration rather than raw values for readability
    #Enumeration Value references:
    #     http://msdn.microsoft.com/en-us/library/windows/desktop/aa379410(v=vs.85).aspx
    #     http://msdn.microsoft.com/en-us/library/system.security.cryptography.x509certificates.x509keyusageflags(v=vs.110).aspx

    [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]$neededKeys =
    #according to the original code and error message content
        [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature -bor 
        [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyEncipherment

    #according to technet article, uncomment below 3 lines to append to the test
#    $neededKeys = $neededKeys -bor
#        [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::NonRepudiation -bor
#        [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DataEncipherment

    if ($keyUsageExtension -eq $null) 
    {
        if ($EnableDiagnostics)
        {
            Write-Host "Test:  Key Usage Extensions Failed" -BackgroundColor Red -ForegroundColor Black 
            Write-Host "`tNo key usage extension found." 
            Write-Host "`tA KeyUsage extension matching 0xA0 (Digital Signature, Key Encipherment)" 
            Write-Host "`tor better is required."
        }
        return $False 
    }

    if ($keyUsageExtension.KeyUsages -eq $null) 
    {
        if ($EnableDiagnostics)
        {
            Write-Host "Test:  Key Usage Extensions Failed" -BackgroundColor Red -ForegroundColor Black 
            Write-Host "`tNo key usages found." 
            Write-Host "`tA KeyUsage extension matching 0xA0 (DigitalSignature, KeyEncipherment)" 
            Write-Host "`tor better is required."
        }
        return $False 
    }

    if (($keyUsageExtension.KeyUsages -band $neededKeys) -ne $neededKeys) 
    {
        Write-Host "Test:  Key Usage Extensions Failed" -BackgroundColor Red -ForegroundColor Black 
        Write-Host "`tKey usage extension exists but does not meet requirements." 
        Write-Host "`tA KeyUsage extension matching"$neededKeys.value__.ToString("X")"("$neededKeys.ToString()")" 
        Write-Host "`tor better is required." 
        Write-Host "`tKeyUsage found on this cert matches:" 
        Write-Host "`t" $keyUsageExtension.KeyUsages
        return $False 
    }
    
    if ($EnableDiagnostics)
    {
        Write-Host "Test:  Key Usage Extensions Passed" -BackgroundColor Green -ForegroundColor Black
    }

    return $True
}

Function isKeySpecCorrect
{
    [OutputType([bool])]
    Param
    (
        [Parameter(Mandatory=$False
            , ValueFromPipeLine=$True
            , ValueFromPipelineByPropertyName=$True)][System.Security.Cryptography.AsymmetricAlgorithm]$keySpec
    )

    #References:
    #http://msdn.microsoft.com/en-us/library/windows/desktop/aa379020(v=vs.85).aspx
    #http://msdn.microsoft.com/en-us/library/windows/desktop/aa379409(v=vs.85).aspx
    #http://msdn.microsoft.com/en-us/library/system.security.cryptography.cspkeycontainerinfo.keynumber(v=vs.110).aspx
    #http://msdn.microsoft.com/en-us/library/system.security.cryptography.keynumber(v=vs.110).aspx

    [System.Security.Cryptography.KeyNumber]$neededValue = [System.Security.Cryptography.KeyNumber]::Exchange
    
    if ($keySpec -eq $null)
    {
        if ($EnableDiagnostics)
        {
            Write-Host "Test:  KeySpec Failed" -BackgroundColor Red -ForegroundColor Black 
            Write-Host "`tKeyspec not found.  A KeySpec of '"([System.Security.Cryptography.KeyNumber]::Exchange)"' is required"
        }
        return $False
    }
    elseif ($keySpec.CspKeyContainerInfo.KeyNumber -ne $neededValue)
    {
        if ($EnableDiagnostics)
        {
            Write-Host "Test:  KeySpec Failed" -BackgroundColor Red -ForegroundColor Black 
            Write-Host "`tKeyspec exists but does not meet requirements." 
            Write-Host "`tA KeySpec of 1 is required." 
            Write-Host "`tKeySpec for this cert: $($keySpec.CspKeyContainerInfo.KeyNumber)"
        }
        return $False
    }
    elseif ($EnableDiagnostics)
    {
        Write-Host "Test:  KeySpec Passed" -BackgroundColor Green -ForegroundColor Black
    }

    return $True
}

Function isCertificateChainValid
{
    # Check that the cert's issuing CA is trusted (This is not technically required 
    # as it is the remote machine cert's CA that must be trusted.  Most users leverage 
    # the same CA for all machines, though, so it's worth checking

    [OutputType([bool])]
    Param()
    
    $chain = new-object Security.Cryptography.X509Certificates.X509Chain 
    $chain.ChainPolicy.RevocationMode = 0 
    if ($chain.Build($cert) -eq $False ) 
    {
        if ($EnableDiagnostics)
        {
            Write-Host "Test:  Certification chain warning" -BackgroundColor Yellow -ForegroundColor Black 
            Write-Host "`tThe following error occurred building a certification chain with this cert:" 
            Write-Host "`t$($chain.ChainStatus[0].StatusInformation)" 
            write-host "`tThis is an error if the certificates on the remote machines are issued" 
            write-host "`tfrom this same CA - $($cert.Issuer)" 
            write-host "`tPlease ensure the certificates for the CAs which issued the certificates configured" 
            write-host "`ton the remote machines is installed to the Local Machine Trusted Root Authorities" 
            write-host "`tstore on this machine."
        }
        return $False
    } 
    else 
    { 
        $rootCaCert = $chain.ChainElements | select -property Certificate -last 1 
        $localMachineRootCert = dir cert:\LocalMachine\Root |? {$_ -eq $rootCaCert.Certificate} 
        if ($localMachineRootCert -eq $null) 
        {
            if ($EnableDiagnostics)
            {
                Write-Host "Test:  Certification chain warning" -BackgroundColor Yellow -ForegroundColor Black 
                Write-Host "`tThis certificate has a valid certification chain installed, but" 
                Write-Host "`ta root CA certificate verifying the issuer $($cert.Issuer)" 
                Write-Host "`twas not found in the Local Machine Trusted Root Authorities store." 
                Write-Host "`tMake sure the proper root CA certificate is installed there, and not in" 
                Write-Host "`tthe Current User Trusted Root Authorities store."
            }
            return $False
        } 
        elseif ($EnableDiagnostics)
        {
            Write-Host "Test:  Certification chain warning" -BackgroundColor Green -ForegroundColor Black 
            Write-Host "`tThere is a valid certification chain installed for this cert," 
            Write-Host "`tbut the remote machines' certificates could potentially be issued from" 
            Write-Host "`tdifferent CAs.  Make sure the proper CA certificates are installed" 
            Write-Host "`tfor these CAs."
        }
    }
    
    return $True
}

Function Test-Certificate
{
    [OutputType([bool])]
    Param
    (
        [Parameter(Mandatory=$True
            , ValueFromPipeLine=$True
            , ValueFromPipelineByPropertyName=$True)][System.Security.Cryptography.X509Certificates.X509Certificate2]$cert
    )

    if ($EnableDiagnostics)
    {
        Write-Host "-------------------------------------------------"  -BackgroundColor Magenta -ForegroundColor White
        Write-Host "Examining certificate" -BackgroundColor DarkMagenta -ForegroundColor White
        Write-Host "Subject:  " $cert.Subject -BackgroundColor DarkMagenta -ForegroundColor White
        Write-Host "Serial#:  " $cert.SerialNumber -BackgroundColor DarkMagenta -ForegroundColor White
    }

    $passed = $True
    #check if subject name of certificate is valid
    if (!(isSubjectNameValid $cert.SubjectName))
    {
        $passed = $False
        if (!$EnableDiagnostics) {Continue}
    }

    #check if has private key and is valid
    if (!(isPrivateKeyValid $cert))
    {
        $passed = $False
        if (!$EnableDiagnostics) {Continue}
    }

    #check if certificate lifetimes are valid
    if (!(isNotExpired $cert))
    {
        $passed = $False
        if (!$EnableDiagnostics) {Continue}
    }

    #check if it has the right key usages
    if (!(areCorrectExtensionsInCertificate ($cert.Extensions|? {$_.ToString() -match "X509EnhancedKeyUsageExtension"})))
    {
        $passed = $False
        if (!$EnableDiagnostics) {Continue}
    }

    if (!(isKeyUsageSetCorrectly ($cert.Extensions |? {$_.ToString() -match "X509KeyUsageExtension"})))
    {
        $passed = $False
        if (!$EnableDiagnostics) {Continue}
    }

    if (!(isKeySpecCorrect $cert.PrivateKey))
    {
        $passed = $False
        if (!$EnableDiagnostics) {Continue}
    }

    if (!$EnableDiagnostics)
    {
        isCertificateChainValid $cert
    }

    return $passed
}
#endregion

#region check registry for certificate value
Function convertSerialNumberToChannelCertificateSerialNumberValue
{
    [OutputType([System.Byte[]])]
    Param
    (
        [Parameter(Mandatory=$True
            , ValueFromPipeLine=$True
            , ValueFromPipelineByPropertyName=$True)][String]$serialNumber
    )

    #This is a "bugfix" (not sure) from the reference script.  The serial number length changes based on the key size of the certificate
    #     the other script only works for key sizes of 1024
    $prefix = "0x"
    $reversedSerialNumber = New-Object System.Byte[] ($serialNumber.Length / 2)
    1..($cert.SerialNumber.Length / 2)|%{$reversedSerialNumber[$_ - 1] = [Byte]($prefix + $serialNumber.Substring($serialNumber.Length - ($_ * 2), 2))}
    return $reversedSerialNumber
}

Function convertChannelCertificateSerialNumberValueToSerialNumber
{
    [OutputType([string])]
    Param
    (
        [Parameter(Mandatory=$True
            , ValueFromPipeLine=$True
            , ValueFromPipelineByPropertyName=$True)][Byte[]]$serialNumberByteArray
    )
    [string]$serialNumber = [string]::Empty
    (($serialNumberByteArray.Length) - 1)..0|%{$serialNumber += $serialNumberByteArray[$_].ToString("X2")}
    return $serialNumber
}

Function getChannelCertificateSerialNumberRegValue
{
    [OutputType([string])]
    Param()
    
    $regValue = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Microsoft Operations Manager\3.0\Machine Settings" -Name ChannelCertificateSerialNumber -ErrorAction SilentlyContinue
    if ($regValue -eq $Null)
    {
        if ($EnableDiagnostics)
        {
            Write-Host "Test:  Registered Certificate Failed" -BackgroundColor Red -ForegroundColor Black
            Write-Host "`tNo certificate has been registered yet"
        }
        return $Null
    }
    return $regValue.ChannelCertificateSerialNumber
}

Function doesChannelCertificateSerialNumberRegValueMatchCertificate
{
    [OutputType([bool])]   
    Param
    (
        [Parameter(Mandatory=$True
            , ValueFromPipeLine=$True
            , ValueFromPipelineByPropertyName=$True)][String]$serialNumber
    )

    $regValue = getChannelCertificateSerialNumberRegValue
    if ($regValue -eq $null)
    {
        return $False
    }
    elseif ((convertChannelCertificateSerialNumberValueToSerialNumber $regValue) -ne $serialNumber)
    {
        if ($EnableDiagnostics)
        {
            Write-Host "Test:  Registered Certificate Failed" -BackgroundColor Red -ForegroundColor Black
            Write-Host "`The registered certificate has a different serial number."
        }
        return $False
    }
    elseif ($EnableDiagnostics)
    {
        Write-Host "Test:  Registered Certificate Passed" -BackgroundColor Green -ForegroundColor Black
    }

    return $True
}
#endregion

#region register SCOM certificate
Function registerChannelCertificateSerialNumber
{
    Param
    (
        [Parameter(Mandatory=$True
            , ValueFromPipeLine=$True
            , ValueFromPipelineByPropertyName=$True)][String]$serialNumber
    )
    [byte[]]$certValue = convertSerialNumberToChannelCertificateSerialNumberValue $serialNumber
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\Microsoft Operations Manager\3.0\Machine Settings" -Name ChannelCertificateSerialNumber -Value $certValue
}

Function registerChannelCertificateHash
{
    Param
    (
        [Parameter(Mandatory=$True
            , ValueFromPipeLine=$True
            , ValueFromPipelineByPropertyName=$True)][String]$thumbrint
    )
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\Microsoft Operations Manager\3.0\Machine Settings" -Name ChannelCertificateHash -Value $thumbrint
}

Function registerCert
{
    [OutputType([bool])]
    Param
    (
        [Parameter(Mandatory=$True
            , ValueFromPipeLine=$True
            , ValueFromPipelineByPropertyName=$True)][System.Security.Cryptography.X509Certificates.X509Certificate2]$cert
    )

    $result = doesChannelCertificateSerialNumberRegValueMatchCertificate $cert.SerialNumber

    if (!$result -and !$ValidateCertOnly)
    {
        Write-Host "`tCertificate has been validated and does not match value in the registry.  Registering current certificate.."
        registerChannelCertificateSerialNumber $cert.SerialNumber
        registerChannelCertificateHash $cert.Thumbprint
        $itWorked = doesChannelCertificateSerialNumberRegValueMatchCertificate $cert.SerialNumber
        if (!$suppressHealthServiceRestart -and $itWorked)
        {
            Restart-Service HealthService
            return $True
        }
        elseif (!$itWorked)
        {
            Write-Error "Error registering certificate."
            return $False
        }
    }
    elseif ($ValidateCertOnly)
    {
        Write-Error "Certificate has only been validated and has not been registered."
        return $False
    }
    return $result
}
#endregion

#region interact with potential SCOM Certificates
Function checkLocalCertificates
{
    Param
    (
        [Parameter(Mandatory=$True)][String]$ScriptParameterSetName
        , [Parameter(Mandatory=$False
            , ValueFromPipeLine=$True
            , ValueFromPipelineByPropertyName=$True)][String]$serialNumber
    )
    #Get a valid certificate with the longest expiration date in to the future
    $certs = Get-ChildItem cert:\LocalMachine\MY|Sort-Object -Property NotAfter -Descending
    if ($certs -eq $null) 
    {
        Write-Host "Test:  Machine has certs failed" -BackgroundColor Red -ForegroundColor Black
        Write-Error "There are no certs in the Local Machine `"Personal`" store." 
        Write-Error "This is where the client authentication certificate should be imported." 
        Write-Error "Check if certificates were mistakenly imported to the Current User" 
        Write-Error "`"Personal`" store or the `"Operations Manager`" store."
        Exit 2
    }
    
    [bool]$ValidCertExists = $False
    foreach($cert in $certs)
    {
        if ([string]::IsNullOrEmpty($serialNumber) -or $serialNumber -eq $cert.SerialNumber)
        {
            if(Test-Certificate $cert)
            {
                $ValidCertExists = $True

                if (!$ValidateCertOnly)
                {
                    return registerCert $cert
                }
            }

            if ($EnableDiagnostics)
            {
                Write-Host
            }
        }
    }


    if ($ScriptParameterSetName -eq "InstallBestFitFromLocalStore" -and !$ValidCertExists)
    {
        Write-Error "No valid certificates for SCOM Agent use found in machine store."
    }
    elseif ($ScriptParameterSetName -eq "InstallBestFitFromSerialNumber" -and !$ValidCertExists)
    {
        Write-Error ("No valid certificates with " + $serialNumber + " for SCOM Agent use found in machine store.")
    }
    elseif ($ScriptParameterSetName -eq "CheckCurrentConfig")
    {
        if ($EnableDiagnostics)
        {
            Write-Error "Certificate used by SCOM Agent does not exist in machine store."
            #The error is here for user interactivity.  Clear it for SCCM interactivity.
        }
    }
    elseif ( !$ValidateCertOnly)
    {
        Write-Error ("Could not find certificate with serial number:  " + $serialNumber)
    }
    return $False
}

Function checkCertificateFile
{
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
    if ([string]::IsNullOrEmpty($Password))
    {
        Write-Error "No password provided for the PFX file."
    }
    $cert.Import($Path, $Password, 0)
    if(Test-Certificate $cert)
    {
        if (!$ValidateCertOnly)
        {
            if (!(isUserAdministrator))
            {
                return "Script is not running under administrative context.  Certificate passed all tests but can not be imported."
            }

            #Since the cert passed, install it.
            $store = New-Object System.Security.Cryptography.X509Certificates.X509Store('My','LocalMachine')
            $store.Open("MaxAllowed")
            $store.Add($cert)
            $store.Close()
            Write-Host "Certificate successfully imported."

            return registerCert $cert
        }
        else
        {
            Write-Warning "Certificate has only been validated and has not been registered."
        }
    }
    else
    {
        Write-Error "No valid certificates for SCOM Agent use found."
    }
}
#endregion

#region Certificate Request/Install
Function isCAEnterpriseCA
{
    [OutputType([bool])]
    Param()

    #region constants
    Set-Variable CR_PROP_NONE -Option Constant -Value 0 #Invalid
    Set-Variable CR_PROP_FILEVERSION -Option Constant -Value 1 #String
    Set-Variable CR_PROP_PRODUCTVERSION -Option Constant -Value 2 #String
    Set-Variable CR_PROP_EXITCOUNT -Option Constant -Value 3 #Long
    Set-Variable CR_PROP_EXITDESCRIPTION -Option Constant -Value 4 #String, Indexed
    Set-Variable CR_PROP_POLICYDESCRIPTION -Option Constant -Value 5 #String
    Set-Variable CR_PROP_CANAME -Option Constant -Value 6 #String
    Set-Variable CR_PROP_SANITIZEDCANAME -Option Constant -Value 7 #String
    Set-Variable CR_PROP_SHAREDFOLDER -Option Constant -Value 8 #String
    Set-Variable CR_PROP_PARENTCA -Option Constant -Value 9 #String
    Set-Variable CR_PROP_CATYPE -Option Constant -Value 10 #Long
    Set-Variable CR_PROP_CASIGCERTCOUNT -Option Constant -Value 11 #Long
    Set-Variable CR_PROP_CASIGCERT -Option Constant -Value 12 #Binary, Indexed
    Set-Variable CR_PROP_CASIGCERTCHAIN -Option Constant -Value 13 #Binary, Indexed
    Set-Variable CR_PROP_CAXCHGCERTCOUNT -Option Constant -Value 14 #Long
    Set-Variable CR_PROP_CAXCHGCERT -Option Constant -Value 15 #Binary, Indexed
    Set-Variable CR_PROP_CAXCHGCERTCHAIN -Option Constant -Value 16 #Binary, Indexed
    Set-Variable CR_PROP_BASECRL -Option Constant -Value 17 #Binary, Indexed
    Set-Variable CR_PROP_DELTACRL -Option Constant -Value 18 #Binary, Indexed
    Set-Variable CR_PROP_CACERTSTATE -Option Constant -Value 19 #Long, Indexed
    Set-Variable CR_PROP_CRLSTATE -Option Constant -Value 20 #Long, Indexed
    Set-Variable CR_PROP_CAPROPIDMAX -Option Constant -Value 21 #Long
    Set-Variable CR_PROP_DNSNAME -Option Constant -Value 22 #String
    Set-Variable CR_PROP_ROLESEPARATIONENABLED -Option Constant -Value 23 #Long
    Set-Variable CR_PROP_KRACERTUSEDCOUNT -Option Constant -Value 24 #Long
    Set-Variable CR_PROP_KRACERTCOUNT -Option Constant -Value 25 #Long
    Set-Variable CR_PROP_KRACERT -Option Constant -Value 26 #Binary, Indexed
    Set-Variable CR_PROP_KRACERTSTATE -Option Constant -Value 27 #Binary, Indexed
    Set-Variable CR_PROP_ADVANCEDSERVER -Option Constant -Value 28 #Long
    Set-Variable CR_PROP_TEMPLATES -Option Constant -Value 29 #String
    Set-Variable CR_PROP_BASECRLPUBLISHSTATUS -Option Constant -Value 30 #Long, Indexed
    Set-Variable CR_PROP_DELTACRLPUBLISHSTATUS -Option Constant -Value 31 #Long, Indexed
    Set-Variable CR_PROP_CASIGCERTCRLCHAIN -Option Constant -Value 32 #Binary, Indexed
    Set-Variable CR_PROP_CAXCHGCERTCRLCHAIN -Option Constant -Value 33 #Binary, Indexed
    Set-Variable CR_PROP_CACERTSTATUSCODE -Option Constant -Value 34 #Long, Indexed
    Set-Variable CR_PROP_CAFORWARDCROSSCERT -Option Constant -Value 35 #Binary, Indexed
    Set-Variable CR_PROP_CABACKWARDCROSSCERT -Option Constant -Value 36 #Binary, Indexed
    Set-Variable CR_PROP_CAFORWARDCROSSCERTSTATE -Option Constant -Value 37 #Long, Indexed
    Set-Variable CR_PROP_CABACKWARDCROSSCERTSTATE -Option Constant -Value 38 #Long, Indexed
    Set-Variable CR_PROP_CACERTVERSION -Option Constant -Value 39 #Long, Indexed
    Set-Variable CR_PROP_SANITIZEDCASHORTNAME -Option Constant -Value 40 #String
    Set-Variable CR_PROP_CERTCDPURLS -Option Constant -Value 41 #String, Indexed
    Set-Variable CR_PROP_CERTAIAURLS -Option Constant -Value 42 #String, Indexed
    Set-Variable CR_PROP_CERTAIAOCSPURLS -Option Constant -Value 43 #String, Indexed
    Set-Variable CR_PROP_LOCALENAME -Option Constant -Value 44 #String
    Set-Variable CR_PROP_SUBJECTTEMPLATE_OIDS -Option Constant -Value 45 #String

    Set-Variable PROPTYPE_LONG -Option Constant -Value 0x00000001
    Set-Variable PROPTYPE_DATE -Option Constant -Value 0x00000002
    Set-Variable PROPTYPE_BINARY -Option Constant -Value 0x00000003
    Set-Variable PROPTYPE_MASK -Option Constant -Value 0x000000ff

    Set-Variable CPF_BASE -Option Constant -Value 0x00000001
    Set-Variable CPF_DELTA -Option Constant -Value 0x00000002
    Set-Variable CPF_COMPLETE -Option Constant -Value 0x00000004
    Set-Variable CPF_SHADOW -Option Constant -Value 0x00000008
    Set-Variable CPF_CASTORE_ERROR -Option Constant -Value 0x00000010
    Set-Variable CPF_BADURL_ERROR -Option Constant -Value 0x00000020
    Set-Variable CPF_MANUAL -Option Constant -Value 0x00000040
    Set-Variable CPF_SIGNATURE_ERROR -Option Constant -Value 0x00000080
    Set-Variable CPF_LDAP_ERROR -Option Constant -Value 0x00000100
    Set-Variable CPF_FILE_ERROR -Option Constant -Value 0x00000200
    Set-Variable CPF_FTP_ERROR -Option Constant -Value 0x00000400
    Set-Variable CPF_HTTP_ERROR -Option Constant -Value 0x00000800
    Set-Variable CPF_POSTPONED_BASE_LDAP_ERROR -Option Constant -Value 0x00001000
    Set-Variable CPF_POSTPONED_BASE_FILE_ERROR -Option Constant -Value 0x00002000
    #endregion

    #region ENUM_CATYPES
    Set-Variable ENUM_ENTERPRISE_ROOTCA -Option Constant -Value 0
    Set-Variable ENUM_ENTERPRISE_SUBCA -Option Constant -Value 1
    #Set-Variable ENUM_UNUSED2 -Option Constant -Value 2
    Set-Variable ENUM_STANDALONE_ROOTCA -Option Constant -Value 3
    Set-Variable ENUM_STANDALONE_SUBCA -Option Constant -Value 4
    Set-Variable ENUM_UNKNOWN_CA -Option Constant -Value 5
    #endregion

    $CA = New-Object -ComObject "CertificateAuthority.Admin" -Strict
    try
    {
        $varPropertyValue = $CA.GetCAProperty($SubmitToOnlineAuthority, $CR_PROP_CATYPE, $null, $PROPTYPE_LONG, $null)
    }
    catch [System.Management.Automation.MethodInvocationException]
    {
        if ($error.Exception.InnerException -ne $null -and $error.Exception.InnerException.HResult -eq -2146232828)
        {
            Write-Error "Unable to access online authority.  Check for typos."
            Exit
        }
        else
        {
            throw
        }
    }

    switch ($varPropertyValue)
    {
        $ENUM_ENTERPRISE_ROOTCA {return $True}
        $ENUM_ENTERPRISE_SUBCA {return $True}
        $ENUM_STANDALONE_ROOTCA {return $False}
        $ENUM_STANDALONE_SUBCA {return $False}
        $ENUM_UNKNOWN_CA {return $False}
    }
}

Function createCertificateRequest
{
    [OutputType([string])]
    Param()

    #Useful reference:  http://geekswithblogs.net/shaunxu/archive/2012/01/13/working-with-active-directory-certificate-service-via-c.aspx

    #region Keyspec enum
    #http://msdn.microsoft.com/en-us/library/windows/desktop/aa379409(v=vs.85).aspx
    Set-Variable X509KeySpec_XCN_AT_NONE -Option Constant -Value 0
    Set-Variable X509KeySpec_XCN_AT_KEYEXCHANGE -Option Constant -Value 1
    Set-Variable X509KeySpec_XCN_AT_SIGNATURE -Option Constant -Value 2
    #endregion

    #region X509PrivateKeyUsageFlags enum
    #http://msdn.microsoft.com/en-us/library/windows/desktop/aa379417(v=vs.85).aspx
    Set-Variable X509PrivateKeyUsageFlags_XCN_NCRYPT_ALLOW_USAGES_NONE -Option Constant -Value 0
    Set-Variable X509PrivateKeyUsageFlags_XCN_NCRYPT_ALLOW_DECRYPT_FLAG -Option Constant -Value 0x1
    Set-Variable X509PrivateKeyUsageFlags_XCN_NCRYPT_ALLOW_SIGNING_FLAG -Option Constant -Value 0x2
    Set-Variable X509PrivateKeyUsageFlags_XCN_NCRYPT_ALLOW_KEY_AGREEMENT_FLAG   -Option Constant -Value 0x4
    Set-Variable X509PrivateKeyUsageFlags_XCN_NCRYPT_ALLOW_ALL_USAGES -Option Constant -Value 0xffffff
    #endregion X509PrivateKeyUsageFlags

    #region X509PrivateKeyExportFlags enum
    #http://msdn.microsoft.com/en-us/library/windows/desktop/aa379412(v=vs.85).aspx
    Set-Variable X509PrivateKeyExportFlags_XCN_NCRYPT_ALLOW_EXPORT_NONE -Option Constant -Value 0
    Set-Variable X509PrivateKeyExportFlags_XCN_NCRYPT_ALLOW_EXPORT_FLAG -Option Constant -Value 0x1
    Set-Variable X509PrivateKeyExportFlags_XCN_NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG -Option Constant -Value 0x2
    Set-Variable X509PrivateKeyExportFlags_XCN_NCRYPT_ALLOW_ARCHIVING_FLAG -Option Constant -Value 0x4
    Set-Variable X509PrivateKeyExportFlags_XCN_NCRYPT_ALLOW_PLAINTEXT_ARCHIVING_FLAG -Option Constant -Value 0x8
    #endregion X509PrivateKeyExportFlags

    #region X509PrivateKeyProtection enum
    #http://msdn.microsoft.com/en-us/library/windows/desktop/aa379414(v=vs.85).aspx
    Set-Variable X509PrivateKeyProtection_XCN_NCRYPT_UI_NO_PROTECTION_FLAG -Option Constant -Value 0
    Set-Variable X509PrivateKeyProtection_XCN_NCRYPT_UI_PROTECT_KEY_FLAG -Option Constant -Value 0x1
    Set-Variable X509PrivateKeyProtection_XCN_NCRYPT_UI_FORCE_HIGH_PROTECTION_FLAG -Option Constant -Value 0x2
    Set-Variable X509PrivateKeyProtection_XCN_NCRYPT_UI_FINGERPRINT_PROTECTION_FLAG -Option Constant -Value 0x4
    #endregion X509PrivateKeyProtection

    #region X500NameFlags enum
    #http://msdn.microsoft.com/en-us/library/windows/desktop/aa379394(v=vs.85).aspx
    Set-Variable X500NameFlags_XCN_CERT_NAME_STR_NONE -Option Constant -Value 0
    Set-Variable X500NameFlags_XCN_CERT_SIMPLE_NAME_STR -Option Constant -Value 0x1
    Set-Variable X500NameFlags_XCN_CERT_OID_NAME_STR -Option Constant -Value 0x2
    Set-Variable X500NameFlags_XCN_CERT_X500_NAME_STR -Option Constant -Value 0x3
    Set-Variable X500NameFlags_XCN_CERT_XML_NAME_STR -Option Constant -Value 0x4
    Set-Variable X500NameFlags_XCN_CERT_NAME_STR_DISABLE_IE4_UTF8_FLAG -Option Constant -Value 0x10000
    Set-Variable X500NameFlags_XCN_CERT_NAME_STR_ENABLE_T61_UNICODE_FLAG -Option Constant -Value 0x20000
    Set-Variable X500NameFlags_XCN_CERT_NAME_STR_ENABLE_UTF8_UNICODE_FLAGE -Option Constant -Value 0x40000
    Set-Variable X500NameFlags_XCN_CERT_NAME_STR_FORCE_UTF8_DIR_STR_FLAG -Option Constant -Value 0x80000
    Set-Variable X500NameFlags_XCN_CERT_NAME_STR_DISABLE_UTF8_DIR_STR_FLAG -Option Constant -Value 0x100000
    Set-Variable X500NameFlags_XCN_CERT_NAME_STR_ENABLE_PUNYCODE_FLAG -Option Constant -Value 0x200000
    Set-Variable X500NameFlags_XCN_CERT_NAME_STR_FORWARD_FLAG -Option Constant -Value 0x1000000
    Set-Variable X500NameFlags_XCN_CERT_NAME_STR_REVERSE_FLAG -Option Constant -Value 0x2000000
    Set-Variable X500NameFlags_XCN_CERT_NAME_STR_COMMA_FLAG -Option Constant -Value 0x4000000
    Set-Variable X500NameFlags_XCN_CERT_NAME_STR_CRLF_FLAG -Option Constant -Value 0x8000000
    Set-Variable X500NameFlags_XCN_CERT_NAME_STR_NO_QUOTING_FLAG -Option Constant -Value 0x10000000
    Set-Variable X500NameFlags_XCN_CERT_NAME_STR_NO_PLUS_FLAG -Option Constant -Value 0x20000000
    Set-Variable X500NameFlags_XCN_CERT_NAME_STR_SEMICOLON_FLAG -Option Constant -Value 0x40000000
    #endregion X500NameFlags

    #region X509KeyUsageFlags
    Set-Variable X509KeyUsageFlags_XCN_CERT_NO_KEY_USAGE -Option Constant -Value 0
    Set-Variable X509KeyUsageFlags_XCN_CERT_DIGITAL_SIGNATURE_KEY_USAGE -Option Constant -Value 0x80
    Set-Variable X509KeyUsageFlags_XCN_CERT_NON_REPUDIATION_KEY_USAGE -Option Constant -Value 0x40
    Set-Variable X509KeyUsageFlags_XCN_CERT_KEY_ENCIPHERMENT_KEY_USAGE -Option Constant -Value 0x20
    Set-Variable X509KeyUsageFlags_XCN_CERT_DATA_ENCIPHERMENT_KEY_USAGE -Option Constant -Value 0x10
    Set-Variable X509KeyUsageFlags_XCN_CERT_KEY_AGREEMENT_KEY_USAGE -Option Constant -Value 0x8
    Set-Variable X509KeyUsageFlags_XCN_CERT_KEY_CERT_SIGN_KEY_USAGE -Option Constant -Value 0x4
    Set-Variable X509KeyUsageFlags_XCN_CERT_OFFLINE_CRL_SIGN_KEY_USAGE -Option Constant -Value 0x2
    Set-Variable X509KeyUsageFlags_XCN_CERT_CRL_SIGN_KEY_USAGE -Option Constant -Value 0x2
    Set-Variable X509KeyUsageFlags_XCN_CERT_ENCIPHER_ONLY_KEY_USAGE -Option Constant -Value 0x1
    #Set-Variable X509KeyUsageFlags_XCN_CERT_DECIPHER_ONLY_KEY_USAGE -Option Constant -Value 0x80 << 8
    #endregion X509KeyUsageFlags

    #region AlternativeNameType
    Set-Variable AlternativeNameType_XCN_CERT_ALT_NAME_UNKNOWN -Option Constant -Value 0
    Set-Variable AlternativeNameType_XCN_CERT_ALT_NAME_OTHER_NAME -Option Constant -Value 1
    Set-Variable AlternativeNameType_XCN_CERT_ALT_NAME_RFC822_NAME -Option Constant -Value 2
    Set-Variable AlternativeNameType_XCN_CERT_ALT_NAME_DNS_NAME -Option Constant -Value 3
    Set-Variable AlternativeNameType_XCN_CERT_ALT_NAME_DIRECTORY_NAME -Option Constant -Value 5
    Set-Variable AlternativeNameType_XCN_CERT_ALT_NAME_URL -Option Constant -Value 7
    Set-Variable AlternativeNameType_XCN_CERT_ALT_NAME_IP_ADDRESSL -Option Constant -Value 8
    Set-Variable AlternativeNameType_XCN_CERT_ALT_NAME_REGISTERED_ID -Option Constant -Value 9
    Set-Variable AlternativeNameType_XCN_CERT_ALT_NAME_GUID -Option Constant -Value 10
    Set-Variable AlternativeNameType_XCN_CERT_ALT_NAME_USER_PRINCIPLE_NAME -Option Constant -Value 11
    #endregion

    $sysinfo = Get-WmiObject -Class Win32_ComputerSystem
    $fqdn = “{0}.{1}” -f $sysinfo.Name, $sysinfo.Domain

    #create x500 subject name
    $subject = New-Object -ComObject "X509Enrollment.CX500DistinguishedName" -Strict
    $subject.Encode("CN=" + $fqdn, $X500NameFlags_XCN_CERT_NAME_STR_NONE) #http://msdn.microsoft.com/en-us/library/windows/desktop/aa377054(v=vs.85).aspx

    $privateKey = New-Object -ComObject "X509Enrollment.CX509PrivateKey.1" -Strict
    $privateKey.Length = $KeyLength
    $privateKey.KeySpec = $X509KeySpec_XCN_AT_KEYEXCHANGE 
    $privateKey.KeyUsage = $X509PrivateKeyUsageFlags_XCN_NCRYPT_ALLOW_SIGNING_FLAG
    $privateKey.MachineContext=$true
    $privateKey.ExportPolicy = $X509PrivateKeyExportFlags_XCN_NCRYPT_ALLOW_EXPORT_NONE
    $privateKey.Create()
    
    #create request
    $certReq = New-Object -ComObject "X509Enrollment.CX509CertificateRequestPkcs10" -Strict

    if ([string]::IsNullOrEmpty($UseCertificateTemplate))
    {
        $certReq.InitializeFromPrivateKey($X509CertificateEnrollmentContext_ContextMachine, $privateKey, "")
        $certReq.Subject = $subject

        #prep basics for request
        $csps = New-Object -ComObject "X509Enrollment.CCspInformations" -Strict
        $csps.AddAvailableCsps()

        #do extension key usage stuff
        $eku = New-Object -ComObject "X509Enrollment.CX509ExtensionKeyUsage" -Strict
        $eku.InitializeEncode($X509KeyUsageFlags_XCN_CERT_DIGITAL_SIGNATURE_KEY_USAGE -bor $X509KeyUsageFlags_XCN_CERT_KEY_ENCIPHERMENT_KEY_USAGE)
        $certReq.X509Extensions.Add($eku)

        #do extension enhanced key usage stuff
        $ekuOIDs = New-Object -ComObject "X509Enrollment.CObjectIds" -Strict
        $serverAuthOid = New-Object -ComObject "X509Enrollment.CObjectId" -Strict
        $serverAuthOid.InitializeFromValue("1.3.6.1.5.5.7.3.1")
        $ekuOIDs.Add($serverAuthOid)
        $clientAuthOid = New-Object -ComObject "X509Enrollment.CObjectId" -Strict
        $clientAuthOid.InitializeFromValue("1.3.6.1.5.5.7.3.2")
        $ekuOIDs.Add($clientAuthOid)
        $ekuext = New-Object -ComObject "X509Enrollment.CX509ExtensionEnhancedKeyUsage" -Strict
        $ekuext.InitializeEncode($ekuOIDs)
        $certReq.X509Extensions.Add($ekuext)
    }
    else
    {
        try
        {
            $certReq.InitializeFromPrivateKey($X509CertificateEnrollmentContext_ContextMachine, $privateKey, $UseCertificateTemplate)
        }
        catch [System.Management.Automation.MethodInvocationException]
        {
            Write-Error "The requested certificate template is not supported by this CA. 0x80094800 (-2146875392 CERTSRV_E_UNSUPPORTED_CERT_TYPE)"
            Exit
#For whatever reason the $Error variable is blank.
#            if ($Error.Exception.InnerException -ne $null -and $Error.Exception.InnerException.HResult -eq -2146875392)
#            {
#                Write-Error "The requested certificate template is not supported by this CA. 0x80094800 (-2146875392 CERTSRV_E_UNSUPPORTED_CERT_TYPE)"
#                Exit
#            }
#            else
#            {
#                throw
#            }
       }
       $certReq.Subject = $subject
    }
    $certReq.Encode()
    $enroll = New-Object -ComObject "X509Enrollment.CX509Enrollment" -Strict
    $enroll.InitializeFromRequest($certReq)
    return $enroll.CreateRequest($EncodingType_XCN_CRYPT_STRING_BASE64HEADER) #http://msdn.microsoft.com/en-us/library/windows/desktop/aa377869(v=vs.85).aspx
}

Function submitCertificateRequest
{
    Param
    (
        [Parameter(Mandatory=$True)]$base64
    )
    #region ICertReqeust3 InFlags
    #http://msdn.microsoft.com/en-us/library/windows/desktop/aa385054(v=vs.85).aspx
    Set-Variable CR_IN_BASE64HEADER -Option Constant -Value 0x0 #Unicode BASE64 format with begin/end.
    Set-Variable CR_IN_BASE64 -Option Constant -Value 0x1 #Unicode BASE64 format without begin/end.
    Set-Variable CR_IN_BINARY -Option Constant -Value 0x2 #Binary format.
    Set-Variable CR_IN_ENCODEANY -Option Constant -Value 0xFF #Try all of the CR_IN_BASE64HEADER, CR_IN_BASE64, or CR_IN_BINARY formats.
    Set-Variable CR_IN_ENCODEMASK -Option Constant -Value 0xFF

    Set-Variable CR_IN_FORMATANY -Option Constant -Value 0
    Set-Variable CR_IN_PKCS10 -Option Constant -Value 0x100 #PKCS #10 request.
    Set-Variable CR_IN_KEYGEN -Option Constant -Value 0x200 #Keygen request (Netscape format).
    Set-Variable CR_IN_PKCS7 -Option Constant -Value 0x300 #PKCS #7 request (renewal or registration agent).
    Set-Variable CR_IN_CMC -Option Constant -Value 0x400 #A Certificate Management over CMS (CMC) request.
    Set-Variable CR_IN_CHALLENGERESPONSE -Option Constant -Value 0x500 #The call is a response to a challenge. The RequestId must be passed in the strAttributes parameter and the response to the challenge must be passed in the strRequest parameter. This flag should be turned on when an application needs to send back the decrypted challenge to the CA. You can then call the GetFullResponseProperty method to get the issued end entity certificate. 
    Set-Variable CR_IN_FORMATMASK -Option Constant -Value 0xFF00

    Set-Variable CR_IN_RPC -Option Constant -Value 0x20000 #Return a challenge that can be submitted to a CA. The challenge is a Certificate Management over CMS (CMC) full request. When this flag is turned on, calling the GetFullResponseProperty method with the FR_PROP_FULLRESPONSE flag returns a CMC response that contains key attestation challenge. 
    Set-Variable CR_IN_FULLRESPONSE -Option Constant -Value 0x40000 #Transmit the messages using RPC instead of DCOM.
    Set-Variable CR_IN_CRLS -Option Constant -Value 0x80000 #Include the current certificate revocation lists.
    Set-Variable CR_IN_MACHINE -Option Constant -Value 0x100000 #Use the context of the key service computer.
    Set-Variable CR_IN_ROBO -Option Constant -Value 0x200000 #Indicates that the message is being requested on behalf of another sender.
    Set-Variable CR_IN_CLIENTIDNONE -Option Constant -Value 0x400000 #Do not include in the request data that identifies the client.
    Set-Variable CR_IN_CONNECTONLY -Option Constant -Value 0x800000 #Specifies that the DCOM connection with the server is established, but the request is not submitted.
    Set-Variable CR_IN_RETURNCHALLENGE -Option Constant -Value 0x1000000 #Return a challenge that can be submitted to a CA. The challenge is a Certificate Management over CMS (CMC) full request. When this flag is turned on, calling the GetFullResponseProperty method with the FR_PROP_FULLRESPONSE flag returns a CMC response that contains key attestation challenge. 

    Set-Variable CR_IN_CLIENTFLAGSMASK -Option Constant -Value ($CR_IN_ENCODEMASK -bor $CR_IN_RPC -bor $CR_IN_MACHINE -bor $CR_IN_CLIENTIDNONE -bor $CR_IN_CONNECTONLY -bor $CR_IN_RETURNCHALLENGE)
    #endregion ICertReqeust3 InFlags

    #http://msdn.microsoft.com/en-us/library/windows/desktop/aa385054(v=vs.85).aspx
    $request = New-Object -ComObject "CertificateAuthority.Request" -Strict
    $iDisposition = $null
    try
    {
        $iDisposition = $request.Submit($CR_IN_BASE64HEADER, $base64, "", $SubmitToOnlineAuthority)  #http://support.microsoft.com/kb/910249
    }
    catch [System.Management.Automation.MethodInvocationException]
    {
        if ($error.Exception.InnerException -ne $null -and $error.Exception.InnerException.HResult -eq -2146232828)
        {
            Write-Error "Unable to access online authority.  Check for typos and network connectivity."
            Exit
        }
        else
        {
            throw
        }
    }

    switch ($iDisposition)
    {
        $CR_DISP_INCOMPLETE {Write-Host "Certificate Request denied"}
        $CR_DISP_ERROR {Write-Host "Certificate Request failed"}
        $CR_DISP_DENIED {Write-Host "Certificate Request did not complete"}
        $CR_DISP_ISSUED
            {
                Write-Host "Certificate issued"
                return $request.GetRequestId()
            }
        $CR_DISP_ISSUED_OUT_OF_BAND {Write-Host "Certificate issued separately"}
        $CR_DISP_UNDER_SUBMISSION
            {
                $requestId = $request.GetRequestId()
                Write-Warning "Request taken under submission"
                Write-Warning "Please have the Certificate Authority administrator issue this certificate."
                Write-Warning "Retain this requestID for the CA admin's use and to retrieve the issued certificate."
                Write-Host
                Write-Host "RequestID:  " $requestId
                Write-Host
                Write-Host "Re-run this script after the certificate is issued with the following syntax."
                Write-Host ".\MOMCertImport.ps1 -SubmitToOnlineAuthority `"$SubmitToOnlineAuthority`" -RequestId" $requestId -ForegroundColor Green
            }
        default {Write-Host "Request:  Unknown Error:  " $iDisposition}
    }
    return -1
}

Function GetCertFromCA
{
    
    Param
    (
        [Parameter(Mandatory=$True)][Int]$RequestId
    )

    Set-Variable CR_OUT_BASE64HEADER -Option Constant -Value 0
    Set-Variable CR_OUT_BASE64 -Option Constant -Value 0x1
    Set-Variable CR_OUT_BINARY -Option Constant -Value 0x2
    Set-Variable CR_OUT_BASE64REQUESTHEADER -Option Constant -Value 0x3
    Set-Variable CR_OUT_HEX -Option Constant -Value 0x4
    Set-Variable CR_OUT_HEXASCII -Option Constant -Value 0x5
    Set-Variable CR_OUT_BASE64X509CRLHEADER -Option Constant -Value 0x9
    Set-Variable CR_OUT_HEXADDR -Option Constant -Value 0xa
    Set-Variable CR_OUT_HEXASCIIADDR -Option Constant -Value 0xb
    Set-Variable CR_OUT_HEXRAW -Option Constant -Value 0xc
    Set-Variable CR_OUT_ENCODEMASK -Option Constant -Value 0xff
    Set-Variable CR_OUT_CHAIN -Option Constant -Value 0x100
    Set-Variable CR_OUT_CRLS -Option Constant -Value 0x200
    Set-Variable CR_OUT_NOCRLF -Option Constant -Value 0x40000000
    Set-Variable CR_OUT_NOCR -Option Constant -Value 0x80000000

    $certReq = New-Object -ComObject "CertificateAuthority.Request" -Strict
    $iDisposition = $certReq.RetrievePending($RequestId, $SubmitToOnlineAuthority)

    switch ($iDisposition)
    {
        $CR_DISP_INCOMPLETE {Write-Host "Certificate Retrieval denied"}
        $CR_DISP_ERROR {Write-Host "Certificate Retrieval failed"}
        $CR_DISP_DENIED
            {
                Write-Host "Certificate Retrieval did not complete.  Things to check:"
                Write-Host " - Check RequestID and make sure it is valid."
                Write-Host " - Certifcate Authority Administrator may have denied the request."
            }
        $CR_DISP_ISSUED_OUT_OF_BAND {Write-Host "Certificate Retrieval issued separately"}
        $CR_DISP_UNDER_SUBMISSION
            {
                Write-Warning "Certificate Request is pending issue"
                Write-Host
                Write-Host "Re-run this script after the certificate is issued with the following syntax."
                Write-Host ".\MOMCertImport.ps1 -SubmitToOnlineAuthority `"$SubmitToOnlineAuthority`" -RequestId" $requestId -ForegroundColor Green
            }
        $CR_DISP_ISSUED
            {
                $base64Cert = $null
                $base64Cert = $certReq.GetCertificate($CR_OUT_BASE64REQUESTHEADER)
                if ($base64Cert -ne $null)
                {
                    Write-Host "Certificate retrieved..."
                }
                else
                {
                    Write-Host "The certifcate was not retrieved."
                    Write-Host "The request ID could be incorrect or it could have been retrieved already."
                }
                return $base64Cert
            }
        default {Write-Host "Retrieval:  Unknown Error:"  $iDisposition}
    }

    return $null
}

Function InstallCertificateResponse
{
    Param
    (
        [Parameter(Mandatory=$True)][System.Array]$base64Header
    )

    #InstallResponseRestrictionFlags enum
    Set-Variable InstallResponseRestrictionFlags_AllowNone -Option Constant -Value 0
    Set-Variable InstallResponseRestrictionFlags_AllowNoOutstandingRequest -Option Constant -Value 0x1
    Set-Variable InstallResponseRestrictionFlags_AllowUntrustedCertificate -Option Constant -Value 0x2
    Set-Variable InstallResponseRestrictionFlags_AllowUntrustedRoot -Option Constant -Value 0x4
    #end InstallResponseRestrictionFlags

    Write-Host "Attempting to install the Certificate..."
    $enroll = New-Object -ComObject "X509Enrollment.CX509Enrollment" -Strict
    $enroll.Initialize($X509CertificateEnrollmentContext_ContextMachine)
    #$enroll.InitializeFromRequest($certReq)
    try
    {
        $enroll.InstallResponse($InstallResponseRestrictionFlags_AllowUntrustedCertificate, $base64Header, $EncodingType_XCN_CRYPT_STRING_BASE64HEADER, $null)
    }
    catch [System.Management.Automation.MethodInvocationException]
    {
        if ($error.Exception.InnerException -ne $null -and $error.Exception.Innerexception.HResult -eq -2146232828)
        {
            Write-Host "Check the following  0x80092004 (CRYPT_E_NOT_FOUND):"
            Write-Host " - This certificate might have been retrieved previously."
            Write-Host " - The Certificate Authority Root is not trusted."
            Write-Error "Unable to install this certificate:"
            Exit
        }
    }
    Write-Host "Certificate installed..."

    ###TODO:  Figure out how to retrieve the SerialNumber or Thumbprint so that it can be passed back and then imported for SCOM agent in one step
    #$certReq = New-Object -ComObject "X509Enrollment.CX509CertificateRequestPkcs10" -Strict
    #$certReq.InitializeFromCertificate($X509CertificateEnrollmentContext_ContextMachine, $enroll.Certificate($EncodingType_XCN_CRYPT_STRING_BASE64), $EncodingType_XCN_CRYPT_STRING_BASE64, 0)
}
#endregion

Function Main
{
    switch($PsCmdlet.ParameterSetName)
    {
        "Remove" #remove the SCOM agent configuration to use a certificate
            {
                if (isUserAdministrator)
                {
                    Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Microsoft Operations Manager\3.0\Machine Settings" -Name ChannelCertificateHash -ErrorAction SilentlyContinue
                    Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Microsoft Operations Manager\3.0\Machine Settings" -Name ChannelCertificateSerialNumber -ErrorAction SilentlyContinue
                }
                else
                {
                    Write-Error "`Error:  This process is not running under administrative context!  Can not delete values."
                }
            }
        "CreateCertificateRequest" #request a certificate and, if issued, retrive and install
            {
                if (isUserAdministrator)
                {
                    if ([string]::IsNullOrEmpty($Path) -and [string]::IsNullOrEmpty($SubmitToOnlineAuthority))
                    {
                        Write-Error "Either -Path OR -SubmitToOnlineAuthority switches need to be specified."
                        return
                    }

                    $base64Request = createCertificateRequest
                    if (![string]::IsNullOrEmpty($Path))
                    {
                        $base64Request|Out-File -FilePath $Path -Encoding ascii -Force
                    }
        
                    if (![string]::IsNullOrEmpty($SubmitToOnlineAuthority))
                    {
                        $requestId = submitCertificateRequest $base64Request
                        if ($requestId -ne -1)
                        {
                            $base64Response = $null
                            $base64Response = GetCertFromCA $requestId
                            if ($base64Response -ne $null)
                            {
                                InstallCertificateResponse $base64Response
                            }
                        }
                    }
                }
                else
                {
                    Write-Warning "Script is not running under administrative context.  No certificate can be requested."
                }           }
        "GetCertificateResponse" #retrieve and install an issued certificate
            {
                if (isUserAdministrator)
                {
                    $base64Response = $null
                    $base64Response = GetCertFromCA $requestId
                    if ($base64Response -ne $null)
                    {
                        InstallCertificateResponse $base64Response
                    }
                }
                else
                {
                    Write-Warning "Script is not running under administrative context.  No certificate can be retrieved."
                }
            }
        "InstallFromPFX" #install PFX file and register
            {
                if (!(Test-Path $Path))
                {
                    Write-Error "Specified certificate file not found"
                    Exit 1
                }
                elseif ((Get-Item $Path).Extension -ne ".pfx")
                {
                    Write-Error "This is not a Personal Information Exchange file format."
                    Exit 1
                }
                else
                {
                    $result = checkCertificateFile
                    if ($Error.Count -gt 0)
                    {
                        Exit 1
                    }
                    elseif ($result)
                    {
                        Write-Host "SCOM Agent certificate successfully registered."
                        Exit 0
                    }
                }
            }
        "InstallBestFitFromLocalStore" #select the first valid cert and install
            {
                $result = checkLocalCertificates $PsCmdlet.ParameterSetName
                $Error|fl -f *
                if ($Error.Count -gt 0)
                {
                    Exit 1
                }
                elseif ($result)
                {
                    Write-Host "SCOM Agent certificate successfully registered."
                    Exit 0
                }
            }
        "InstallBestFitFromSerialNumber"
            {
                $result = checkLocalCertificates $PsCmdlet.ParameterSetName $SerialNumber
                if ($Error.Count -gt 0)
                {
                    Exit 1
                }
                elseif ($result)
                {
                    Write-Host "SCOM Agent certificate successfully registered."
                    Exit 0
                }
            }
        "CheckCurrentConfig"
            {
                $regValue = getChannelCertificateSerialNumberRegValue
                if ($regValue -eq $null)
                {
                    #stdout should be null so SCCM should translate this as "Not Installed"
                    Exit 0
                }
                $SerialNumber = convertChannelCertificateSerialNumberValueToSerialNumber $regValue

                $ValidateOnly = $True
                $result = checkLocalCertificates $PsCmdlet.ParameterSetName $SerialNumber
                if ($Error.Count -gt 0)
                {
                    Exit 1
                }
                elseif ($result)
                {
                    Write-Host "SCOM Agent certificate successfully registered."
                    Exit 0
                }
                else #pass back value 0 because the script completed, but the certificate isn't valid for SCOM or missing
                {
                    Exit 0
                }
            }
    }
}

$Error.Clear()
Main