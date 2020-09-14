$DscWorkingFolder = $PSScriptRoot

configuration DomainController
{
   param
   (
        [Parameter(Mandatory)]
        [String]$Subject,

        [Parameter(Mandatory)]
        [Int]$ADFSFarmCount,

        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]$AdminCreds,

        [Parameter(Mandatory)]
        [String]$ADFSIPAddress,

		[Parameter(Mandatory)]
		[Object]$usersArray,

		[Parameter(Mandatory)]
		[System.Management.Automation.PSCredential]$UserCreds,

        [Int]$RetryCount=20,
        [Int]$RetryIntervalSec=30
    )
    
    $wmiDomain      = Get-WmiObject Win32_NTDomain -Filter "DnsForestName = '$( (Get-WmiObject Win32_ComputerSystem).Domain)'"
    $shortDomain    = $wmiDomain.DomainName
    $DomainName     = $wmidomain.DnsForestName
    $ComputerName   = $wmiDomain.PSComputerName
    #$CARootName     = "$($shortDomain.ToLower())-$($ComputerName.ToUpper())-CA"
    #$CAServerFQDN   = "$ComputerName.$DomainName"

    $CertPw         = $AdminCreds.Password
    $ClearPw        = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($CertPw))
	$ClearDefUserPw = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($UserCreds.Password))

    Import-DscResource -ModuleName xComputerManagement,xNetworking,xSmbShare,xAdcsDeployment,xCertificate,PSDesiredStateConfiguration

    [System.Management.Automation.PSCredential]$DomainCreds = New-Object System.Management.Automation.PSCredential ("${shortDomain}\$($Admincreds.UserName)", $Admincreds.Password)
    
    Node 'localhost'
    {
        LocalConfigurationManager
        {
            DebugMode = 'All'
            RebootNodeIfNeeded = $true
        }

        WindowsFeature RSAT-ADCS-Mgmt
        {
            Ensure = 'Present'
            Name = 'RSAT-ADCS-Mgmt'
        }  
    }
}