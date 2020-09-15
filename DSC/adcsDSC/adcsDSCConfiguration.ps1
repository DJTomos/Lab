$DscWorkingFolder = $PSScriptRoot

configuration CertificateServices
{
   param
   (        

        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]$AdminCreds,

        [Int]$RetryCount=20,
        [Int]$RetryIntervalSec=30
    )
    
    $wmiDomain      = Get-WmiObject Win32_NTDomain -Filter "DnsForestName = '$( (Get-WmiObject Win32_ComputerSystem).Domain)'"
    $shortDomain    = $wmiDomain.DomainName
    $DomainName     = $wmidomain.DnsForestName
    $ComputerName   = $wmiDomain.PSComputerName
    $CARootName     = "$($shortDomain.ToLower())-$($ComputerName.ToUpper())-CA"
    $CAServerFQDN   = "$ComputerName.$DomainName"

	$CertPw         = $AdminCreds.Password
	#$ClearPw        = [System.Net.NetworkCredential]::new("", $CertPw).Password
    #$ClearPw        = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($CertPw))
	#$ClearDefUserPw = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($UserCreds.Password))

    Import-DscResource -ModuleName xComputerManagement,xNetworking,xSmbShare,xAdcsDeployment,xCertificate,PSDesiredStateConfiguration

    [System.Management.Automation.PSCredential]$DomainCreds = New-Object System.Management.Automation.PSCredential ("${shortDomain}\$($Admincreds.UserName)", $Admincreds.Password)
    
    Node localhost
    {
        LocalConfigurationManager
        {
            DebugMode = 'All'
            RebootNodeIfNeeded = $true
        }

        WindowsFeature ADCS-Cert-Authority
        {
            Ensure = 'Present'
            Name = 'ADCS-Cert-Authority'
        }

        WindowsFeature RSAT-ADCS-Mgmt
        {
            Ensure = 'Present'
            Name = 'RSAT-ADCS-Mgmt'
        }

        File SrcFolder
        {
            DestinationPath = "C:\src"
            Type = "Directory"
            Ensure = "Present"
        }

        xSmbShare SrcShare
        {
            Ensure = "Present"
            Name = "src"
            Path = "C:\src"
            FullAccess = @("Domain Admins","Domain Computers")
            ReadAccess = "Authenticated Users"
            DependsOn = "[File]SrcFolder"
        }

        xADCSCertificationAuthority ADCS
        {
            Ensure = 'Present'
            Credential = $DomainCreds
            CAType = 'EnterpriseRootCA'
            DependsOn = '[WindowsFeature]ADCS-Cert-Authority'             
        }

        WindowsFeature ADCS-Web-Enrollment
        {
            Ensure = 'Present'
            Name = 'ADCS-Web-Enrollment'
            DependsOn = '[WindowsFeature]ADCS-Cert-Authority','[WindowsFeature]ADCS-Cert-Authority'
        }

        xADCSWebEnrollment CertSrv
        {
            Ensure = 'Present'
            IsSingleInstance = 'Yes'
            Credential = $DomainCreds
            DependsOn = '[WindowsFeature]ADCS-Web-Enrollment','[xADCSCertificationAuthority]ADCS'
        }
        <#
		Script ExportRoot
		{
			SetScript = {
							$arr       = $($using:DomainName).split('.')
							$d         = $($using:shortDomain).ToLower()
							$c         = $($using:ComputerName).ToUpper()
							$shortname = "$d-$c-CA"
                            $rootName  = "CN={0}, {1}" -f $shortname, [string]::Join(", ", ($arr | % { "DC={0}" -f $_ }))

							$rootcert  = Get-ChildItem Cert:\LocalMachine\CA | where {$_.Subject -eq "$rootName"}
							if ($rootcert -eq $null) {
							    Write-Verbose "ERROR: ROOT CERT `"$rootName`" NOT FOUND, cancelling cert export"
							} else {
								$root      = if ($rootcert.GetType().BaseType.Name -eq "Array") {$rootCert[0]} else {$rootCert}
								Export-Certificate -FilePath "c:\src\$shortname.cer" -Cert $root
							}

						}
			TestScript = {
					$arr       = $($using:DomainName).split('.')
					$d         = $($using:shortDomain).ToLower()
					$c         = $($using:ComputerName).ToUpper()
					$shortname = "$d-$c-CA"
					return Test-Path "C:\src\$shortname.cer"
			}
			GetScript = { @{} }
			DependsOn = '[xADCSWebEnrollment]CertSrv'
		}       
        

		xCertReq "SSLCert"
		{
			CARootName                = "$CARootName"
			CAServerFQDN              = "$ComputerName.$DomainName"
			Subject                   = "$Subject"
			KeyLength                 = 2048
			Exportable                = $true
			ProviderName              = '"Microsoft RSA SChannel Cryptographic Provider"'
			OID                       = '1.3.6.1.5.5.7.3.1'
			KeyUsage                  = '0xa0'
			CertificateTemplate       = 'WebServer'
			AutoRenew                 = $true
			Credential                = $DomainCreds
			DependsOn                 = '[Script]ExportRoot'
		}

		Script "SaveCert"
		{
			SetScript  = {
								$s = $using:subject;								
								write-verbose "subject = $s";
								$cert = Get-ChildItem Cert:\LocalMachine\My | where {$_.Subject -eq "CN=$s"}
								Export-PfxCertificate -FilePath "c:\src\$s.pfx" -Cert $cert -Password (ConvertTo-SecureString $Using:ClearPw -AsPlainText -Force)
							}

			GetScript  = { @{ 
								$s = $using:subject;								
								Result = (Get-Content "C:\src\$s.pfx") } 
							}
			TestScript = {
							$s = $using:subject;							
							return Test-Path "C:\src\$s.pfx" 
							}
			DependsOn  = "[xCertReq]SSLCert"
		}
		#>
		<#
		Script "UpdateDNS"
		{
			SetScript  = {
							$NodeAddr  = ([int]$($using:instance) + [int]$($using:adfsStartIpNodeAddress)) - 1
							$IPAddress = "$($using:adfsNetworkString)$NodeAddr"

							$s        = $using:subject;
							$s        = $s -f $using:instance
							$ZoneName = $s
							$Zone     = Add-DnsServerPrimaryZone -Name $ZoneName -ReplicationScope Forest -PassThru
							$rec      = Add-DnsServerResourceRecordA -ZoneName $ZoneName -Name "@" -AllowUpdateAny -IPv4Address $IPAddress
							}

			GetScript =  { @{} }
			TestScript = { 
				$s        = $using:subject;
				$s        = $s -f $using:instance
				$ZoneName = $s
				$Zone = Get-DnsServerZone -Name $ZoneName -ErrorAction SilentlyContinue
				return ($Zone -ine $null)
			}
		}
		#>		        
    }
}