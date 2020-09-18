$DscWorkingFolder = $PSScriptRoot



configuration CertificateServices
{
   param
   (        

        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]$AdminCreds,

		[Parameter(Mandatory)]
        [String]$Subject,

        [Int]$RetryCount=20,
        [Int]$RetryIntervalSec=30
    )
    md c:\tom -ErrorAction Ignore
	Start-Transcript -Path "c:\tom\log.txt"
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
	Import-Module WebAdministration

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
            DependsOn = '[File]SrcFolder'
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
		

		WindowsFeature Web-Mgmt-Console
        {
            Ensure = 'Present'
            Name = 'Web-Mgmt-Console'
            DependsOn = '[WindowsFeature]ADCS-Web-Enrollment'
		}	

        xADCSWebEnrollment CertSrv
        {
            Ensure = 'Present'
            IsSingleInstance = 'Yes'
            Credential = $DomainCreds
            DependsOn = '[WindowsFeature]ADCS-Web-Enrollment','[xADCSCertificationAuthority]ADCS'
		}

		Script CopyRoot
		{
			SetScript = {
				$d         = $($using:shortDomain).ToLower()
				$c         = $($using:ComputerName).ToUpper()
				$shortname = "$d-$c-CA"
				Copy-Item -Path "C:\Windows\System32\Certsrv\CertEnroll\*.crt" -Destination "c:\src\$shortname.crt" -Force
			}
			TestScript = {					
					$d         = $($using:shortDomain).ToLower()
					$c         = $($using:ComputerName).ToUpper()
					$shortname = "$d-$c-CA"
					return Test-Path "C:\src\$shortname.crt"
			}
			GetScript = { @{} }
			DependsOn = '[xADCSWebEnrollment]CertSrv'
		}
		
		Script ConfigureADCS
		{
			SetScript  = {	
						$crllist = Get-CACrlDistributionPoint 
						foreach ($crl in $crllist) {
							Remove-CACrlDistributionPoint $crl.uri -Force
						}
						Add-CACRLDistributionPoint -Uri "C:\Windows\System32\CertSrv\CertEnroll\%3%8%9.crl" -PublishToServer -PublishDeltaToServer -Force
						Add-CACRLDistributionPoint -Uri "http://$Subject`:81/certenroll/%3%8%9.crl" -AddToCertificateCDP -AddToFreshestCrl -Force

						$aialist = Get-CAAuthorityInformationAccess
						foreach ($aia in $aialist) {
							Remove-CAAuthorityInformationAccess $aia.uri -Force
						}
						#certutil -setreg CA\CACertPublicationURLs "1:C:\Windows\system32\CertSrv\CertEnroll\%1_%3%4.crt"
						Add-CAAuthorityInformationAccess -uri "http://$Subject`:81/certEnroll/%1_%3%4.crt" -AddToCertificateAia -Force

						restart-service certsvc
						start-sleep -s 5		
			}
						<#
						New-Item "IIS:\Sites\Default Web Site\CertEnroll" -itemtype VirtualDirectory -physicalPath "c:\Windows\System32\CertSrv\Certenroll"
						Set-WebConfiguration -Filter "/system.webServer/directoryBrowse" -Value true -PSPath "IIS:\Sites\Default Web Site\CertEnroll"
						Set-WebConfigurationproperty -Filter "/system.webServer/Security/requestFiltering" -name allowdoubleescaping -Value true -PSPath "IIS:\Sites\Default Web Site"
						Set-WebConfigurationproperty -Filter "/system.webServer/Security/requestFiltering" -name allowdoubleescaping -Value true -PSPath "IIS:\Sites\Default Web Site\CertEnroll"
						Set-WebBinding -Name "Default Web Site" -BindingInformation "*:80:" ‑PropertyName Port -Value 81

								Start-Process "iisreset.exe" -NoNewWindow -Wait	
						#restart-service w3svc
						
						






						If ($Using:Node.CADistinguishedNameSuffix) {
            & "$($ENV:SystemRoot)\system32\certutil.exe" -setreg CA\DSConfigDN "CN=Configuration,$($Using:Node.CADistinguishedNameSuffix)"
            & "$($ENV:SystemRoot)\system32\certutil.exe" -setreg CA\DSDomainDN "$($Using:Node.CADistinguishedNameSuffix)"
        }
        If ($Using:Node.CRLPublicationURLs) {
            & "$($ENV:SystemRoot)\System32\certutil.exe" -setreg CA\CRLPublicationURLs $($Using:Node.CRLPublicationURLs)
        }
        If ($Using:Node.CACertPublicationURLs) {
            & "$($ENV:SystemRoot)\System32\certutil.exe" -setreg CA\CACertPublicationURLs $($Using:Node.CACertPublicationURLs)
        }
        Restart-Service -Name CertSvc
				#> 	
					
					
			
			TestScript = {					
					$crl = Get-CACrlDistributionPoint
					if($crl -eq $null)
					{
						return $false
					}
					else
					{
						return $true
					}
			}
			GetScript = { @{} }
			DependsOn = '[Script]CopyRoot'
		}   
	   

		xCertReq SSLCert
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
			DependsOn                 = '[Script]ConfigureADCS'
		}
		
		Script SaveCert
		{
			SetScript  = {
						$s = $using:subject			
						write-verbose "subject = $s"
						$cert = Get-ChildItem Cert:\LocalMachine\My | where {$_.Subject -eq "CN=$s"}
						Export-PfxCertificate -FilePath "c:\src\$s.pfx" -Cert $cert -Password $using:CertPw
			}
			GetScript  = { @{ 
								$s = $using:subject								
								Result = (Get-Content "C:\src\$s.pfx") } 
			}
			TestScript = {
						$s = $using:subject							
						return Test-Path "C:\src\$s.pfx" 
			}
			DependsOn  = '[xCertReq]SSLCert'
		}	        
	}
	Stop-Transcript
}
