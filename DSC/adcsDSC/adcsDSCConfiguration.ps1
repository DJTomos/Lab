$DscWorkingFolder = $PSScriptRoot



configuration CertificateServices
{
   param
   (        

        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]$AdminCreds,

		[Parameter(Mandatory)]
		[String]$Subject,
		
		[Parameter(Mandatory)]
        [String]$useAdDomainNameForExternalDNS,

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

	if($useAdDomainNameForExternalDNS -eq "true")
	{
		$pkiFQDN = "pki.$DomainName"
		$adfsFQDN = "adfs.$DomainName"
	}
	else
	{
		$pkiFQDN = $subject
		$adfsFQDN = $subject
	}

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
						& "$($ENV:SystemRoot)\System32\inetsrv\appcmd.exe" set site "Default Web Site" /bindings:http/*:81:
						& "$($ENV:SystemRoot)\System32\inetsrv\appcmd.exe" add vdir /app.name:"Default Web Site/" /path:"/CertEnroll" /physicalPath:"C:\windows\System32\CertSrv\Certenroll"
						& "$($ENV:SystemRoot)\System32\inetsrv\appcmd.exe" set config "Default Web Site/CertEnroll" /section:directoryBrowse /enabled:true
						& "$($ENV:SystemRoot)\System32\inetsrv\appcmd.exe" set config "Default Web Site/CertEnroll" /section:requestfiltering /allowdoubleescaping:true
						& "$($ENV:SystemRoot)\System32\iisreset.exe"				
						$s = $using:pkiFQDN
						$CRLURLs = "65:C:\Windows\System32\CertSrv\CertEnroll\%3%8%9.crl\n6:http://$s`:81/certenroll/%3%8%9.crl"
						& "$($ENV:SystemRoot)\System32\certutil.exe" -setreg CA\CRLPublicationURLs $CRLURLs						
						$AIAURLs = "1:C:\Windows\system32\CertSrv\CertEnroll\%1_%3%4.crt\n2:http://$s`:81/certEnroll/%1_%3%4.crt"
						& "$($ENV:SystemRoot)\System32\certutil.exe" -setreg CA\CACertPublicationURLs $AIAURLs					
						Restart-Service -Name CertSvc								
			}							
			
			TestScript = {	
					$s = $using:pkiFQDN
					$d         = $($using:shortDomain).ToLower()
					$c         = $($using:ComputerName).ToUpper()
					$shortname = "$d-$c-CA"
					$CRLURL = "6:http://$s`:81/certenroll/%3%8%9.crl"				
					$crl = (Get-ItemProperty -path "HKLM:\system\CurrentControlSet\Services\CertSvc\Configuration\$shortname").CRLPublicationURLs[1]
					if($crl -eq $CRLURL)
					{
						return $true
					}
					else
					{
						return $false
					}
			}
			GetScript =  { @{} }
			DependsOn = '[Script]CopyRoot'
		}   	   

		xCertReq SSLCert
		{
			CARootName                = "$CARootName"
			CAServerFQDN              = "$ComputerName.$DomainName"
			#Subject                   = "$Subject"
			Subject                   = "$adfsFQDN"
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
						#$s = $using:subject
						$s = $using:adfsFQDN			
						write-verbose "subject = $s"
						$cert = Get-ChildItem Cert:\LocalMachine\My | where {$_.Subject -eq "CN=$s"}
						Export-PfxCertificate -FilePath "c:\src\$s.pfx" -Cert $cert -Password $using:CertPw
			}
			GetScript  = { @{ 
								#$s = $using:subject
								$s = $using:adfsFQDN						
								Result = (Get-Content "C:\src\$s.pfx") } 
			}
			TestScript = {
						#$s = $using:subject
						$s = $using:adfsFQDN							
						return Test-Path "C:\src\$s.pfx" 
			}
			DependsOn  = '[xCertReq]SSLCert'
		}	        
	}
	Stop-Transcript
}
