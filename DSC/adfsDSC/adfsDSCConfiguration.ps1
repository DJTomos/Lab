Configuration Main
{
    Param 
    ( 
        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]$AdminCreds,

        [Parameter(Mandatory)]
        [String]$ADCSname
,

        [Int]$RetryCount=20,
        [Int]$RetryIntervalSec=30
    )

    $wmiDomain = Get-WmiObject Win32_NTDomain -Filter "DnsForestName = '$( (Get-WmiObject Win32_ComputerSystem).Domain)'"
    $shortDomain = $wmiDomain.DomainName
    $domainName = $wmiDomain.DnsForestName
    $ADCSFQDN = "$ADCSname.$domainName"
    $CARootName     = "$($shortDomain.ToLower())-$($ADCSname.ToUpper())-CA"

    Import-DscResource -ModuleName PSDesiredStateConfiguration,xCertificate

    [System.Management.Automation.PSCredential]$DomainCreds = New-Object System.Management.Automation.PSCredential ("${shortDomain}\$($AdminCreds.UserName)", $AdminCreds.Password)
        
    Node localhost
    {
        LocalConfigurationManager            
        {            
            DebugMode = 'All'
            ActionAfterReboot = 'ContinueConfiguration'            
            ConfigurationMode = 'ApplyOnly'            
            RebootNodeIfNeeded = $true
        }

        WindowsFeature installADFS  #install ADFS
        {
            Ensure = "Present"
            Name   = "ADFS-Federation"
        }
<#
        xCertReq "SSLCert"
		{
			CARootName                = "$CARootName" 
			CAServerFQDN              = "$ADCSFQDN"
			Subject                   = "$Subject"
			KeyLength                 = 2048
			Exportable                = $true
			ProviderName              = '"Microsoft RSA SChannel Cryptographic Provider"'
			OID                       = '1.3.6.1.5.5.7.3.1'
			KeyUsage                  = '0xa0'
			CertificateTemplate       = 'WebServer'
			AutoRenew                 = $true
			Credential                = $DomainCreds			
		}
#>
        
        Script SaveCert
        {
            SetScript  = {
				#install the certificate(s) that will be used for ADFS Service
                $cred=$using:DomainCreds
                #$wmiDomain = $using:wmiDomain
                #$DCName = $wmiDomain.DomainControllerName
                $PathToCert="$using:ADCSFQDN\src\*.pfx"
                $CertFile = Get-ChildItem -Path $PathToCert
				for ($file=0; $file -lt $CertFile.Count; $file++)
				{
					$Subject   = $CertFile[$file].BaseName
					$CertPath  = $CertFile[$file].FullName
					$cert      = Import-PfxCertificate -Exportable -Password $cred.Password -CertStoreLocation cert:\localmachine\my -FilePath $CertPath
				}
            }

            GetScript =  { @{} }

            TestScript = { 
                #$wmiDomain = $using:wmiDomain
                #$DCName = $wmiDomain.DomainControllerName
                $PathToCert="$using:ADCSFQDN\src\*.pfx"
                $File = Get-ChildItem -Path $PathToCert
                $Subject=$File.BaseName
                $cert = Get-ChildItem Cert:\LocalMachine\My | where {$_.Subject -eq "CN=$Subject"} -ErrorAction SilentlyContinue
                return ($cert -ine $null)   #if not null (if we have the cert) return true
            }
        }
        #>
        <#
        Script InstallAADConnect
        {
            SetScript = {
                $AADConnectDLUrl="https://download.microsoft.com/download/B/0/0/B00291D0-5A83-4DE7-86F5-980BC00DE05A/AzureADConnect.msi"
                $exe="$env:SystemRoot\system32\msiexec.exe"

                $tempfile = [System.IO.Path]::GetTempFileName()
                $folder = [System.IO.Path]::GetDirectoryName($tempfile)

                $webclient = New-Object System.Net.WebClient
                $webclient.DownloadFile($AADConnectDLUrl, $tempfile)

                Rename-Item -Path $tempfile -NewName "AzureADConnect.msi"
                $MSIPath = $folder + "\AzureADConnect.msi"

                Invoke-Expression "& `"$exe`" /i $MSIPath /qn /passive /forcerestart"
            }

            GetScript =  { @{} }
            TestScript = { 
                return Test-Path "$env:TEMP\AzureADConnect.msi" 
            }
            DependsOn  = '[Script]SaveCert','[WindowsFeature]installADFS'
        }
        #>
    }
}
