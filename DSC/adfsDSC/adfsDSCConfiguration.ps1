Configuration Main
{
    Param 
    ( 
        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]$AdminCreds,

        [Parameter(Mandatory)]
        [String]$ADCSname,

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
        
        Script SaveCert
        {
            SetScript  = {
				#install the certificate(s) that will be used for ADFS Service
                
                #$wmiDomain = $using:wmiDomain
                #$DCName = $wmiDomain.DomainControllerName
                $cred=$using:DomainCreds
                $PathToCert="\\$using:ADCSFQDN\src" #Cannot find path 'C:\\windows\\system32\\TSTX-CS.TomTest8.nl\\src' because it does not exist.   $PathToCert="\\$using:ADCSFQDN\src\*.pfx"
                $drive = New-PSDrive -Name P -PSProvider FileSystem -Root $PathToCert -credential $cred
                $CertFile = Get-ChildItem -Path "P:\*.pfx"
                $CertPath  = $CertFile.FullName
                Import-PfxCertificate -Exportable -Password $cred.Password -CertStoreLocation cert:\localmachine\my -FilePath $CertPath
                Remove-PSDrive $drive	
            }

            GetScript =  { @{} }

            TestScript = { 
                #$wmiDomain = $using:wmiDomain
                #$DCName = $wmiDomain.DomainControllerName
                $cred=$using:DomainCreds
                $PathToCert="\\$using:ADCSFQDN\src"
                $drive = New-PSDrive -Name P -PSProvider FileSystem -Root $PathToCert -credential $cred
                $File = Get-ChildItem -Path "P:\*.pfx"
                $Subject=$File.BaseName
                $cert = Get-ChildItem Cert:\LocalMachine\My | where {$_.Subject -eq "CN=$Subject"} -ErrorAction SilentlyContinue
                Remove-PSDrive $drive
                return ($cert -ne $null)   #if not null (if we have the cert) return true
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
