param (
    [Parameter(Mandatory)]
    [string]$ADCSFQDN,

    [Parameter(Mandatory)]
    [string]$adminuser,

    [Parameter(Mandatory)]
    [string]$password,

    [Parameter(Mandatory)]
    [string]$useAdDomainNameForExternalDNS,

    [Parameter(Mandatory)]
	[string]$DnsForestName,

	[Parameter(Mandatory)]
	[string]$WapFqdn
)
$ErrorActionPreference = "Stop"
$arr = $ADCSFQDN.split('.')
$DomainName = $arr[1]
$SecPW=ConvertTo-SecureString $password -AsPlainText -Force
$File=$null
$Subject=$null

[System.Management.Automation.PSCredential]$DomainCreds = New-Object System.Management.Automation.PSCredential ("${DomainName}\$($adminuser)", $SecPW)

if($useAdDomainNameForExternalDNS -eq "true")
{    
    $adfsFQDN = "adfs.$DnsForestName"
    $pkiFQDN = "pki.$DnsForestName"
}
else
{    
    $adfsFQDN = $WapFqdn
    $pkiFQDN = $WapFqdn
}

$completeFile="c:\temp\prereqsComplete"
md "c:\temp" -ErrorAction Ignore
md "c:\AADLab" -ErrorAction Ignore


if (!(Test-Path -Path "$($completeFile)0")) {    
    $PathToCert="\\$ADCSFQDN\src" #Cannot find path 'C:\\windows\\system32\\TSTX-CS.TomTest8.nl\\src' because it does not exist.   $PathToCert="\\$using:ADCSFQDN\src\*.pfx"
    $drive = New-PSDrive -Name P -PSProvider FileSystem -Root $PathToCert -credential $DomainCreds
    
    #install root cert
    $RootFile = Get-ChildItem -Path "P:\*.crt"
    $RootPath  = $RootFile.FullName
    Import-Certificate -CertStoreLocation Cert:\LocalMachine\Root -FilePath $RootPath
    
    #install the certificate that will be used for ADFS Service
    $CertFile = Get-ChildItem -Path "P:\*.pfx"
    $CertPath  = $CertFile.FullName
    Import-PfxCertificate -Exportable -Password $SecPW -CertStoreLocation cert:\localmachine\my -FilePath $CertPath
    Remove-PSDrive $drive
    
    #record that we got this far
    New-Item -ItemType file "$($completeFile)0"
}

if (!(Test-Path -Path "$($completeFile)1")) {	

	$Subject = $adfsFQDN
    $cert      = Get-ChildItem Cert:\LocalMachine\My | where {$_.Subject -eq "CN=$Subject"} -ErrorAction SilentlyContinue

    Install-WebApplicationProxy -FederationServiceTrustCredential $DomainCreds -CertificateThumbprint $cert.Thumbprint -FederationServiceName $Subject
    
    New-NetFirewallRule -DisplayName "PKI CRL Port 81" -Name "Port81" -Direction Inbound -LocalPort 81 -Protocol TCP -Action Allow -Profile Any
    if($useAdDomainNameForExternalDNS -eq "true")
    { 
        Add-WebApplicationProxyApplication -BackendServerURL "http://$pkiFQDN`:81/" -ExternalURL "http://$pkiFQDN`:81/" -Name 'PKI CRL' -ExternalPreAuthentication PassThrough
    }
    else 
    {
        Add-WebApplicationProxyApplication -BackendServerURL "http://$ADCSFQDN`:81/" -ExternalURL "http://$pkiFQDN`:81/" -Name 'PKI CRL' -ExternalPreAuthentication PassThrough
    }
    
    #record that we got this far
    New-Item -ItemType file "$($completeFile)1"
}
<#



if (!(Test-Path -Path "$($completeFile)2")) {
	$Subject = $WapFqdn
	$str = @"
#https://blogs.technet.microsoft.com/rmilne/2015/04/20/adfs-2012-r2-web-application-proxy-re-establish-proxy-trust/
`$DomainCreds = Get-Credential
`$File      = Get-ChildItem -Path "c:\temp\*.pfx"
`$Subject   = "$Subject"

`$cert      = Get-ChildItem Cert:\LocalMachine\My | where {`$_.Subject -eq "CN=`$Subject"} -ErrorAction SilentlyContinue

Install-WebApplicationProxy ``
	-FederationServiceTrustCredential `$DomainCreds ``
	-CertificateThumbprint `$cert.Thumbprint ``
	-FederationServiceName `$Subject

Start-Service -Name appproxysvc
"@

	$scriptBlock = [Scriptblock]::Create($str)
	$scriptBlock.ToString() | out-file C:\AADLab\resetWAPTrust.ps1

    #record that we got this far
    New-Item -ItemType file "$($completeFile)2"
}
#>
