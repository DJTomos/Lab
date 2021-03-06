﻿param (
    [Parameter(Mandatory)]
    [string]$Acct,

    [Parameter(Mandatory)]
    [string]$PW,

    [Parameter(Mandatory)]
    [string]$useAdDomainNameForExternalDNS,

	[Parameter(Mandatory)]
	[string]$WapFqdn
)

$wmiDomain = Get-WmiObject Win32_NTDomain -Filter "DnsForestName = '$( (Get-WmiObject Win32_ComputerSystem).Domain)'"
$DCName = $wmiDomain.DomainControllerName
$ComputerName = $wmiDomain.PSComputerName

$DomainName = $wmiDomain.DomainName

$DomainNetbiosName = $DomainName.split('.')[0]
$SecPw = ConvertTo-SecureString $PW -AsPlainText -Force
[System.Management.Automation.PSCredential]$DomainCreds = New-Object System.Management.Automation.PSCredential ("${DomainNetbiosName}\$($Acct)", $SecPW)
$DnsForestName = $wmidomain.DnsForestName
if($useAdDomainNameForExternalDNS -eq "true")
{    
    $adfsFQDN = "adfs.$DnsForestName"
}
else
{    
    $adfsFQDN = $WapFqdn
}


$identity = [Security.Principal.WindowsIdentity]::GetCurrent()  
$principal = new-object Security.Principal.WindowsPrincipal $identity 
$elevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)  

if (-not $elevated) {
    $a = $PSBoundParameters
    $cl = "-Acct $($a.Acct) -PW $($a.PW)"
    $arglist = (@("-file", (join-path $psscriptroot $myinvocation.mycommand)) + $args + $cl)
    Write-host "Not elevated, restarting as admin..."
    Start-Process cmd.exe -Credential $DomainCreds -NoNewWindow -ArgumentList “/c powershell.exe $arglist”
} else {
    Write-Host "Elevated, continuing..." -Verbose

    #Configure ADFS Farm
    Import-Module ADFS
    $wmiDomain = Get-WmiObject Win32_NTDomain -Filter "DnsForestName = '$( (Get-WmiObject Win32_ComputerSystem).Domain)'"
    $DCName = $wmiDomain.DomainControllerName
    $ComputerName = $wmiDomain.PSComputerName
    $DomainName=$wmiDomain.DomainName
    $DomainNetbiosName = $DomainName.split('.')[0]
    $SecPw = ConvertTo-SecureString $PW -AsPlainText -Force

    [System.Management.Automation.PSCredential]$DomainCreds = New-Object System.Management.Automation.PSCredential ("${DomainNetbiosName}\$($Acct)", $SecPW)

    $Subject = $adfsFQDN
	Write-Host "Subject: $Subject"

    #get thumbprint of certificate
    $cert = Get-ChildItem Cert:\LocalMachine\My | where {$_.Subject -eq "CN=$Subject"}
	try {
	    Get-ADfsProperties -ErrorAction Stop
        Write-Host "Farm already configured" -Verbose
	}
	catch {
        Install-AdfsFarm `
            -Credential $DomainCreds `
            -CertificateThumbprint $cert.thumbprint `
            -FederationServiceName $Subject `
            -FederationServiceDisplayName "ADFS" `
            -ServiceAccountCredential $DomainCreds `
            -OverwriteConfiguration

        Write-Host "Farm configured" -Verbose
	}
 
	# Install AAD Tools
	md c:\temp -ErrorAction Ignore
	[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12;
	Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force

	#Install-Module -Name Azure -AllowClobber -Force
	#Install-Module -Name AzureRM -AllowClobber -Force

	Install-Module -Name MSOnline -Force

	Install-Module -Name AzureAD -Force

	Install-Module -Name AzureADPreview -AllowClobber -Force
	
}
