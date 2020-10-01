$DscWorkingFolder = $PSScriptRoot

configuration DomainController
{
   param
   (
        [Parameter(Mandatory)]
        [String]$Subject,
        
        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]$AdminCreds,

        [Parameter(Mandatory)]
        [String]$ADFSIPAddress,

        [Parameter(Mandatory)]
        [String]$ADCSIPAddress,

        [Parameter(Mandatory)]
        [String]$useAdDomainNameForExternalDNS,

        [Int]$RetryCount=20,
        [Int]$RetryIntervalSec=30
    )
    


    Import-DscResource -ModuleName xComputerManagement,xNetworking,xSmbShare,xAdcsDeployment,xCertificate,PSDesiredStateConfiguration
    
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

       
        Script CreateDNSRecords
    	{
			SetScript  = {   
                            if($using:useAdDomainNameForExternalDNS -eq "true")
                            {
                                $wmiDomain      = Get-WmiObject Win32_NTDomain -Filter "DnsForestName = '$( (Get-WmiObject Win32_ComputerSystem).Domain)'"                                
                                $DomainName     = $wmidomain.DnsForestName
                                Add-DnsServerResourceRecordA -ZoneName $DomainName -Name "adfs" -AllowUpdateAny -IPv4Address $using:ADFSIPAddress
                                Add-DnsServerResourceRecordA -ZoneName $DomainName -Name "pki" -AllowUpdateAny -IPv4Address $using:ADCSIPAddress
                            }
                            else
                            {                                
                                #Used for internal ADFS if using Azure DNS                         
                                <#
                                $IPAddress = $using:ADFSIPAddress														
                                $ZoneName = $using:subject
                                Add-DnsServerPrimaryZone -Name $ZoneName -ReplicationScope "Forest" -PassThru
                                Add-DnsServerResourceRecordA -ZoneName $ZoneName -Name "@" -AllowUpdateAny -IPv4Address $IPAddress
                                #>
                            }
                        }
			GetScript =  { @{} }
			TestScript = { 
                            if($useAdDomainNameForExternalDNS -eq "true")
                            {
                                $wmiDomain      = Get-WmiObject Win32_NTDomain -Filter "DnsForestName = '$( (Get-WmiObject Win32_ComputerSystem).Domain)'"                                
                                $DomainName     = $wmidomain.DnsForestName
                                return ((Resolve-DnsName "adfs.$DomainName").ipaddress -eq $using:ADFSIPAddress)
                            }
                            else
                            {        
                                <#
                                $ZoneName = $using:subject
                                $Zone = Get-DnsServerZone -Name $ZoneName -ErrorAction SilentlyContinue
                                return ($Zone -ne $null)
                                #>
                                return $true
                            }
            }
            DependsOn = '[WindowsFeature]RSAT-ADCS-Mgmt'
        }  
         		
		
<#        
        Script UpdateAdfsSiteGPO
        {
            SetScript = {
                $SiteName = $using:Subject
                $TargetGPO = Get-GPO -Name "Default Domain Policy"
                $ZoneName = '1'
                $TargetHive = 'HKEY_LOCAL_MACHINE'
                $BaseKey = 'Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
                $Key = "$($TargetHive)\$($BaseKey)\ZoneMapKey"

                Set-GPRegistryValue -Guid $TargetGPO.Id -Additive -Key $Key -ValueName $SiteName -Type "String" -Value "1" | Out-Null
            }
            GetScript =  { @{} }
            TestScript = { 
                $CurrKey = Get-GPRegistryValue -Guid $TargetGPO.Id -Key $Key -ValueName $SiteName -ErrorAction SilentlyContinue
                return ($CurrKey -ine $null)
            }
        }
        #>
    }
}