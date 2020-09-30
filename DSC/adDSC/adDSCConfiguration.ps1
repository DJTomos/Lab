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

        <# #Used for internal ADFS if using Azure DNS
        Script CreateDMZDNS
    	{
			SetScript  = {                            
							$IPAddress = $using:ADFSIPAddress														
							$ZoneName = $using:subject
							Add-DnsServerPrimaryZone -Name $ZoneName -ReplicationScope "Forest" -PassThru
							Add-DnsServerResourceRecordA -ZoneName $ZoneName -Name "@" -AllowUpdateAny -IPv4Address $IPAddress
							}

			GetScript =  { @{} }
			TestScript = { 
				$ZoneName = $using:subject
				$Zone = Get-DnsServerZone -Name $ZoneName -ErrorAction SilentlyContinue
				return ($Zone -ne $null)
            }
            DependsOn = '[WindowsFeature]RSAT-ADCS-Mgmt'
        }  
        #>  		
		
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