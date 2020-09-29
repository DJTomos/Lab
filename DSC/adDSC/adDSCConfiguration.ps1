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

	# NOTE: see adfsDeploy.json variable block to see how the internal IP is constructed 
	#       (punting and reproducing logic here)
	$adfsNetworkArr         = $ADFSIPAddress.Split('.')
	#$adfsStartIpNodeAddress = [int]$adfsNetworkArr[3]
	#$adfsNetworkString      = "$($adfsNetworkArr[0]).$($adfsNetworkArr[1]).$($adfsNetworkArr[2])."

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

        Script CreateDMZDNS
    	{
			SetScript  = {
                            md c:\tom -ErrorAction Ignore
							$IPAddress = $using:ADFSIPAddress														
							$ZoneName = $using:subject
							Add-DnsServerPrimaryZone -Name $ZoneName -ReplicationScope Forest -PassThru | out-file -FilePath "C:\tom\primary.txt"
							Add-DnsServerResourceRecordA -ZoneName $ZoneName -Name "@" -AllowUpdateAny -IPv4Address $IPAddress | out-file -FilePath "C:\tom\Arec.txt"
							}

			GetScript =  { @{} }
			TestScript = { 
				$ZoneName = $using:subject
				$Zone = Get-DnsServerZone -Name $ZoneName -ErrorAction SilentlyContinue
				return ($Zone -ne $null)
			}
		}    		
		
<#
        Script CreateOU
        {
            SetScript = {
                $wmiDomain = Get-WmiObject Win32_NTDomain -Filter "DnsForestName = '$( (Get-WmiObject Win32_ComputerSystem).Domain)'"
                $segments = $wmiDomain.DnsForestName.Split('.')
                $path = [string]::Join(", ", ($segments | % { "DC={0}" -f $_ }))
                New-ADOrganizationalUnit -Name "OrgUsers" -Path $path
            }
            GetScript =  { @{} }
            TestScript = { 
                $test=Get-ADOrganizationalUnit -Server "$using:ComputerName.$using:DomainName" -Filter 'Name -like "OrgUsers"' -ErrorAction SilentlyContinue
                return ($test -ine $null)
            }
        }

        Script AddTestUsers
        {
            SetScript = {
                $wmiDomain = Get-WmiObject Win32_NTDomain -Filter "DnsForestName = '$( (Get-WmiObject Win32_ComputerSystem).Domain)'"
                $mailDomain=$wmiDomain.DnsForestName
                $server="$($wmiDomain.PSComputerName).$($wmiDomain.DnsForestName)"
                $segments = $wmiDomain.DnsForestName.Split('.')
                $OU = "OU=OrgUsers, {0}" -f [string]::Join(", ", ($segments | % { "DC={0}" -f $_ }))
                
                $folder=$using:DscWorkingFolder

				$clearPw = $using:ClearDefUserPw
				$Users = $using:usersArray

                foreach ($User in $Users)
                {
                    $Displayname = $User.'FName' + " " + $User.'LName'
                    $UserFirstname = $User.'FName'
                    $UserLastname = $User.'LName'
                    $SAM = $User.'SAM'
                    $UPN = $User.'FName' + "." + $User.'LName' + "@" + $Maildomain
                    #$Password = $User.'Password'
                    $Password = $clearPw
                    "$DisplayName, $Password, $SAM"
                    New-ADUser `
                        -Name "$Displayname" `
                        -DisplayName "$Displayname" `
                        -SamAccountName $SAM `
                        -UserPrincipalName $UPN `
                        -GivenName "$UserFirstname" `
                        -Surname "$UserLastname" `
                        -Description "$Description" `
                        -AccountPassword (ConvertTo-SecureString $Password -AsPlainText -Force) `
                        -Enabled $true `
                        -Path "$OU" `
                        -ChangePasswordAtLogon $false `
                        -PasswordNeverExpires $true `
                        -server $server `
                        -EmailAddress $UPN
                }
            }
            GetScript =  { @{} }
            TestScript = { 
				$Users = $using:usersArray
                $samname=$Users[0].'SAM'
                $user = get-aduser -filter {SamAccountName -eq $samname} -ErrorAction SilentlyContinue
                return ($user -ine $null)
            }
            DependsOn  = '[Script]CreateOU'
        }
		
        #using service credentials for ADFS for now
		Script AddTools
        {
            SetScript  = {
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

            GetScript =  { @{} }
            TestScript = { 
                $key=Get-Module -Name MSOnline -ListAvailable
                return ($key -ine $null)
            }
            #Credential = $DomainCreds
            #PsDscRunAsCredential = $DomainCreds

            DependsOn = '[Script]AddTestUsers'
        }
		

        
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