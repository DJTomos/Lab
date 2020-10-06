$DscWorkingFolder = $PSScriptRoot


Configuration Main
{
   param
   (        
        [Parameter(Mandatory)]
        [System.Management.Automation.PSCredential]$AdminCreds,

        [Int]$RetryCount=20,
        [Int]$RetryIntervalSec=30
    )


    Import-DscResource -ModuleName PSDesiredStateConfiguration

    Node localhost
    {
        LocalConfigurationManager            
        {            
            DebugMode = 'All'
            ActionAfterReboot = 'ContinueConfiguration'            
            ConfigurationMode = 'ApplyOnly'            
            RebootNodeIfNeeded = $true
        }

	    WindowsFeature Tools 
        {
            Ensure = "Present"
            Name = "RSAT-RemoteAccess"
            IncludeAllSubFeature = $true
        }

        WindowsFeature MoreTools 
        {
            Ensure = "Present"
            Name = "RSAT-AD-Tools"
            IncludeAllSubFeature = $true
        }        

        WindowsFeature RSAT-ADCS-Mgmt
        {
            Ensure = 'Present'
            Name = 'RSAT-ADCS-Mgmt'
        }
        

        WindowsFeature Web-Mgmt-Console
        {
            Ensure = 'Present'
            Name = 'Web-Mgmt-Console'            
		}	

        WindowsFeature Telnet
        {
            Ensure = "Present"
            Name = "Telnet-Client"
        }

        WindowsFeature NDES
        {
            Ensure = "Present"
            Name = "ADCS-Device-Enrollment"
        }        

        Script InstallAADConnect
        {
            SetScript = {
                        $WshShell = New-Object -comObject WScript.Shell
                        $dt="C:\Users\Public\Desktop\"	
                    
                        $links = @(	
                            @{site="%windir%\system32\WindowsPowerShell\v1.0\PowerShell_ISE.exe";name="PowerShell ISE";icon="%SystemRoot%\system32\WindowsPowerShell\v1.0\powershell_ise.exe, 0"},
                            @{site="%SystemRoot%\system32\dsa.msc";name="AD Users and Computers";icon="%SystemRoot%\system32\dsadmin.dll, 0"},
                            @{site="%SystemRoot%\system32\certsrv.msc";name="Certificate Authority";icon="%SystemRoot%\system32\certsrv.msc, 0"},
                            @{site="%SystemRoot%\system32\domain.msc";name="AD Domains and Trusts";icon="%SystemRoot%\system32\domadmin.dll, 0"},
                            @{site="%SystemRoot%\system32\dnsmgmt.msc";name="DNS";icon="%SystemRoot%\system32\dnsmgr.dll, 0"}
                        )
                    
                        foreach($link in $links){
                            $Shortcut = $WshShell.CreateShortcut("$($dt)$($link.name).lnk")
                            $Shortcut.TargetPath = $link.site
                            $Shortcut.IconLocation = $link.icon
                            $Shortcut.Save()
                        }
            }    
            GetScript =  { @{} }
            TestScript = { 
                return Test-Path "C:\Users\Public\Desktop\PowerShell ISE.lnk" 
            } 
            DependsOn = '[WindowsFeature]NDES'           
        }
        
       <# Script InstallAADConnect
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
            DependsOn = '[WindowsFeature]NDES'           
        }
        #>
    }
}