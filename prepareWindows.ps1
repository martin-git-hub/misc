#Prerequisities: run as Administrator
[String]$sUsr                 = "RTG"
[SecureString]$sPwd           = ConvertTo-SecureString "rtg" -AsPlainText -Force
[String]$sHostname            = "3D-PC"
[SecureString]$sLocalAdminPwd = ConvertTo-SecureString -String "DEsupport17" -AsPlainText -Force
[int]$nInitialMemorySize      = 32768   #Force to set 32768 initial memory size (virtual memory/pagefile.sys) on 16 GB memory system
[int]$nMaximumMemorySize      = 32768   #Force to set 32768 maximum memory size (virtual memory/pagefile.sys) on 16 GB memory system


function CreateUser {
    param(
        [string]$sUser,
        [SecureString]$sPassword
    )
    New-LocalUser -Name $sUser -Password $sPassword -AccountNeverExpires -PasswordNeverExpires
}

function ChangeHostname {
    param(
        [string]$sNewHostname
    )
    Write-Host "Changing hostname to: " $sNewHostname
    Rename-Computer -NewName $sNewHostname #-Restart    #Restart later
}

function ActivateLocalAdmin {
    Write-Host "Activating local administrator."
    $LocalAdmin = Get-LocalUser -Name "Administrator" | Enable-LocalUser
    $LocalAdmin | Set-LocalUser -Password $sLocalAdminPwd
}
function ConfigureGroupPolicy {

    Write-Host "Configuring group policy."
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows" -Name "WindowsUpdate"

    #Configure Automatic Updates policy
    #When you configure Automatic Updates directly by using the policy registry keys, the policy overrides the preferences that are set by the local administrative user to configure the client. 
    #If an administrator removes the registry keys at a later date, the preferences that were set by the local administrative user are used again.   
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "AU"
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -Value "2" -PropertyType "Dword"
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -Value "0" -PropertyType "Dword"
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "ScheduledInstallDay" -Value "0" -PropertyType "Dword"
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "ScheduledInstallEveryWeek" -Value "1" -PropertyType "Dword"
    New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "ScheduledInstallTime" -Value "3" -PropertyType "Dword"

    #Do not includes drivers with Windows Updates
    New-ItemProperty -path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -name "ExcludeWUDriversInQualityUpdate" -value "1" -PropertyType "Dword"
}

function SetVirtualMemory {    
    param(
        [int]$nInitMemSize,
        [int]$nMaxMemSize
    )
    Write-Host "Changing virtual memory."
    #wmic computersystem where name="%computername%" set AutomaticManagedPagefile=false
    #wmic pagefileset where name="C:\\pagefile.sys" set InitialSize=<InitialSizeinMB>,MaximumSize=<MaximumSizeinMB>

    $computersys = Get-WmiObject Win32_ComputerSystem -EnableAllPrivileges
    $computersys.AutomaticManagedPagefile = $False
    $computersys.Put()
    $pagefile = Get-WmiObject -Query "Select * From Win32_PageFileSetting Where Name like '%pagefile.sys'"
    $pagefile.InitialSize = $nInitMemSize
    $pagefile.MaximumSize = $nMaxMemSize
    $pagefile.Put()

    #Restart is needed
}

function DisableSleeping {

    Write-Host "Disabling sleep mode."
    powercfg -x -disk-timeout-ac 0
    powercfg -x -disk-timeout-dc 0
    powercfg -x -standby-timeout-ac 0
    powercfg -x -standby-timeout-dc 0
    powercfg -x -hibernate-timeout-ac 0
    powercfg -x -hibernate-timeout-dc 0
}

function ConfigureDateTime {
    Write-Host "Changing date format."
    Set-ItemProperty -Path "HKCU:\Control Panel\International" -Name sShortDate -Value "dd.MM.yyyy";
}

function ConfigureKeyboardLayouts {
    Write-Host "Adding keyboard layouts."
    $LanguageList = Get-WinUserLanguageList
    $LanguageList.Add("cs-CZ")
    $LanguageList.Add("sk-SK")
    $LanguageList.Add("en-US")
    Set-WinUserLanguageList -LanguageList $LanguageList -Force
}

function UninstallApps {
    Write-Host "Uninstalling apps."
    #Uninstall office365, McAffee etc....
    $WmiObjectsToUninstall = Get-WmiObject -Class Win32_Product | Select-Object -Property Name | Where-Object {$_ -match "Office"}
    $PackagesToUninstall   = Get-Package -Provider Programs -IncludeWindowsInstaller | Select-Object -Property Name | Where-Object {$_ -match "365"}

    foreach ($Object in $WmiObjectsToUninstall) {
        $Object.uninstall();
    }
    foreach ($Package in $PackagesToUninstall) {
        Uninstall-Package -Name $Package
    }
}

function InstallApps {
    Write-Host "Installing apps:"
    #Enable .Net 3.5
    Write-Host "Installing .NET 3.5"
    Enable-WindowsOptionalFeature -Online -FeatureName "NetFx3"

    #Install TeamViewer 11
    Write-Host "Installing TeamViewer 11"
    Start-Process '.\Install\TeamViewer_Setup11.exe' "/S"
    #Install Total Commander
    Write-Host "Installing Total Commander"
    Start-Process '.\tcmd951x32_64.exe' "/AHLMGDU"
    #Install network drivers
}

CreateUser $sUsr $sPwd  #neotestovane, user existuje
ActivateLocalAdmin
DisableSleeping    
ConfigureDateTime
ConfigureKeyboardLayouts

#Changes will be applied after reboot
SetVirtualMemory $nInitialMemorySize $nMaximumMemorySize
ConfigureGroupPolicy #registre nastavuje
ChangeHostname $sHostname