##########  Powershell script GPO deploiement antivirus forticlient repackagé  #############
##      Mathieu Chot-plassot                                                              ##
#       @Mathieu_chot                                                                      #
############################################################################################
$ErrorActionPreference= 'silentlycontinue'
#################################################################
Function Test-CurrentAdminRights 
{  
    # $True = droit admin   sinon $False  
    $user = [System.Security.Principal.WindowsIdentity]::GetCurrent()  
    $Role = [System.Security.Principal.WindowsBuiltinRole]::Administrator
    return (New-Object Security.Principal.WindowsPrincipal $User).IsInRole($Role)  
} 

#################################################################
Function Runas-ThisPowerShellScript()
{
    # Get powershell path
    [String]$str_PowershellPath = [Microsoft.Win32.Registry]::GetValue("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell","Path",$null)
    # Lance ce script avec les privileges administrateur
    $cmdstartinfo = new-object System.Diagnostics.ProcessStartInfo($str_PowershellPath,"-ExecutionPolicy Bypass -File ""$Global:ScriptFullName""")
    $cmdstartinfo.WindowStyle="Hidden"
    $cmdstartinfo.Verb = "runas";
    $cmdprocess = [System.Diagnostics.Process]::start($cmdstartinfo)
}

#################################################################
Function WriteLogFile()
{
    Param(
    	[Parameter(Mandatory=$false)]
       	[String]$strOutput=""

    ,	[Parameter(Mandatory=$false)]
    	[Int]$flagAppend=1
    )

    #Update Log File #
    If ($strOutput -ne "")
    {
    	$date_Now = Get-Date
    	[String]$text = $date_Now.ToString("dd/MM/yyyy HH:mm:ss")
    	$text = "$text : $strOutput"
    }
    else {[String]$text = ""}

    If ([Int]$flagAppend -eq 1){$text | Out-File $Global:strLogFile -append}
    Else {$text | Out-File $Global:strLogFile}
}

#################################################################
function Get-antivirus
{
    # clés x86 et x64 differents
    #32bit
    if ([IntPtr]::Size -eq 4) 
    {
        $path = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
    }
    #64bit
    else 
    {
        $path = @(
            'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
            'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
        )
    }

    Get-ItemProperty $path |
    Select-Object DisplayName 
}
 
#################################################################
#                            main                               #
#################################################################

################### Declaration de variables #####################
[String]$PackageName = "Forticlient"
[String]$Global:strLogFile = "C:\Pkglogs\$PackageName.Log"
$Logfolder = "c:\Pkglogs"
$forticlient_x64 = "\\192.168.0.32\packages\Forticlient\x64\ActiveDirectory\Fortinet.msi"
$forticlient_x86 = "\\192.168.0.32\packages\Forticlient\x86\ActiveDirectory\Fortinet.msi"
$FCremove = "\\192.168.0.32\Packages\Forticlient\FCRemove.exe"
$tempp = "c:\users\$env:USERNAME"
$architecture = "$ENV:PROCESSOR_ARCHITECTURE"
$wmiQuery = "SELECT * FROM AntiVirusProduct"
$AntivirusProduct = Get-WmiObject -Namespace "root\SecurityCenter2" -Query $wmiQuery
$antivirusname = $AntivirusProduct.displayName
$OS = gwmi win32_operatingsystem | select name | FL
$OSver = [Environment]::OSVersion.VersionString
$servercheck = $OS -Contains "Microsoft Windows Server"
$programmes= Get-antivirus
##################################################################   

# Check Admin rights
$lret = Test-CurrentAdminRights

If ($lret -eq $false)
{
	WriteLogFile "Role administrateur : False"
	# Relancer ce script avec les droit administrateur
	WriteLogFile "Runas-ThisPowerShellScript()"
	Runas-ThisPowerShellScript
}

#ne pas appliquer pour les serveurs  
if ($servercheck)
{
    exit 2 
}

# Creation du dossier local de logs si absent 
$obj_DirectoryInfo = new-object System.IO.DirectoryInfo($Logfolder)
If ($obj_DirectoryInfo.Exists -eq $false)
{
    $_ = [System.IO.Directory]::CreateDirectory($Logfolder)
    $(Get-Item "$Logfolder" ).Attributes = 'Hidden'
    WriteLogFile "creation du dossier de logs $Logfolder "   
}
  
#Check antivirus 
WriteLogFile "OS = $OSver"
if ((!($antivirusname)) -or ($antivirusname -eq "Microsoft Security Essentials"))
{
    WriteLogFile "check antivirus: aucun antivirus installés sur ce poste"

    #WriteLogFile "nettoyage anciennes installations forticlient.."
    #Copy-Item $FCremove -Destination $tempp
    #& "$tempp\FCRemove.exe" -quiet -noreboot -silent
    
    if ($architecture -eq "AMD64")
    {
        Copy-Item -Path $forticlient_x64 -Destination $tempp -Force -Recurse
        $arch_ver = "x64"
    }
    else
    {
        Copy-Item -Path $forticlient_x86 -Destination $tempp -Force -Recurse
        $arch_ver = "x86"
    }
    if(Test-Path "$tempp\Fortinet.msi")
    {
        WriteLogFile "Forticlient $arch_ver télechargé !"
        WriteLogFile "installation de Forticlient $arch_ver.."
        msiexec /i "$tempp\Fortinet.msi" /qn /norestart /L*V "$Logfolder\Forticlient$arch_ver.log" 
        Copy-Item -Path "$Logfolder\Forticlient$arch_ver.log" -Destination "\\192.168.0.32\Logs\Forticlient\$env:COMPUTERNAME  -  $PackageName $arch_ver.log" -Recurse
        #$count="pasbon"
        #start-sleep -s 20
        #foreach ($programme in $programmes) 
        #{      
        #   if ($programme -like '*Forticlient*')
        #   {
        #       WriteLogFile "installation de Forticlient $arch_ver reussi"  
        #       $count="bon"  
        #   }    
        #}
        #if ($count -eq "pasbon")
        #{
        #   WriteLogFile "l'installation de Forticlient $arch_ver a echoué"
        #}
        if((test-path "C:\Program Files\Fortinet\Forticlient") -Or (test-path "C:\Program Files (x86)\Fortinet\Forticlient"))
        {
            WriteLogFile "installation de Forticlient $arch_ver reussi"  
        }
        else
        {
            WriteLogFile "l'installation de Forticlient $arch_ver a echoué"
        }
    }
    else 
    {
        #echo "a"
        WriteLogFile "echec du telechargement de Forticlient $arch_ver"
    }
}
else
{
    WriteLogFile "check antivirus: $antivirusname est déjà installé sur ce poste "
}

# Copie du fichier de log sur le Shared folder
Copy-Item -Path $Global:strLogFile -Destination "\\192.168.0.32\Logs\Forticlient\$env:COMPUTERNAME  -  $PackageName.log" -Recurse
WriteLogFile "---------------execution du script terminé---------------"
      <#
  
#$wshell = New-Object -ComObject Wscript.Shell
#$wshell.Popup(" COMODO ANTIVIRUS a été installé sur votre poste",0,"@Mathieu_chot contact: mathieu.chot-plassot@mondom.com ")

$message = [System.windows.forms.MessageBox]::Show(
			"L'Antivirus Comodo a été installé sur votre poste"`
			," Information - mathieu.chot-plassot@mondom.com "`
			,[System.Windows.Forms.MessageBoxButtons]::OK`
			,[System.Windows.Forms.MessageBoxIcon]::Information`
			,[System.Windows.Forms.MessageBoxDefaultButton]::Button1
		)
[System.Windows.Forms.

a faire
#Create a new trigger that is configured to trigger at startup
                              $STTrigger = New-ScheduledTaskTrigger -AtStartup
                              #Name for the scheduled task
                              $STName = "Running Task 1"
                              #Action to run as
                              $STAction = New-ScheduledTaskAction -Execute "image.exe"
                              #Configure when to stop the task and how long it can run for. In this example it does not stop on idle and uses the maximum possible duration by setting a timelimit of 0
                              $STSettings = New-ScheduledTaskSettingsSet -DontStopOnIdleEnd -ExecutionTimeLimit ([TimeSpan]::Zero)
                              #Configure the principal to use for the scheduled task and the level to run as
                              $STPrincipal = New-ScheduledTaskPrincipal -GroupId "BUILTIN\Administrators" -RunLevel "Highest"
                              #Register the new scheduled task
                              Register-ScheduledTask $STName -Action $STAction -Trigger $STTrigger -Principal $STPrincipal -Settings $STSettings




                              $getprocess = Get-Process | where Description -eq "comodo internet security" | Format-List -Property Name | Out-File c:\list.txt -Force
[string]$getprocess2 = Get-Content C:\list.txt | ForEach-Object {$_.split(" ")[2]} 
$comodoprocess = ("$getprocess2").Replace("  ",";")



    #else
    #{
        #WriteLogFile "check antivirus:  $antivirusname est installé sur le poste ${env:COMPUTERNAME}"
        #if ($antivirusname -eq "Forticlient Antivirus")
        #{   
         
        #}
        #else
        #{

        #}
        #}    


        #>

  
  

 






