##########  Powershell script deploiement GPO - setup ansible & config de base #############   
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
    # Get Powershell Path
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
    	[String]$text = $date_Now.ToString("yyyy/MM/dd HH:mm:ss")
    	$text = "$text : $strOutput"
    }
    else {[String]$text = ""}

    If ([Int]$flagAppend -eq 1){$text | Out-File $Global:strLogFile -append}
    Else {$text | Out-File $Global:strLogFile}
}

##################################################################
# a rajouter
Function download-file()
{
    param ([string]$path, [string]$local)
    $client = new-object system.net.WebClient
    $client.Headers.Add("user-agent", "PowerShell")
    $client.downloadfile($path, $local)
}
##################################################################
# pour winrm (script de ansible)
Function New-LegacySelfSignedCert
{
    Param (
        [string]$SubjectName,
        [int]$ValidDays = 365
    )
    
    $name = New-Object -COM "X509Enrollment.CX500DistinguishedName.1"
    $name.Encode("CN=$SubjectName", 0)

    $key = New-Object -COM "X509Enrollment.CX509PrivateKey.1"
    $key.ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
    $key.KeySpec = 1
    $key.Length = 1024
    $key.SecurityDescriptor = "D:PAI(A;;0xd01f01ff;;;SY)(A;;0xd01f01ff;;;BA)(A;;0x80120089;;;NS)"
    $key.MachineContext = 1
    $key.Create()

    $serverauthoid = New-Object -COM "X509Enrollment.CObjectId.1"
    $serverauthoid.InitializeFromValue("1.3.6.1.5.5.7.3.1")
    $ekuoids = New-Object -COM "X509Enrollment.CObjectIds.1"
    $ekuoids.Add($serverauthoid)
    $ekuext = New-Object -COM "X509Enrollment.CX509ExtensionEnhancedKeyUsage.1"
    $ekuext.InitializeEncode($ekuoids)

    $cert = New-Object -COM "X509Enrollment.CX509CertificateRequestCertificate.1"
    $cert.InitializeFromPrivateKey(2, $key, "")
    $cert.Subject = $name
    $cert.Issuer = $cert.Subject
    $cert.NotBefore = (Get-Date).AddDays(-1)
    $cert.NotAfter = $cert.NotBefore.AddDays($ValidDays)
    $cert.X509Extensions.Add($ekuext)
    $cert.Encode()

    $enrollment = New-Object -COM "X509Enrollment.CX509Enrollment.1"
    $enrollment.InitializeFromRequest($cert)
    $certdata = $enrollment.CreateRequest(0)
    $enrollment.InstallResponse(2, $certdata, 0, "")

    # Return the thumbprint of the last installed cert.
    Get-ChildItem "Cert:\LocalMachine\my"| Sort-Object NotBefore -Descending | Select -First 1 | Select -Expand Thumbprint
}





#################################################################
#                            main                               #
#################################################################


# Check Admin rights
$lret = Test-CurrentAdminRights

If ($lret -eq $false)
{
	WriteLogFile "Role administrateur : False"
	
	# Relancer ce script avec les droit administrateur
	WriteLogFile "Runas-ThisPowerShellScript()"
	Runas-ThisPowerShellScript
}
else
{
    ################### Declaration de variables ######################
    [String]$PackageName = "Script-default"
    [String]$Global:strLogFile = "C:\Pkglogs\$PackageName.Log"
    $dotnet = "\\192.168.0.32\Packages\dotnet4\dotNetFx40_Full_x86_x64.exe"
    $ps3_x64 = "\\192.168.0.32\Packages\powershell3\Windows6.1-KB2506143-x64.msu"
    $ps3_x86 = "\\192.168.0.32\Packages\powershell3\Windows6.1-KB2506143-x86.msu"
    #correctif out of memory w7 et w2008r3 avec le fw 3
    $correctif_x64 = "\\192.168.0.32\Packages\powershell3\correctif\Windows6.1-KB2842230-x64.msu"
    $correctif_x86 = "\\192.168.0.32\Packages\powershell3\correctif\Windows6.1-KB2842230-x86.msu"
    $utilisateur = "$env:username"
    $powershellpath = "C:\users\$utilisateur\powershell" 
    $login = "xxx"
    $_password = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("bWF0aGlldWNob3QtcGxhc3NvdC5jb20="))
    ####################################################################   
    # Creation du dossier local de logs si absent 
    $obj_DirectoryInfo = new-object System.IO.DirectoryInfo("C:\Pkglogs")
    If ($obj_DirectoryInfo.Exists -eq $false)
    {
    	$_ = [System.IO.Directory]::CreateDirectory("C:\Pkglogs")
        $(Get-Item "C:\Pkglogs" ).Attributes = 'Hidden'
        WriteLogFile "creation du dossier de logs c:\Pkglogs "   
    }
    
	Set-ExecutionPolicy Remotesigned 
  
    # Version de powershell
    $ver = $Psversiontable.PSVersion.Major 
    WriteLogFile "version de powershell : $ver"
    # utilisateur courant
    WriteLogFile " utilisateur courant : $utilisateur"

    # Creation d'un administrateur local 
    $Computer = [ADSI]"WinNT://$Env:COMPUTERNAME,Computer" 
    $colUsers = ($Computer.psbase.children | Where-Object {$_.psBase.schemaClassName -eq "User"} | Select-Object -expand Name)
    $blnFound = $colUsers -contains "xxx"
    if ($blnFound)
    { 
        WriteLogFile "L utilisateur $login existe :)"
    }
    else
    { 
        WriteLogFile "Creation de l utilisateur $login"
        $LocalAdmin = $Computer.Create("User", "$login")
        $LocalAdmin.SetPassword(($_password))
        $LocalAdmin.SetInfo()
        $LocalAdmin.FullName = "$login"
        $LocalAdmin.Parent
        $LocalAdmin.SetInfo()
        $LocalAdmin.UserFlags = 64 + 65536 # ADS_UF_PASSWD_CANT_CHANGE + ADS_UF_DONT_EXPIRE_PASSWD
        $LocalAdmin.SetInfo()
        # ajout de l'user dans le groupe administrateur
        if ([ADSI]::Exists('WinNT://./administrateurs'))
        {
            NET LOCALGROUP "Administrateurs" "$login" /add
        }
        else
        {
            NET LOCALGROUP "Administrators" "$login" /add
        }   
    }
    
    #Check antivirus 
    $wmiQuery = "SELECT * FROM AntiVirusProduct"
    $AntivirusProduct = Get-WmiObject -Namespace "root\SecurityCenter2" -Query $wmiQuery
    $antivirusname = $AntivirusProduct.displayName
    if($antivirusname -eq "")
    {
         WriteLogFile "check antivirus: aucun antivirus n'est installés sur ce poste"
    }
    else
    {
        WriteLogFile "check antivirus:  $antivirusname est installé sur le poste ${env:COMPUTERNAME}"
    }
    
    #if ($antivirusname -eq "Forticlient Antivirus")
    #{    
    #}
    #else
    #{
    #}
    








    if ([Environment]::OSVersion.Version.Major -gt 6) {WriteLogFile "La version de windows est recente "}
 
    ####  Upgrade to powershell 3 ! 
    if ($PSVersionTable.psversion.Major -ge 3){WriteLogFile "Powershell 3 est deja installé"}
    if ($PSVersionTable.psversion.Major -lt 3)
    {
        if (!(test-path $powershellpath))
        {
            New-Item -ItemType directory -Path $powershellpath
            $(Get-Item $powershellpath ).Attributes = 'Hidden'
            WriteLogFile "le repertoire $powershellpath a ete cree"
        }
        else
        {
            WriteLogFile "le repertoire $powershellpath existe deja"
        }    
        
        # .NET Framework 4.0 est necessaire
        $checkdotnet = Get-WmiObject -Class Win32_Product | sort-object Name | select Name | where { $_.Name -imatch “Microsoft .NET Framework 4”}
        
        #if (($PSVersionTable.CLRVersion.Major) -le 2) # CLR 2.0 = framework 2 3 3.52 CLR 4 = framework 4 4.5 #pas tout le temps vrai 
        if(!($checkdotnet)) 
        {
            WriteLogFile "telechargement du framework 4.0"
            if (test-path $powershellpath)
            {
                Copy-Item -Path $dotnet -Destination "$powershellpath\dotnet.exe"
                if (!(Test-Path "$powershellpath\dotnet.exe"))
                {
                    WriteLogFile "le telechargement de .NET Framework 4 depuis $dotnet a échoué"
                    # a rajouter pour tout les liens
                    #$DownloadUrl = "http://download.microsoft.com/download/B/A/4/BA4A7E71-2906-4B2D-A0E1-80CF16844F5F/dotNetFx45_Full_x86_x64.exe"
                    #$FileName = $DownLoadUrl.Split('/')[-1]
                    #download-file $downloadurl "$powershellpath\$filename"
                    #."$powershellpath\$filename" /quiet /norestart
                    #if (Test-Path "$powershellpath\$filename")
                    #WriteLogFile "le telechargement de .NET Framework 4 depuis $DownloadUrl a échoué"
                }
                else
                {
                    WriteLogFile "telechargement de $dotnet réussi"
                }
                ."$powershellpath\dotnet.exe" /quiet /norestart    
                       
                if (!($checkdotnet))
                {
                    WriteLogFile ".NET Framework 4 ne s'est pas correctement installé.."
                    regsvr32 MSXML3.dll /s  
                    Stop-Service wuauserv  
                    cd $env:windir\SoftwareDistribution  
                    rd /s /q DataStore  
                    Start-Service wuauserv   
                    regsvr32  softpub.dll /s
                    regsvr32  mssip32.dll /s
                    WriteLogFile "Deuxieme essai"
                    ."$powershellpath\dotnet.exe" /quiet /norestart
                    if (!($checkdotnet))
                    { WriteLogFile "une erreur s'est produite lors de l'installation du framework 4"}
                    else
                    {WriteLogFile ".NET Framework 4 a été installé avec succés, reboot necessaire"}
                }
            }
        }
        #powershell3 installation    
        if ($checkdotnet)
        {
            WriteLogFile ".NET Framework 4 est correctement installé"
            $osminor = [environment]::OSVersion.Version.Minor
            $architecture = $ENV:PROCESSOR_ARCHITECTURE
            if ($architecture -eq "AMD64")
            {
                $architecture = "x64"
            }
            else
            {
                $architecture = "x86"
            }
            if ($architecture  -eq "x86")
            {
                Copy-Item -Path $ps3_x86 -Destination "$powershellpath\ps3x86.msu" 
                WriteLogFile "installation powershell3 x86..."
                wusa.exe $powershellpath\ps3x86.msu /quiet /norestart /log:c:\Pkglogs\Powershell3.evt
            }
            elseif ($architecture -eq "x64")
            {
                Copy-Item -Path $ps3_x64 -Destination "$powershellpath\ps3x64.msu"   
                WriteLogFile "installation powershell3 x64..."
                wusa.exe $powershellpath\ps3x64.msu /quiet /norestart /log:c:\Pkglogs\Powershell3.evt
            }
            else
            {
                WriteLogFile "erreur fatal"
                exit
            }
            Copy-Item -Path c:\Pkglogs\Powershell3.evt -Destination "\\192.168.0.32\Logs\Script-default\$env:COMPUTERNAME  -  $PackageName-powershell3.evt" -Recurse
            
        } 

    }
    
    # installation du correctif 
    if(((Get-WmiObject win32_operatingsystem).version) -imatch "6.1") #w7 et w2008r2
    {
        $checkcorrectif = Get-HotFix | where hotfixid -eq  "KB2842230"
        if(!($checkcorrectif))
        {
            if($ENV:PROCESSOR_ARCHITECTURE -eq "AMD64")
            {
                Copy-Item -Path $correctif_x64 -Destination "$powershellpath\correctif_x64.msu"
                WriteLogFile "installation correctif x64..."
                wusa.exe $powershellpath\correctif_x64.msu /quiet /norestart /log:c:\Pkglogs\correctif_x64.evt
                Copy-Item -Path "c:\Pkglogs\correctif_x64.evt" -Destination "\\192.168.0.32\Logs\Script-default\$env:COMPUTERNAME  -  $PackageName-correctif_x64.evt" -Recurse
            }
            if($ENV:PROCESSOR_ARCHITECTURE -eq "x86")
            {
                Copy-Item -Path $correctif_x86 -Destination "$powershellpath\correctif_x86.msu"
                WriteLogFile "installation correctif x86..."
                wusa.exe $powershellpath\correctif_x86.msu /quiet /norestart /log:c:\Pkglogs\correctif_x86.evt
                Copy-Item -Path "c:\Pkglogs\correctif_x86.evt" -Destination "\\192.168.0.32\Logs\Script-default\$env:COMPUTERNAME  -  $PackageName-correctif_x86.evt" -Recurse
            }  
        }
        else
        {
            WriteLogFile "le correctif KB2842230 est installé (correction bug out of memory)"
        }
    
    }
    

    
    ############# WINRM ############
    
    # gere les erreurs
    Trap
    {
        $_
        Exit 1
    }
    $ErrorActionPreference = "Stop"

    # Find and start the WinRM service.
    WriteLogFile "verification winrm service"
    If (!(Get-Service "WinRM"))
    {
        WriteLogFile "impossible de trouver le service winrm"
    }
    ElseIf ((Get-Service "WinRM").Status -ne "Running")
    {
        WriteLogFile "execution du service winrm"
        Start-Service -Name "WinRM" -ErrorAction Stop
    }


    # WinRM doit etre en cours d'execution; verification que l'on a une  PS session config.
    If (!(Get-PSSessionConfiguration -Verbose:$false) -or (!(Get-ChildItem WSMan:\localhost\Listener)))
    {
        WriteLogFile "activation de PS Remoting."
        Enable-PSRemoting -Force -ErrorAction Stop
    }
    Else
    {
        WriteLogFile "PS Remoting est deja active"
    }


    # Test a d'une remote connection sur localhost
    $httpResult = Invoke-Command -ComputerName "localhost" -ScriptBlock {$env:COMPUTERNAME} -ErrorVariable httpError -ErrorAction SilentlyContinue
    $httpsOptions = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck

    $httpsResult = New-PSSession -UseSSL -ComputerName "localhost" -SessionOption $httpsOptions -ErrorVariable httpsError -ErrorAction SilentlyContinue

    If ($httpResult -and $httpsResult)
    {
        WriteLogFile "HTTP et HTTPS sessions sont actives"
    }
    ElseIf ($httpsResult -and !$httpResult)
    {
        WriteLogFile "HTTP sessions sont desactives, HTTPS session sont actives"
    }
    ElseIf ($httpResult -and !$httpsResult)
    {
        WriteLogFile "HTTPS sessions sont actives, HTTP session sont actives"
    }
    Else
    {
        WriteLogFile "impossible d etablir une connections HTTP ou HTTPS "
    }


    # s'assurer qu'il y a un SSL listener.
    $listeners = Get-ChildItem WSMan:\localhost\Listener
    If (!($listeners | Where {$_.Keys -like "TRANSPORT=HTTPS"}))
    {
        # HTTPS-based endpoint does not exist.
        If (Get-Command "New-SelfSignedCertificate" -ErrorAction SilentlyContinue)
        {
            $cert = New-SelfSignedCertificate -DnsName $env:COMPUTERNAME -CertStoreLocation "Cert:\LocalMachine\My"
            $thumbprint = $cert.Thumbprint
        }
        Else
        {
            $thumbprint = New-LegacySelfSignedCert -SubjectName $env:COMPUTERNAME
        }

        # Create the hashtables of settings to be used.
        $valueset = @{}
        $valueset.Add('Hostname', $env:COMPUTERNAME)
        $valueset.Add('CertificateThumbprint', $thumbprint)

        $selectorset = @{}
        $selectorset.Add('Transport', 'HTTPS')
        $selectorset.Add('Address', '*')

        WriteLogFile "activation de SSL listener."
        New-WSManInstance -ResourceURI 'winrm/config/Listener' -SelectorSet $selectorset -ValueSet $valueset
    }
    Else
    {
        WriteLogFile "SSL listener est deja active"
    }


    # Check pour Basic auth
    $basicAuthSetting = Get-ChildItem WSMan:\localhost\Service\Auth | Where {$_.Name -eq "Basic"}
    If (($basicAuthSetting.Value) -eq $false)
    {
        WriteLogFile "activation de basic auth support."
        Set-Item -Path "WSMan:\localhost\Service\Auth\Basic" -Value $true
    }
    Else
    {
       WriteLogFile "Basic auth est deja active."
    }


    # configuration du firewall pour autoriser les connection HTTPS WINRM
    $fwtest1 = netsh advfirewall firewall show rule name="Allow WinRM HTTPS"
    $fwtest2 = netsh advfirewall firewall show rule name="Allow WinRM HTTPS" profile=any
    If ($fwtest1.count -lt 5)
    {
        WriteLogFile "ajout de la regle pour autoriser WinRM HTTPS."
        netsh advfirewall firewall add rule profile=any name="Allow WinRM HTTPS" dir=in localport=5986 protocol=TCP action=allow
    }
    ElseIf (($fwtest1.count -ge 5) -and ($fwtest2.count -lt 5))
    {
        WriteLogFile "Maj de la regle firewall pour autoriser WinRM HTTPS sur n importe quel profile (profiles public prive ou dromaine ...)"
        netsh advfirewall firewall set rule name="Allow WinRM HTTPS" new profile=any    # a changer en fonction des besoins 
    }
    Else
    {
         WriteLogFile  "la regle firewall existe deja pour autoriser WinRM HTTPS."
    }
    # hotes autorises a utilise winrm
    winrm set winrm/config/client '@{TrustedHosts="mamachine.blabla.com,ansiblemachine.blabla.com,monip,ipmachineansible"}'
    WriteLogFile "-------------------------------Execution du script termine---------------------------------------"
    
    # Copie du fichier de log sur le Shared folder
    Copy-Item -Path $Global:strLogFile -Destination "\\192.168.0.32\Logs\Script-default\$env:COMPUTERNAME  -  $PackageName.log" -Recurse
    Exit $lret_main








 

    <#     NOTES
    #generer mot de passe 
$Key = [byte]35,31,32,45,55,11,09,08,11,34,67,99,12,20,09,98      #utilisable sur n'importe quel machines 
"monmotdepasse" | Convertto-SecureString -AsPlainText -Force | ConvertFrom-SecureString -key $key
#resultat = xxx

New-Object System.Management.Automation.Pscredential -Argumentlist $login,$password # dans un script pour executer en tant que sans prompt
Start-Process powershell -Credential "xxx"    # test start en tant que xxx

#>



}



