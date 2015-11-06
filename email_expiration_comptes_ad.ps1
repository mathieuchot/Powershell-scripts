##########  Powershell script tâche planifié tous les jours a 8:00 sur l'AD  ###############
##      Mathieu Chot-plassot                                                              ##
#       @Mathieu_chot                                                                      #
############################################################################################

##############Declaration de variables#####################
$SmtpServer ="mail.mathieuchot.com"
$expireindays = 7
$from = "Mathieuchotcorp <Support@mathieuchot.com>"
$logging = "yes"     #yes pour activer le log
$logFile = "c:\Pkglogs\AD_expiring_accounts.csv"
$testing = "no"     #yes pour tester avec l'email Admin_email 
$date = Get-Date -format dd/MM/yyyy
$Admin_email = "mchotplassot@mathieuchot.com"
#Encodage UTF8 pour l'affichage dans le mail
$UTF8 = [System.Text.Encoding]::UTF8
###########################################################

if (($logging) -eq "yes")
{
    $logfilePath = (Test-Path $logFile)
    if (($logFilePath) -ne "True")
    {
        New-Item $logfile -ItemType File
        Add-Content $logfile "Date,Nom,Email,Jours restant,Expire le"
    }
} 

Import-Module ActiveDirectory
$users = get-aduser -filter * -properties Name, PasswordNeverExpires, PasswordExpired, PasswordLastSet, EmailAddress |where {$_.Enabled -eq "True"} | where { $_.PasswordNeverExpires -eq $false } | where { $_.passwordexpired -eq $false }
$Defaultmaxpasswd_age = (Get-ADDefaultDomainPasswordPolicy).MaxPasswordAge

foreach ($user in $users)
{
    $Name = $user.Name
    $emailaddress = $user.emailaddress
    $Passwd_SetDate = $user.PasswordLastSet
    $Passwd_policy = (Get-AduserResultantPasswordPolicy $user)

    if (($Passwd_policy) -ne $null)
    {
        $MaxPasswordAge = ($Passwd_policy).MaxPasswordAge
    }
    else
    {
        $MaxPasswordAge = $Defaultmaxpasswd_age
    }

  
    $expireson = $Passwd_SetDate + $MaxPasswordAge
    $today = (get-date)
    $daystoexpire = (New-TimeSpan -Start $today -End $Expireson).Days
        
    # check le nombre de jours restant
    $messageDays = $daystoexpire

    if (($messageDays) -ge "1")
    {
        $messageDays = "dans " + "$daystoexpire" + " jours."
    }
    else
    {
        $messageDays = "aujourd'hui."
    }

    # sujet du mail
    $subject="Votre mot de passe expire $messageDays"
  
    # body du mail 
    $body ="
    Bonjour $name,
    <p> Ceci est un mail automatique, le mot de passe de votre compte Active Directory expire $messageDays.<br>
    Dépassée cette date, vous serez dans l'impossibilité de vous connecter au réseau de l'entreprise <br>
    <p>Pour changer votre mot de passe avant l'expiration <a href=https://selfservice.mathieuchot.com/pwm/private/Login> cliquez ici </a> <br> 
    <p>Veuillez contacter <b>$Admin_email</b> si vous rencontrez des difficultés.<br> 
    </P>"

   
    # Si la variable Testing = yes > on envoie sur mon mail
    if (($testing) -eq "yes")
    {
        $emailaddress = $Admin_email
    } 

    # si l'user n'a pas d'adresse email renseigné > on envoie sur mon mail
    if (($emailaddress) -eq $null)
    {
        $emailaddress = $Admin_email    
    }


    if (($daystoexpire -ge "0") -and ($daystoexpire -le $expireindays))
    {
        if (($logging) -eq "yes")
        {
            Add-Content $logfile "$date,$Name,$emailaddress,$daystoExpire,$expireson" 
        }
        # envoyer le mail
        Send-Mailmessage -from $from -to $emailaddress -subject $subject -SmtpServer $SmtpServer -Body $body -BodyAsHtml -Encoding $UTF8 -Priority High  
    }   
}
