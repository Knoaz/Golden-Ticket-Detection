$adminSID = "S-1-5-21-2439045635-180506259-1748410918-500"
$lastQuarter = (Get-Date).AddMinutes(-15)
$lastQuarterLogs= Get-EventLog -LogName Security -After $lastQuarter
$dcSyncEvents= $lastQuarterLogs | Where-Object {$_.message -match "0x100" -and $_.message -match $adminSID -and $_.EventID -eq 4662}
$lowerCaseDomainNameEvents= $lastQuarterLogs | Where-Object {$_.message -cmatch "testlab\.local" -and ($_.EventID -eq 4624 -OR $_.EventID -eq 4672 -OR $_.EventID -eq 4769 )}
$idMistachEvents= $lastQuarterLogs | Where-Object {$_.message -cmatch $adminSID -and $_.message -notmatch "Administrator" -and ($_.EventID -eq 4624 -OR $_.EventID -eq 4672 -OR $_.EventID -eq 4769 ) }
$detectedLogs = $dcSyncEvents + $lowerCaseDomainNameEvents + $idMistachEvents
$detectedFilteredLogs = $detectedLogs | Select-Object -ExpandProperty message -Property EventID, message
if($detectedFilteredLogs){
    $logNumber = 1
    $body = "Detected Logs: `n"
    foreach( $log in $detectedFilteredLogs){
        $eventId = $log.EventID.ToString()
        $message = $log.message
        $body += "Log Number: " + $logNumber.ToString() + " `n" +  "Event Id: " + $eventId +" `n" + $message + " `n`n *-*-*-*-*-*-*-*-*-*-*-* `n`n"
        $logNumber += 1
    }
    #Write-Host($body)
    $password = ConvertTo-SecureString 'Password' -AsPlainText -Force
    $credential = New-Object System.Management.Automation.PSCredential ('kozan16', $password)
    Send-MailMessage -From 'kozan16@itu.edu.tr' -To 'kozan16@itu.edu.tr' -Subject 'Golden Ticket Detection' -Body $body -Credential $credential -SmtpServer 'smtp.itu.edu.tr' -port 587 -UseSsl
    }
