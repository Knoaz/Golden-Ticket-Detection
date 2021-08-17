$logPath = Read-Host -Prompt 'Input evtx file path'
$adminSID = "S-1-5-21-2439045635-180506259-1748410918-500"
$lastQuarterLogs= Get-WinEvent -FilterHashtable @{Path=$logPath; Providername="Microsoft-Windows-Security-Auditing";StartTime="1/8/2021"} 
$dcSyncEvents= $lastQuarterLogs | Where-Object {$_.message -match "0x100" -and $_.message -match $adminSID -and $_.ID -eq 4662}
$lowerCaseDomainNameEvents= $lastQuarterLogs | Where-Object {$_.message -cmatch "testlab\.local" -and ($_.ID -eq 4624 -OR $_.ID -eq 4672 -OR $_.ID -eq 4769 )}
$idMistachEvents= $lastQuarterLogs | Where-Object {$_.message -cmatch $adminSID -and $_.message -notmatch "Administrator" -and ($_.ID -eq 4624 -OR $_.ID -eq 4672 -OR $_.ID -eq 4769 ) }
$detectedLogs = $dcSyncEvents + $lowerCaseDomainNameEvents + $idMistachEvents
$detectedFilteredLogs = $detectedLogs | Select-Object -ExpandProperty message -Property ID, message
if($detectedFilteredLogs){
    $logNumber = 1
    $body = "Detected Logs: `n"
    foreach( $log in $detectedFilteredLogs){
        $ID = $log.ID.ToString()
        $message = $log.message
        $body += "Log Number: " + $logNumber.ToString() + " `n" +  "Event Id: " + $ID +" `n" + $message + " `n`n *-*-*-*-*-*-*-*-*-*-*-* `n`n"
        $logNumber += 1
    }
    $detectionReportPath = Read-Host -Prompt 'Input where to store'
    Out-File -FilePath $detectionReportPath -InputObject $body
    }