function write-DRMMDiag ($messages) {
    Write-Host  '<-Start Diagnostic->'
    foreach ($message in $messages) { $message }
    Write-Host '<-End Diagnostic->'
} 
function write-DRRMAlert ($message) {
    Write-Host '<-Start Result->'
    Write-Host "Alert=$message"
    Write-Host '<-End Result->'
}

$results = @()
$diagMessages = @()

if ($ENV:drives -eq 'System') {
    $drivesToMonitor = @("$env:SystemDrive")
} elseif ($ENV:drives -eq 'All_internal') {
    $drivesToMonitor = Get-WMIObject -query "SELECT * from win32_logicaldisk where DriveType = '3'" | % {$_.DeviceID}
}

foreach ($drive in $drivesToMonitor) {
    try{
        $BitlockerStatus = & manage-bde -status  $drive
    } catch {
        $results += "Drive '$drive': Status Error."
        $diagMessages += "Drive '$drive': An error has occured while trying to get the BitLocker status for drive $drive using manage-bde -status. `nError: $_"
        continue
    }

    if (($BitlockerStatus -match "Protection\s+Off" -and $BitlockerStatus -match "reboots\s+left") -or ($BitlockerStatus -match "Protection\s+On" -and $BitlockerStatus -match "Percentage Encrypted:\s+100\.0%")){
        $results += "Drive '$drive': Status Enabled."
        $diagMessages += "Drive '$drive': BitLocker is enabled. Full output for drive '$drive': `n $BitlockerStatus"
    } else {
        $results += "Drive '$drive': Status Disabled."
        $diagMessages += "Drive '$drive': BitLocker NOT enabled. Full output for drive '$drive': `n $BitlockerStatus"
    }
}

if ($results -match "Status Disabled") {
    write-DRRMAlert "Bitlocker is disabled for 1 or more drives. Check diagnistics for details."
    write-DRMMDiag $diagMessages
    exit 1 
}
elseif ($results -match "Status Error") {
    write-DRRMAlert "An error has occured while trying to get the BitLocker status. Check diagnistics for details."
    write-DRMMDiag $diagMessages
    exit 1 
} elseif ($results -match "Status Enabled") { 
    write-DRRMAlert "Healthy. Bitlocker enabled" 
    exit 0
} else {
    write-DRRMAlert "An unknown error has occured. Check diagnistics for details."
    exit 1
}