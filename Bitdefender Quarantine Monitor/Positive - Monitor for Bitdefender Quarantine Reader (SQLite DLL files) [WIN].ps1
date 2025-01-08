function write-DRMMDiag ($messages) {
    write-host  '<-Start Diagnostic->'
    foreach ($Message in $Messages) { $Message }
    write-host '<-End Diagnostic->'
} 

function write-DRMMAlert ($message) {
    write-host '<-Start Result->'
    write-host "Alert=$message"
    write-host '<-End Result->'
}
$SQLLiteName = "System.Data.SQLite.dll"
$SQLLiteOldName = "System.Data.SQLite-Old.dll"
$SQLLitePath = "$env:ProgramData\$SQLLiteName"
$SQLLiteOldPath = "$env:ProgramData\$SQLLiteOldName"
$SQLLiteDownloadUrl = "https://raw.githubusercontent.com/github-positive/Bitdefender-Quarantine-Monitor/refs/heads/main/System.Data.SQLite.dll"
$SQLLiteOldDownloadUrl = "https://raw.githubusercontent.com/github-positive/Bitdefender-Quarantine-Monitor/refs/heads/main/System.Data.SQLite-Old.dll"
$DiagMessages = @()
$AlertMessage = ""
$ExitCode = 0

if (!(Test-Path $SQLLitePath)) {
    try {
        Invoke-WebRequest -Uri $SQLLiteDownloadUrl -OutFile $SQLLitePath -UseBasicParsing -ErrorAction SilentlyContinue
    } catch {
        #do nothing
    }
}
if (!(Test-Path $SQLLiteOldPath)) {
    try {
        Invoke-WebRequest -Uri $SQLLiteOldDownloadUrl -OutFile $SQLLiteOldPath -UseBasicParsing -ErrorAction SilentlyContinue
    } catch {
        #do nothing
    }
}
$SQLLitePresent = (Test-Path $SQLLitePath -ErrorAction SilentlyContinue)
$SQLLiteOldPresent = (Test-Path $SQLLiteOldPath -ErrorAction SilentlyContinue)
$SQLLiteSize = ((Get-Item $SQLLitePath -ErrorAction SilentlyContinue).Length )
$SQLLiteOldSize = ((Get-Item $SQLLiteOldPath -ErrorAction SilentlyContinue).Length )


if ((! $SQLLitePresent) -or (! $SQLLiteOldPresent) ) {
    $DiagMessages += "Error: 1 or both of the SQLite DLL files are missing. `nPlease run 'Positive - Add Bitdefender Quarantine Reader [WIN]' to add the DLL file. `nIf that fails you can download them from $SQLLiteDownloadUrl and $SQLLiteOldDownloadUrl and save them as $SQLLitePath and $SQLLiteOldPath"
    $AlertMessage = "1 or both of the SQLite DLL files are missing. "
    $ExitCode = 1
}


if (($SQLLitePresent -and ($SQLLiteSize -lt 1024000)) -or ($SQLLiteOldPresent -and ($SQLLiteOldSize -lt 1024000) ) ) {
    $DiagMessages += "Error: 1 or both of the SQLite DLL files are below the expected file size and are likely corrupted or failed the download. `nDownload by running the 'Positive - Add Bitdefender Quarantine Reader [WIN]' component  or from $SQLLiteDownloadUrl and $SQLLiteOldDownloadUrl"
    $AlertMessage += "1 or both of the SQLite DLL files are missing."
    $ExitCode = 1
}


if ($ExitCode -eq 0) {
    write-DRMMAlert "Healthy - Both DLL files are present."
    Exit $ExitCode
} else {
    write-DRMMDiag $DiagMessages
    write-DRMMAlert $AlertMessage
    Exit $ExitCode
}