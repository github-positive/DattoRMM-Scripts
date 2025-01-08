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
$SQLLitePath = "$env:ProgramData\System.Data.SQLite.dll"
$SQLLiteOldPath = "$env:ProgramData\System.Data.SQLite-Old.dll"
$SQLLiteDownloadUrl = "https://raw.githubusercontent.com/github-positive/Bitdefender-Quarantine-Monitor/refs/heads/main/System.Data.SQLite.dll"
$SQLLiteOldDownloadUrl = "https://raw.githubusercontent.com/github-positive/Bitdefender-Quarantine-Monitor/refs/heads/main/System.Data.SQLite-Old.dll"

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
if ((!(Test-Path $SQLLitePath)) -or (!(Test-Path $SQLLiteOldPath)) ) {
    write-DRMMDiag "Error: 1 or both of the SQLite DLL files are missing. `nPlease run 'Positive - Add Bitdefender Quarantine Reader [WIN]' to add the DLL file. `nIf that fails you can download them from $SQLLiteDownloadUrl and $SQLLiteOldDownloadUrl and save them as $SQLLitePath and $SQLLiteOldPath"
    write-DRMMAlert "1 or both of the SQLite DLL files are missing."
    Exit 1
}
