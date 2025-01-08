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
$version = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").CurrentVersion
if ($Version -lt "6.3") {
    write-DRMMDiag "Unsupported OS. Only Server 2012R2 and up are supported."
    write-DRRMAlert "Unsupported OS. Only Server 2012R2 and up are supported."
    exit 1
}
$SQLLitePath = "$env:ProgramData\System.Data.SQLite.dll"
$SQLLiteOldPath = "$env:ProgramData\System.Data.SQLite-Old.dll"
$alertThreshold = (Get-Date).AddDays(-1)
$diagMessages = @()

if ((Test-Path $SQLLitePath) -and (Test-Path $SQLLiteOldPath)) {
    try {
        add-type -path $SQLLitePath
    }
    catch {
        try {
            add-type -path $SQLLiteOldPath
        }
        catch {
            write-DRMMDiag "Could not load database components."
            write-DRMMAlert "Could not load database components."
            exit 1
        }
    }
    $con = New-Object -TypeName System.Data.SQLite.SQLiteConnection
    $con.ConnectionString = "Data Source=$env:systemdrive\Program Files\Bitdefender\Endpoint Security\Quarantine\cache.db"
    $con.Open()
    $sql = $con.CreateCommand()
    $sql.CommandText = "select * from entries"
    $adapter = New-Object -TypeName System.Data.SQLite.SQLiteDataAdapter $sql
    $data = New-Object System.Data.DataSet
    [void]$adapter.Fill($data)
    $sql.Dispose()
    $con.Close()
    
    $CurrentQ = foreach ($row in $Data.Tables.rows) {
        $quarantinedOn = [timezone]::CurrentTimeZone.ToLocalTime(([datetime]'1/1/1970').AddSeconds($row.quartime))
        $lastAccessedOn = [timezone]::CurrentTimeZone.ToLocalTime(([datetime]'1/1/1970').AddSeconds($row.acctime))
        $lastModifiedOn = [timezone]::CurrentTimeZone.ToLocalTime(([datetime]'1/1/1970').AddSeconds($row.modtime))
        
        # Check if any of the dates are within the date range
        if ($quarantinedOn -gt $alertThreshold -or $lastAccessedOn -gt $alertThreshold -or $lastModifiedOn -gt $alertThreshold) {
            [PSCustomObject]@{
                Path               = $row.path
                Threat             = $row.threat
                Size               = $row.Size
                'Quarantined On'   = $quarantinedOn
                'Last accessed On' = $lastAccessedOn
                'Last Modified On' = $lastModifiedOn
            }
        }
    }
    
    if ($CurrentQ) {
        $diagMessages += $CurrentQ
        write-DRMMDiag $diagMessages
        write-DRMMAlert "Unhealthy - $($CurrentQ.Count) Quarantine files found within the last $alertThreshold days. See Diagnostic data."
        exit 1
    }
    else {
        write-DRMMAlert "Healthy - No infections found."
    }
} else {
    #Do nothing, we have another monitor/response for this
    write-DRMMAlert "SQLite DLL files missing."
}