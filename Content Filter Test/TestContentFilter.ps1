function Test-SiteAccess ($url) {
    try{
        $headers = @{
            "User-Agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
            "Accept" = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"
            "Accept-Language" = "en-US,en;q=0.5"
        }
        $ivrResults = Invoke-WebRequest "https://$url" -UseBasicParsing -Headers $headers
        if((($ivrResults).headers.'set-cookie' -match "domain=\.$url") -or (($ivrResults).headers.'set-cookie' -match "domain=\*\.$url")){
            return $true
        } else {
            return $false
        }
    }catch{
        return $false
    }
}

# Create/set the log file
try {
    $logFolderPath = Join-Path -Path $env:ProgramData -ChildPath "Positive"
    $logFilePath = Join-Path -Path $logFolderPath -ChildPath "ContentFilteringStatus.log"
    $logRetentionDays = 90

    if (-Not (Test-Path -Path $logFolderPath)) {
        New-Item -Path $logFolderPath -ItemType Directory -Force | Out-Null
    }
    if (-Not (Test-Path -Path $logFilePath)) {
        New-Item -Path $logFilePath -ItemType File -Force | Out-Null
    }
} catch {
    Write-Host "Error setting up log file: $_"
    exit 1
}

# Add current user info
$currentUser = whoami 2>$null
$results = @{
    User = $currentUser
}

# Test Content Filter Status
$sites = @(
    @{ URL = "instagram.com"; Category = "Social Media" }
    @{ URL = "zappos.com"; Category = "Shopping" }
    @{ URL = "nbcnews.com"; Category = "News" }
    @{ URL = "disneyplus.com"; Category = "Entertainment" }
    @{ URL = "porn.com"; Category = "Adult Content" }
)
foreach ($site in $sites) {
    #Write-Host "Testing, Category: $($site.Category), URL: $($site.URL)"
    $isAccessible = Test-SiteAccess -url $site.URL
    $status = if ($isAccessible -eq $true) {
         "Allowed" 
    } elseif ($isAccessible -eq $false) {
        "Blocked"
    } else {
        "Unknown"
    }
    $results[$site.Category] = $status
}
$JsonOutput = $results | ConvertTo-Json -Depth 2 -Compress
Write-Host "======================================================================================"
Write-Host "Results: $JsonOutput"
Write-Host "======================================================================================"

# Write the results to the log file
try {
    $currentDateTime = Get-Date -Format "MM-dd-yyyy HH:mm:ss"
    Add-Content -Path $logFilePath -Value "$currentDateTime - $JsonOutput"
}
catch {
    Write-Host "Error writing the results to the log file. Error $_"
    exit 1
}

### Clean up old logs ###

$retentionThreshold = (Get-Date).AddDays(-$logRetentionDays)
$tempFilePath = "$logFilePath.tmp"
$logFileData = Get-Content -Path $logFilePath
foreach ($line in $logFileData) {

    # Attempt to extract the date from each line (assuming the format: MM-dd-yyyy HH:mm:ss)
    if ($line -match "^(\d{2}-\d{2}-\d{4} \d{2}:\d{2}:\d{2})") {
        $logDate = Get-Date $matches[1] -ErrorAction SilentlyContinue

        # Check if the log date is older than the retention threshold
        if ($logDate -and ($logDate -lt $retentionThreshold)) {
            # Skip this line (older than retention period)
            continue
        } else {
            Add-Content -Path $tempFilePath -Value $line
        }
    } else {
        Add-Content -Path $tempFilePath -Value $line
    }
}

# Replace the original log file with the cleaned temporary file
if (Test-Path -Path $tempFilePath) {
    Move-Item -Path $tempFilePath -Destination $logFilePath -Force
}
### END Clean up old logs ###