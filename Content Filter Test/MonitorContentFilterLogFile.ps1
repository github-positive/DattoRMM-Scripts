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

### general variables
$logFolderPath = Join-Path -Path $env:ProgramData -ChildPath "Positive"
$logFilePath = Join-Path -Path $logFolderPath -ChildPath "ContentFilteringStatus.log"

$expectedBlockedCategories = "Social Media,Shopping,News,Entertainment,Adult Content"
$expectedBlockedCategoriesArray = $expectedBlockedCategories -split ','

$alert = $false
$diagMessages = @()

$udfNumber = "13"

# Check if the log file exists
if (-Not (Test-Path -Path $logFilePath)) {
    Write-Host "Log file not found: $logFilePath"
    exit 1
}

# Read the latest log entry from the log file
try {
    $latestLogLine = Get-Content -Path $logFilePath -Tail 1

    # Write to UDF
    Set-ItemProperty "HKLM:\Software\CentraStage" -Name "Custom$udfNumber" -Value $latestLogLine -Force | Out-Null

    # Extract the JSON portion of the log line
    if ($latestLogLine -match "{.+}") {
        $jsonContent = $matches[0]
        $latestResults = $jsonContent | ConvertFrom-Json
        $results = ""

        foreach ($category in $expectedBlockedCategoriesArray) {
            $category = $category.Trim() # Remove any extra spaces
            if ($null -ne $latestResults.$category -and $latestResults.$category -eq "Allowed") {
                $alert = $true
                $results += "$category is Allowed but should be Blocked.`n"
            }
        }
        $results += "`nCurrent expected blocked categories: $expectedBlockedCategories"
        $results += "`nTo exclude a category from alerting for this client, adjust the site variable 'expectedBlockedCategories'"
        $diagMessages += $results
    } else {
        Write-Host "No valid JSON found in the latest log entry."
        exit 1
    }
} catch {
    Write-Host "Error processing the log file or writing the UDF. Error: $_"
    exit 1
}

if ($alert){
    write-DRMMDiag $diagMessages
    write-DRRMAlert "Content filter settings are incorrect."
    Exit 1
} else {
    write-DRRMAlert "Content filter settings are correct."
}
