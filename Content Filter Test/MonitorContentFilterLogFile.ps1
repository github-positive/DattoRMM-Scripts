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

$expectedBlockedCategories = $ENV:expectedBlockedCategories
if ($expectedBlockedCategories.Length -lt 1){
    $expectedBlockedCategories = "Adult Content"
}
$expectedBlockedCategoriesArray = $expectedBlockedCategories -split ','
#$supportedBlockedCategories = "Social Media,Shopping,News,Entertainment,Adult Content"
#$supportedBlockedCategoriesArray = $supportedBlockedCategories -split ','

$alert = $false
$diagMessages = @()

$udfNumber = "13"

# Check if the log file exists
if (-Not (Test-Path -Path $logFilePath)) {
    write-DRRMAlert "Log file not found: $logFilePath"
    exit 0
} else{

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

                # Check if all categories are supported
                <#
                if ($category -inotin $supportedBlockedCategoriesArray){
                    write-DRMMDiag "An unsupported category found in site variable 'expectedBlockedCategories'."
                    write-DRRMAlert "An unsupported category found in site variable 'expectedBlockedCategories'."
                    Exit 1
                } #>
                if ($null -ne $latestResults.$category -and $latestResults.$category -eq "Allowed") {
                    $alert = $true
                    $results += "$category is Allowed but should be Blocked.`n"
                }
            }
            $results += "`nCurrent expected blocked categories: $expectedBlockedCategories"
            $results += "`nFor exclusions see https://positivecomputers.itglue.com/2538598/docs/18348433#id-bba8bb25-c3d8-4ba7-887f-5c0a5a73a41e"
            $diagMessages += $results
        } else {
            write-DRRMAlert "No valid JSON found in the latest log entry."
            exit 1
        }
    } catch {
        write-DRRMAlert "Error processing the log file or writing the UDF. Error: $_"
        exit 1
    }
}

if ($alert){
    write-DRMMDiag $diagMessages
    write-DRRMAlert "Content filter settings are incorrect."
    Exit 1
} else {
    write-DRRMAlert "Content filter settings are correct."
}
