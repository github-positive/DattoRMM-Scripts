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
function Get-LoggedOnUsers {
    try {
        $QuserRaw = quser.exe 2>&1
        if ($QuserRaw -match "No User exists for \*") {
            return @()
        }
        $QuserCSV = $QUserRaw.Trim().Replace("  ",",").Replace(", ",",").Replace(" ,",",").Replace(",,,,,",",").Replace(",,,,",",").Replace(",,,",",").Replace(",,",",")
        $QuserArray = $QuserCSV -split "`n"
    
        # Iterate over each row in the array to find any row with only five data values and add an extra comma for SESSIONNAME
        for ($i=0; $i -lt $QuserArray.Length; $i++) {
            # Count the number of commas in the row
            $commaCount = ([regex]::Matches($QuserArray[$i], ",")).Count
            
            # If there are only four commas, replace the first comma with two commas
            if ($commaCount -eq 4) {
                $firstCommaIndex = $QuserArray[$i].IndexOf(",")
                $QuserArray[$i] = $QuserArray[$i].Insert($firstCommaIndex + 1, ",")
            }
        }
    
        # Convert string array to CSV object and remove first row (header)
        $QuserArray = $QuserArray | ConvertFrom-Csv -Header "USERNAME","SESSIONNAME","ID","STATE","IDLE_TIME","LOGON_TIME"
        $QuserArray = $QuserArray | Select-Object -Skip 1
        $QuserArray = $QuserArray | ForEach-Object {
            $_.USERNAME = $_.USERNAME.Replace('>', '')
            $_
        }
    
        # Output the corrected array with added columns
        return $QuserArray
    } catch {
        $script:diagMessages += "Error retrieving logged-on users: $_"
        $script:success = $false
        return @()
    }
}
function Test-IsExcluded ($username) {
    $excludedUsers = @("positive","admin")
    foreach ($exclusion in $excludedUsers) {
        if ($username -like "*$exclusion*") {
            return $true
        }
    }
    return $false
}
function Test-IsValidJson {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$InputLine
    )

    try {
        ConvertFrom-Json -InputObject $InputLine -ErrorAction Stop
        return $true
    } catch {
        return $false
    }
}

### general variables
$diagMessages = @()
$success = $true
$ufdNumber = "14"
$approvedUdfValues = @("No login for 30 days","Complimentary Device", "Discounted Device")

# Create/set the log file
try {
    $logFolderPath = Join-Path -Path $env:ProgramData -ChildPath "Positive"
    $logFilePath = Join-Path -Path $logFolderPath -ChildPath "UserLogonHistory.log"
    $logRetentionDays = 90

    if (-Not (Test-Path -Path $logFolderPath)) {
        New-Item -Path $logFolderPath -ItemType Directory -Force | Out-Null
    }
    if (-Not (Test-Path -Path $logFilePath)) {
        New-Item -Path $logFilePath -ItemType File -Force | Out-Null
    }
} catch {
    $diagMessages += "Error setting up log file: $_"
    $success = $false
}

# Retrieve all currently logged-on users
$userData = @()
try {
    $loggedOnUsers = Get-LoggedOnUsers
    if ($loggedOnUsers) {
        foreach ($entry in $loggedOnUsers) {
            $isExcluded = Test-IsExcluded -username $entry.Username

            # Add user details to the collection
            $userData += @{
                Username      = $entry.Username
                IsExcluded    = $isExcluded
                LastLogonTime = $entry.LOGON_TIME
                IdleTime      = $entry.IDLE_TIME
                state         = $entry.STATE
                id            = $entry.ID
            }
        }

        # Convert the user data collection to JSON and output it
        $jsonOutput = $userData | ConvertTo-Json -Depth 3 -Compress
        if ($jsonOutput.StartsWith("{")) {
            # Wrap it in square brackets
            $jsonOutput = "[$jsonOutput]"
        }
    } else {
        $jsonOutput = '[{"Message": "No logged-on users."}]'
    }
} catch {
    $diagMessages += "Error retrieving logged-on user data: $_"
    $success = $false
}

# Add a new log entry with the current date and time in MM-dd-yyyy HH:mm:ss format
try {
    $currentDateTime = Get-Date -Format "MM-dd-yyyy HH:mm:ss"
    Add-Content -Path $logFilePath -Value "$currentDateTime - $jsonOutput"
} catch {
    $diagMessages += "Error writing to log file: $_"
    $success = $false
}

$logFileData = Get-Content -Path $logFilePath
if (-not $logFileData -or $logFileData.Count -eq 0) {
    $diagMessages += "Log file is empty or unavailable."
    $success = $false
} else {

    ### Review the logs and set the UDF ###
    try {
        $currentUdfValue = (Get-Item "ENV:\UDF_$ufdNumber").value
        $cutoffDate = (Get-Date).AddDays(-30)
        $foundNonExcludedUsersLogonWithin30Days = $false
        $logsFoundWithin30Days = $false
        $oldestLogTimestamp = $null
        foreach ($line in $logFileData) {
            if ($line -match '^(?<timestamp>\d{2}-\d{2}-\d{4} \d{2}:\d{2}:\d{2}) - (?<entry>\[.*\])$') {
                $logTimestamp = [datetime]::ParseExact($matches['timestamp'], 'MM-dd-yyyy HH:mm:ss', $null)
                $logEntry = $matches['entry']  # Keep the log entry as-is, since it is now a valid JSON array

                # Track the oldest log timestamp
                if (-not $oldestLogTimestamp -or $logTimestamp -lt $oldestLogTimestamp) {
                    $oldestLogTimestamp = $logTimestamp
                }

                # Check if the log entry date is within the past 30 days
                if ($logTimestamp -ge $cutoffDate) {
                    if(Test-IsValidJson -InputLine $line) {
                        $logsFoundWithin30Days = $true  # Mark that at least one log entry exists in the past 30 days

                        $logData = $logEntry | ConvertFrom-Json -ErrorAction Stop
                        # Iterate through each JSON object in the array
                        $logData | ForEach-Object {
                            if ((-not ($_.Message -eq "No logged-on users.")) -and ($_.state -eq "Active") -and (-not (Test-IsExcluded -username $_.Username))) {
                                $script:foundNonExcludedUsersLogonWithin30Days = $true
                            }
                        }
                    }
                }
            }
        }

        if ($currentUdfValue -eq "No login for 30 days"){
            if ($foundNonExcludedUsersLogonWithin30Days) {
                Set-ItemProperty "HKLM:\Software\CentraStage" -Name "Custom$ufdNumber" -Value $null -Force | Out-Null
            }
        } elseif ([string]::IsNullOrEmpty($currentUdfValue) ) {
            if (($foundNonExcludedUsersLogonWithin30Days -eq $false) -and $logsFoundWithin30Days -and $oldestLogTimestamp -and ($oldestLogTimestamp -lt $cutoffDate) ) {
                Set-ItemProperty "HKLM:\Software\CentraStage" -Name "Custom$ufdNumber" -PropertyType String -Value "No login for 30 days" -Force | Out-Null
            }
        } elseif ($currentUdfValue -notin $approvedUdfValues) {
            $diagMessages += "Warning! there is non-approved data in UDF $ufdNumber so the system can't set the correct billing information."
            $success = $false
        }
        
    }
    catch {
        $diagMessages += "Error checking the log file and determining the billing state or setting the UDF. Error: $_"
        $success = $false
    }
    ### END Review the logs and set the UDF ###

    ### Clean up old logs ###
    $retentionThreshold = (Get-Date).AddDays(-$logRetentionDays)
    $tempFilePath = "$logFilePath.tmp"

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

}

if ($diagMessages.Count -gt 0) {
    write-DRMMDiag $diagMessages
}

if ($success -eq $true) {
    write-DRRMAlert "Completed success!"
    Exit 0
} else {
    write-DRRMAlert "Completed with errors!"
    Exit 1
}