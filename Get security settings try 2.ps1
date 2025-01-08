function write-DRMMDiag ($messages) {
    write-host  '<-Start Diagnostic->'
    foreach ($Message in $Messages) { $Message }
    write-host '<-End Diagnostic->'
} 
$DRMMDiagMessages = @()

function write-DRRMAlert ($message) {
    write-host '<-Start Result->'
    write-host "Alert=$message"
    write-host '<-End Result->'
}

#Variables
$exportPath = "C:\temp"
$exportFile = "$exportPath\secpol.cfg"
$passwordComplexity = "Disabled"
$accountLockoutThreshold = "Disabled"
$accountLockoutDurationMinutes = "Not Configured"
$screenLockTimeoutSeconds = "Never"

##Alert Thresholds
#$Alert_passwordComplexity = "Disabled" 
#$Alert_accountLockoutThreshold = "" #Options are "Disabled" "Disabled or less than 8 attempts"
#$Alert_accountLockoutDuration = "" #Options are "Not Configured" "Not Configured or less than 2 minutes" "Not Configured or less than 5 minutes"
#$Alert_screenLockTimeout = "" #Options are "Never" "Never or less than 10 minutes" "Never or less than 30 minutes"

try {
    if (-not (Test-Path -Path $exportPath)) {
        New-Item -ItemType Directory -Path $exportPath | Out-Null
    }

    secedit /export /cfg $exportFile | Out-Null
} catch {
    write-DRRMAlert "Error: Failed to export security settings. Error Message: $_"
    Write-Host "exit 1"
}

try {
    $securitySettings = Get-Content $exportFile | Select-String "PasswordComplexity", "LockoutBadCount", "LockoutDuration", "ResetLockoutCount"

    foreach ($setting in $securitySettings) {
        if ($setting -match "PasswordComplexity\s*=\s*(\d)") {
            $passwordComplexity = if ($matches[1] -eq '1') {"Enabled"} else {"Disabled"}
        }
        if ($setting -match "LockoutBadCount\s*=\s*(\d+)") {
            $accountLockoutThreshold = if ($matches[1] -eq '0') {"Disabled"} else {"$($matches[1])"}
        }
        if ($setting -match "LockoutDuration\s*=\s*(\d+)") {
            $accountLockoutDurationMinutes = if ($matches[1] -eq '0') {"Not Configured"} else {"$($matches[1])"}
        }
    }
} catch {
    write-DRRMAlert "Error: Error reading or processing security settings file. Error Message: $_"
	Write-Host "exit 1"
}

try {
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop"
    $registryName = "ScreenSaveTimeOut"
    if (Test-Path $registryPath) {
        $timeoutValue = (Get-ItemProperty -Path $registryPath -Name $registryName).$registryName
        $screenLockTimeoutSeconds = "$timeoutValue"
    }
} catch {
    write-DRRMAlert "Error: Failed to access or read registry for screen lock timeout. Error Message: $_"
	Write-Host "exit 1"
}

try {
    Remove-Item $exportFile
} catch {
    # "Failed to clean up export file $exportFile. Error: $_"
}


##Create the alerts


# Check Password Complexity
if ($passwordComplexity -eq $ENV:Alert_passwordComplexity) {
    $DRMMDiagMessages += "Alert: Password Complexity is set to '$passwordComplexity', which is considered insecure."
}

# Check Account Lockout Threshold
if ($ENV:Alert_accountLockoutThreshold -eq "Disabled" -and $accountLockoutThreshold -eq "Disabled") {
    $DRMMDiagMessages += "Alert: Account Lockout Threshold is disabled."
} elseif ($ENV:Alert_accountLockoutThreshold -eq "Disabled or less than 8 attempts") {
    if ($accountLockoutThreshold -eq "Disabled" -or ($accountLockoutThreshold -match "\d+" -and $accountLockoutThreshold -lt 8)) {
        $DRMMDiagMessages += "Alert: Account Lockout Threshold is either disabled or set to less than 8 attempts."
    }
}

# Check Account Lockout Duration
if ($ENV:Alert_accountLockoutDuration -eq "Not Configured" -and $accountLockoutDurationMinutes -eq "Not Configured") {
    $DRMMDiagMessages += "Alert: Account Lockout Duration is not configured."
} elseif ($ENV:Alert_accountLockoutDuration -eq "Not Configured or less than 2 minutes") {
    if ($accountLockoutDurationMinutes -eq "Not Configured" -or ($accountLockoutDurationMinutes -ne "Not Configured" -and $accountLockoutDurationMinutes -lt 2)) {
        $DRMMDiagMessages += "Alert: Account Lockout Duration is not configured or less than 2 minutes."
    }
} elseif ($ENV:Alert_accountLockoutDuration -eq "Not Configured or less than 5 minutes") {
    if ($accountLockoutDurationMinutes -eq "Not Configured" -or ($accountLockoutDurationMinutes -ne "Not Configured" -and $accountLockoutDurationMinutes -lt 5)) {
        $DRMMDiagMessages += "Alert: Account Lockout Duration is not configured or less than 5 minutes."
    }
}

# Check Screen Lock Timeout
if ($ENV:Alert_screenLockTimeout -eq "Never" -and $screenLockTimeoutSeconds -eq "Never") {
    $DRMMDiagMessages += "Alert: Screen Lock Timeout is set to 'Never'."
} elseif ($ENV:Alert_screenLockTimeout -eq "Never or less than 10 minutes") {
    if ($screenLockTimeoutSeconds -eq "Never" -or ($screenLockTimeoutSeconds -ne "Never" -and $screenLockTimeoutSeconds -lt 600)) {
        $DRMMDiagMessages += "Alert: Screen Lock Timeout is set to 'Never' or less than 10 minutes."
    }
} elseif ($ENV:Alert_screenLockTimeout -eq "Never or less than 30 minutes") {
    if ($screenLockTimeoutSeconds -eq "Never" -or ($screenLockTimeoutSeconds -ne "Never" -and $screenLockTimeoutSeconds -lt 1800)) {
        $DRMMDiagMessages += "Alert: Screen Lock Timeout is set to 'Never' or less than 30 minutes."
    }
}

# Check if there are any alerts to display
if ($DRMMDiagMessages.Count -gt 0) {
    # Join all alerts into a single string separated by new lines for readability
    #$alertMessage = $alerts -join "`n"
    write-DRRMAlert "Some of the password security settings do not meet our standards. `nSee diagnostics/ticket notes for details"
	write-DRMMDiag $DRMMDiagMessages
	Write-Host "exit 1"
} else {
    write-DRRMAlert "No password security configuration issues detected."
	Write-Host "exit 0"
}













## Display the settings
Write-Host "Current Password and Lockout Policy Settings:"
Write-Host "Password Complexity: $passwordComplexity"
Write-Host "Account Lockout Threshold: $accountLockoutThreshold"
Write-Host "Account Lockout Duration: $accountLockoutDurationMinutes"
Write-Host "Screen Lock Timeout: $screenLockTimeoutSeconds"
#