# Define path for the security settings export
$exportPath = "C:\temp"
$exportFile = "$exportPath\secpol.cfg"

if (-not (Test-Path -Path $exportPath)) {
    New-Item -ItemType Directory -Path $exportPath | Out-Null
}

# Export current security settings
secedit /export /cfg $exportFile | Out-Null

# Display password complexity and lockout policy settings
Write-Host "Current Password and Lockout Policy Settings:"
Get-Content $exportFile | Select-String "PasswordComplexity", "LockoutBadCount", "ResetLockoutCount", "LockoutDuration" | ForEach-Object {
    switch -Regex ($_){
        "PasswordComplexity\s*=\s*(\d)" {
            $complexityStatus = if ($matches[1] -eq '1') {'Enabled'} else {'Disabled'}
            "Password Complexity: $complexityStatus"
        }
        "LockoutBadCount\s*=\s*(\d+)" {
            "Account Lockout Threshold: $($matches[1]) attempts"
        }
        "ResetLockoutCount\s*=\s*(\d+)" {
            "Reset Account Lockout Counter After: $($matches[1]) minutes"
        }
        "LockoutDuration\s*=\s*(\d+)" {
            "Account Lockout Duration: $($matches[1]) minutes"
        }
    }
}


# Screen lock timeout setting for all users
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop"
$registryName = "ScreenSaveTimeOut"

# Check if the registry key exists and display the screen lock timeout
if (Test-Path $registryPath) {
    $timeoutValue = (Get-ItemProperty -Path $registryPath -Name $registryName).$registryName
    Write-Host "Screen Lock Timeout: $timeoutValue seconds"
} else {
    Write-Host "Screen Lock Timeout: Not Configured"
}

# Clean up
Remove-Item $exportFile
