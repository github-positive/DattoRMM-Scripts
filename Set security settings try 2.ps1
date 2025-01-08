# Function to export, modify, and import security policy settings
function Update-SecurityPolicy {
    param (
        [string]$exportPath = "C:\temp\secpol.cfg",
        [string]$passwordComplexity = "1", # 1 for Enabled, 0 for Disabled
        [string]$lockoutThreshold = "8", # 0 to disable
        [string]$lockoutDuration = "2", # Minutes, 1 to specify infinite duration since 0 is not accepted
        [string]$resetLockoutCount = "15" # Minutes after which the lockout counter is reset
    )

    # Ensure the export directory exists
    $exportDir = Split-Path -Path $exportPath -Parent
    If (-not (Test-Path -Path $exportDir)) {
        New-Item -ItemType Directory -Path $exportDir | Out-Null
    }

    # Export the current security settings
    secedit /export /cfg $exportPath /quiet

    # Read the exported settings
    $securitySettings = Get-Content -Path $exportPath

    # Modify the settings within the file
    $updatedSettings = $securitySettings -replace "(?<=PasswordComplexity\s*=\s*).+", $passwordComplexity `
                                        -replace "(?<=LockoutBadCount\s*=\s*).+", $lockoutThreshold `
                                        -replace "(?<=LockoutDuration\s*=\s*).+", $lockoutDuration `
                                        -replace "(?<=ResetLockoutCount\s*=\s*).+", $resetLockoutCount

    # Write the updated settings back to the file
    $updatedSettings | Out-File -FilePath $exportPath -Force -Encoding Default

    # Import the updated settings
    secedit /configure /db $env:windir\security\local.sdb /cfg $exportPath /quiet

    Write-Host "Security policy updated successfully."
}

# Update the screen lock timeout setting in the registry
function Set-ScreenLockTimeout {
    param (
        [string]$timeoutSeconds = "600" # Screen lock timeout in seconds (10 minutes)
    )
    $registryPath = "HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop"
    $registryName = "ScreenSaveTimeOut"
    If (-not (Test-Path $registryPath)) {
        New-Item -Path $registryPath -Force | Out-Null
    }
    Set-ItemProperty -Path $registryPath -Name $registryName -Value $timeoutSeconds
}

# Call the functions to update security policy and screen lock timeout
Update-SecurityPolicy -passwordComplexity "1" -lockoutThreshold "8" -lockoutDuration "2" -resetLockoutCount "15"
Set-ScreenLockTimeout -timeoutSeconds "900" # 15 minutes
