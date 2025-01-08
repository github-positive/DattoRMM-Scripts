# Define path for the security settings export
$exportPath = "C:\secpol.cfg"
$modifiedPath = "C:\secpol_modified.cfg"

# Export current security settings
secedit /export /cfg $exportPath

# Read the file and modify the necessary lines for password complexity and lockout policy
$content = Get-Content $exportPath
$content | ForEach-Object {
    if ($_ -match "PasswordComplexity =") {
        "PasswordComplexity = 1" # Enable password complexity
    } elseif ($_ -match "LockoutBadCount =") {
        "LockoutBadCount = 5" # Set account lockout threshold to 5 attempts
    } elseif ($_ -match "ResetLockoutCount =") {
        "ResetLockoutCount = 15" # Set the duration for resetting the account lockout counter to 15 minutes
    } elseif ($_ -match "LockoutDuration =") {
        "LockoutDuration = 15" # Set the lockout duration to 15 minutes
    } else {
        $_ # Keep the line as is if it doesn't match any of the above
    }
} | Set-Content $modifiedPath

# Import the modified security settings
secedit /configure /db secedit.sdb /cfg $modifiedPath

# Screen lock timeout setting for all users
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop"
$registryName = "ScreenSaveTimeOut"
$timeoutValue = "900" # 15 minutes in seconds

# Check if the path exists and create it if it doesn't
if (-not (Test-Path $registryPath)) {
    New-Item -Path $registryPath -Force | Out-Null
}

# Set the screen lock timeout
Set-ItemProperty -Path $registryPath -Name $registryName -Value $timeoutValue

# Clean up
Remove-Item $exportPath
Remove-Item $modifiedPath
