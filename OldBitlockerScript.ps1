# Function to document the key to DRMM UDF
function Document-BitlockerKeyToUDF {
    $BitlockerKey = ((Get-BitLockerVolume -MountPoint $env:SystemDrive).keyprotector | Where-Object { $_.KeyProtectorType -EQ "RecoveryPassword" -and $_.RecoveryPassword -ne $null } | Select-Object -Last 1).recoverypassword
    if ($BitlockerKey) {
    Write-Host "We're documenting the bitlocker key: $BitlockerKey"
    New-ItemProperty "HKLM:\SOFTWARE\CentraStage" -Name "Custom$env:UDFNumber" -PropertyType string -Value $BitlockerKey -Force
    }
    else {
    Write-Host "We could not detect a bitlocker key. Enabling Bitlocker failed. This is the current bitlocker status:"
    Get-BitLockerVolume -MountPoint $env:SystemDrive
    exit 1
    }
}

# Enabling Bitlocker
Write-Host "Enabling the bitlocker recovery agent in case this has been disabled by OS upgrades"
reagentc /enable
Write-Host "Checking if Bitlocker is already enabled, and if so, documenting keys"
$Bitlockervolumes = Get-BitLockerVolume | Where-Object -Property mountpoint -EQ $env:SystemDrive
Write-Host "We've found the following Bitlocker capable volumes:"
$Bitlockervolumes | Format-List
if ($Bitlockervolumes.volumeStatus -eq "FullyEncrypted" -and $Bitlockervolumes.ProtectionStatus -eq "On") { 
    Write-Host "Bitlocker is enabled. We're going to document the keys." 
}
else {
    Write-Host "Bitlocker is not enabled. We're checking if Bitlocker can be enabled."
    $TPMState = Get-Tpm
    if ($TPMState.TPMReady -eq $true) {
        Write-Host "We have found TPM is ready, so we are going to try to enable Bitlocker"

        try {
            Write-Host "TPM is ready, we're going to try to encrypt the system volume."
            $RecoveryPasswordProtector = Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -RecoveryPasswordProtector
            Write-Host "We have added a Bitlocker Key Protector succesfully"
            Enable-BitLocker -MountPoint $env:SystemDrive -UsedSpaceOnly -SkipHardwareTest -TpmProtector -ErrorAction Stop
            Write-Host "We have enabled bitlocker succesfully"           
            Resume-BitLocker $env:SystemDrive
            Write-Host "We have resumed bitlocker protection if it was disabled by the user."
            Write-Host "=================Bit locker successfully enabled======================="

        }
        catch {
            Write-Host "Could not enable bitlocker $($_.Exception.Message)"
        }
    }
    else {
        Write-Host "The device is not ready for bitlocker. The TPM is reporting that it is not ready for use. Reported TPM information:"
        $TPMState
        exit 1
    }
}


# Check if the device is AAD joined or registered
Write-Host "Checking devices AAD join status..."
$DSRegStatus = & "$env:SystemDrive\Windows\System32\dsregcmd.exe" /status
$AADJoined = $DSRegStatus | Select-String "AzureAdJoined\s*:\s*YES" -Quiet

# If the device is not AAD joined, just save the key to the UDF and exit with a warning
if (!($AADJoined)) {
    Write-Host "This PC is not joined to or registered with Azure AD."
    $AAD_Result = "Not AAD joined or registered"
    Write-Host "WARNING: The key will only be saved to the UDF in Datto RMM which syncs to IT Glue!"
    Write-Host "If it's AD joined and there is a GPO to save they key, GPO will auto save the key at the next gpupdate."
    Document-BitlockerKeyToUDF
    Write-Host "Exiting as warning."
}

# If AAD joined, document Bitlocker Keys to Azure AD
if ($AADJoined){
    Write-Host "This PC is joined to Azure Active Directory (AAD)."
    Write-Host "We are going to try documenting the keys in Azure AD"
    $BLV = Get-BitLockerVolume -MountPoint $env:SystemDrive
    $BitlockerKeyBackupToAAD = BackupToAAD-BitLockerKeyProtector -MountPoint $env:SystemDrive -KeyProtectorId $BLV.KeyProtector[1].KeyProtectorId
    if ($BitlockerKeyBackupToAAD) {
        Write-Host "Keys successfully documented in Azure AD"
        Document-BitlockerKeyToUDF
    } else {
        Write-Host "Keys couldn't be documented in Azure AD"
        Document-BitlockerKeyToUDF
        exit 1
    }
}
