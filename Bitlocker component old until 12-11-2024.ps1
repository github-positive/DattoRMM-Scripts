<#
Credits: Shmily Strasser, Dov Silber, Positive Tech
Related blog: https://www.cyberdrain.com/documenting-with-powershell-chapter-2-documenting-bitlocker-keys/

Enables Bitlocker and documents the recovery key to a UDF (we use UDF 2) and to AAD. 
Supports AD GPO but you have to create the GPO for it to backup to AD. 

#>

function Get-BitLockerStatus {
    param (
        [string]$DriveLetter
    )

    try{
        $ManageBdeStatus = & manage-bde -status $DriveLetter
        if (($ManageBdeStatus -match "Protection\s+Off" -and $ManageBdeStatus -match "reboots\s+left") -or ($ManageBdeStatus -match "Protection\s+On" -and $ManageBdeStatus -match "Percentage Encrypted:\s+100[.,]0%")) {
            return  "Enabled"
        } else {
            return "Disabled"
        }
    } catch {
        Write-Host "An error has occurred while trying to get the current BitLocker status for drive $DriveLetter"
        Write-Host "Error: $_"
        $script:exitCode = "1"
        return  "Error"
    }
    
}

function Get-OutputAndDocumentToUDF {
    ## Get TPM information
    Write-Host "Gathering output data for UDF"
    $varTPM=@(0,0,0) # present :: enabled :: activated
    if ((Get-WmiObject -Class Win32_TPM -EnableAllPrivileges -Namespace "root\CIMV2\Security\MicrosoftTpm").__SERVER) { # TPM installed
        $varTPM[0]=1
        if ((Get-WmiObject -Namespace ROOT\CIMV2\Security\MicrosoftTpm -Class Win32_Tpm).IsEnabled().isenabled -eq $true) { # TPM enabled
            $varTPM[1]=1
            if ((Get-WmiObject -Namespace ROOT\CIMV2\Security\MicrosoftTpm -Class Win32_Tpm).IsActivated().isactivated -eq $true) { # TPM activated
                $varTPM[2]=1
            } else {
                $varTPM[2]=0
            }
        } else {
            $varTPM[1]=0
            $varTPM[2]=0
        }
        # Add newest-supported TPM version
        switch -Regex ((get-wmiobject -class win32_tpm -EnableAllPrivileges -Namespace "root\cimv2\security\microsofttpm").SpecVersion -split ',' -replace ' ' | select -first 1) {
            '^2' { $varTPMVer="Modern: v2.x" }
            '^1.3' { $varTPMVer="Legacy: v1.3x" }
            '^1.2' { $varTPMVer="Legacy: v1.2x" }
            $null { $varTPMVer="No version" }
            default { $varTPMVer="No version" }
        }
    }

    switch -Regex ($varTPM -as [string]) {
        '^0' {
            $varTPMStatus="Absent"
            $logTPMStatusToUDF = $true
            write-host "- Status:   No TPM was detected on this system."
            break
        }
        '0 0$' {
            $varTPMStatus="Disabled [$varTPMVer]"
            $logTPMStatusToUDF = $true
            write-host "- Status:   A TPM was detected ($varTPMVer), but it is not enabled."
            break
        }
        default {
            $varTPMStatus="Deactivated [$varTPMVer]"
            $logTPMStatusToUDF = $true
            write-host "- Status:   A TPM was detected ($varTPMVer), but it is not activated."
            break
        }
        '1$' {
            $varTPMStatus="Active [$varTPMVer]"
            $logTPMStatusToUDF = $false
            write-host "- Status:   A TPM was detected ($varTPMVer) and is ready for use." 
            break
        }
        $null {
            write-host "- Notice:   An error stopped the script working properly. Please report this issue." 
        }
    }

    # Disk check
    write-host "- - - - - - - - - - - - - - - -"
    write-host "= Disk Check:"
    write-host ": Enumerating fixed disks..."
    # Gathering all disks including external drives in case BL is enabled
    $arrDisks=Get-WMIObject -query "SELECT * from win32_logicaldisk where DriveType = '3'" | % {$_.DeviceID}

    # Disk analysis, for PS2.0
    foreach ($iteration in $arrDisks) {
        $BitLockerStatus = Get-BitLockerStatus $iteration
        if ($BitLockerStatus -eq "Enabled") {
            Write-Host "BitLocker is enabled on drive $iteration."
            $varDiskStatus+=" $iteration"

            # Recount encryption key
            $varRecovery=$((get-bitlockervolume -mountpoint ($iteration).replace(':','')).keyprotector | foreach {$_.recoverypassword} | where {$_ -ne ""})
            if (($varRecovery -as [string]).Length -ge 2) {
                write-host "  Recovery Key: $varRecovery"
                $varDiskStatus+="`/$varRecovery"
            } else {
                write-host "! ERROR: No BitLocker recovery key could be found on the device."
                write-host "  This is an issue requiring immediate attention. BitLocker should be disabled"
                write-host "  and re-enabled with the resulting key being archived. As it is, the contents"
                write-host "  of this disk may not be recoverable after a locking operation."
                $varDiskStatus+="`/-!! NO RECOVERY KEY !!-"
                $script:exitCode = "1"
            }
        } elseif ($BitLockerStatus -eq "Disabled") {
            Write-Host "BitLocker is not enabled on drive $iteration."
            $varDiskStatus+=" $iteration`ENCFAIL"
        } else {
            $varDiskStatus+=" $iteration`ERROR"
        }
    }
    # Closeout
    $varDiskStatus=$varDiskStatus.Substring(1)
    if ($logTPMStatusToUDF){
        $outputForUDF="TPM: $varTPMStatus | DISKS: $varDiskStatus"
    } else {
        $outputForUDF="$varDiskStatus"
    }

    # Document the output to the UDF
    New-ItemProperty "HKLM:\SOFTWARE\CentraStage" -Name "Custom$env:UDFNumber" -PropertyType string -Value "$outputForUDF" -Force | out-null
    if (($outputForUDF).length -gt 255) {
        write-host "! ALERT: Final output for UDF is longer than 255 characters and will be truncated in UDF form."
    }
    Write-Host "Successfully documented to UDF. Output: $outputForUDF"
}


function Enable-BitLockerOnDrive {
    param (
        [string]$DriveLetter
    )

    function Wait-ForEncryption {    
        Write-Host "Waiting for encryption to complete on drive $DriveLetter."
        $EncryptionStatus = $null
        do {
            Start-Sleep -Seconds 30
            $EncryptionStatus = Get-BitLockerVolume -MountPoint $DriveLetter | Select-Object -ExpandProperty EncryptionPercentage
            Write-Host "Encryption in progress on drive $DriveLetter $EncryptionStatus% complete."
        } while ($EncryptionStatus -lt 100)
        Write-Host "Encryption complete on drive $DriveLetter."
    }

    $BitLockerStatus = Get-BitLockerStatus $DriveLetter
    try{
        $TPMState = Get-Tpm
    } catch {
        Write-Host "An error has occurred while trying to get the TPM information for drive $DriveLetter"
        Write-Host "Error: $_"
        $script:exitCode = "1"
        return  # Exit the function if an error occurs
    }

    if ($BitLockerStatus -eq "Enabled") {
        Write-Host "BitLocker is already enabled on drive $DriveLetter."
    } elseif ($BitLockerStatus -eq "Disabled") {
        Write-Host "BitLocker is not enabled on drive $DriveLetter. Attempting to enable BitLocker."
        if ($TPMState.TPMReady -eq $true) {
            Write-Host "TPM is ready. Enabling BitLocker on drive $DriveLetter."
            try {
                $ExistingKeyProtectors = Get-BitLockerVolume -MountPoint $DriveLetter -ErrorAction SilentlyContinue | Select-Object -ExpandProperty KeyProtector
                if ($ExistingKeyProtectors) {
                    Write-Host "Existing key protectors found on drive $DriveLetter."
                } else {
                    # Create the key
                    Add-BitLockerKeyProtector -MountPoint $DriveLetter -RecoveryPasswordProtector
                    #verify it was created
                    $KeyProtectors = Get-BitLockerVolume -MountPoint $DriveLetter -ErrorAction SilentlyContinue | Select-Object -ExpandProperty KeyProtector
                    if ($KeyProtectors){
                        Write-Host "Successfully added a BitLocker Key Protector on drive $DriveLetter."
                    } else {
                        Write-Host "Could not create a key protector for drive $DriveLetter. Skipping this drive."
                        $script:exitCode = "1"
                        return
                    }
                }

                #saving the keys before encrypting and confirming success
                Write-Host "Trying to save the keys before encrypting the drive"
                $savingResult =""
                $savingResult = Save-CurrentDriveKey -DriveLetter $DriveLetter
                if ($savingResult -ne "Saved") {
                    Write-Host "error saving the keys for drivr $DriveLetter Not encrypting the drive"
                    return
                } else {
                    Write-Host "Keys for drive $DriveLetter have been saved successfully. Continuing to encrypt the drive"
                }


                if ($DriveLetter -eq "$env:SystemDrive") {
                    $KeyProtectors = Get-BitLockerVolume -MountPoint $DriveLetter -ErrorAction SilentlyContinue | Select-Object -ExpandProperty KeyProtector
                    if ($KeyProtectors | Where-Object { $_.KeyProtectorType -eq "tpm" }){
                        Enable-BitLocker -MountPoint $DriveLetter -UsedSpaceOnly -SkipHardwareTest -ErrorAction Stop
                        Write-Host "Successfully enabled BitLocker on drive $DriveLetter."
                        Wait-ForEncryption
                    } else {
                        Enable-BitLocker -MountPoint $DriveLetter -UsedSpaceOnly -SkipHardwareTest -TpmProtector -ErrorAction Stop
                        Write-Host "Successfully enabled BitLocker on drive $DriveLetter."
                        Wait-ForEncryption
                    }
                } else {
                    Enable-BitLocker -MountPoint $DriveLetter -UsedSpaceOnly -SkipHardwareTest -ErrorAction Stop
                    Write-Host "Successfully enabled BitLocker on drive $DriveLetter."
                    Wait-ForEncryption
                    Enable-BitLockerAutoUnlock -MountPoint $DriveLetter
                    Write-Host "Auto-unlock enabled for drive $DriveLetter."
                }

                Resume-BitLocker $DriveLetter
                Write-Host "Resumed BitLocker protection on drive $DriveLetter if it was suspended."

            } catch {
                Write-Host "Could not enable BitLocker on drive $DriveLetter. Error: $($_.Exception.Message)"
                $script:exitCode = "1"
            }
        } else {
            Write-Host "The TPM is not ready for use. Failed to enabele BitLocker for on drive $DriveLetter."
            $script:exitCode = "1"
        }
    } else {
        Write-Host "An error occurred. Skipping drive $DriveLetter"
        $script:exitCode = "1"
    }
}


function Save-CurrentDriveKey {
    param (
        [string]$DriveLetter
    )

    if ($AADJoined) {
        $savingToAADResult = ""
        Write-Host "Documenting the key for drive $DriveLetter in Azure AD."
        $KeyProtectorIds = Get-BitLockerVolume -MountPoint $DriveLetter | Select-Object -ExpandProperty KeyProtector | Where-Object {$_.KeyProtectorType -eq "RecoveryPassword" -and $_.RecoveryPassword -ne ""}
        $BitlockerKeyBackupToAAD = @()
        foreach ($key in $KeyProtectorIds){
            $BitlockerKeyBackupToAAD += BackupToAAD-BitLockerKeyProtector -MountPoint $DriveLetter -KeyProtectorId $key.KeyProtectorId
        }
        if ($BitlockerKeyBackupToAAD) {
            Write-Host "Keys successfully documented in Azure AD for drive $DriveLetter."
            $savingToAADResult = "Saved"
        } else {
            Write-Host "Keys couldn't be documented in Azure AD for drive $DriveLetter." -ForegroundColor Red
            $savingToAADResult = "Error"
            $script:exitCode = "1"
        }
    } else {
        $savingToAADResult = "N/A"
    }
    
    Write-Host "Documenting the key for drive $DriveLetter in UDF $env:UDFNumber."    
    try{
        $savingToUDFResult = ""
        # Recount encryption key
        $currentDriveKey=$((get-bitlockervolume -mountpoint ($DriveLetter).replace(':','')).keyprotector | foreach {$_.recoverypassword} | where {$_ -ne ""})
        if (($currentDriveKey -as [string]).Length -ge 2) {
            write-host "Drive: $DriveLetter. Recovery Key: $currentDriveKey"
            $keysTempArray += "'$DriveLetter': $currentDriveKey. "
        }
        # Document the output to the UDF
        New-ItemProperty "HKLM:\SOFTWARE\CentraStage" -Name "Custom$env:UDFNumber" -PropertyType string -Value "$keysTempArray" -Force | out-null
        Write-Host "Successfully documented to UDF."
        $savingToUDFResult = "Saved"
    } catch {
        Write-Host "Error saving key to UDF"
        $savingToUDFResult = "Error"
        $script:exitCode = "1"
    }

    if (($savingToAADResult -eq "Saved" -or $savingToAADResult -eq "N/A") -and $savingToUDFResult -eq "Saved") {
        return "Saved"
    } else {
        return "Error"
    }
}

# Main Script
$exitCode = "0"

# Check if the device is AAD joined or registered
Write-Host "Checking device's AAD join status..."
$DSRegStatus = & "$env:SystemDrive\Windows\System32\dsregcmd.exe" /status
$AADJoined = $DSRegStatus | Select-String "AzureAdJoined\s*:\s*YES" -Quiet
if ($AADJoined) {
    Write-Host "This PC is joined to Azure Active Directory (AAD)."
} else {
    Write-Host "This PC is not joined to Azure Active Directory (AAD)."
}

#array to keep the keys during the encryption iteratuon 
$keysTempArray = ""

if ($ENV:drives -eq 'System') {
    Write-Host "Selected system drive only."
    $DrivesToEncrypt = @("$env:SystemDrive")
} elseif ($ENV:drives -eq 'All_internal') {
    Write-Host "Selected all internal drives."
    $DrivesToEncrypt = @()
    $internalBusTypes = @('SATA', 'SAS', 'NVMe', 'RAID', 'ATA', 'SCSI')
    $internalDisks = Get-Disk | Where-Object { $internalBusTypes -contains $_.BusType } | Select-Object -ExpandProperty Number
    foreach ($disk in $internalDisks) {
        $DrivesToEncrypt += Get-Partition -DiskNumber $disk | Get-Volume | Where-Object { $_.DriveType -eq 'Fixed' } | Select-Object -ExpandProperty DriveLetter | ForEach-Object {$_ + ":"}
    }
    Write-Host "The following drives will be encrypted. $DrivesToEncrypt"
}

Write-Host "Enabling the BitLocker recovery agent in case this has been disabled by OS upgrades"
try {
    reagentc /enable    
}
catch {
    Write-Host "An error occurred while attempting to enable the BitLocker recovery agent."
    Write-Host "Error: $_"
    Exit 1
}


foreach ($drive in $DrivesToEncrypt) {
    Enable-BitLockerOnDrive -DriveLetter $drive
}

if ($AADJoined) {
    Write-Host "We are going to try documenting the keys in Azure AD."
    foreach ($drive in $DrivesToEncrypt) {
        $KeyProtectorIds = Get-BitLockerVolume -MountPoint $drive | Select-Object -ExpandProperty KeyProtector | Where-Object {$_.KeyProtectorType -eq "RecoveryPassword" -and $_.RecoveryPassword -ne ""}
        $BitlockerKeyBackupToAAD = @()
        foreach ($key in $KeyProtectorIds){
            $BitlockerKeyBackupToAAD += BackupToAAD-BitLockerKeyProtector -MountPoint $drive -KeyProtectorId $key.KeyProtectorId
        }
        if ($BitlockerKeyBackupToAAD) {
            Write-Host "Keys successfully documented in Azure AD for drive $drive."
        } else {
            Write-Host "Keys couldn't be documented in Azure AD for drive $drive."
            $exitCode = "1"
        }
    }
    Get-OutputAndDocumentToUDF
    Exit $exitCode
} else {
    Write-Host "This PC is not joined to or registered with Azure AD."
    Write-Host "WARNING: The key will only be saved to the UDF in Datto RMM which syncs to IT Glue!"
    Write-Host "If this device is AD joined and there is a GPO to save the key, GPO will auto save the key at the next gpupdate."
    Get-OutputAndDocumentToUDF
    # Write-Host "Exiting as warning."
    exit $exitCode
}

# Adding an open exit in case something wasn't captured and exited by the logic
Exit $exitCode 