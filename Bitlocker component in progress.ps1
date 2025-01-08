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
            write-host "- Status:   No TPM was detected on this system."
            break
        }
        '0 0$' {
            $varTPMStatus="Disabled [$varTPMVer]"
            write-host "- Status:   A TPM was detected ($varTPMVer), but it is not enabled."
            break
        }
        default {
            $varTPMStatus="Deactivated [$varTPMVer]"
            write-host "- Status:   A TPM was detected ($varTPMVer), but it is not activated."
            break
        }
        '1$' {
            $varTPMStatus="Active [$varTPMVer]"
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
    $arrDisks=Get-WMIObject -query "SELECT * from win32_logicaldisk where DriveType = '3'" | % {$_.DeviceID}

    # Disk analysis, for PS2.0
    foreach ($iteration in $arrDisks) {
        $varEncStatus=Get-WmiObject -namespace "Root\cimv2\security\MicrosoftVolumeEncryption" -Class "Win32_Encryptablevolume" -Filter "DriveLetter='$iteration'"
        if ($varEncStatus.ProtectionStatus -eq 1) {
            write-host "- Status:   Disk $iteration is encrypted with BitLocker."
            $varDiskStatus+=" $iteration`ENCPASS"
            if ($varEncStatus.EncryptionMethod -eq 5) {
                # Alert on hardware enc
                write-host "- Status:   Disk $iteration is using hardware encryption."
                write-host "  More info: https://www.theregister.co.uk/2018/11/05/busted_ssd_encryption/"
                $varDiskStatus+="[HW!]"
            }
            
            # Recount encryption key
            $varRecovery=$((get-bitlockervolume -mountpoint ($iteration).replace(':','')).keyprotector | foreach {$_.recoverypassword} | where {$_ -ne ""})
            if (($varRecovery -as [string]).Length -ge 2) {
                write-host "  Recovery: $varRecovery"
                $varDiskStatus+="/$varRecovery"
            } else {
                write-host "! ERROR: No BitLocker recovery key could be found on the device."
                write-host "  This is an issue requiring immediate attention. BitLocker should be disabled"
                write-host "  and re-enabled with the resulting key being archived. As it is, the contents"
                write-host "  of this disk may not be recoverable after a locking operation."
                $varDiskStatus+="/-------- NO RECOVERY KEY --------"
            }
            
        } else {
            write-host "- Status:   Disk $iteration is not encrypted with BitLocker."
            $varDiskStatus+=" $iteration`ENCFAIL"
        }
    }

    # Closeout
    $varDiskStatus=$varDiskStatus.Substring(1)
    $outputForUDF="TPM: $varTPMStatus | DISKS: $varDiskStatus"

    # Document the output to the UDF
    New-ItemProperty "HKLM:\SOFTWARE\CentraStage" -Name "Custom$env:UDFNumber" -PropertyType string -Value "$outputForUDF" -Force | out-null
    Write-Host "Successfully documented to UDF. Output: $outputForUDF"
}

function Enable-BitLockerOnDrive {
    param (
        [string]$DriveLetter
    )

    try{
        $BitlockerStatus = & manage-bde -status $DriveLetter
        $TPMState = Get-Tpm
    } catch {
        Write-Host "An error has occured while trying to get the current BitLocker status for drive $DriveLetter or whilw trying to get the TPM information"
        Write-Host "Error: $_"
        $exitCode = "1"
        return  # Exit the function if an error occurs
    }

    if (($BitlockerStatus -match "Protection\s+Off" -and $BitlockerStatus -match "reboots\s+left") -or ($BitlockerStatus -match "Protection\s+On" -and $BitlockerStatus -match "Percentage Encrypted:\s+100\.0%")) {
        Write-Host "BitLocker is already enabled on drive $DriveLetter."
    } else {
        Write-Host "BitLocker is not enabled on drive $DriveLetter. Attempting to enable BitLocker."
        if ($TPMState.TPMReady -eq $true) {
            Write-Host "TPM is ready. Enabling BitLocker on drive $DriveLetter."
            try {
                $ExistingKeyProtectors = Get-BitLockerVolume -MountPoint $DriveLetter -ErrorAction SilentlyContinue | Select-Object -ExpandProperty KeyProtector
                if ($ExistingKeyProtectors) {
                    Write-Host "Existing key protectors found on drive $DriveLetter."
                } else {
                    $RecoveryPasswordProtector = Add-BitLockerKeyProtector -MountPoint $DriveLetter -RecoveryPasswordProtector
                    Write-Host "Successfully added a BitLocker Key Protector on drive $DriveLetter."
                }
                if ($DriveLetter -eq "$env:SystemDrive") {
                    Enable-BitLocker -MountPoint $DriveLetter -UsedSpaceOnly -SkipHardwareTest -TpmProtector -ErrorAction Stop
                    Write-Host "Successfully enabled BitLocker on drive $DriveLetter."
                    Resume-BitLocker $DriveLetter
                    Write-Host "Resumed BitLocker protection on drive $DriveLetter if it was suspended."
                } else {
                    Enable-BitLocker -MountPoint $DriveLetter -UsedSpaceOnly -SkipHardwareTest -RecoveryPasswordProtector -ErrorAction Stop
                    Write-Host "Successfully enabled BitLocker on drive $DriveLetter."
                    Enable-BitLockerAutoUnlock -MountPoint $DriveLetter
                    Write-Host "Auto-unlock enabled for drive $DriveLetter."
                    Resume-BitLocker $DriveLetter
                    Write-Host "Resumed BitLocker protection on drive $DriveLetter if it was suspended."
                }

            } catch {
                Write-Host "Could not enable BitLocker on drive $DriveLetter. Error: $($_.Exception.Message)"
                $exitCode = "1"
            }
        } else {
            Write-Host "The TPM is not ready for use. Failed to enabele BitLocker for on drive $DriveLetter."
            $exitCode = "1"
        }
    }
}

# Main Script
$exitCode = "0"
$driveChoice = "All"

if ($driveChoice -eq 'System') {
    Write-Host "Selected system drive only."
    $DrivesToEncrypt = @("$env:SystemDrive")
} elseif ($driveChoice -eq 'All') {
    Write-Host "Selected all internal drives."
    $DrivesToEncrypt = Get-WMIObject -query "SELECT * from win32_logicaldisk where DriveType = '3'" | % {$_.DeviceID}
}

Write-Host "Enabling the BitLocker recovery agent in case this has been disabled by OS upgrades"
reagentc /enable

foreach ($drive in $DrivesToEncrypt) {
    Enable-BitLockerOnDrive -DriveLetter $drive
}

try{
    $BitlockerStatus = & manage-bde -status
} catch {
    Write-Host "An error has occured while trying to get the current BitLocker status using manage-bde -status"
    Write-Host "Error: $_"
    $exitCode = "1"
}

if (($BitlockerStatus -match "Protection\s+Off" -and $BitlockerStatus -match "reboots\s+left") -or ($BitlockerStatus -match "Protection\s+On" -and $BitlockerStatus -match "Percentage Encrypted:\s+100\.0%")){
    
    # Check if the device is AAD joined or registered
    Write-Host "Checking device's AAD join status..."
    $DSRegStatus = & "$env:SystemDrive\Windows\System32\dsregcmd.exe" /status
    $AADJoined = $DSRegStatus | Select-String "AzureAdJoined\s*:\s*YES" -Quiet

    # If the device is not AAD joined, just save the key to the UDF and exit with a warning
    if (!($AADJoined)) {
        Write-Host "This PC is not joined to or registered with Azure AD."
        $AAD_Result = "Not AAD joined or registered"
        Write-Host "WARNING: The key will only be saved to the UDF in Datto RMM which syncs to IT Glue!"
        Write-Host "If this device is AD joined and there is a GPO to save the key, GPO will auto save the key at the next gpupdate."
        Get-OutputAndDocumentToUDF
        Write-Host "Exiting as warning."
        exit $exitCode
    }

    # If AAD joined, document BitLocker Keys to Azure AD
    if ($AADJoined) {
        Write-Host "This PC is joined to Azure Active Directory (AAD)."
        Write-Host "We are going to try documenting the keys in Azure AD."
        foreach ($drive in $DrivesToEncrypt) {
            $BLV = Get-BitLockerVolume -MountPoint $drive
            $BitlockerKeyBackupToAAD = BackupToAAD-BitLockerKeyProtector -MountPoint $drive -KeyProtectorId $BLV.KeyProtector[1].KeyProtectorId
            if ($BitlockerKeyBackupToAAD) {
                Write-Host "Keys successfully documented in Azure AD for drive $drive."
            } else {
                Write-Host "Keys couldn't be documented in Azure AD for drive $drive."
                $exitCode = "1"
            }
        }
        Get-OutputAndDocumentToUDF
        Exit $exitCode
    }

} else {
    Write-Host "BitLocker is not enabled on any drive or there was an error getting the BitLocker status. `nDocumenting the TPM and BitLocker status to UDF"
    Get-OutputAndDocumentToUDF
    Exit $ExitCode
}