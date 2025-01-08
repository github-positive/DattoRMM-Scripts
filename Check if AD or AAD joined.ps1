# Check AD domain join status
$DomainJoinStatus = (Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain

if ($DomainJoinStatus) {
    Write-Host "This PC is joined to Active Directory."
} else {
    # Attempt to check Azure AD join status using the full path to dsregcmd
    try {
        $AADStatus = & "C:\Windows\System32\dsregcmd.exe" /status | Select-String "AzureAdJoined\s*:\s*YES" -Quiet
        if ($AADStatus) {
            Write-Host "This PC is joined to Azure Active Directory (AAD)."
        } else {
            Write-Host "This PC is not joined to any domain."
        }
    } catch {
        Write-Host "Failed to check Azure AD join status."
    }
}
