try {
    $taskName = "InstallWindows365App"
    $scriptPathFolder = "$env:ProgramData\Positive"
    $scriptPath = Join-Path -Path  $scriptPathFolder -ChildPath "InstallWindows365AppIfMissing.ps1"

    # Create the script file if it doesn't exist
    try {
        if (-not (Test-Path $scriptPathFolder)) {
            New-Item -ItemType Directory -Path $scriptPathFolder -Force | Out-Null
        }
        if (-not (Test-Path $scriptPath)) {
            Copy-Item -Path ".\InstallWindows365AppIfMissing.ps1" -Destination $scriptPath -Force | Out-Null
        }
    }
    catch {
        Write-Output "Failed to create script file $scriptPath. Error: $_"
        exit 1
    }

    # Check if task exists
    if (-not (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue)) {
        try {
            # Define the trigger (at logon)
            $trigger = New-ScheduledTaskTrigger -AtLogOn

            # Define the action (run PowerShell script)
            $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$scriptPath`""

            # Create task settings with no power restrictions
            $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

            # Register the task under the current user
            Register-ScheduledTask -TaskName $taskName -Trigger $trigger -Action $action -Settings $settings -User "SYSTEM" -RunLevel Limited |Out-Null
            Write-Output "Scheduled task '$taskName' created successfully."
            #exit 0
        }
        catch {
            Write-Output "Failed to create scheduled task: $_"
            #exit 1
        }
    } else {
        Write-Output "Scheduled task '$taskName' already exists."
        #exit 0
    }
} catch {
    Write-Output "An Unhandled error occurred: $_"
    exit 1
}