# Fatal error Function
Function Write-ErrorAndExit {
	param ($errorMessage)
	Write-Host -ForegroundColor Red $errorMessage
	Write-Host -ForegroundColor Red "Exiting..."
	Pause
	exit
}

# Install required modules if not installed
Function Install-ModuleIfIsNotInstalled {
	param ($moduleName)
	if(-not (Get-Module $moduleName -ListAvailable)){
		Write-Host "Installing $moduleName module"
		Install-Module $moduleName -Scope AllUsers -Force
	}
	else {
		Write-Host "Found $moduleName module"
	}
}
Install-ModuleIfIsNotInstalled "Microsoft.Graph"
Install-ModuleIfIsNotInstalled "MSOnline"
Install-ModuleIfIsNotInstalled "AzureAD"
Install-ModuleIfIsNotInstalled "ExchangeOnlineManagement"
Install-ModuleIfIsNotInstalled "ActiveDirectory"
Install-ModuleIfIsNotInstalled "SharePointPnPPowerShellOnline"
Install-ModuleIfIsNotInstalled "Az"

# Import required modules
# Importing all functions crashes with an error that functions limit has been reached,
# therefore only import required functions
# Function Import-ModuleAndRequiredFunctions {
	# param ($moduleName, $functionNames)
	# Write-Host "Importing $moduleName module"
	# if(-not (Import-Module $moduleName -Function $functionNames)) {
		# Write-ErrorAndExit "Failed to import the $moduleName module"
	# }
# }

# Import-ModuleAndRequiredFunctions "Microsoft.Graph" "Connect-MgGraph, Get-AvailableLicenses, Get-MgUser, Get-MgSubscribedSku, Set-MgUserLicense"
# Import-ModuleAndRequiredFunctions "MSOnline" "Set-MsolUser, Get-MsolAccountSku, Add-MsolGroupMember"
# Import-ModuleAndRequiredFunctions "AzureAD" "Get-AzureADUser"
# Import-ModuleAndRequiredFunctions "ExchangeOnlineManagement" "Enable-Mailbox, Add-MailboxPermission, Add-DistributionGroupMember"
# Import-ModuleAndRequiredFunctions "ActiveDirectory" "Get-ADUser, New-ADUser, Set-ADUser, Add-ADGroupMember"

# Connect to MSOL and Exchange Online
Connect-MgGraph -Scopes User.ReadWrite.All, Organization.Read.All -NoWelcome
Connect-MsolService
Connect-AzureAD
Connect-ExchangeOnline -UserPrincipalName admin@mbhpays.com -ShowBanner:$false
Connect-AzAccount #for the OTP token 

# ADSync Service Hostname
# Default hostname for the ADSync service. Update only if necessary.
$ADSyncServiceHost = "aadconnect.mbh.local"

# Add necessary assemblies
Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Application]::EnableVisualStyles()

# Form setup
$form = New-Object System.Windows.Forms.Form
$form.Text = "AD & Office 365 User Creation Tool"
$form.Size = New-Object System.Drawing.Size(430, 450)
$form.StartPosition = "CenterScreen"

# Helper function to add controls
function Add-FormControl {
	param ($type, $text, $locationY, $width = 200)
	$label = New-Object System.Windows.Forms.Label
	$label.Location = New-Object System.Drawing.Point(10,$locationY)
	$label.Size = New-Object System.Drawing.Size(180, 20)
	$label.Text = $text
	$form.Controls.Add($label)
	$control = New-Object "System.Windows.Forms.$type"
	$control.Location = New-Object System.Drawing.Point(200, $locationY)
	$control.Size = New-Object System.Drawing.Size($width, 20)
	$form.Controls.Add($control)
	return $control
}

# Add form controls
$txtFirstName = Add-FormControl -type "TextBox" -text "User First Name:" -locationY 10
$txtLastName = Add-FormControl -type "TextBox" -text "User Last Name:" -locationY 40
$txtEmail = Add-FormControl -type "TextBox" -text "User Email Address:" -locationY 70
$txtExtNumber = Add-FormControl -type "TextBox" -text "User EXT Number:" -locationY 100
$txtManager = Add-FormControl -type "TextBox" -text "User's Manager:" -locationY 130
$btnAddHardwareToken = Add-FormControl -type "CheckBox" -text "Add Hardware Token?" -locationY 160
$txtTokenSerialNumber = Add-FormControl -type "TextBox" -text "Token Serial Number" -locationY 190
$txtTokenSecretKey = Add-FormControl -type "TextBox" -text "Token Secret Key" -locationY 210


$dropdownUserType = Add-FormControl -type "ComboBox" -text "Select User Type:" -locationY 160
@("Local User Operations Office", "Local User Executive Office", "WVD Israel", "WVD Philippine Assistant", "WVD Philippine Developer") | ForEach-Object { $dropdownUserType.Items.Add($_) }
$dropdownLicense = Add-FormControl -type "ComboBox" -text "Select License:" -locationY 190
@("SPB", "E3") | ForEach-Object { $dropdownLicense.Items.Add($_) }

# Create licenses availability form control
$lblAvailableLicenses = New-Object System.Windows.Forms.Label
$lblAvailableLicenses.Location = New-Object System.Drawing.Point(10, 230)
$lblAvailableLicenses.Size = New-Object System.Drawing.Size(100, 50)
$form.Controls.Add($lblAvailableLicenses)

# Function to execute Exchange Online cmdlets in a separate runspace
function Execute-ExchangeOnlineCmdlets {
  param (
    $scriptBlock
  )

  $runspace = [runspacefactory]::CreateRunspace()
  $runspace.ApartmentState = "STA"
  $runspace.ThreadOptions = "ReuseThread"
  $runspace.Open()

  $runspace.SessionStateProxy.SetVariable("lblAvailableLicenses", $lblAvailableLicenses)

  $powershell = [powershell]::Create()
  $powershell.Runspace = $runspace
  $powershell.AddScript($scriptBlock)
  $powershell.Invoke()
  $powershell.Dispose()
  $runspace.Close()
  $runspace.Dispose()
}

# Function to get the available licenses
function Get-AvailableLicenses {
  $sku1 = Get-MsolAccountSku | Where-Object { $_.AccountSkuId -eq "mbhservicesllc:SPE_E3" }
  $sku3 = Get-MsolAccountSku | Where-Object { $_.AccountSkuId -eq "mbhservicesllc:SPB" } # SPB license
    
  if ($sku1 -and $sku3) {
    return @{
      "SPE_E3" = $sku1.ActiveUnits - $sku1.ConsumedUnits
      "SPB"    = $sku3.ActiveUnits - $sku3.ConsumedUnits
    }
  }

  return $null
}

# Function to update available licenses label with separate lines
function UpdateAvailableLicensesLabel {
  $licenses = Get-AvailableLicenses

  if ($licenses) {
    $availableLicensesLabel = "Available Licenses:`r`nSPE_E3: $($licenses["SPE_E3"])`r`nSPB: $($licenses["SPB"])"
    $lblAvailableLicenses.Text = $availableLicensesLabel
  }
  else {
    $lblAvailableLicenses.Text = "License information not available."
  }
}

# Initial auto call to update available licenses
UpdateAvailableLicensesLabel | Out-Null

# Initialize button to update available licenses
$btnUpdateLicenseCount = New-Object System.Windows.Forms.Button
$btnUpdateLicenseCount.Text = "Update"
$btnUpdateLicenseCount.Location = New-Object System.Drawing.Point(150, 250)

# Create button to update available licenses
$btnUpdateLicenseCount.Add_Click({
    UpdateAvailableLicensesLabel
  })

# Add the button to update available licenses to the form
$form.Controls.Add($btnUpdateLicenseCount)

# Add button to submit the form
$btnSubmit = New-Object System.Windows.Forms.Button
$btnSubmit.Text = "Submit"
$btnSubmit.Location = New-Object System.Drawing.Point(150, 350)
$btnSubmit.Size = New-Object System.Drawing.Size(100, 40)
$form.Controls.Add($btnSubmit)



# Form submittion action
$btnSubmit.Add_Click({
	# Manager validation
	if ($txtManager.Text -eq "") {
		[System.Windows.Forms.MessageBox]::Show("User's Manager cannot be empty.`nEnter none if the user doesn't have a manager.", "Validation Error")
		return
	}
    $manager = Get-ADUser -Filter { UserPrincipalName -eq $txtManager.Text -and Enabled -eq $true }
	if (-not ("$($txtManager.Text)".ToLower() -eq "none")) {
		if ($manager -eq $null) {
			[System.Windows.Forms.MessageBox]::Show("Specified manager is not valid or not enabled.`nEnter none if the user doesn't have a manager.", "Validation Error")
			return
		}
	}
	
    $password = "Mbh@4588755"
    
    $firstName = $txtFirstName.Text
    $lastName = $txtLastName.Text
    $email = $txtEmail.Text
    $extNumber = $txtExtNumber.Text
	$selection = ($dropdownUserType.SelectedIndex + 1).ToString()
    $roleSelection = ($dropdownRole.SelectedIndex + 1).ToString()
    $serialNumber = $txtTokenSerialNumber.Text
    $secretKey = $txtTokenSecretKey.Text

    $ouMappings = @{
      1 = "OU=Operations Office,OU=Local Users,OU=MBH,DC=MBH,DC=LOCAL"
      2 = "OU=Executive Office,OU=Local Users,OU=MBH,DC=MBH,DC=LOCAL"
      3 = "OU=WVD,OU=Remote Users,OU=MBH,DC=MBH,DC=LOCAL"
      4 = "OU=WVD,OU=Remote Users,OU=MBH,DC=MBH,DC=LOCAL"
      5 = "OU=WVD,OU=Remote Users,OU=MBH,DC=MBH,DC=LOCAL"
    }

    $groupMappings = @{
      3 = "WVD users"
      4 = "WVD Southeast Asia Users"
      5 = "WVD RPA Developers"
    }

    $userTypeGroupMappings = @{
      1 = "WomensFilterGroup"
      2 = "MensFilterGroup"
      3 = "WomensFilterGroup"
      4 = "WomensFilterGroup"
      5 = "WomensFilterGroup"
    }

    if ($ouMappings.ContainsKey([int]$selection)) {
      $ouPath = $ouMappings[[int]$selection]
      $email = $email.ToLower()
      $userPrincipalName = ($firstName[0].ToString().ToLower() + "." + $lastName.ToLower() + "@mbhpays.com")
      $samAccountName = ($firstName[0].ToString().ToLower() + "." + $lastName.ToLower())
      $displayAccountName = ($firstName[0].ToString() + "." + " " + $lastName)

      New-ADUser -Name $displayAccountName -GivenName $firstName -Surname $lastName -SamAccountName $samAccountName -UserPrincipalName $userPrincipalName -EmailAddress $email -AccountPassword (ConvertTo-SecureString $password -AsPlainText -Force) -Path $ouPath -Enabled $true

      $user = Get-ADUser -Filter { EmailAddress -eq $userPrincipalName } | Select-Object -ExpandProperty DistinguishedName

      # Add manager to user if a valid manager has been assigned
      if (-not ("$($txtManager.Text)".ToLower() -eq "none")) {
        Set-ADUser -Identity $user -Manager $manager      
      }

      Set-ADUser -Identity $user -Replace @{telephoneNumber = $extNumber; title = $extNumber; displayName = $displayAccountName }

      Add-ADGroupMember -Identity "AAD Sync" -Members "$user"
      Add-ADGroupMember -Identity "MBH Users" -Members "$user"
      Add-ADGroupMember -Identity "RoboForm Sync" -Members "$user"
      Add-ADGroupMember -Identity "All Users 10-26-23 and UP" -Members "$user"

      <#
      Add user to "WVD users" if they are of type "Local User Executive Office" or "Local User Operations Office"
        
      This is deprecated since their AVD infrastructure is managed through Positive's Nerdion MSP Manager
      and Nerdio licenses are calculated by assigned users and not by how many users actively used AVD
      #>
      <#
      if ($selection -eq "1" -or $selection -eq "2") {
        Add-ADGroupMember -Identity $groupMappings[3] -Members "$user"
      }
      #>

      # Add remote users to their appropriate AVD Group
      if ($groupMappings.ContainsKey([int]$selection)) {
        Add-ADGroupMember -Identity $groupMappings[[int]$selection] -Members "$user"
      }

      # Add user to specific (filter) group based on user type selection
      if ($userTypeGroupMappings.ContainsKey([int]$selection)) {
        Add-ADGroupMember -Identity $userTypeGroupMappings[[int]$selection] -Members "$user"
      }

      # Start a Delta Sync Cycle
	  Invoke-Command -ComputerName $ADSyncServiceHost -ScriptBlock { Start-ADSyncSyncCycle -PolicyType Delta }

      # Wait for 1 minute
      Start-Sleep -Seconds 60  # 60 seconds is equivalent to 1 minute

      # Retrieve the user's ID
      $user = Get-MgUser -Filter "userPrincipalName eq '$userPrincipalName'"
      $userId = $user.Id

      # Set the user location first
      Set-MsolUser -UserPrincipalName $userPrincipalName -UsageLocation "US"

      # Wait for 10 seconds
      Start-Sleep -Seconds 10 

      # Retrieve the selected license type
      $selectedLicense = $dropdownLicense.SelectedItem

      # Initialize the license variables based on the selection
      $licenseToAssign = if ($selectedLicense -eq "SPB") {
        Get-MgSubscribedSku -All | Where-Object { $_.SkuPartNumber -eq 'SPB' }
      }
      else {
        Get-MgSubscribedSku -All | Where-Object { $_.SkuPartNumber -eq 'SPE_E3' }
      }

      $powerBiLicense = Get-MgSubscribedSku -All | Where-Object { $_.SkuPartNumber -eq 'POWER_BI_STANDARD' }

      $addLicenses = @(
        @{ SkuId = $licenseToAssign.SkuId },
        @{ SkuId = $powerBiLicense.SkuId }
      )

      Set-MgUserLicense -UserId $email -AddLicenses $addLicenses -RemoveLicenses @()

      # Wait for 10 seconds
      Start-Sleep -Seconds 80 

      # Enable Archiving
      Enable-Mailbox -Identity $email -Archive

      # Add Mailbox permissions
      Add-MailboxPermission -Identity $email -User s.posner@mbhpays.com -AccessRights 'FullAccess,SendAs' -automapping $false
      Add-MailboxPermission -Identity $email -User c.berkowitz@mbhpays.com -AccessRights FullAccess -automapping $false
      Add-MailboxPermission -Identity $email -User simonb@mbhpays.com -AccessRights FullAccess -automapping $false

      # Add user to distribution groups
      $groupEmail = "mbhlocalusers@mbhpays.com"
      Add-DistributionGroupMember -Identity $groupEmail -Member $email

      # Add users to security groups
      $retrievedUser = Get-AzureADUser -ObjectId $email
      $objectId = $retrievedUser.ObjectId

      $Knowbe4Users_groupObjectId = "b21a1811-5002-4008-ad2c-16a1567c6be6"
      Add-MsolGroupMember -GroupObjectId $Knowbe4Users_groupObjectId -GroupMemberType User -GroupMemberObjectId $objectId

      $WordtuneSSO_groupObjectId = "303aca34-785d-449f-9a1a-7337f53dc905"
      Add-MsolGroupMember -GroupObjectId $WordtuneSSO_groupObjectId -GroupMemberType User -GroupMemberObjectId $objectId

      # Check user type and add to the distribution group "mbhoperationsdepartment@mbhpays.com" if they are of type "Local User Operations Office"
      if ($selection -eq "1") {
        $roleGroupEmail_1 = "mbhoperationsdepartment@mbhpays.com"
        Add-DistributionGroupMember -Identity $roleGroupEmail_1 -Member $email
      }

         # Check user type and add to the distribution group "virtualassistants@mbhpays.com" if they are of type "WVD Philppine"
      if ($selection -eq "4" -or $selection -eq "5") {
        $roleGroupEmail_4_5 = "virtualassistants@mbhpays.com"
        Add-DistributionGroupMember -Identity $roleGroupEmail_4_5 -Member $email
      }

      # Add the user to the correct CodeTwo group. local users to CodeTwo@mbhpays.com and remote users to CodeTwoWithoutExt@mbhpays.com
      if ($selection -eq "1" -or $selection -eq "2"){
        $codeTowGroup = "CodeTwo@mbhpays.com"
        Add-DistributionGroupMember -Identity $codeTowGroup -Member $email
      }
      if ($selection -eq "3" -or $selection -eq "4" -or $selection -eq "5"){
        $codeTowGroup = "CodeTwoWithoutExt@mbhpays.com"
        Add-DistributionGroupMember -Identity $codeTowGroup -Member $email
      }

      #########################====--Start SharePoint Portion--====################################
        
        $siteUrl = "https://mbhservicesllc.sharepoint.com"
        Connect-PnPOnline -Url $siteUrl -UseWebLogin

        # Add the user to the MBH Users sharepoint group.
        Add-PnPUserToGroup -LoginName $email -Identity "MBH Users"


        ## Create a folder in Users library for the employee with 2 subfolders for scans and timesheets and assigne the correct permissions.
        # Don't run for local men users
        if ($selection -ne "2"){
            $siteUrl = "https://mbhservicesllc.sharepoint.com"
            Connect-PnPOnline -Url $siteUrl -UseWebLogin

            # Define the main folder, subfolders, and users
            $documentLibrary = "Shared Documents"
            $parentFolder = "$documentLibrary/Users"
            $mainFolderName = $email.Split('@')[0]
            $subFolderScans = "Scans"
            $subFolderTimeSheets = "Time Sheets"
            $scansUser = "scantosharepoint@mbhpays.com"

            # Create the main folder
            Add-PnPFolder -Name $mainFolderName -Folder $parentFolder

            $mainFolderPath = "$parentFolder/$mainFolderName"
            $getMainFolder = Get-PnPFolder -Url $mainFolderPath

            # Break inheritance for the main folder
            Set-PnPFolderPermission -List $documentLibrary -Identity $getMainFolder -InheritPermissions:$false

            # Remove all existing permissions and give Edit to the user
            Set-PnPFolderPermission -List $documentLibrary -Identity $getMainFolder -User $email -AddRole "Edit" -ClearExisting

            # Give access for the scan user
            Set-PnPFolderPermission -List $documentLibrary -Identity $getMainFolder -User $scansUser -AddRole "Edit"

            # Give access for the management Access Security Group
            Set-PnPFolderPermission -List $documentLibrary -Identity $getMainFolder -Group "Management Access" -AddRole "Edit"

            # Create two subfolders under the main folder
            Add-PnPFolder -Name $subFolderScans -Folder $mainFolderPath
            Add-PnPFolder -Name $subFolderTimeSheets -Folder $mainFolderPath
        }

      #########################====--End SharePoint Portion--====################################

#########################====--Start Hardware Token Portion--====################################
# Only run in the Add Hardware Token button was checked.
if($btnAddHardwareToken.Checked){

    ####====--Start predefined variables Setion--====####

    $timeInterval = "60"
    $manufacturer = "NoInformation"
    $model = "HardwareKey"

    $activate = $true
    $environment = "AzureCloud"

    $content = [PSCustomObject]@{
    }
    $content | Add-Member -MemberType NoteProperty -Name "UPN" -Value $upn
    $content | Add-Member -MemberType NoteProperty -Name "Serial Number" -Value $serialNumber
    $content | Add-Member -MemberType NoteProperty -Name "Secret Key" -Value $secretKey
    $content | Add-Member -MemberType NoteProperty -Name "Time Interval" -Value $timeInterval
    $content | Add-Member -MemberType NoteProperty -Name "Manufacturer" -Value $manufacturer
    $content | Add-Member -MemberType NoteProperty -Name "Model" -Value $model

    # Set variables based on Azure environment
    $apiHost = if ($environment -eq "AzureUSGovernment") {"main.iam.ad.ext.azure.us"} else {"main.iam.ad.ext.azure.com"}
    $imageHost = if($environment -eq "AzureUSGovernment"){"iam.hosting.azureportal.usgovcloudapi.net"} else {"iam.hosting.portal.azure.net"}
    $tokenApplication = if($environment -eq "AzureUSGovernment"){"ee62de39-b9b0-4886-aa58-08b89c4e3db3"} else {"74658136-14ec-4630-ad9b-26e160ff0fc6"}

    ####====--End predefined variables Setion--====####

    ####====--Start Functions Setion--====####
    function Get-Otp($Secret, $Length, $Window) {

      function Get-TimeByteArray($WINDOW) {
        $span = (New-TimeSpan -Start (Get-Date -Year 1970 -Month 1 -Day 1 -Hour 0 -Minute 0 -Second 0) -End (Get-Date).ToUniversalTime()).TotalSeconds
        $unixTime = [Convert]::ToInt64([Math]::Floor($span / $WINDOW))
        $byteArray = [BitConverter]::GetBytes($unixTime)
        [array]::Reverse($byteArray)
        return $byteArray
      }

      function Convert-HexToByteArray($hexString) {
        $byteArray = $hexString -replace '^0x', '' -split "(?<=\G\w{2})(?=\w{2})" | ForEach-Object { [Convert]::ToByte( $_, 16 ) }
        return $byteArray
      }

      function Convert-Base32ToHex($base32) {
        $base32chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        $bits = "";
        $hex = "";

        for ($i = 0; $i -lt $base32.Length; $i++) {
          $val = $base32chars.IndexOf($base32.Chars($i));
          $binary = [Convert]::ToString($val, 2)
          $staticLen = 5
          $padding = '0'
          # Write-Host $binary
          $bits += Add-LeftPad $binary.ToString()  $staticLen  $padding
        }

        for ($i = 0; $i + 4 -le $bits.Length; $i += 4) {
          $chunk = $bits.Substring($i, 4)
          # Write-Host $chunk
          $intChunk = [Convert]::ToInt32($chunk, 2)
          $hexChunk = Convert-IntToHex($intChunk)
          # Write-Host $hexChunk
          $hex = $hex + $hexChunk
        }
        return $hex;

      }

      function Convert-IntToHex([int]$num) {
        return ('{0:x}' -f $num)
      }

      function Add-LeftPad($str, $len, $pad) {
        if (($len + 1) -ge $str.Length) {
          while (($len - 1) -ge $str.Length) {
            $str = ($pad + $str)
          }
        }
        return $str;
      }

      $hmac = New-Object -TypeName System.Security.Cryptography.HMACSHA1
      $hmac.key = Convert-HexToByteArray(Convert-Base32ToHex(($SECRET.ToUpper())))
      $timeBytes = Get-TimeByteArray $WINDOW
      $randHash = $hmac.ComputeHash($timeBytes)
    
      $offset = $randHash[($randHash.Length - 1)] -band 0xf
      $fullOTP = ($randHash[$offset] -band 0x7f) * [math]::pow(2, 24)
      $fullOTP += ($randHash[$offset + 1] -band 0xff) * [math]::pow(2, 16)
      $fullOTP += ($randHash[$offset + 2] -band 0xff) * [math]::pow(2, 8)
      $fullOTP += ($randHash[$offset + 3] -band 0xff)

      $modNumber = [math]::pow(10, $LENGTH)
      $otp = $fullOTP % $modNumber
      $otp = $otp.ToString("0" * $LENGTH)

      return $otp
    }

    function Wait-AzMfaTokenUpload ($name, $apiHost, $tokenApplication) {

      $result = $false
      $pollPeriod = 5
      $numTries = 20
      $try = 0


      while ($result -eq $false -and $try++ -lt $numTries) {

        Start-Sleep -Seconds $pollPeriod    
    
        $context = Get-AzContext
        $token = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate($context.Account, $context.Environment, $context.Tenant.Id, $null, "Never", $null, $tokenApplication)

        $headers = @{"Authorization" = "Bearer $($token.AccessToken)"
          'x-ms-client-request-id'   = [guid]::NewGuid()
          'x-ms-correlation-id'      = [guid]::NewGuid()

        }

        Write-Host "Waiting for `"$name`" upload to complete, try $try/$numTries..."
        
        $testUrl = "https://$($apiHost)/api/MultiFactorAuthentication/HardwareToken/listUploads"

        $uploadStatus = Invoke-RestMethod -Uri $testUrl `
          -Headers $headers `
          -Method GET `
          -ContentType "application/json"


        Write-Host  $uploadStatus

        $currentUpload = $uploadStatus | Where-Object { $_.fileName -eq $name } | Select-Object -First 1

        if ($currentUpload) {
          if ($currentUpload.fileProcessingStatus -eq "CompletedWithNoErrors") {
            Write-Host "Token Upload Completed" -ForegroundColor Green
            return $true
          }
          elseif ($currentUpload.fileProcessingStatus -eq "CompletedWithErrors") {

            Write-Host "Token Upload Failed" -ForegroundColor Red
            return $false

          }

        }
        else {
          Write-Host "Error Uploading new Serial, no upload status found" -ForegroundColor Red
          return $false
        }
       
      }

      Write-Host "Upload issue, did not succeed in time" -ForegroundColor Red
      return $false
    }

    function Enable-AzMfaToken($upn, $serialNumber, $Secret, $apiHost, $imageHost, $tokenApplication) {

      $context = Get-AzContext
      $token = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate($context.Account, $context.Environment, $context.Tenant.Id, $null, "Never", $null, $tokenApplication)

      $headers = @{"Authorization" = "Bearer $($token.AccessToken)"
        'x-ms-client-request-id'   = [guid]::NewGuid()
        'x-ms-correlation-id'      = [guid]::NewGuid()
      }

      $tokenDetailsUrl = "https://$($apiHost)/api/MultifactorAuthentication/HardwareToken/users?skipToken=&upn=$UPN&enabledFilter="

      $tokenDetail = Invoke-RestMethod -Uri $tokenDetailsUrl `
        -Headers $headers `
        -Method GET `
        -ContentType "application/json" `
      | Select-Object -ExpandProperty items `
      | Where-Object { $_.serialNumber -eq $serialNumber } `
      | Select-Object -First 1

      $oneTimePasscode = Get-Otp -SECRET $Secret -LENGTH 6 -WINDOW $tokenDetail.timeInterval

      $payload = @{

        displayName      = $tokenDetail.displayName
        enableAction     = "Activate"
        enabled          = $tokenDetail.enabled
        enabledImg       = "https://$($imageHost)/iam/Content/Images/Directories/directoryDeletionRequirementMet.svg"
        manufacturer     = $tokenDetail.manufacturer
        model            = $tokenDetail.model
        oathId           = $tokenDetail.oathId
        objectId         = $tokenDetail.objectId
        serialNumber     = $tokenDetail.serialNumber
        timeInterval     = $tokenDetail.timeInterval
        upn              = $tokenDetail.upn
        verificationCode = $oneTimePasscode
      } | ConvertTo-Json

      Write-Host "Attempting to activate token, upn: $($tokenDetail.upn), serial $($tokenDetail.serialNumber), otp: $oneTimePasscode"

      $MfaActivateUri = "https://$($apiHost)/api/MultifactorAuthentication/HardwareToken/enable"

      $headers = @{"Authorization" = "Bearer $($token.AccessToken)"
        'x-ms-client-request-id'   = [guid]::NewGuid()
        'x-ms-correlation-id'      = [guid]::NewGuid()
      }

      $activated = $false

      try {
        $activated = Invoke-RestMethod -Uri $MfaActivateUri `
          -Headers $headers `
          -Method POST `
          -ContentType "application/json" `
          -body $payload
      }
      catch {
        Write-Host "An Error Occurred: " -ForegroundColor Red
        $_.Exception.Response | Format-List    
      }

      if ($activated) {
        Write-Host "Success" -ForegroundColor Green
      }
      else {
        Write-Host "Failed" -ForegroundColor Red
      }

    }

    ####====--End Functions Setion--====####

    # Create a unique name used when uploading a new token
    $uploadName = "$([guid]::NewGuid()).csv"

    # Convert to CSV and strip out quotation marks added by PowerShell command
    $contentCsvString = ($content | ConvertTo-Csv -NoTypeInformation | Out-String) -replace "`""

    # Create JSON payload for API call
    $payload = @{
    "id"       = $null
    "name"     = $uploadName
    "content"  = $contentCsvString
    "mimeType" = "application/vnd.ms-excel"
    } | ConvertTo-Json

    $uploaded = $false


    try {

    # Endpoint for uploading hardware token
    $uploadUrl = "https://$($apiHost)/api/MultifactorAuthentication/HardwareToken/upload"

    # Get authorization token
    $context = Get-AzContext
    $token = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate($context.Account, $context.Environment, $context.Tenant.Id, $null, "Never", $null, $tokenApplication)

    # Headers for API call
    $headers = @{
        "Authorization"          = "Bearer $($token.AccessToken)"
        'x-ms-client-request-id' = [guid]::NewGuid()
        'x-ms-correlation-id'    = [guid]::NewGuid()
    }

    # API request to upload a token
    $uploaded = Invoke-RestMethod -Uri $uploadUrl  `
        -Headers $headers `
        -Method POST `
        -ContentType "application/json" `
        -body $payload

    }
    catch {
    Write-Host "An Error Occurred: " -ForegroundColor Red
    $_.Exception.Response | Format-List
    }

    if ($uploaded -ne $false) {
            
    Write-Host "Uploaded Token Data" -ForegroundColor Green 
    # Poll upload until it applied

    $uploadState = Wait-AzMfaTokenUpload -name $uploadName -apiHost $apiHost -tokenApplication $tokenApplication
            
    if ($uploadState -eq $true) {
        if($activate -eq $true) {
        # Activate token
        Enable-AzMfaToken -upn $upn -serialNumber $serialNumber -Secret $content.'Secret Key' -apiHost $apiHost -imageHost $imageHost -tokenApplication $tokenApplication
        }
    }
    else {

        Write-Host "Abandon, issue with upload" -ForegroundColor Red
    }
    }
} 


#########################====--End Hardware Token Portion--====################################


      $form.Close()
    }
    else {
      [System.Windows.Forms.MessageBox]::Show("Invalid User Type selection. Please select a valid option.")
    }
  })


# Show the form
$form.ShowDialog()


## If not useing ISE, wait for 'Q' to close the powershell window

if ($host.Name -ne 'Windows PowerShell ISE Host') {
    Write-Host "Press Q to exit..."
    do {
        $key = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown").Character
    } until ($key -eq 'Q' -or $key -eq 'q')
}
