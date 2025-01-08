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

# Install-ModuleIfIsNotInstalled "Az" #Not running this as get-module doesn't list AZ and is causing re-instellation

Connect-AzAccount 


# Add necessary assemblies
Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Application]::EnableVisualStyles()

# Form setup
$form = New-Object System.Windows.Forms.Form
$form.Text = "OTP token"
$form.Size = New-Object System.Drawing.Size(430, 250)
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
$txtEmail = Add-FormControl -type "TextBox" -text "User Email Address:" -locationY 10
$txtTokenSerialNumber = Add-FormControl -type "TextBox" -text "Token Serial Number" -locationY 40
$txtTokenSecretKey = Add-FormControl -type "TextBox" -text "Token Secret Key" -locationY 70
$dropdownTimeInterval = Add-FormControl -type "ComboBox" -text "Time Interval" -locationY 100
@("30", "60") | ForEach-Object { $dropdownTimeInterval.Items.Add($_) }


# Add button to submit the form
$btnSubmit = New-Object System.Windows.Forms.Button
$btnSubmit.Text = "Submit"
$btnSubmit.Location = New-Object System.Drawing.Point(150, 150)
$btnSubmit.Size = New-Object System.Drawing.Size(100, 40)
$form.Controls.Add($btnSubmit)



# Form submittion action
$btnSubmit.Add_Click({

    $email = $txtEmail.Text
    $serialNumber = $txtTokenSerialNumber.Text
    $secretKey = $txtTokenSecretKey.Text
    $timeInterval = $dropdownTimeInterval.SelectedItem

    ####====--Start predefined variables Setion--====####

    $upn = $email
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

      $activated = $false
      $activationNumTries = 10
      $activationTry = 0

      while ($activated -eq $false -and $activationTry++ -lt $activationNumTries) {
      Write-Host "Waiting for activation to complete, try $activationTry/$activationNumTries..."
        

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

          Start-Sleep -Seconds 5
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



      $form.Close()
    
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
