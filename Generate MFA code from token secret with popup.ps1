# Fatal error Function
Function Write-ErrorAndExit {
	param ($errorMessage)
	Write-Host -ForegroundColor Red $errorMessage
	Write-Host -ForegroundColor Red "Exiting..."
	Pause
	exit
}




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
$txtTokenSecretKey = Add-FormControl -type "TextBox" -text "Token Secret Key" -locationY 10
$dropdownTimeInterval = Add-FormControl -type "ComboBox" -text "Time Interval" -locationY 40
@("30", "60") | ForEach-Object { $dropdownTimeInterval.Items.Add($_) }


# Add button to generate the code
$btnSubmit = New-Object System.Windows.Forms.Button
$btnSubmit.Text = "Generate"
$btnSubmit.Location = New-Object System.Drawing.Point(150, 150)
$btnSubmit.Size = New-Object System.Drawing.Size(100, 40)
$form.Controls.Add($btnSubmit)



# Form submittion action
$btnSubmit.Add_Click({

    $secretKey = $txtTokenSecretKey.Text
    $timeInterval = $dropdownTimeInterval.SelectedItem
    $LengthVar = "6"


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

#Generate the code
$otp = Get-Otp -Secret $secretKey -Length $LengthVar -Window $timeInterval

Write-Host $otp
      #$form.Close()
    
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
