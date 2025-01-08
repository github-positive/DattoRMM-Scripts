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
  
  
  $oneTimePasscode = Get-Otp -SECRET "2234567abcdef2234567abcdef" -LENGTH 6 -WINDOW 60
  $oneTimePasscode