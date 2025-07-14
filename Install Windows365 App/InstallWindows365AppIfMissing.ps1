## Update the app with the specified AppId
$appId = "9n1f85v9t8bn" # for downloading the app from Microsoft Store
$appName = "MicrosoftCorporationII.Windows365" # for checking if the app is already installed

function Download-AppxPackage {
[CmdletBinding()]
param (
  [string]$Uri,
  [string]$Path = "."
)
   
  process {
    $Path = (Resolve-Path $Path).Path
    #Get Urls to download
    $WebResponse = Invoke-WebRequest -UseBasicParsing -Method 'POST' -Uri 'https://store.rg-adguard.net/api/GetFiles' -Body "type=url&url=$Uri&ring=Retail" -ContentType 'application/x-www-form-urlencoded'
    $LinksMatch = $WebResponse.Links | Where-Object {$_ -like '*.appx*' -or $_ -like '*.appxbundle*' -or $_ -like '*.msix*' -or $_ -like '*.msixbundle*'} | Where-Object {$_ -like '*_neutral_*' -or $_ -like "*_"+$env:PROCESSOR_ARCHITECTURE.Replace("AMD","X").Replace("IA","X")+"_*"} | Select-String -Pattern '(?<=a href=").+(?=" r)'
    $DownloadLinks = $LinksMatch.matches.value 

    function Resolve-NameConflict{
    #Accepts Path to a FILE and changes it so there are no name conflicts
    param(
    [string]$Path
    )
        $newPath = $Path
        if(Test-Path $Path){
            $i = 0;
            $item = (Get-Item $Path)
            while(Test-Path $newPath){
                $i += 1;
                $newPath = Join-Path $item.DirectoryName ($item.BaseName+"($i)"+$item.Extension)
            }
        }
        return $newPath
    }
    # Find the largest file by checking Content-Length
    $largestDownloadLink = $null
    $maxSize = 0
    foreach ($link in $DownloadLinks) {
        try {
            $head = Invoke-WebRequest -Uri $link -Method Head -UseBasicParsing
            $size = [int64]$head.Headers["Content-Length"]
            if ($size -gt $maxSize) {
                $maxSize = $size
                $largestDownloadLink = $link
            }
        } catch {
            # silent catch for links that fail
        }
    }
    #Download File
    if ($largestDownloadLink) {
        $FileRequest = Invoke-WebRequest -Uri $largestDownloadLink -UseBasicParsing
        $FileName = ($FileRequest.Headers["Content-Disposition"] | Select-String -Pattern  '(?<=filename=).+').matches.value
        $FilePath = Join-Path $Path $FileName; $FilePath = Resolve-NameConflict($FilePath)
        [System.IO.File]::WriteAllBytes($FilePath, $FileRequest.content)
        echo $FilePath
    }
  }
}
## End Function
$appInstalled = Get-AppxPackage -User $env:USERNAME -Name $appName -ErrorAction SilentlyContinue
if ($null -eq $appInstalled) {
    $appxPackagePath = Download-AppxPackage -Uri "https://www.microsoft.com/store/productId/$appId" -Path $env:TEMP
    if ($appxPackagePath) {
        try{
            Add-AppxPackage -Path $appxPackagePath
            Write-Output "App installed successfully."
        } catch {
            Write-Error "Failed to install the app: $_"
            exit 1
        }
    } else {
        Write-Error "Failed to download the app."
        exit 1
    }
} else {
    Write-Output "App is already installed."
    exit 0
}