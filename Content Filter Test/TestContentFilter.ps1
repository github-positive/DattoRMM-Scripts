#Test Content Filtering
function Test-SiteAccess ($url) {
    try{
        $headers = @{
            "User-Agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
            "Accept" = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"
            "Accept-Language" = "en-US,en;q=0.5"
        }
        $ivrResults = Invoke-WebRequest "https://$url" -UseBasicParsing -Headers $headers
        if((($ivrResults).headers.'set-cookie' -match "domain=\.$url") -or (($ivrResults).headers.'set-cookie' -match "domain=\*\.$url")){
            return $true
        } else {
            return $false
        }
    }catch{
        return $false
    }
}
$sites = @(
    @{ URL = "instagram.com"; Category = "Social Media" }
    @{ URL = "zappos.com"; Category = "Shopping" }
    @{ URL = "nbcnews.com"; Category = "News" }
    @{ URL = "disneyplus.com"; Category = "Entertainment" }
    @{ URL = "porn.com"; Category = "Adult Content" }
)
$currentUser = whoami 2>$null
$results = "User: $currentUser. "
$ufdNumber = "14"
foreach ($site in $sites) {
    #Write-Host "Testing, Category: $($site.Category), URL: $($site.URL)"
    $isAccessible = Test-SiteAccess -url $site.URL
    $status = if ($isAccessible -eq $true) {
         "Allowed" 
    } elseif ($isAccessible -eq $false) {
        "Blocked"
    } else {
        "Unknown"
    }
    $results += "$($site.Category) is $status. "
}
Write-Host "======================================================================================"
Write-Host "Results: $results"
Write-Host "======================================================================================"
try {
    #Set-ItemProperty "HKLM:\Software\CentraStage" -Name "Custom$ufdNumber" -PropertyType String -Value $results -Force | Out-Null
    Write-Host "UDF $ufdNumber has been set."
}
catch {
    Write-Host "Error writing UDF. Error $_"
    exit 1
}