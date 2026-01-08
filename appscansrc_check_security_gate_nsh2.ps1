# Copyright 2024 HCL America
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

Write-Host "======== Step: Checking Security Gate ========"

# -------------------------------
# Login to ASE
# -------------------------------
$sessionId = (
    Invoke-WebRequest `
        -Method "POST" `
        -Headers @{ "Accept" = "application/json" } `
        -ContentType "application/json" `
        -Body "{`"keyId`": `"$aseApiKeyId`", `"keySecret`": `"$aseApiKeySecret`"}" `
        -Uri "https://$aseHostname`:9443/ase/api/keylogin/apikeylogin" `
        -SkipCertificateCheck |
    Select-Object -Expand Content |
    ConvertFrom-Json |
    Select-Object -ExpandProperty sessionId
)

$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
$session.Cookies.Add(
    (New-Object System.Net.Cookie("asc_session_id", "$sessionId", "/", "$aseHostname"))
)

# -------------------------------
# Fetch application attributes
# -------------------------------
$aseAppId = (
    Invoke-WebRequest `
        -WebSession $session `
        -Headers @{ "Asc_xsrf_token" = "$sessionId" } `
        -Uri "https://$aseHostname`:9443/ase/api/applications/search?searchTerm=$aseAppName" `
        -SkipCertificateCheck |
    ConvertFrom-Json
).id

$aseAppAtrib = (
    Invoke-WebRequest `
        -WebSession $session `
        -Headers @{ "Asc_xsrf_token" = "$sessionId" } `
        -Uri "https://$aseHostname`:9443/ase/api/applications/$aseAppId" `
        -SkipCertificateCheck |
    ConvertFrom-Json
)

$secGw = (
    $aseAppAtrib.attributeCollection.attributeArray |
    Where-Object { $_.name -eq "Security Gate" } |
    Select-Object -ExpandProperty value
)

# Jenkins overrides
$sevSecGw = $env:SEV_SEC_GW
$maxIssuesAllowed = [int]$env:MAX_ISSUES_ALLOWED

# Logout
Invoke-WebRequest `
    -WebSession $session `
    -Headers @{ "Asc_xsrf_token" = "$sessionId" } `
    -Uri "https://$aseHostname`:9443/ase/api/logout" `
    -SkipCertificateCheck |
    Out-Null

# -------------------------------
# Security Gate enabled?
# -------------------------------
if ($secGw -eq "Disabled") {
    Write-Host "Security Gate disabled."
    exit 0
}

Write-Host "Security Gate enabled."

# -------------------------------
# Load AppScan Source result
# -------------------------------
[xml]$xml = Get-Content "$aseAppName-$BuildNumber.ozasmt"

# -------------------------------
# DEFINITIVE HIGH ONLY (critical fix)
# -------------------------------
$highIssues = ($xml.AssessmentRun.FindingSummary.Definitive.High) -as [int]
if ($highIssues -eq $null) { $highIssues = 0 }

Write-Host "There is $highIssues definitive high issues."
Write-Host "The company policy permits less than $maxIssuesAllowed highIssues severity."

# -------------------------------
# Security Gate logic (HIGH ONLY)
# -------------------------------
if ($sevSecGw -eq "highIssues" -and $highIssues -gt $maxIssuesAllowed) {
    Write-Host "Security Gate build failed – Definitive High issues detected"
    exit 1
}
else {
    Write-Host "Security Gate passed – No Definitive High issues"
}

# -------------------------------
# Optional cleanup
# -------------------------------
# Remove-Item -Path $workingDirectory\* -Recurse -Exclude *.pdf,*.xml,*.ozasmt
