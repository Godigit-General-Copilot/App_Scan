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

write-host "======== Step: Checking Security Gate ========"
$sessionId=$(Invoke-WebRequest -Method "POST" -Headers @{"Accept"="application/json"} -ContentType 'application/json' -Body "{`"keyId`": `"$aseApiKeyId`",`"keySecret`": `"$aseApiKeySecret`"}" -Uri "https://$aseHostname`:9443/ase/api/keylogin/apikeylogin" -SkipCertificateCheck | Select-Object -Expand Content | ConvertFrom-Json | select -ExpandProperty sessionId);
# Get the aseAppId from ASE
$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession;
$session.Cookies.Add((New-Object System.Net.Cookie("asc_session_id", "$sessionId", "/", "$aseHostname")));
$aseAppId=$(Invoke-WebRequest -WebSession $session -Headers @{"Asc_xsrf_token"="$sessionId"} -Uri "https://$aseHostname`:9443/ase/api/applications/search?searchTerm=$aseAppName" -SkipCertificateCheck | ConvertFrom-Json).id;

$aseAppAtrib = $(Invoke-WebRequest -WebSession $session -Headers @{"Asc_xsrf_token"="$sessionId"} -Uri "https://$aseHostname`:9443/ase/api/applications/$aseAppId" -SkipCertificateCheck|ConvertFrom-Json);
$secGw=$($aseAppAtrib.attributeCollection.attributeArray | Where-Object { $_.name -eq "Security Gate" } | Select-Object -ExpandProperty value)
$sevSecGw=$($aseAppAtrib.attributeCollection.attributeArray | Where-Object { $_.name -eq "Severity Sec Gate" } | Select-Object -ExpandProperty value)
$maxIssuesAllowed=$($aseAppAtrib.attributeCollection.attributeArray | Where-Object { $_.name -eq "Build Failure Amount" } | Select-Object -ExpandProperty value)

Invoke-WebRequest -WebSession $session -Headers @{"Asc_xsrf_token"="$sessionId"} -Uri "https://$aseHostname`:9443/ase/api/logout" -SkipCertificateCheck | Out-Null

if ( $secGw -eq "Disabled" ) {
  write-host "Security Gate disabled.";
  exit 0
  }
write-host "Security Gate enabled.";

# Loading ozasmt (AppScan Source result scan file) file into a variable
[XML]$xml=Get-Content $aseAppName-$BuildNumber.ozasmt
[int]$highIssues = $xml.AssessmentRun.AssessmentStats.total_high_finding
[int]$mediumIssues = $xml.AssessmentRun.AssessmentStats.total_med_finding
[int]$lowIssues = $xml.AssessmentRun.AssessmentStats.total_low_finding
[int]$totalIssues = $highIssues+$mediumIssues+$lowIssues
$maxIssuesAllowed = $maxIssuesAllowed -as [int]

write-host "There is $highIssues high issues, $mediumIssues medium issues and $lowIssues low issues."
write-host "The company policy permit less than $maxIssuesAllowed $sevSecGw severity."

if (( $highIssues -gt $maxIssuesAllowed ) -and ( "$sevSecGw" -eq "highIssues" )) {
  write-host "Security Gate build failed";
  exit 1
  }
elseif (( $mediumIssues -gt $maxIssuesAllowed ) -and ( "$sevSecGw" -eq "mediumIssues" )) {
  write-host "Security Gate build failed";
  exit 1
  }
elseif (( $lowIssues -gt $maxIssuesAllowed ) -and ( "$sevSecGw" -eq "lowIssues" )) {
  write-host "Security Gate build failed";
  exit 1
  }
elseif (( $totalIssues -gt $maxIssuesAllowed ) -and ( "$sevSecGw" -eq "totalIssues" )) {
  write-host "Security Gate build failed";
  exit 1
  }
else{
write-host "Security Gate passed"
  }
# If you want to delete files after execution excepted pdf and xml files
#Remove-Item -path $workingDirectory\* -recurse -exclude *.pdf,*.xml,*.ozasmt
