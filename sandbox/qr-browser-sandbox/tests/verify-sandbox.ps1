$ErrorActionPreference = "Stop"
$base = "http://127.0.0.1:8765"

Write-Host "[1/5] Worker health"
$health = Invoke-RestMethod -Method Get -Uri "$base/health" -TimeoutSec 5
$health | ConvertTo-Json -Depth 4
if ($health.status -ne "ok") { throw "Worker health check failed." }

Write-Host "`n[2/5] Reject HTTP URL"
try {
    $payload = @{ url = "http://example.com" } | ConvertTo-Json -Compress
    Invoke-RestMethod -Method Post -Uri "$base/analyze" -ContentType "application/json" -Body $payload -TimeoutSec 5
    throw "Expected HTTP URL to be rejected."
} catch {
    if ($_.Exception.Response -and [int]$_.Exception.Response.StatusCode -eq 400) {
        Write-Host "PASS: HTTP URL rejected with 400"
    } else { throw }
}

Write-Host "`n[3/5] Reject loopback URL"
try {
    $payload = @{ url = "https://127.0.0.1/" } | ConvertTo-Json -Compress
    Invoke-RestMethod -Method Post -Uri "$base/analyze" -ContentType "application/json" -Body $payload -TimeoutSec 5
    throw "Expected loopback URL to be rejected."
} catch {
    if ($_.Exception.Response -and [int]$_.Exception.Response.StatusCode -eq 400) {
        Write-Host "PASS: loopback URL rejected with 400"
    } else { throw }
}

Write-Host "`n[4/5] Reject malformed JSON"
try {
    Invoke-WebRequest -Method Post -Uri "$base/analyze" -ContentType "application/json" -Body "not-json" -TimeoutSec 5
    throw "Expected malformed JSON to be rejected."
} catch {
    if ($_.Exception.Response -and [int]$_.Exception.Response.StatusCode -eq 400) {
        Write-Host "PASS: malformed JSON rejected with 400"
    } else { throw }
}

Write-Host "`n[5/5] Analyze public HTTPS test page"
$payload = @{ url = "https://example.com/" } | ConvertTo-Json -Compress
$result = Invoke-RestMethod -Method Post -Uri "$base/analyze" -ContentType "application/json" -Body $payload -TimeoutSec 45
$result | Select-Object status, originalUrl, finalUrl, pageTitle, httpStatus, navigationError, requestCountRecorded | Format-List
if (-not $result.status) { throw "No sandbox status returned." }
Write-Host "PASS: sandbox returned a structured result. Review navigationError if the external network blocks the test page."
