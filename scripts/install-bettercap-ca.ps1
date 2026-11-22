param(
    [string]$CertPath = "$env:USERPROFILE\.bettercap-ca.cert.pem"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $CertPath)) {
    throw "CA certificate not found: $CertPath. Start https.proxy once or pass -CertPath."
}

$principal = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run PowerShell as Administrator to install a machine-wide trusted root."
}

& certutil.exe -addstore -f Root $CertPath | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "certutil failed to import the CA into the machine root store."
}

Write-Host "Installed the BetterCAP CA from $CertPath."
Write-Host "Restart the browser or client application."
Write-Host "Firefox and applications with a private trust store or certificate pinning"
Write-Host "will keep using passthrough instead of decryption."
Write-Host "Remove the CA from the root store when you no longer need HTTPS inspection."
