param(
    [Parameter(Mandatory = $true)]
    [string]$TargetPath,

    [Parameter(Mandatory = $true)]
    [string]$Label
)

$ErrorActionPreference = 'Stop'

$subjectName = 'CN=nine-security Inc'
$timestampServer = 'http://timestamp.digicert.com'
$codeSigningOid = '1.3.6.1.5.5.7.3.3'

function Get-LocalCodeSigningCertificate {
    param(
        [string]$SubjectName,
        [string]$RequiredEkuOid
    )

    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store('My', 'CurrentUser')
    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
    try {
        $matches = @(
            $store.Certificates |
                Where-Object {
                    $_.Subject -eq $SubjectName -and
                    $_.HasPrivateKey -and
                    (@($_.EnhancedKeyUsageList | Where-Object { $_.ObjectId.Value -eq $RequiredEkuOid }).Count -gt 0)
                } |
                Sort-Object NotAfter -Descending
        )

        if ($matches.Count -gt 0) {
            return $matches[0]
        }

        return $null
    }
    finally {
        $store.Close()
    }
}

function Test-ExpectedLocalSelfSignedStatus {
    param(
        $Signature,
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$ExpectedCertificate
    )

    if (-not $Signature -or -not $Signature.SignerCertificate) {
        return $false
    }

    if ($Signature.Status -ne [System.Management.Automation.SignatureStatus]::UnknownError) {
        return $false
    }

    if ($Signature.SignerCertificate.Thumbprint -ne $ExpectedCertificate.Thumbprint) {
        return $false
    }

    if ($Signature.SignerCertificate.Subject -ne $Signature.SignerCertificate.Issuer) {
        return $false
    }

    return ($Signature.StatusMessage -like '*root certificate which is not trusted by the trust provider*')
}

$target = (Resolve-Path -LiteralPath $TargetPath).Path
Write-Host ('[+] Signing ' + $Label + ': ' + $target)

$cert = Get-LocalCodeSigningCertificate -SubjectName $subjectName -RequiredEkuOid $codeSigningOid
if (-not $cert) {
    Write-Host '[+] Creating new self-signed certificate...'
    try {
        $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject $subjectName -CertStoreLocation 'Cert:\CurrentUser\My' -HashAlgorithm SHA256
    }
    catch {
        Write-Host '[!] Signature status: SkippedLocalCertUnavailable'
        Write-Host ('[!] Signature detail: Local code-signing certificate could not be created on this machine. ' + $_.Exception.Message)
        exit 0
    }
}

Write-Host ('[+] Signing with cert: ' + $cert.Thumbprint)

$sig = Set-AuthenticodeSignature -Certificate $cert -FilePath $target -HashAlgorithm SHA256 -TimestampServer $timestampServer
if (-not $sig.SignerCertificate -or $sig.Status -eq [System.Management.Automation.SignatureStatus]::NotSigned -or $sig.Status -eq [System.Management.Automation.SignatureStatus]::HashMismatch) {
    throw ('Signing failed: ' + $sig.Status)
}

$verify = Get-AuthenticodeSignature -LiteralPath $target
if (-not $verify.SignerCertificate -or $verify.SignerCertificate.Thumbprint -ne $cert.Thumbprint) {
    throw ('Signature verification failed: signer mismatch (' + $verify.Status + ')')
}

if ($verify.Status -eq [System.Management.Automation.SignatureStatus]::Valid) {
    Write-Host '[+] Signature status: Valid'
}
elseif (Test-ExpectedLocalSelfSignedStatus -Signature $verify -ExpectedCertificate $cert) {
    Write-Host '[+] Signature status: LocalSelfSignedUntrusted'
    Write-Host '[+] Signature detail: The file is signed and timestamped, but the local self-signed root is not trusted on this machine.'
}
else {
    $detail = $verify.StatusMessage
    if (-not $detail) {
        $detail = 'No additional status message.'
    }

    throw ('Signature verification failed: ' + $verify.Status + ' - ' + $detail)
}

if ($verify.TimeStamperCertificate) {
    Write-Host ('[+] Timestamp signer: ' + $verify.TimeStamperCertificate.Subject)
}
else {
    Write-Host '[!] Timestamp signer: not attached'
}
