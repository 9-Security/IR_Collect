param(
    [Parameter(Mandatory = $true)]
    [string]$TargetPath,

    [Parameter(Mandatory = $true)]
    [string]$Label,

    [switch]$RequireSignature,

    [switch]$RequireTimestamp
)

$ErrorActionPreference = 'Stop'

$subjectName = 'CN=nine-security Inc'
$timestampServer = 'http://timestamp.digicert.com'
$codeSigningOid = '1.3.6.1.5.5.7.3.3'

function Test-CertificateHasEku {
    param(
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [string]$RequiredEkuOid
    )

    foreach ($eku in @($Certificate.EnhancedKeyUsageList)) {
        $oid = $null
        if ($eku -and $eku.PSObject.Properties['Value']) {
            $oid = [string]$eku.Value
        }
        if ([string]::IsNullOrWhiteSpace($oid) -and
            $eku -and
            $eku.PSObject.Properties['ObjectId']) {
            if ($eku.ObjectId -is [System.Security.Cryptography.Oid]) {
                $oid = $eku.ObjectId.Value
            }
            else {
                $oid = [string]$eku.ObjectId
            }
        }

        if ($oid -eq $RequiredEkuOid) {
            return $true
        }
    }

    return $false
}

function Test-CertificatePrivateKeyAccessible {
    param(
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    if (-not $Certificate -or -not $Certificate.HasPrivateKey) {
        return $false
    }

    $rsa = $null
    try {
        $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate)
        return ($null -ne $rsa)
    }
    catch {
        return $false
    }
    finally {
        if ($rsa) {
            $rsa.Dispose()
        }
    }
}

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
                    (Test-CertificateHasEku -Certificate $_ -RequiredEkuOid $RequiredEkuOid) -and
                    (Test-CertificatePrivateKeyAccessible -Certificate $_)
                } |
                Sort-Object -Property @{ Expression = 'NotAfter'; Descending = $true }, @{ Expression = 'Thumbprint'; Descending = $false }
        )

        if ($matches.Count -gt 0) {
            return $matches[0]
        }

        # Some local certificates omit or expose EKU metadata inconsistently. Reuse only a
        # certificate whose private key can actually be opened by the signing process.
        $fallbackMatches = @(
            $store.Certificates |
                Where-Object {
                    $_.Subject -eq $SubjectName -and
                    (Test-CertificatePrivateKeyAccessible -Certificate $_)
                } |
                Sort-Object -Property @{ Expression = 'NotAfter'; Descending = $true }, @{ Expression = 'Thumbprint'; Descending = $false }
        )

        if ($fallbackMatches.Count -gt 0) {
            return $fallbackMatches[0]
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

function Get-TimestampFailureDetail {
    param(
        $Signature
    )

    if (-not $Signature) {
        return $null
    }

    if ($Signature.Status -ne [System.Management.Automation.SignatureStatus]::UnknownError) {
        return $null
    }

    $message = $Signature.StatusMessage
    if ([string]::IsNullOrWhiteSpace($message)) {
        return $null
    }

    if ($message -like '*0x80072efd*' -or
        $message -like '*0x80072ee7*' -or
        $message -like '*timestamp*' -or
        $message -like '*server name or address could not be resolved*' -or
        $message -like '*could not establish trust relationship*') {
        return $message
    }

    return $null
}

function Test-FileSharingViolation {
    param(
        $ErrorRecord
    )

    $exception = $ErrorRecord.Exception
    while ($exception) {
        if ($exception -is [System.IO.IOException]) {
            $win32Code = $exception.HResult -band 0xFFFF
            if ($win32Code -eq 32 -or $win32Code -eq 33) {
                return $true
            }
        }
        $exception = $exception.InnerException
    }

    return $false
}

function Set-SignatureWithFileLockRetry {
    param(
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [string]$FilePath,
        [string]$TimestampUrl
    )

    $maxAttempts = 5
    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        try {
            return Set-AuthenticodeSignature -Certificate $Certificate -FilePath $FilePath -HashAlgorithm SHA256 -TimestampServer $TimestampUrl
        }
        catch {
            if (-not (Test-FileSharingViolation -ErrorRecord $_) -or $attempt -ge $maxAttempts) {
                throw
            }

            $delayMs = 500 * $attempt
            Write-Host ('[!] Signing target is temporarily locked; retrying in ' + $delayMs + ' ms (' + $attempt + '/' + $maxAttempts + ').')
            Start-Sleep -Milliseconds $delayMs
        }
    }
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
        if ($RequireSignature) {
            throw 'A signature is required for this release build.'
        }
        exit 0
    }
}

Write-Host ('[+] Signing with cert: ' + $cert.Thumbprint)

$sig = Set-SignatureWithFileLockRetry -Certificate $cert -FilePath $target -TimestampUrl $timestampServer
$timestampFailureDetail = Get-TimestampFailureDetail -Signature $sig
if (($sig.Status -eq [System.Management.Automation.SignatureStatus]::NotSigned -or
     $sig.Status -eq [System.Management.Automation.SignatureStatus]::HashMismatch) -and
    -not $timestampFailureDetail) {
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
    if ($verify.TimeStamperCertificate) {
        Write-Host '[+] Signature detail: The file is signed and timestamped, but the local self-signed root is not trusted on this machine.'
    }
    else {
        Write-Host '[+] Signature detail: The file is signed, but the local self-signed root is not trusted on this machine.'
    }
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
    if ($timestampFailureDetail) {
        Write-Host '[!] Timestamp status: TimestampServerUnavailable'
        Write-Host ('[!] Timestamp detail: Signature was applied, but the timestamp server could not be reached. ' + $timestampFailureDetail)
    }
    if ($RequireTimestamp) {
        throw 'A trusted timestamp is required for this release build.'
    }
}
