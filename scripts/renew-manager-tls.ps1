[CmdletBinding()]
param([ValidateSet('check', 'scheduled', 'challenge', 'rotate')] [string]$Mode = 'scheduled')

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$domain = 'updates.wuyouxiang.top'
$renewBefore = 30
$env:POSHACME_PLUGINS = Join-Path $PSScriptRoot 'acme-plugins'
. (Join-Path $env:POSHACME_PLUGINS 'QiniuManagerUpdates.ps1')

function Get-PublicCertificate {
    $client = [Net.Sockets.TcpClient]::new()
    try {
        $null = $client.ConnectAsync($domain, 443).WaitAsync([TimeSpan]::FromSeconds(15)).GetAwaiter().GetResult()
        $stream = [Net.Security.SslStream]::new($client.GetStream())
        try {
            $null = $stream.AuthenticateAsClientAsync($domain).WaitAsync([TimeSpan]::FromSeconds(15)).GetAwaiter().GetResult()
            return [Security.Cryptography.X509Certificates.X509Certificate2]::new($stream.RemoteCertificate)
        } finally { $stream.Dispose() }
    } finally { $client.Dispose() }
}

function Invoke-QiniuApi([string]$Method, [string]$Path, [hashtable]$Payload) {
    $json = if ($Payload) { $Payload | ConvertTo-Json -Compress -Depth 6 }
    if ($Path -eq '/sslcert') {
        $endpoint = 'fusion.qiniuapi.com'
        $scheme = 'QBox'
        $data = "$Path`n"
        $headers = @{}
    } else {
        $endpoint = 'api.qiniu.com'
        $scheme = 'Qiniu'
        $date = [DateTime]::UtcNow.ToString("yyyyMMdd'T'HHmmss'Z'")
        $data = "$Method $Path`nHost: $endpoint`n"
        if ($json) { $data += "Content-Type: application/json`n" }
        $data += "X-Qiniu-Date: $date`n`n$json"
        $headers = @{ 'X-Qiniu-Date' = $date }
    }
    $headers.Authorization = "$scheme $($env:QINIU_TLS_ACCESS_KEY):$(Get-QiniuSignature $data)"
    $request = @{ Uri = "https://$endpoint$Path"; Method = $Method; Headers = $headers; TimeoutSec = 30; MaximumRedirection = 0; SkipHttpErrorCheck = $true }
    if ($json) {
        $request.ContentType = 'application/json'
        $request.Body = [Text.Encoding]::UTF8.GetBytes($json)
    }
    $reply = Invoke-WebRequest @request
    if ($reply.StatusCode -ne 200) { throw "Qiniu API $Method $Path returned HTTP $($reply.StatusCode)." }
    return $reply.Content | ConvertFrom-Json
}

$current = Get-PublicCertificate
try {
    $expires = $current.NotAfter.ToUniversalTime()
    Write-Output "Current public certificate expires $($expires.ToString('u'))."
    if ($Mode -eq 'check') {
        if ($expires -le [DateTime]::UtcNow.AddDays($renewBefore)) { throw 'Certificate renewal is due.' }
        return
    }
    if ($Mode -eq 'scheduled' -and $expires -gt [DateTime]::UtcNow.AddDays($renewBefore)) { return }
    if (!$env:QINIU_TLS_ACCESS_KEY -or !$env:QINIU_TLS_SECRET_KEY) { throw 'The TLS renewal credentials are missing.' }

    $domainPath = "/domain/$domain"
    $original = Invoke-QiniuApi Get $domainPath
    $https = $original.https
    if ($original.name -ne $domain -or $original.protocol -ne 'https' -or $original.operatingState -ne 'success' -or
        $https.certId -notmatch '^[a-f0-9]{24}$' -or $https.forceHttps -isnot [bool] -or
        $https.http2Enable -isnot [bool] -or $https.tlsVersions -isnot [string] -or !$https.tlsVersions) {
        throw 'The current CDN HTTPS settings could not be verified.'
    }
    if ($Mode -eq 'challenge') {
        $token = ConvertTo-QiniuBase64 ([Security.Cryptography.RandomNumberGenerator]::GetBytes(24))
        $proof = ConvertTo-QiniuBase64 ([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
        Add-HttpChallenge $domain $token "$token.$($proof.TrimEnd('='))"
        Write-Output 'The public HTTP-01 route and the CDN configuration passed preflight.'
        return
    }

    if (!$env:HLNW_ACME_ACCOUNT_KEY) { throw "The Let's Encrypt account key is missing." }
    $moduleVersion = '4.35.0'
    Install-Module -Name Posh-ACME -RequiredVersion $moduleVersion -Repository PSGallery -Scope CurrentUser -Force
    $env:POSHACME_HOME = Join-Path $env:RUNNER_TEMP ('hln-w-acme-' + [guid]::NewGuid().ToString('n'))
    $accountFile = Join-Path $env:POSHACME_HOME 'account.pem'
    [IO.Directory]::CreateDirectory($env:POSHACME_HOME) | Out-Null
    try {
        [IO.File]::WriteAllText($accountFile, $env:HLNW_ACME_ACCOUNT_KEY)
        Import-Module Posh-ACME -RequiredVersion $moduleVersion
        Set-PAServer LE_PROD | Out-Null
        $account = New-PAAccount -KeyFile $accountFile -OnlyReturnExisting -Force
        if ($account.status -ne 'valid') { throw 'The configured ACME account is unavailable.' }
        Remove-Item -LiteralPath $accountFile -Force
        $cert = New-PACertificate $domain -Plugin QiniuManagerUpdates -CertKeyLength 2048 -ValidationTimeout 180
        $candidate = [Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPemFile($cert.CertFile, $cert.KeyFile)
        try {
            if ($candidate.GetNameInfo('DnsName', $false) -cne $domain -or !$candidate.HasPrivateKey -or
                $candidate.NotAfter.ToUniversalTime() -le $expires.AddMinutes(5) -or
                $candidate.NotAfter.ToUniversalTime() -le [DateTime]::UtcNow.AddDays($renewBefore)) {
                throw 'The issued certificate did not extend the current certificate for the expected domain.'
            }
            $uploaded = Invoke-QiniuApi Post '/sslcert' @{
                name = "HLN-W $domain $($candidate.NotAfter.ToString('yyyy-MM-dd'))"
                pri = [IO.File]::ReadAllText($cert.KeyFile)
                ca = [IO.File]::ReadAllText($cert.FullChainFile)
            }
            if ($uploaded.certID -notmatch '^[a-f0-9]{24}$') { throw 'Qiniu did not return a certificate identifier.' }
            $latestConfig = Invoke-QiniuApi Get $domainPath
            if ($latestConfig.modifyAt -ne $original.modifyAt -or $latestConfig.https.certId -ne $https.certId) {
                throw 'The CDN configuration changed during issuance. Rerun after checking the new configuration.'
            }
            $updated = Invoke-QiniuApi Put "$domainPath/httpsconf" @{
                certId = $uploaded.certID
                forceHttps = $https.forceHttps
                http2Enable = $https.http2Enable
                tlsVersions = $https.tlsVersions
            }
            if ($updated.code -ne 200) { throw "Qiniu rejected the HTTPS update (code $($updated.code))." }
            for ($attempt = 0; $attempt -lt 30; $attempt++) {
                try {
                    $active = Get-PublicCertificate
                    try {
                        if ($active.Thumbprint -eq $candidate.Thumbprint) {
                            Write-Output "The renewed certificate is public and expires $($active.NotAfter.ToUniversalTime().ToString('u'))."
                            return
                        }
                    } finally { $active.Dispose() }
                } catch { Write-Output 'Waiting for a trusted public TLS response.' }
                Start-Sleep -Seconds 20
            }
            throw 'Qiniu accepted the HTTPS change, but the CDN did not present the new certificate before the verification deadline.'
        } finally { $candidate.Dispose() }
    } finally {
        $state = Get-Item -LiteralPath $env:POSHACME_HOME -ErrorAction SilentlyContinue
        if ($state -and $state.Parent.FullName -eq (Get-Item -LiteralPath $env:RUNNER_TEMP).FullName -and $state.Name -match '^hln-w-acme-[a-f0-9]{32}$') {
            Remove-Item -LiteralPath $state.FullName -Recurse -Force
        }
    }
} finally { $current.Dispose() }
