function Get-CurrentPluginType { 'http-01' }

function Add-HttpChallenge {
    param(
        [Parameter(Mandatory, Position=0)] [string]$Domain,
        [Parameter(Mandatory, Position=1)] [string]$Token,
        [Parameter(Mandatory, Position=2)] [string]$Body,
        [Parameter(ValueFromRemainingArguments)] $ExtraParams
    )

    if ($Domain -cne 'updates.wuyouxiang.top' -or $Token -cnotmatch '^[A-Za-z0-9_-]{20,128}$' -or
        $Body -cnotmatch ('^' + [regex]::Escape($Token) + '\.[A-Za-z0-9_-]{43}$')) {
        throw 'Unexpected HTTP-01 challenge.'
    }

    $object = ".well-known/acme-challenge/$Token"
    $challengeFile = New-TemporaryFile
    try {
        [IO.File]::WriteAllText($challengeFile.FullName, $Body)
        $start = [Diagnostics.ProcessStartInfo]::new('aws')
        $start.UseShellExecute = $false
        $start.CreateNoWindow = $true
        $start.RedirectStandardOutput = $true
        $start.RedirectStandardError = $true
        foreach ($argument in @('s3api', 'put-object', '--endpoint-url', 'https://s3.cn-south-1.qiniucs.com',
            '--region', 'cn-south-1', '--no-cli-pager', '--no-cli-auto-prompt', '--cli-connect-timeout', '15',
            '--cli-read-timeout', '25', '--bucket', 'hln-w-updates-wuyouxiang', '--key', $object,
            '--body', $challengeFile.FullName, '--content-type', 'text/plain', '--cache-control', 'no-store')) {
            $start.ArgumentList.Add($argument)
        }
        $start.Environment['AWS_ACCESS_KEY_ID'] = $env:QINIU_TLS_ACCESS_KEY
        $start.Environment['AWS_SECRET_ACCESS_KEY'] = $env:QINIU_TLS_SECRET_KEY
        $start.Environment['AWS_EC2_METADATA_DISABLED'] = 'true'
        $start.Environment['AWS_REQUEST_CHECKSUM_CALCULATION'] = 'when_required'
        foreach ($name in @('AWS_SESSION_TOKEN', 'HLNW_ACME_ACCOUNT_KEY', 'QINIU_TLS_ACCESS_KEY', 'QINIU_TLS_SECRET_KEY')) {
            $null = $start.Environment.Remove($name)
        }
        $upload = [Diagnostics.Process]::Start($start)
        try {
            $null = $upload.StandardOutput.ReadToEndAsync()
            $errorTask = $upload.StandardError.ReadToEndAsync()
            if (!$upload.WaitForExit(60000)) {
                $upload.Kill()
                throw 'Qiniu S3 challenge upload timed out.'
            }
            if ($upload.ExitCode -ne 0) {
                $errorCode = [regex]::Match($errorTask.Result, 'An error occurred \(([A-Za-z0-9_-]{1,40})\)').Groups[1].Value
                throw "Qiniu S3 challenge upload failed (exit $($upload.ExitCode), service code $errorCode)."
            }
        } finally { $upload.Dispose() }
        for ($attempt = 0; $attempt -lt 6; $attempt++) {
            $reply = Invoke-WebRequest -Uri "http://$Domain/$object" -MaximumRedirection 3 -TimeoutSec 20 -SkipHttpErrorCheck
            if ($reply.StatusCode -eq 200 -and [Text.Encoding]::UTF8.GetString($reply.RawContentStream.ToArray()) -ceq $Body) {
                return
            }
            Start-Sleep -Seconds 5
        }
        throw 'The public HTTP-01 route did not return the expected challenge.'
    } finally {
        Remove-Item -LiteralPath $challengeFile.FullName -Force -ErrorAction SilentlyContinue
    }
}

# Each challenge has a unique URL. The renewal account has upload-only access.
function Remove-HttpChallenge {
    param(
        [Parameter(Mandatory, Position=0)] [string]$Domain,
        [Parameter(Mandatory, Position=1)] [string]$Token,
        [Parameter(Mandatory, Position=2)] [string]$Body,
        [Parameter(ValueFromRemainingArguments)] $ExtraParams
    )
}

function Save-HttpChallenge { param([Parameter(ValueFromRemainingArguments)] $ExtraParams) }

function ConvertTo-QiniuBase64([byte[]]$Bytes) {
    [Convert]::ToBase64String($Bytes).Replace('+', '-').Replace('/', '_')
}

function Get-QiniuSignature([string]$Data) {
    $hmac = [Security.Cryptography.HMACSHA1]::new([Text.Encoding]::UTF8.GetBytes($env:QINIU_TLS_SECRET_KEY))
    try { ConvertTo-QiniuBase64 ($hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($Data))) }
    finally { $hmac.Dispose() }
}
