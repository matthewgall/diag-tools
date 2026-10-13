#Requires -Version 5.1
<#
.SYNOPSIS
    Reproduces the connectivity pre-checks that cloudflared runs at startup.

.DESCRIPTION
    This script is a Windows/PowerShell equivalent of cloudflared-diag.sh.
    It deliberately does NOT depend on the cloudflared binary or libraries, so a failure
    here means the network path is blocked, not a bug in cloudflared.

    It checks:
      1. SRV discovery for region*.v2.argotunnel.com
      2. TCP reachability to the resolved edge IPs on port 7844
      3. TLS handshake for the HTTP/2 probe (SNI probe.cftunnel.com)
      4. QUIC handshake, if OpenSSL 3.2+ is available

.PARAMETER Region
    Optional region prefix, e.g. "us" or "fed". Default is global.

.PARAMETER DnsServer
    Optional DNS server override, e.g. "1.1.1.1". Default is the system resolver.

.EXAMPLE
    .\cloudflared-diag.ps1

.EXAMPLE
    .\cloudflared-diag.ps1 -Region us -DnsServer 1.1.1.1
#>

[CmdletBinding()]
param(
    [string]$Region = "",
    [string]$DnsServer = ""
)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

$SRV_SERVICE = "v2-origintunneld"
$SRV_PROTO   = "tcp"
$SRV_DOMAIN  = "argotunnel.com"

$PROBE_SNI   = "probe.cftunnel.com"
$QUIC_ALPN  = "argotunnel"
$DEFAULT_EDGE_PORT = 7844

$PROBE_TIMEOUT_MS = 8000

if ($Region) {
    $SRV_QNAME = "_${Region}-${SRV_SERVICE}._${SRV_PROTO}.${SRV_DOMAIN}"
    $REGION_LABEL = $Region
} else {
    $SRV_QNAME = "_${SRV_SERVICE}._${SRV_PROTO}.${SRV_DOMAIN}"
    $REGION_LABEL = "global"
}

# Cloudflare Origin CA root certificates (from cloudflared/tlsconfig/cloudflare_ca.go).
# The edge presents a certificate signed by one of these during the probe handshake.
$CF_ORIGIN_CA_PEM = @'
-----BEGIN CERTIFICATE-----
MIICiTCCAi6gAwIBAgIUXZP3MWb8MKwBE1Qbawsp1sfA/Y4wCgYIKoZIzj0EAwIw
gY8xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQHEw1T
YW4gRnJhbmNpc2NvMRkwFwYDVQQKExBDbG91ZEZsYXJlLCBJbmMuMTgwNgYDVQQL
Ey9DbG91ZEZsYXJlIE9yaWdpbiBTU0wgRUNDIENlcnRpZmljYXRlIEF1dGhvcml0
eTAeFw0xOTA4MjMyMTA4MDBaFw0yOTA4MTUxNzAwMDBaMIGPMQswCQYDVQQGEwJV
UzETMBEGA1UECBMKQ2FsaWZvcm5pYTEWMBQGA1UEBxMNU2FuIEZyYW5jaXNjbzEZ
MBcGA1UEChMQQ2xvdWRGbGFyZSwgSW5jLjE4MDYGA1UECxMvQ2xvdWRGbGFyZSBP
cmlnaW4gU1NMIEVDQyBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkwWTATBgcqhkjOPQIB
BggqhkjOPQMBBwNCAASR+sGALuaGshnUbcxKry+0LEXZ4NY6JUAtSeA6g87K3jaA
xpIg9G50PokpfWkhbarLfpcZu0UAoYy2su0EhN7wo2YwZDAOBgNVHQ8BAf8EBAMC
AQYwEgYDVR0TAQH/BAgwBgEB/wIBAjAdBgNVHQ4EFgQUhTBdOypw1O3VkmcH/es5
tBoOOKcwHwYDVR0jBBgwFoAUhTBdOypw1O3VkmcH/es5tBoOOKcwCgYIKoZIzj0E
AwIDSQAwRgIhAKilfntP2ILGZjwajktkBtXE1pB4Y/fjAfLkIRUzrI15AiEA5UCL
XYZZ9m2c3fKwIenMMojL1eqydsgqj/wK4p5kagQ=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIEADCCAuigAwIBAgIID+rOSdTGfGcwDQYJKoZIhvcNAQELBQAwgYsxCzAJBgNV
BAYTAlVTMRkwFwYDVQQKExBDbG91ZEZsYXJlLCBJbmMuMTQwMgYDVQQLEytDbG91
ZEZsYXJlIE9yaWdpbiBTU0wgQ2VydGlmaWNhdGUgQXV0aG9yaXR5MRYwFAYDVQQH
Ew1TYW4gRnJhbmNpc2NvMRMwEQYDVQQIEwpDYWxpZm9ybmlhMB4XDTE5MDgyMzIx
MDgwMFoXDTI5MDgxNTE3MDAwMFowgYsxCzAJBgNVBAYTAlVTMRkwFwYDVQQKExBD
bG91ZEZsYXJlLCBJbmMuMTQwMgYDVQQLEytDbG91ZEZsYXJlIE9yaWdpbiBTU0wg
Q2VydGlmaWNhdGUgQXV0aG9yaXR5MRYwFAYDVQQHEw1TYW4gRnJhbmNpc2NvMRMw
EQYDVQQIEwpDYWxpZm9ybmlhMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC
AQEAwEiVZ/UoQpHmFsHvk5isBxRehukP8DG9JhFev3WZtG76WoTthvLJFRKFCHXm
V6Z5/66Z4S09mgsUuFwvJzMnE6Ej6yIsYNCb9r9QORa8BdhrkNn6kdTly3mdnykb
OomnwbUfLlExVgNdlP0XoRoeMwbQ4598foiHblO2B/LKuNfJzAMfS7oZe34b+vLB
yrP/1bgCSLdc1AxQc1AC0EsQQhgcyTJNgnG4va1c7ogPlwKyhbDyZ4e59N5lbYPJ
SmXI/cAe3jXj1FBLJZkwnoDKe0v13xeF+nF32smSH0qB7aJX2tBMW4TWtFPmzs5I
lwrFSySWAdwYdgxw180yKU0dvwIDAQABo2YwZDAOBgNVHQ8BAf8EBAMCAQYwEgYD
VR0TAQH/BAgwBgEB/wIBAjAdBgNVHQ4EFgQUJOhTV118NECHqeuU27rhFnj8KaQw
HwYDVR0jBBgwFoAUJOhTV118NECHqeuU27rhFnj8KaQwDQYJKoZIhvcNAQELBQAD
ggEBAHwOf9Ur1l0Ar5vFE6PNrZWrDfQIMyEfdgSKofCdTckbqXNTiXdgbHs+TWoQ
wAB0pfJDAHJDXOTCWRyTeXOseeOi5Btj5CnEuw3P0oXqdqevM1/+uWp0CM35zgZ8
VD4aITxity0djzE6Qnx3Syzz+ZkoBgTnNum7d9A66/V636x4vTeqbZFBr9erJzgz
hhurjcoacvRNhnjtDRM0dPeiCJ50CP3wEYuvUzDHUaowOsnLCjQIkWbR7Ni6KEIk
MOz2U0OBSif3FTkhCgZWQKOOLo1P42jHC3ssUZAtVNXrCk3fw9/E15k8NPkBazZ6
0iykLhH1trywrKRMVw67F44IE8Y=
-----END CERTIFICATE-----
'@

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

function Write-Pass($msg)  { Write-Host "  PASS" -ForegroundColor Green -NoNewline; Write-Host ": $msg" }
function Write-Fail($msg)  { Write-Host "  FAIL" -ForegroundColor Red -NoNewline; Write-Host ": $msg" }
function Write-Skip($msg)  { Write-Host "  SKIP" -ForegroundColor Yellow -NoNewline; Write-Host ": $msg" }
function Write-Info($msg)  { Write-Host "  INFO" -ForegroundColor Cyan -NoNewline; Write-Host ": $msg" }
function Write-Hr($len = 80) { Write-Host ("-" * $len) }

function Test-Command($name) {
    return [bool](Get-Command -Name $name -ErrorAction SilentlyContinue)
}

function Format-Endpoint($ip, $port) {
    $addr = [System.Net.IPAddress]::Parse($ip)
    if ($addr.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
        return "[${ip}]:${port}"
    }
    return "${ip}:${port}"
}

function Invoke-OpenSSLWithTimeout($ArgumentList, $InputFile, $TimeoutMs) {
    $stdoutFile = [System.IO.Path]::GetTempFileName()
    try {
        $proc = New-Object System.Diagnostics.Process
        $proc.StartInfo.FileName = (Get-Command openssl).Source
        $proc.StartInfo.Arguments = $ArgumentList -join ' '
        $proc.StartInfo.RedirectStandardInput = $true
        $proc.StartInfo.RedirectStandardOutput = $true
        $proc.StartInfo.UseShellExecute = $false
        $proc.StartInfo.WindowStyle = 'Hidden'
        $proc.StartInfo.CreateNoWindow = $true
        $proc.StartInfo.StandardOutputEncoding = [System.Text.Encoding]::UTF8

        [void]$proc.Start()

        # Feed openssl a single newline and then close stdin. This is enough to
        # drive s_client through the handshake and then EOF, so it exits cleanly.
        $proc.StandardInput.WriteLine()
        $proc.StandardInput.Close()

        $exited = $proc.WaitForExit($TimeoutMs)
        if (-not $exited) {
            $proc.Kill()
            $proc.WaitForExit(2000) | Out-Null
        }

        $proc.StandardOutput.ReadToEnd()
    } finally {
        if (Test-Path $stdoutFile) { Remove-Item $stdoutFile -Force }
    }
}

function Write-CAFile() {
    $tmp = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "cf_origin_ca_" + [Guid]::NewGuid().ToString("N") + ".pem")
    [System.IO.File]::WriteAllText($tmp, $CF_ORIGIN_CA_PEM)
    return $tmp
}

function Resolve-SrvRecords($qname, $server) {
    $params = @{
        Type    = 'SRV'
        Name    = $qname
        ErrorAction = 'SilentlyContinue'
        WarningAction = 'SilentlyContinue'
    }
    if ($server) { $params['Server'] = $server }
    return Resolve-DnsName @params | Select-Object -Property NameTarget, Port, Priority, Weight
}

function Resolve-EdgeIps($hostname, $server) {
    $ips = @()
    foreach ($type in @('A', 'AAAA')) {
        $params = @{
            Type    = $type
            Name    = $hostname
            ErrorAction = 'SilentlyContinue'
            WarningAction = 'SilentlyContinue'
        }
        if ($server) { $params['Server'] = $server }
        $records = Resolve-DnsName @params
        if ($records) {
            $ips += $records | ForEach-Object { $_.IPAddress }
        }
    }
    return $ips
}

function Test-TcpPort($ip, $port) {
    try {
        $ipAddr = [System.Net.IPAddress]::Parse($ip)
        $client = New-Object System.Net.Sockets.TcpClient
        $ar = $client.BeginConnect($ipAddr, $port, $null, $null)
        $ok = $ar.AsyncWaitHandle.WaitOne($PROBE_TIMEOUT_MS, $false)
        if ($ok -and $client.Connected) {
            $client.EndConnect($ar)
            $client.Close()
            return $true
        }
        $client.Close()
        return $false
    } catch {
        return $false
    }
}

function Test-Http2Tls($ip, $port, $caFile) {
    # Prefer OpenSSL if available; it is the closest match to the Linux script.
    if (Test-Command openssl) {
        $out = Invoke-OpenSSLWithTimeout `
            -ArgumentList @('s_client', '-connect', (Format-Endpoint $ip $port), '-servername', $PROBE_SNI, '-tls1_3', '-CAfile', $caFile) `
            -InputFile $INPUT_FILE `
            -TimeoutMs $PROBE_TIMEOUT_MS
        return ($out -match 'Verify return code: 0 ')
    }

    # Fallback: use .NET SslStream. This validates the server certificate using the
    # embedded Cloudflare Origin CA roots.
    try {
        $ipAddr = [System.Net.IPAddress]::Parse($ip)
        $client = New-Object System.Net.Sockets.TcpClient
        $ar = $client.BeginConnect($ipAddr, $port, $null, $null)
        if (-not $ar.AsyncWaitHandle.WaitOne($PROBE_TIMEOUT_MS, $false)) { return $false }
        $client.EndConnect($ar)

        $cas = Parse-CACerts

        $callback = {
            param($sender, $cert, $chain, $sslPolicyErrors)
            $c = New-Object System.Security.Cryptography.X509Certificates.X509Chain
            $c.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
            $c.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::AllowUnknownCertificateAuthority
            foreach ($ca in $cas) { [void]$c.ChainPolicy.ExtraStore.Add($ca) }
            $valid = $c.Build($cert)
            return $valid
        }.GetNewClosure()

        $sslProtocols = [System.Security.Authentication.SslProtocols]::Tls12
        $tls13Name = 'Tls13'
        if ([Enum]::GetNames([System.Security.Authentication.SslProtocols]) -contains $tls13Name) {
            $sslProtocols = $sslProtocols -bor [System.Security.Authentication.SslProtocols]::$tls13Name
        }

        $ssl = New-Object System.Net.Security.SslStream($client.GetStream(), $false, [System.Net.Security.RemoteCertificateValidationCallback]$callback)
        $ssl.AuthenticateAsClient($PROBE_SNI, $null, $sslProtocols, $false)
        $ssl.Close()
        $client.Close()
        return $true
    } catch {
        return $false
    }
}

function Test-Quic($ip, $port, $caFile) {
    if (-not (Test-Command openssl)) { return 'missing' }
    $help = Invoke-OpenSSLWithTimeout -ArgumentList @('s_client', '-quic', '-help') -InputFile $INPUT_FILE -TimeoutMs 3000
    if (-not ($help -match '-quic')) { return 'unsupported' }

    $out = Invoke-OpenSSLWithTimeout `
        -ArgumentList @('s_client', '-quic', '-connect', (Format-Endpoint $ip $port), '-servername', $PROBE_SNI, '-alpn', $QUIC_ALPN, '-CAfile', $caFile) `
        -InputFile $INPUT_FILE `
        -TimeoutMs $PROBE_TIMEOUT_MS
    if ($out -match 'Verify return code: 0 ') { return 'ok' }
    return 'fail'
}

function Parse-CACerts() {
    $certs = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
    $regex = [regex]'-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----'
    foreach ($m in $regex.Matches($CF_ORIGIN_CA_PEM, [System.Text.RegularExpressions.RegexOptions]::Singleline)) {
        $b64 = $m.Groups[1].Value -replace "`r?`n", ''
        $bytes = [Convert]::FromBase64String($b64)
        $certs.Add((New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 @(,$bytes))) | Out-Null
    }
    return $certs
}

function Invoke-CurlProbe($ip, $port, $caFile) {
    if (-not (Test-Command curl)) { return }
    Write-Info "curl.exe --http2 --resolve ${PROBE_SNI}:${port}:${ip} --cacert $caFile https://${PROBE_SNI}:${port}/"
    $output = & curl.exe -v --http2 `
        --resolve "${PROBE_SNI}:${port}:${ip}" `
        --cacert "$caFile" `
        --max-time ($PROBE_TIMEOUT_MS / 1000) `
        "https://${PROBE_SNI}:${port}/" 2>&1 | Select-Object -Last 5
    $output | ForEach-Object { Write-Host "    $_" }
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

Clear-Host
Write-Hr
Write-Host "Cloudflared edge connectivity reproduction script" -ForegroundColor White
Write-Host "Region:      $REGION_LABEL"
Write-Host "SRV query:   $SRV_QNAME"
if ($DnsServer) { Write-Host "DNS server:  $DnsServer (override)" }
else { Write-Host "DNS server:  system resolver" }
Write-Hr
Write-Host

$CA_FILE = Write-CAFile
$INPUT_FILE = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "cf_probe_input_" + [Guid]::NewGuid().ToString("N") + ".txt")
# A single CRLF is enough to drive openssl s_client through the handshake and then EOF.
[System.IO.File]::WriteAllText($INPUT_FILE, "`r`n")

function Cleanup {
    if (Test-Path $CA_FILE) { Remove-Item $CA_FILE -Force }
    if (Test-Path $INPUT_FILE) { Remove-Item $INPUT_FILE -Force }
}

Write-Info "Looking up SRV records for edge discovery..."
$srv = Resolve-SrvRecords $SRV_QNAME $DnsServer
if (-not $srv) {
    Write-Fail "No SRV records returned for $SRV_QNAME"
    Write-Host "Action: ensure your DNS resolver can resolve '$SRV_QNAME'."
    if ($DnsServer) {
        Write-Host "Try running without -DnsServer to use the system resolver."
    } else {
        Write-Host "Try: nslookup -type=srv $SRV_QNAME 1.1.1.1"
    }
    exit 1
}

Write-Host
Write-Host "SRV records returned:" -ForegroundColor White
$srv | Format-Table -AutoSize | Out-String | Write-Host

Write-Info "Resolving SRV targets to IP addresses..."
$hosts = @{}
foreach ($rec in $srv) {
    $target = $rec.NameTarget
    $ips = Resolve-EdgeIps $target $DnsServer
    if (-not $ips) {
        Write-Fail "Could not resolve $target to an IP address"
    } else {
        $hosts[$target] = @{
            Port = if ($rec.Port) { $rec.Port } else { $DEFAULT_EDGE_PORT }
            IPs  = $ips
        }
        Write-Host ("{0,-40} -> {1}" -f $target, ($ips -join ' '))
    }
}

Write-Host
Write-Hr
Write-Host "Transport probes" -ForegroundColor White
Write-Hr
Write-Host

foreach ($entry in $hosts.GetEnumerator()) {
    $hostName = $entry.Key
    $port = $entry.Value.Port
    $ips = $entry.Value.IPs

    Write-Host "Target: $hostName (port $port)" -ForegroundColor White
    Write-Host ("-" * 60)

    foreach ($ip in $ips) {
        $display = "{0,-39}" -f $ip

        Write-Host "  IP: $display TCP open -> " -NoNewline
        if (Test-TcpPort $ip $port) { Write-Pass "" }
        else { Write-Fail "port ${port}/tcp unreachable" }

        Write-Host "  IP: $display H2 TLS   -> " -NoNewline
        if (Test-Http2Tls $ip $port $CA_FILE) { Write-Pass "" }
        else { Write-Fail "TLS handshake with SNI $PROBE_SNI failed" }

        Write-Host "  IP: $display QUIC    -> " -NoNewline
        $quic = Test-Quic $ip $port $CA_FILE
        switch ($quic) {
            'ok'          { Write-Pass "" }
            'missing'     { Write-Skip "openssl not installed" }
            'unsupported' { Write-Skip "openssl 3.2+ with -quic required" }
            default       { Write-Fail "QUIC handshake with SNI $PROBE_SNI ALPN $QUIC_ALPN failed" }
        }
        Write-Host
    }
}

Write-Host
Write-Hr
Write-Host "Optional curl HTTP/2 probe (sends a real HTTP request)" -ForegroundColor White
Write-Hr
Write-Host

if (Test-Command curl) {
    foreach ($entry in $hosts.GetEnumerator()) {
        $port = $entry.Value.Port
        # Prefer an IPv4 address for curl because --resolve is simpler with IPv4.
        $ip = $entry.Value.IPs | Where-Object {
            ([System.Net.IPAddress]::Parse($_)).AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork
        } | Select-Object -First 1
        if (-not $ip) { $ip = $entry.Value.IPs | Select-Object -First 1 }
        Invoke-CurlProbe $ip $port $CA_FILE
        Write-Host
    }
} else {
    Write-Skip "curl.exe not found"
}

Write-Host
Write-Hr
Write-Host "Summary" -ForegroundColor White
Write-Info "If all TCP/H2/QUIC probes FAIL, outbound port 7844 is likely blocked."
Write-Info "If TCP/H2 passes but QUIC fails, UDP/QUIC to port 7844 is blocked."
Write-Info "If DNS fails first, fix DNS resolution before debugging transport."
Write-Info "Cloudflared production SNI is probe.cftunnel.com for these probes."
Write-Hr

try { Cleanup } catch { }
