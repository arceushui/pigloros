<#
.SYNOPSIS
Verify and extract the retained ADR-110 Fixed Runtime for packaging or CI.
.DESCRIPTION
Read only the canonical GitHub Release asset selected by Accepted ADR-110.
An unavailable Release fails closed; every downloaded byte is verified before
extraction and no alternative runtime source is selected.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string] $OutputRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$version = '153.0.4234.48'
$cabName = "Microsoft.WebView2.FixedVersionRuntime.$version.x64.cab"
$expectedHash = '11e8240cb0bc56dcd3e4498907203c251346f65107fe35a3a13e152c7d51c79e'
if (Test-Path -LiteralPath $OutputRoot) {
    throw 'OutputRoot must be fresh; retained evidence must not be overwritten'
}
$null = New-Item -ItemType Directory -Path $OutputRoot
$OutputRoot = (Resolve-Path -LiteralPath $OutputRoot).Path
$cab = Join-Path $OutputRoot $cabName

& gh release download "owner-bridge-runtime-$version" --repo arceushui/pigloros --pattern $cabName --dir $OutputRoot
if ($LASTEXITCODE -ne 0) { throw 'The retained runtime release is unavailable' }
if ((Get-FileHash -LiteralPath $cab -Algorithm SHA256).Hash.ToLowerInvariant() -cne $expectedHash) {
    throw 'CAB digest differs from Accepted ADR-110'
}

$signTool = Get-ChildItem -Path "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe" |
    Sort-Object FullName -Descending | Select-Object -First 1
if ($null -eq $signTool) { throw 'Windows SDK signtool is required for timestamp evidence' }

function Get-MicrosoftSignatureEvidence([string] $Path) {
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne 'Valid' -or
        $signature.SignerCertificate.GetNameInfo('SimpleName', $false) -cne 'Microsoft Corporation' -or
        $null -eq $signature.TimeStamperCertificate) {
        throw 'Runtime Authenticode signer, trust or timestamp verification failed'
    }
    $chain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
    try {
        if (-not $chain.Build($signature.SignerCertificate)) { throw 'Runtime signer chain failed' }
        $log = Join-Path $OutputRoot ((Split-Path -Leaf $Path) + '.signature.txt')
        & $signTool.FullName verify /pa /all /v $Path 2>&1 | Out-File -LiteralPath $log -Encoding utf8
        if ($LASTEXITCODE -ne 0) { throw 'signtool rejected the runtime signature or timestamp' }
        return [ordered]@{
            file = Split-Path -Leaf $Path
            status = [string]$signature.Status
            subject = $signature.SignerCertificate.Subject
            thumbprint = $signature.SignerCertificate.Thumbprint
            timestamp_certificate = $signature.TimeStamperCertificate.Subject
            timestamp_thumbprint = $signature.TimeStamperCertificate.Thumbprint
            chain = @($chain.ChainElements | ForEach-Object { $_.Certificate.Subject })
            timestamp_and_chain_log = Split-Path -Leaf $log
        }
    } finally {
        $chain.Dispose()
    }
}

$signatures = @(Get-MicrosoftSignatureEvidence $cab)
$unpacked = Join-Path $OutputRoot 'unpacked'
$null = New-Item -ItemType Directory -Path $unpacked
& expand.exe '-F:*' $cab $unpacked
if ($LASTEXITCODE -ne 0) { throw 'Fixed Runtime CAB extraction failed' }
$runtime = Join-Path $unpacked "Microsoft.WebView2.FixedVersionRuntime.$version.x64"
if (-not (Test-Path -LiteralPath $runtime -PathType Container)) { throw 'Unexpected CAB layout' }
foreach ($relative in @('msedgewebview2.exe', 'msedge.dll', 'msedge_elf.dll', 'EBWebView\x64\EmbeddedBrowserWebView.dll')) {
    $signatures += Get-MicrosoftSignatureEvidence (Join-Path $runtime $relative)
}
& python (Join-Path $PSScriptRoot 'owner_bridge_runtime.py') $runtime --output (Join-Path $OutputRoot 'runtime-install-manifest.json')
if ($LASTEXITCODE -ne 0) { throw 'Extracted runtime differs from the retained manifest' }
[ordered]@{
    runtime_version = $version
    cab_sha256 = $expectedHash
    mode = 'Package'
    source = "https://github.com/arceushui/pigloros/releases/tag/owner-bridge-runtime-$version"
    commit = $env:GITHUB_SHA
    windows_build = [System.Environment]::OSVersion.Version.ToString()
    signatures = $signatures
} | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $OutputRoot 'runtime-custody.json') -Encoding utf8
if ($env:GITHUB_OUTPUT) {
    "runtime=$runtime" | Out-File -FilePath $env:GITHUB_OUTPUT -Encoding utf8 -Append
}
