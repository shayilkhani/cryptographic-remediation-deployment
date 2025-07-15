<#
.SYNOPSIS
    Toggles cryptographic protocol and system-level crypto hardening settings.

.DESCRIPTION
    Expands cryptographic hardening by disabling weak SSL/TLS protocols, outdated cipher suites,
    insecure hash algorithms, and enables FIPS-compliant crypto. Designed to meet security
    baselines and mitigate CVEs like POODLE, BEAST, Logjam, SWEET32, RC4 bias, and others.

.NOTES
    Author         : Shay Ilkhani
    Date Created   : 2025-03-27
    Last Modified  : 2025-07-10
    Must be run with Administrator privileges.

    CVEs:
    - CVE-2011-3389 : BEAST attack
    - CVE-2014-3566 : POODLE
    - CVE-2015-2808 : RC4 biases
    - CVE-2015-4000 : Logjam
    - CVE-2016-2183 : SWEET32
    - CVE-2017-15361: ROCA
    - CVE-2008-5161 : Weak SSH + key exchange
    - CVE-2021-23839: TLS 1.0/1.1 downgrade
    
    Plugin IDs:
    - 58751
    - 217432
    - 65821
    - 83875
    - 218753
    - 42873
    - 94437
    - 103864
    - 70658
    - 44065
    - 202851
    - 184148
    - 212513
    
    Plugin Page(s):
    - https://www.tenable.com/plugins/nessus/58751
    - https://www.tenable.com/plugins/nessus/217432
    - https://www.tenable.com/plugins/nessus/65821
    - https://www.tenable.com/plugins/nessus/83875
    - https://www.tenable.com/plugins/nessus/218753
    - https://www.tenable.com/plugins/nessus/42873
    - https://www.tenable.com/plugins/nessus/94437
    - https://www.tenable.com/plugins/nessus/103864
    - https://www.tenable.com/plugins/nessus/70658
    - https://www.tenable.com/plugins/nessus/44065
    - https://www.tenable.com/plugins/nessus/202851
    - https://www.tenable.com/plugins/nessus/184148
    - https://www.tenable.com/plugins/nessus/212513

.TESTED ON
    Date(s) Tested  : 2024-03-27
    Tested By       : Shay Ilkhani
    Systems Tested  : Windows Server 2019 Datacenter, Build 1809
                      Windows 10 Pro, Build 22H2
    PowerShell Ver. : 5.1.17763.6189

.USAGE
    Set [$makeSecure = $true] to secure the system
    Example syntax:
    PS C:\> .\toggle-protocols.ps1 
#>

$makeSecure = $true

function Check-Admin {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Check-Admin)) {
    Write-Error "Access Denied. Please run as Administrator."
    exit 1
}

function Set-ProtocolState {
    param (
        [string]$ProtocolName,
        [string]$BaseKeyPath,
        [bool]$Enable
    )

    $serverPath = "$BaseKeyPath\$ProtocolName\Server"
    $clientPath = "$BaseKeyPath\$ProtocolName\Client"

    $enabled = if ($Enable) { 1 } else { 0 }
    $disabled = if ($Enable) { 0 } else { 1 }

    foreach ($path in @($serverPath, $clientPath)) {
        New-Item -Path $path -Force | Out-Null
        New-ItemProperty -Path $path -Name 'Enabled' -Value $enabled -PropertyType 'DWord' -Force | Out-Null
        New-ItemProperty -Path $path -Name 'DisabledByDefault' -Value $disabled -PropertyType 'DWord' -Force | Out-Null
    }

    $status = if ($Enable) { "enabled" } else { "disabled" }
    Write-Host "$ProtocolName has been $status."
}

$baseRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"

# === Secure or Insecure Protocols ===
if ($makeSecure) {
    Set-ProtocolState "SSL 2.0" $baseRegPath $false
    Set-ProtocolState "SSL 3.0" $baseRegPath $false
    Set-ProtocolState "TLS 1.0" $baseRegPath $false
    Set-ProtocolState "TLS 1.1" $baseRegPath $false
    Set-ProtocolState "TLS 1.2" $baseRegPath $true
} else {
    Set-ProtocolState "SSL 2.0" $baseRegPath $true
    Set-ProtocolState "SSL 3.0" $baseRegPath $true
    Set-ProtocolState "TLS 1.0" $baseRegPath $true
    Set-ProtocolState "TLS 1.1" $baseRegPath $true
    Set-ProtocolState "TLS 1.2" $baseRegPath $false
}

# === RC4 Cipher Suite Mitigation ===
$rc4Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128"
if ($makeSecure) {
    New-Item -Path $rc4Path -Force | Out-Null
    New-ItemProperty -Path $rc4Path -Name 'Enabled' -Value 0 -PropertyType DWord -Force | Out-Null
    Write-Host "RC4 cipher disabled."
} else {
    Remove-Item -Path $rc4Path -Recurse -ErrorAction SilentlyContinue
    Write-Host "RC4 cipher settings reset (default enabled)."
}

# === Enforce FIPS-compliant algorithms only ===
$fipsPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy"
if ($makeSecure) {
    New-ItemProperty -Path $fipsPath -Name 'Enabled' -Value 1 -PropertyType DWord -Force | Out-Null
    Write-Host "FIPS mode enabled."
} else {
    New-ItemProperty -Path $fipsPath -Name 'Enabled' -Value 0 -PropertyType DWord -Force | Out-Null
    Write-Host "FIPS mode disabled."
}

# === Disable NULL, DES, 3DES, EXPORT, and 56/40-bit Ciphers ===
$weakCiphers = @(
    "NULL", "DES 56/56", "TRIPLE DES 168", "RC2 128/128", "RC2 56/128", "RC2 40/128",
    "EXPORT40", "EXPORT56"
)

foreach ($cipher in $weakCiphers) {
    $path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\$cipher"
    if ($makeSecure) {
        New-Item -Path $path -Force | Out-Null
        New-ItemProperty -Path $path -Name 'Enabled' -Value 0 -PropertyType DWord -Force | Out-Null
        Write-Host "$cipher disabled."
    } else {
        Remove-Item -Path $path -Recurse -ErrorAction SilentlyContinue
        Write-Host "$cipher settings reset."
    }
}

Write-Host "`n[!] Reboot required for protocol and cipher suite changes to take effect." -ForegroundColor Yellow

