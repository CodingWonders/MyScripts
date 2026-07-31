#requires -runasadministrator
#requires -version 5.0

# Source: https://woshub.com/security-warnings-opening-rdp-files-windows/

using namespace System.Security.Cryptography.X509Certificates

[CmdletBinding(DefaultParameterSetName='FileNewCert')]
param (
    [Parameter(Mandatory, Position=0)]
    [ValidateSet('Directory','File')]
    [string] $signOperation,

    [Parameter(ParameterSetName='DirectoryNewCert', Mandatory, Position=1)]
    [Parameter(ParameterSetName='DirectoryCertByObject', Mandatory, Position=1)]
    [Parameter(ParameterSetName='DirectoryCertByThumbprint', Mandatory, Position=1)]
    [string] $rdpDirectory,

    [Parameter(ParameterSetName='FileNewCert', Mandatory, Position=1)]
    [Parameter(ParameterSetName='FileCertByObject', Mandatory, Position=1)]
    [Parameter(ParameterSetName='FileCertByThumbprint', Mandatory, Position=1)]
    [string] $rdpFile,

    [Parameter(ParameterSetName='FileNewCert')]
    [Parameter(ParameterSetName='DirectoryNewCert')]
    [string] $certificateSubject = "Self-Signed Code Signing Certificate for RDP files",

    [Parameter(ParameterSetName='FileCertByObject', Mandatory)]
    [Parameter(ParameterSetName='DirectoryCertByObject', Mandatory)]
    [X509Certificate2] $sourceCertificate,

    [Parameter(ParameterSetName='FileCertByThumbprint', Mandatory)]
    [Parameter(ParameterSetName='DirectoryCertByThumbprint', Mandatory)]
    [string] $certificateThumbprint,
    
    [ValidateSet('','sha256','sha384','sha512')]
    [string] $thumbprintPrefix = ""
)


function Invoke-RdpFileSigning {
    param (
        [Parameter(Mandatory = $true, Position = 0)] [string] $rdpFilePath,
        [Parameter(Mandatory = $true, Position = 1)] [string] $rdpCertThumb
    )

    if (-not (Test-Path -Path "$rdpFilePath" -PathType Leaf)) {
        return $false
    }

    if ($rdpCertThumb -eq "") {
        return $false
    }

    rdpsign.exe /sha256 $rdpCertThumb "$rdpFilePath"
    return $?
}

# July 2026 cumulative updates allow specifying SHA256, SHA384 and SHA512 thumbprints, which are more secure than SHA1. Detect
# if we're on those supported platforms
# --------------------
# Hold the UBRs for all supported systems
$UBR_WIN11_BR_SHAUPD = 2525
$UBR_WIN11_GE_SHAUPD = 8875
$UBR_WS2025_SHAUPD = 33158
$UBR_WS2022_SHAUPD = 5386
$UBR_WS2019_SHAUPD = 9020
$UBR_WS2016_SHAUPD = 9339
$UBR_WIN10_VB_SHAUPD = 7548

$shaUpdateSupported = $false
$sysBuild = [int](Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name "CurrentBuildNumber")
$sysUBR = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name "UBR"
# sysIsServer only for Windows 11 24H2, and Server 2025
$sysIsServer = (Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name "InstallationType") -like "*Server*"

# If we're running anything greater than 28000 then we automatically mark it as compatible with the SHA update
$shaUpdateSupported = $sysBuild -gt 28000

if (-not $shaUpdateSupported) {
    switch -Wildcard ($sysBuild) {
        28000 {
            # Windows 11 26H1 (Bromine)
            $shaUpdateSupported = $sysUBR -ge $UBR_WIN11_BR_SHAUPD
        }
        26300 {
            # Windows 11 26H2; already supported
            $shaUpdateSupported = $true
        }
        26200 {
            # Windows 11 25H2
            $shaUpdateSupported = $sysUBR -ge $UBR_WIN11_GE_SHAUPD
        }
        26100 {
            # Windows 11 24H2; Windows Server 2025. We have to check
            $ubrLowerThreshold = 0
            if ($sysIsServer) {
                $ubrLowerThreshold = $UBR_WS2025_SHAUPD
            } else {
                $ubrLowerThreshold = $UBR_WIN11_GE_SHAUPD
            }
            $shaUpdateSupported = $sysUBR -ge $ubrLowerThreshold
        }
        20348 {
            # Windows Server 2022
            $shaUpdateSupported = $sysUBR -ge $UBR_WS2022_SHAUPD
        }
        {($_ -eq 19044) -or ($_ -eq 19045)} {
            # Windows 10 IoT LTSC 2021; Windows 10 22H2 (+ ESU)
            $shaUpdateSupported = $sysUBR -ge $UBR_WIN10_VB_SHAUPD
        }
        17063 {
            # Windows 10 1809; Windows Server 2019
            $shaUpdateSupported = $sysUBR -ge $UBR_WS2019_SHAUPD
        }
        14393 {
            # Windows 10 1607; Windows Server 2016
            $shaUpdateSupported = $sysUBR -ge $UBR_WS2016_SHAUPD
        }
    }
}

# Look at certificate modes: whether we need to create a new self-signed cert, or if we use an existing cert by
# either object or thumbprint
$cert = $null
if ($certificateSubject) {
    # This certificate lasts 10 years
    $curdate = Get-Date
    $cert = New-SelfSignedCertificate -Subject "$certificateSubject" -CertStoreLocation "Cert:\LocalMachine\My" -KeyExportPolicy Exportable -KeySpec Signature -KeyLength 2048 -KeyAlgorithm RSA -HashAlgorithm SHA256 -Type CodeSigningCert -NotAfter ($curdate.AddYears(10))

    if ((-not $?) -or ($null -eq $cert)) {
        Write-Error -Message "The certificate could not be created."
    }

    if ($null -ne $cert) {
        Export-Certificate -Cert $cert -FilePath "\rootcert.cer" -Force -Verbose | Out-Null
        if (Test-Path -Path "\rootcert.cer" -PathType Leaf) {
            certutil -addstore "Root" "\rootcert.cer"
            Remove-Item -Path "\rootcert.cer" -Force
        }
        Write-Host -NoNewline "`nIMPORTANT! You must add this certificate's thumbprint, "
        if (($shaUpdateSupported) -and ($thumbprintPrefix -ne "")) {
            Write-Host -NoNewline "including the prefix, "
            Write-Host -NoNewline "$($thumbprintPrefix):$($cert.GetCertHashString("$thumbprintPrefix"))" -BackgroundColor DarkGreen -ForegroundColor White
        } else {
            Write-Host -NoNewline $($cert.Thumbprint) -BackgroundColor DarkGreen -ForegroundColor White
        }
        Write-Host ", to the following Group Policy Object:"
        Write-Host "    Computer Configuration\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Connection Client"
        if ($shaUpdateSupported) {
            Write-Host "Add this thumbprint to the `"Specify thumbprints of certificates representing trusted .rdp publishers`" policy. Enable"
        } else {
            Write-Host "Add this thumbprint to the `"Specify SHA1 thumbprints of certificates representing trusted .rdp publishers`" policy. Enable"
        }
        Write-Host "said policy if not already enabled.`n"
    }
} elseif ($sourceCertificate) {
    if ($null -ne $sourceCertificate) {
        $cert = $sourceCertificate
    } else {
        Write-Error -Message "No valid certificate object has been passed."
    }
} elseif ($certificateThumbprint) {
    # Even though we only need the thumbprint for signing files we'll see if we have a certificate by that thumbprint
    if ((Get-ChildItem -Path "Cert:\LocalMachine\My" | Where-Object { $_.Thumbprint -eq "$certificateThumbprint" }).Count -eq 0) {
        Write-Error -Message "No certificates exist with the provided thumbprint in the local machine scope."
    } else {
        $cert = Get-ChildItem -Path "Cert:\LocalMachine\My" | Where-Object { $_.Thumbprint -eq "$certificateThumbprint" }
    }
}

if ($null -eq $cert) {
    return
}

# Now we'll focus on operation modes: by either directory or file
switch ($signOperation) {
    "Directory" {
        if (($rdpDirectory -eq "") -or (-not (Test-Path -Path "$rdpDirectory"))) {
            Write-Error -Message "The provided directory does not exist."
            return
        }
        
        $rdpFiles = Get-ChildItem -Path "$rdpDirectory" -Filter "*.rdp"
        
        $successfulSigns = 0
        $failedSigns = 0
        $rdpFileCount = $rdpFiles.Count

        $idx = 0
        foreach ($rdp in Get-ChildItem -Path "$rdpDirectory" -Filter "*.rdp") {
            Write-Progress -Activity "Signing RDP files..." -Status "Signing RDP file $($idx + 1) of $rdpFileCount..." -PercentComplete (($idx / $rdpFileCount) * 100)
            if (Invoke-RdpFileSigning -rdpFilePath "$($rdp.FullName)" -rdpCertThumb "$($cert.Thumbprint)") {
                $successfulSigns++
            } else {
                $failedSigns++
            }
            $idx++
        }
        Write-Progress -Activity "Signing RDP files..." -Completed
        Write-Host "`nSignature Operation Summary:"
        Write-Host "- $($successfulSigns + $failedSigns) file(s) were processed"
        Write-Host "- $successfulSigns file(s) were successfully signed"
        Write-Host "- $failedSigns file(s) were not signed"
    }
    "File" {
        if (($rdpFile -eq "") -or (-not (Test-Path -Path "$rdpFile" -PathType Leaf))) {
            Write-Error -Message "The provided file does not exist."
            return
        }

        if (Invoke-RdpFileSigning -rdpFilePath "$rdpFile" -rdpCertThumb "$($cert.Thumbprint)") {
            Write-Host "This file was successfully signed."
        } else {
            Write-Host "This file was not signed."
        }
    }
}