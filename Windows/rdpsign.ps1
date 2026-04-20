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
    [string] $certificateThumbprint
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
        Write-Host -NoNewline $($cert.Thumbprint) -BackgroundColor DarkGreen -ForegroundColor White
        Write-Host ", to the following Group Policy Object:"
        Write-Host "    Computer Configuration\Administrative Templates\Windows Components\Remote Desktop Services\Remote Desktop Connection Client"
        Write-Host "Add this thumbprint to the `"Specify SHA1 thumbprints of certificates representing trusted .rdp publishers`" policy. Enable"
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