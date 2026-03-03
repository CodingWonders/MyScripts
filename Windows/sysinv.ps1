#requires -version 5.0
#requires -runasadministrator

function Get-ComputerInventory {
    <#
        .SYNOPSIS
            Gets and stores computer inventory related to system hardware and software.
        .OUTPUTS
            The reported computer inventory.
    #>

    # hinv variable name makes reference to ARCS-based SGI systems and hinv command
    $hinv = "---- HARDWARE INVENTORY:"

    # first we get all hardware inventory possible: CPU, memory, disks, BIOS, computer system...
    $computerSystemInformation = Get-CimInstance Win32_ComputerSystem
    $processorInformation = Get-CimInstance Win32_Processor
    $memoryInformation = Get-CimInstance Win32_PhysicalMemory
    $volumeInformation = Get-Volume | Where-Object { $_.DriveType -eq "Fixed" }
    $biosInformation = Get-CimInstance Win32_BIOS

    $hinv += "`n`n-- Computer System:`n"

    # Computer System information reported:
    # - Manufacturer
    # - Model
    # - System Family
    # - System SKU Number
    # - Hypervisor Present
    $hinv += "`n    - Manufacturer: $($computerSystemInformation.Manufacturer)"
    $hinv += "`n    - Model: $($computerSystemInformation.Model)"
    $hinv += "`n    - System Family: $($computerSystemInformation.SystemFamily)"
    $hinv += "`n    - System SKU Number: $($computerSystemInformation.SystemSKUNumber)"
    $hinv += "`n    - Hypervisor Present? $($computerSystemInformation.HypervisorPresent)"

    $hinv += "`n`n-- Processor:`n"

    # Processor information reported, for each processor:
    # - Device ID
    #     - Name
    #     - Manufacturer
    #     - Caption
    #    - Number of Cores (of which Number of Enabled Cores)
    #     - Number of Total Logical processors
    $processorInformation | Foreach-Object {
        $hinv += "`nFor device ID $($_.DeviceID):"
        $hinv += "`n    - Name: $($_.Name)"
        $hinv += "`n    - Manufacturer: $($_.Manufacturer)"
        $hinv += "`n    - Caption: $($_.Caption)"
        $hinv += "`n    - Number of Cores: $($_.NumberOfCores), of which $($_.NumberOfEnabledCore) are enabled"
        $hinv += "`n    - Number of Total Logical Processors: $($_.NumberOfLogicalProcessors)"
    }

    $hinv += "`n`n-- Memory information:`n"

    # Memory information reported, for each module:
    # - Module number
    #     - Bank Label
    #     - Tag
    #     - Manufacturer -- this is the reference provided by manufacturer. For example, HMCG88AGBSA092N returns a SK Hynix module
    #     - Part Number
    #     - Clock Speed
    $moduleNumber = 0
    $memoryInformation | Foreach-Object {
        $hinv += "`nModule number $($moduleNumber):"
        $hinv += "`n    - Bank Label: $($_.BankLabel)"
        $hinv += "`n    - Tag: $($_.Tag)"
        $hinv += "`n    - Manufacturer: $($_.Manufacturer)"
        $hinv += "`n    - Part Number: $($_.PartNumber)"
        $hinv += "`n    - Clock Speed: $($_.Speed) MT/s"
        $moduleNumber++
    }

    $hinv += "`n`n-- Available Volumes as of reporting tool run time:`n"

    # Disk Volume information reported, for each volume:
    # - Drive UniqueID
    #     - Drive Letter
    #     - Drive Label
    #     - Drive Type
    #     - File System type
    #     - Health Status
    #     - Total Size
    #     - Remaining Size (Size Percentage)
    $volumeInformation | Foreach-Object {
        $hinv += "`nFor volume with UniqueID $($_.UniqueId):"
        $hinv += "`n    - Drive Letter: $($_.DriveLetter)"
        $hinv += "`n    - Drive Label: $($_.FriendlyName)"
        $hinv += "`n    - Drive Type: $($_.DriveType)"
        $hinv += "`n    - File System: $($_.FileSystemType)"
        $hinv += "`n    - Health: $($_.HealthStatus)"
        $hinv += "`n    - Size: $([Math]::Round($_.Size / 1GB, 2)) GB"
        $hinv += "`n    - Size Remaining: $([Math]::Round($_.SizeRemaining / 1GB, 2)) GB. Percentage: $([Math]::Round((($_.SizeRemaining / $_.Size) * 100), 2))%"
    }

    $hinv += "`n`n-- BIOS information:`n"

    # BIOS information:
    # - Manufacturer
    # - Name
    # - Caption
    # - BIOS version
    # - Serial Number
    $hinv += "`n    - Manufacturer: $($biosInformation.Manufacturer)"
    $hinv += "`n    - Name: $($biosInformation.Name)"
    $hinv += "`n    - Caption: $($biosInformation.Caption)"
    $hinv += "`n    - Version: $($biosInformation.SMBIOSBIOSVersion)"
    $hinv += "`n    - Serial Number: $($biosInformation.SerialNumber)"

    $sinv = "---- SOFTWARE INVENTORY:`n"

    $computerInformation = Get-ComputerInfo

    $sinv += "`n$($computerInformation.OsName). Version: $($computerInformation.OsVersion). Version Display Name: $($computerInformation.OSDisplayVersion). Build String: $($computerInformation.WindowsBuildLabEx)"
    $sinv += "`nBuild Type: $($computerInformation.OsBuildType)"
    $sinv += "`nEdition ID: $($computerInformation.WindowsEditionId)"
    $sinv += "`nInstalled Hotfixes:"

    $computerInformation.OsHotFixes | Foreach-Object {
        $sinv += "`n    - $($_.HotFixID): $($_.Description). Installed on $($_.InstalledOn)"
    }

    $sinv += "`nEnvironment Variables:"
    Get-ChildItem "ENV:" | ForEach-Object {
        $sinv += "`n    - $($_.Name): $($_.Value)"
    }

    $inv = "$($hinv)`n`n$($sinv)"

    return $inv
}

function Get-ImageInventory {
    $imageInv = "---- IMAGE INFORMATION:`n"
    Write-Host "Getting operating system packages..."

    $imageInv += "`n-- Operating System Packages:`n"

    try {
        $packageInformation = Get-WindowsPackage -Online
        $imageInv += "`nPackage Count: $($packageInformation.Count)`n"
        $packageInformation | ForEach-Object {
            $imageInv += "`n- Package $($_.PackageName):"
            $imageInv += "`n    - State: $($_.PackageState)"
            $imageInv += "`n    - Release Type: $($_.ReleaseType)"
            $imageInv += "`n    - Installation Time: $($_.InstallTime)"
        }
    } catch {
        $imageInv += "`nCould not get package information."
    }

    Write-Host "Getting operating system features..."

    $imageInv += "`n`n-- Operating System Features:`n"

    try {
        $featureInformation = Get-WindowsOptionalFeature -Online
        $imageInv += "`nFeature Count: $($featureInformation.Count)`n"
        $featureInformation | ForEach-Object {
            $imageInv += "`n- Feature $($_.FeatureName):"
            $imageInv += "`n    - State: $($_.State)"
        }
    } catch {
        $imageInv += "`nCould not get feature information."
    }

    Write-Host "Getting operating system AppX packages for all users..."

    $imageInv += "`n`n-- Operating System AppX packages:`n"

    try {
        $appxPackageInformation = Get-AppxPackage -AllUsers
        $imageInv += "`nAppX Package Count: $($appxPackageInformation.Count)`n"
        $appxPackageInformation | ForEach-Object {
            $imageInv += "`n- Package $($_.PackageFullName):"
            $imageInv += "`n    - Name: $($_.Name)"
            $imageInv += "`n    - Publisher: $($_.Publisher)"
            $imageInv += "`n    - Architecture: $($_.Architecture)"
            $imageInv += "`n    - Resource ID: $($_.ResourceId)"
            $imageInv += "`n    - Version: $($_.Version)"
            $imageInv += "`n    - Installation Location: $($_.InstallLocation)"
            $imageInv += "`n    - Is a framework? $($_.IsFramework)"
            $imageInv += "`n    - Package Family Name: $($_.PackageFamilyName)"
            $imageInv += "`n    - Publisher ID: $($_.PublisherId)"
            $imageInv += "`n    - User Information: $($_.PackageUserInformation | Foreach-Object {
    @(
        "`n        - For SID: $($_.UserSecurityId.Sid):"
        "`n            - Name: $($_.UserSecurityId.Username.Replace("$env:USERNAME", "Your user"))"
        "`n            - State: $($_.InstallState)"
    )
})"
            $imageInv += "`n    - Is a resource package?: $($_.IsResourcePackage)"
            $imageInv += "`n    - Is a bundle? $($_.IsBundle)"
            $imageInv += "`n    - Is in development mode? $($_.IsDevelopmentMode)"
            $imageInv += "`n    - Is non removable? $($_.NonRemovable)"
            $imageInv += "`n    - Dependencies: $($_.Dependencies | Foreach-Object {
                @(
                    "`n        - $($_.PackageFullName)"
                )
})"
            $imageInv += "`n    - Is partially staged? $($_.IsPartiallyStaged)"
            $imageInv += "`n    - Signature kind: $($_.SignatureKind)"
            $imageInv += "`n    - Status: $($_.Status)"
        }
    } catch {
        $imageInv += "`nCould not get AppX package information."
    }

    Write-Host "Getting operating system capabilities..."

    $imageInv += "`n`n-- Operating System Capabilities:`n"

    try {
        $capabilityInformation = Get-WindowsCapability -Online
        $imageInv += "`nCapability Count: $($capabilityInformation.Count)`n"
        $capabilityInformation | ForEach-Object {
            $imageInv += "`n- Capability $($_.Name):"
            $imageInv += "`n    - State: $($_.State)"
        }
    } catch {
        $imageInv += "`nCould not get capability information."
    }

    Write-Host "Getting operating system drivers (1st and 3rd party)..."

    $imageInv += "`n`n-- Operating System Drivers:`n"

    try {
        $driverInformation = Get-WindowsDriver -All -Online
        $imageInv += "`nDriver Count: $($driverInformation.Count)`n"
        $driverInformation | ForEach-Object {
            $imageInv += "`n- Driver $($_.Driver):"
            $imageInv += "`n    - Original File Name: $($_.OriginalFileName)"
            $imageInv += "`n    - Is Inbox Driver? $($_.Inbox)"
            $imageInv += "`n    - Class Name: $($_.ClassName)"
            $imageInv += "`n    - Is critical to the boot process? $($_.BootCritical)"
            $imageInv += "`n    - Provider Name: $($_.ProviderName)"
            $imageInv += "`n    - Date: $($_.Date)"
            $imageInv += "`n    - Version: $($_.Version)"
        }
    } catch {
        $imageInv += "`nCould not get driver information."
    }

    return $imageInv
}

function Compress-Report {
    param (
        [Parameter(Mandatory = $true, Position = 0)] [string]$itemToCompress,
        [Parameter(Mandatory = $true, Position = 1)] [string]$destinationZip
    )

    try {
        Compress-Archive -Path "$itemToCompress" -DestinationPath "$destinationZip" -Force
    } catch {
        Write-Host "ZIP file could not be created..."
    }
}

Clear-Host
Write-Host "Saving system information to a report file. The report file will be saved to your desktop. This will take some time..."

$SysInvReportToolPath = "$env:USERPROFILE\Desktop\SysInvFiles"

New-Item -ItemType Directory -Path "$SysInvReportToolPath" -Force | Out-Null
Get-ComputerInventory | Out-File -Force -Encoding UTF8 -FilePath "$SysInvReportToolPath\computerReport.txt"
Get-ImageInventory | Out-File -Force -Encoding UTF8 -FilePath "$SysInvReportToolPath\imageReport.txt"

Write-Host "Preparing report ZIP file..."
Compress-Report -itemToCompress "$SysInvReportToolPath" -destinationZip "$SysInvReportToolPath\..\SysInv_$((Get-Date).ToString('yyMMdd-HHmm')).zip"
Remove-Item -Path "$SysInvReportToolPath" -Recurse
