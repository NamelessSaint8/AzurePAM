<#
.SYNOPSIS
    EntraChecks-Devices.psm1
    Optional module for device security and Intune compliance checks

.DESCRIPTION
    This module extends Invoke-EntraChecks.ps1 with device-focused security checks.
    Covers device inventory, compliance status, BitLocker, and device-related policies.

    Checks included:
    - Test-DeviceOverview: Inventory of registered/joined devices
    - Test-StaleDevices: Devices not seen in configurable days
    - Test-DeviceComplianceStatus: Intune compliance state
    - Test-DeviceCompliancePolicies: Compliance policy coverage
    - Check-BitLockerPolicy: BitLocker policy and encryption status
    - Test-DeviceRegistrationPolicy: Device registration settings
    - Test-ConditionalAccessDeviceControls: CA policies requiring device compliance
    
.NOTES
    Version: 1.0.0
    Author: NamelessSaint
    Requires: Microsoft.Graph PowerShell SDK
    
    License Requirements:
    - Basic device info: Azure AD Free
    - Device compliance: Microsoft Intune
    - BitLocker policy: Intune
    
    Required Graph Permissions:
    - Device.Read.All
    - DeviceManagementManagedDevices.Read.All
    - DeviceManagementConfiguration.Read.All
    - Policy.Read.All
    
    Note: This module checks BitLocker POLICY configuration and device 
    encryption STATUS. It does NOT read actual BitLocker recovery keys.
    
.LINK
    Main Script: Invoke-EntraChecks.ps1
    Graph API Reference: https://learn.microsoft.com/en-us/graph/api/resources/device
#>

#Requires -Version 5.1

# Module version
$script:ModuleVersion = "1.0.0"
$script:ModuleName = "EntraChecks-Devices"

# Default thresholds (can be overridden by config)
$script:StaleDeviceThresholdDays = 90
$script:CriticalStaleDeviceThresholdDays = 180

#region ==================== MODULE INITIALIZATION ====================

<#
.SYNOPSIS
    Initializes the Devices module.

.DESCRIPTION
    Checks prerequisites and registers module checks with the main script.
    Called automatically when module is imported.
#>
function Initialize-DevicesModule {
    [OutputType([hashtable])]
    [CmdletBinding()]
    param()
    
    Write-Host "`n[+] Loading module: $script:ModuleName v$script:ModuleVersion" -ForegroundColor Magenta
    
    # Verify main script context
    if (-not (Get-Variable -Name "Findings" -Scope Script -ErrorAction SilentlyContinue)) {
        $script:Findings = @()
        Write-Host "    [!] Running in standalone mode (no main script context)" -ForegroundColor Yellow
    }
    
    # Load thresholds from config if available
    if (Get-Variable -Name "Config" -Scope Script -ErrorAction SilentlyContinue) {
        if ($script:Config.Modules.Devices.StaleDeviceThresholdDays) {
            $script:StaleDeviceThresholdDays = $script:Config.Modules.Devices.StaleDeviceThresholdDays
        }
        if ($script:Config.Modules.Devices.CriticalStaleDeviceThresholdDays) {
            $script:CriticalStaleDeviceThresholdDays = $script:Config.Modules.Devices.CriticalStaleDeviceThresholdDays
        }
    }
    
    Write-Host "    [OK] Module loaded successfully" -ForegroundColor Green
    Write-Host "    [i] Stale device threshold: $script:StaleDeviceThresholdDays days (critical: $script:CriticalStaleDeviceThresholdDays days)" -ForegroundColor Gray
    
    # Return module info
    return @{
        Name = $script:ModuleName
        Version = $script:ModuleVersion
        Checks = @(
            "Test-DeviceOverview",
            "Test-StaleDevices",
            "Test-DeviceComplianceStatus",
            "Test-DeviceCompliancePolicies",
            "Test-BitLockerRecoveryKeys",
            "Test-DeviceRegistrationPolicy",
            "Test-ConditionalAccessDeviceControls"
        )
        RequiredLicense = "Azure AD Free (basic), Intune (compliance)"
        RequiredPermissions = @(
            "Device.Read.All",
            "DeviceManagementManagedDevices.Read.All",
            "DeviceManagementConfiguration.Read.All",
            "Policy.Read.All"
        )
    }
}

#endregion

#region ==================== HELPER FUNCTIONS ====================

<#
.SYNOPSIS
    Adds a finding to the findings collection.
#>
function Add-ModuleFinding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet("OK", "INFO", "WARNING", "FAIL")]
        [string]$Status,
        
        [Parameter(Mandatory)]
        [string]$Object,
        
        [Parameter(Mandatory)]
        [string]$Description,
        
        [string]$Remediation = ""
    )
    
    if (Get-Command -Name "Add-Finding" -ErrorAction SilentlyContinue) {
        Add-Finding -Status $Status -Object $Object -Description $Description -Remediation $Remediation
    }
    else {
        $finding = [PSCustomObject]@{
            Time = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
            Status = $Status
            Object = $Object
            Description = $Description
            Remediation = $Remediation
            Module = $script:ModuleName
        }
        
        $script:Findings += $finding
        
        $color = switch ($Status) {
            "OK" { "Green" }
            "INFO" { "Cyan" }
            "WARNING" { "Yellow" }
            "FAIL" { "Red" }
        }
        Write-Host "[$Status] $Object" -ForegroundColor $color
    }
}

<#
.SYNOPSIS
    Invokes a Graph API request.
#>
function Invoke-ModuleGraphRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Uri,
        
        [switch]$AllPages
    )
    
    if (Get-Command -Name "Invoke-GraphRequest" -ErrorAction SilentlyContinue) {
        if ($AllPages) {
            return Invoke-GraphRequest -Uri $Uri -AllPages
        }
        else {
            return Invoke-GraphRequest -Uri $Uri
        }
    }
    else {
        try {
            $results = @()
            $response = Invoke-MgGraphRequest -Uri $Uri -Method GET
            
            if ($response.value) {
                $results += $response.value
                
                if ($AllPages) {
                    while ($response.'@odata.nextLink') {
                        $response = Invoke-MgGraphRequest -Uri $response.'@odata.nextLink' -Method GET
                        if ($response.value) {
                            $results += $response.value
                        }
                    }
                }
                
                return $results
            }
            else {
                return $response
            }
        }
        catch {
            Write-Host "[!] Graph API Error: $($_.Exception.Message)" -ForegroundColor Red
            return $null
        }
    }
}

#endregion

#region ==================== DEVICE CHECKS ====================

<#
.SYNOPSIS
    Test-DeviceOverview - Provides inventory of all registered and joined devices.

.DESCRIPTION
    Examines the device landscape in Azure AD:
    - Total device count
    - Device join types (Azure AD Joined, Hybrid, Registered)
    - Operating system distribution
    - Managed vs unmanaged devices
    - Device trust types
    
    Graph Endpoints Used:
    - GET /devices
    - GET /deviceManagement/managedDevices (if Intune available)
    
.OUTPUTS
    Informational findings about device inventory
    
.NOTES
    Required Permissions: Device.Read.All
    Minimum License: Azure AD Free
    
.LINK
    Graph Reference: https://learn.microsoft.com/en-us/graph/api/device-list
#>
function Test-DeviceOverview {
    [CmdletBinding()]
    param()
    
    Write-Host "`n[+] Gathering device overview..." -ForegroundColor Cyan
    
    try {
        # Get all Azure AD devices
        $devices = Invoke-ModuleGraphRequest -Uri "https://graph.microsoft.com/v1.0/devices?`$select=id,displayName,operatingSystem,operatingSystemVersion,trustType,isManaged,isCompliant,registrationDateTime,approximateLastSignInDateTime,deviceId" -AllPages
        
        if (-not $devices -or $devices.Count -eq 0) {
            Add-ModuleFinding -Status "INFO" `
                -Object "Device Overview" `
                -Description "No devices found in Azure AD. This may indicate a cloud-only environment without device registration." `
                -Remediation "Consider enabling device registration to improve security posture with device-based Conditional Access."
            return
        }
        
        # Categorize by trust type
        $azureADJoined = $devices | Where-Object { $_.trustType -eq "AzureAd" }
        $hybridJoined = $devices | Where-Object { $_.trustType -eq "ServerAd" }
        $registered = $devices | Where-Object { $_.trustType -eq "Workplace" }
        
        # Categorize by OS
        $windows = $devices | Where-Object { $_.operatingSystem -match "Windows" }
        $ios = $devices | Where-Object { $_.operatingSystem -match "iOS|iPhone|iPad" }
        $android = $devices | Where-Object { $_.operatingSystem -match "Android" }
        $macos = $devices | Where-Object { $_.operatingSystem -match "macOS|Mac OS" }
        $linux = $devices | Where-Object { $_.operatingSystem -match "Linux" }
        $other = $devices | Where-Object { 
            $_.operatingSystem -notmatch "Windows|iOS|iPhone|iPad|Android|macOS|Mac OS|Linux" 
        }
        
        # Check managed status
        $managed = $devices | Where-Object { $_.isManaged -eq $true }
        $compliant = $devices | Where-Object { $_.isCompliant -eq $true }
        
        # Summary finding
        Add-ModuleFinding -Status "INFO" `
            -Object "Device Overview" `
            -Description "Total devices: $($devices.Count). Azure AD Joined: $($azureADJoined.Count). Hybrid Joined: $($hybridJoined.Count). Registered: $($registered.Count). Managed: $($managed.Count). Compliant: $($compliant.Count)." `
            -Remediation "Review device distribution. Aim to have all corporate devices managed and compliant."
        
        # OS distribution
        $osDistribution = "Windows: $($windows.Count), iOS: $($ios.Count), Android: $($android.Count), macOS: $($macos.Count), Linux: $($linux.Count)"
        if ($other.Count -gt 0) { $osDistribution += ", Other: $($other.Count)" }
        
        Add-ModuleFinding -Status "INFO" `
            -Object "OS Distribution" `
            -Description $osDistribution `
            -Remediation "Ensure compliance policies exist for each operating system in use."
        
        # Check for unmanaged devices
        $unmanaged = $devices | Where-Object { $_.isManaged -ne $true }
        $unmanagedPercent = if ($devices.Count -gt 0) { [math]::Round(($unmanaged.Count / $devices.Count) * 100, 0) } else { 0 }
        
        if ($unmanaged.Count -gt 0 -and $unmanagedPercent -gt 20) {
            Add-ModuleFinding -Status "WARNING" `
                -Object "Unmanaged Devices" `
                -Description "$($unmanaged.Count) devices ($unmanagedPercent%) are not managed by Intune or another MDM. Unmanaged devices cannot be evaluated for compliance." `
                -Remediation "Enroll devices in Intune to enable compliance evaluation. Consider blocking unmanaged device access to corporate resources."
        }
        elseif ($unmanaged.Count -gt 0) {
            Add-ModuleFinding -Status "INFO" `
                -Object "Unmanaged Devices" `
                -Description "$($unmanaged.Count) devices ($unmanagedPercent%) are not managed. This may include BYOD devices." `
                -Remediation "Review if unmanaged devices should be enrolled or restricted from corporate resource access."
        }
        
        # Check for non-compliant devices
        $nonCompliant = $devices | Where-Object { $_.isCompliant -eq $false }
        
        if ($nonCompliant.Count -gt 0) {
            Add-ModuleFinding -Status "REVIEW" `
                -Object "Non-Compliant Devices" `
                -Description "$($nonCompliant.Count) devices are marked as non-compliant. These devices may not meet security requirements." `
                -Remediation "Review non-compliant devices in Intune. Identify compliance failures and remediate or block access."
        }
        
        # Try to get Intune managed devices for more detail
        try {
            $intuneDevices = Invoke-ModuleGraphRequest -Uri "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?`$select=id,deviceName,managementAgent,ownerType&`$top=999" -AllPages
            
            if ($intuneDevices -and $intuneDevices.Count -gt 0) {
                # Count by ownership
                $corporate = $intuneDevices | Where-Object { $_.ownerType -eq "company" }
                $personal = $intuneDevices | Where-Object { $_.ownerType -eq "personal" }
                
                Add-ModuleFinding -Status "INFO" `
                    -Object "Intune Device Ownership" `
                    -Description "Intune managed: $($intuneDevices.Count). Corporate-owned: $($corporate.Count). Personal (BYOD): $($personal.Count)." `
                    -Remediation "Ensure different policies apply to corporate vs personal devices as appropriate."
                
                # Check management agents
                $configManager = $intuneDevices | Where-Object { $_.managementAgent -eq "configurationManagerClientMdm" }
                
                if ($configManager.Count -gt 0) {
                    Add-ModuleFinding -Status "INFO" `
                        -Object "Co-Managed Devices" `
                        -Description "$($configManager.Count) devices are co-managed with Configuration Manager and Intune." `
                        -Remediation "Verify co-management workloads are configured appropriately."
                }
            }
        }
        catch {
            Add-ModuleFinding -Status "INFO" `
                -Object "Intune Integration" `
                -Description "Unable to retrieve Intune device details. Intune may not be licensed or permissions are missing." `
                -Remediation "For full device compliance visibility, ensure Intune is licensed and DeviceManagementManagedDevices.Read.All permission is granted."
        }
    }
    catch {
        Add-ModuleFinding -Status "WARNING" `
            -Object "Device Overview" `
            -Description "Unable to retrieve device inventory: $($_.Exception.Message)" `
            -Remediation "Check Graph permissions (Device.Read.All required)."
    }
}

<#
.SYNOPSIS
    Test-StaleDevices - Identifies devices that haven't signed in recently.

.DESCRIPTION
    Examines device sign-in activity to find stale devices:
    - Devices not seen in 90+ days (WARNING - configurable)
    - Devices not seen in 180+ days (FAIL - configurable)
    - Devices that have never signed in
    - Recommendations for cleanup
    
    Graph Endpoints Used:
    - GET /devices (with approximateLastSignInDateTime)
    
.OUTPUTS
    Findings based on device staleness
    
.NOTES
    Required Permissions: Device.Read.All
    Minimum License: Azure AD Free
    
.LINK
    Graph Reference: https://learn.microsoft.com/en-us/graph/api/device-list
#>
function Test-StaleDevices {
    [CmdletBinding()]
    param()
    
    Write-Host "`n[+] Checking for stale devices..." -ForegroundColor Cyan
    
    try {
        # Get all devices with last sign-in info
        $devices = Invoke-ModuleGraphRequest -Uri "https://graph.microsoft.com/v1.0/devices?`$select=id,displayName,operatingSystem,trustType,approximateLastSignInDateTime,registrationDateTime" -AllPages
        
        if (-not $devices -or $devices.Count -eq 0) {
            Add-ModuleFinding -Status "OK" `
                -Object "Stale Devices" `
                -Description "No devices found to evaluate for staleness." `
                -Remediation "N/A"
            return
        }
        
        $now = Get-Date
        $warningThreshold = $now.AddDays(-$script:StaleDeviceThresholdDays)
        $criticalThreshold = $now.AddDays(-$script:CriticalStaleDeviceThresholdDays)
        
        # Categorize devices
        $neverSignedIn = @()
        $criticalStale = @()
        $stale = @()
        $active = @()
        
        foreach ($device in $devices) {
            if (-not $device.approximateLastSignInDateTime) {
                $neverSignedIn += $device
            }
            else {
                $lastSignIn = [DateTime]$device.approximateLastSignInDateTime
                
                if ($lastSignIn -lt $criticalThreshold) {
                    $criticalStale += $device
                }
                elseif ($lastSignIn -lt $warningThreshold) {
                    $stale += $device
                }
                else {
                    $active += $device
                }
            }
        }
        
        # Summary
        Add-ModuleFinding -Status "INFO" `
            -Object "Device Activity Summary" `
            -Description "Total: $($devices.Count). Active (<$($script:StaleDeviceThresholdDays)d): $($active.Count). Stale ($($script:StaleDeviceThresholdDays)-$($script:CriticalStaleDeviceThresholdDays)d): $($stale.Count). Critical (>$($script:CriticalStaleDeviceThresholdDays)d): $($criticalStale.Count). Never signed in: $($neverSignedIn.Count)." `
            -Remediation "Regularly review and remove stale devices to maintain accurate inventory."
        
        # Critical stale devices (>180 days)
        if ($criticalStale.Count -gt 0) {
            $criticalByOS = $criticalStale | Group-Object -Property operatingSystem | Sort-Object Count -Descending
            $osSummary = ($criticalByOS | ForEach-Object { "$($_.Name): $($_.Count)" }) -join ", "
            
            Add-ModuleFinding -Status "FAIL" `
                -Object "Critical Stale Devices (>$($script:CriticalStaleDeviceThresholdDays) days)" `
                -Description "$($criticalStale.Count) devices haven't signed in for over $script:CriticalStaleDeviceThresholdDays days. By OS: $osSummary. These devices are likely decommissioned or lost." `
                -Remediation "RECOMMENDED: Review and delete these devices from Azure AD. Stale devices increase attack surface and may indicate lost/stolen devices with valid credentials."
            
            # List up to 10 oldest
            $oldest = $criticalStale | Sort-Object approximateLastSignInDateTime | Select-Object -First 10
            foreach ($device in $oldest) {
                $lastSeen = ([DateTime]$device.approximateLastSignInDateTime).ToString("yyyy-MM-dd")
                $daysSince = [math]::Round(($now - [DateTime]$device.approximateLastSignInDateTime).TotalDays, 0)
                
                Add-ModuleFinding -Status "FAIL" `
                    -Object $device.displayName `
                    -Description "Device last seen $lastSeen ($daysSince days ago). OS: $($device.operatingSystem). Type: $($device.trustType)." `
                    -Remediation "Investigate and remove if no longer in use. If device is lost/stolen, also revoke any associated credentials."
            }
            
            if ($criticalStale.Count -gt 10) {
                Add-ModuleFinding -Status "INFO" `
                    -Object "Additional Critical Stale Devices" `
                    -Description "$($criticalStale.Count - 10) more devices are critically stale. Export full device list for review." `
                    -Remediation "Use Azure Portal or Graph API to export complete device list for cleanup project."
            }
        }
        
        # Stale devices (90-180 days)
        if ($stale.Count -gt 0) {
            $staleByOS = $stale | Group-Object -Property operatingSystem | Sort-Object Count -Descending
            $osSummary = ($staleByOS | ForEach-Object { "$($_.Name): $($_.Count)" }) -join ", "
            
            Add-ModuleFinding -Status "REVIEW" `
                -Object "Stale Devices ($($script:StaleDeviceThresholdDays)-$($script:CriticalStaleDeviceThresholdDays) days)" `
                -Description "$($stale.Count) devices haven't signed in for $script:StaleDeviceThresholdDays-$script:CriticalStaleDeviceThresholdDays days. By OS: $osSummary." `
                -Remediation "Review these devices. They may be seasonal users, on leave, or decommissioned. Plan for cleanup if not reactivated."
        }
        
        # Never signed in devices
        if ($neverSignedIn.Count -gt 0) {
            $oldNeverSignedIn = $neverSignedIn | Where-Object { 
                $_.registrationDateTime -and 
                ([DateTime]$_.registrationDateTime) -lt $warningThreshold 
            }
            
            if ($oldNeverSignedIn.Count -gt 0) {
                Add-ModuleFinding -Status "REVIEW" `
                    -Object "Never Signed In Devices" `
                    -Description "$($oldNeverSignedIn.Count) devices were registered over $script:StaleDeviceThresholdDays days ago but have never signed in." `
                    -Remediation "These may be test devices, failed enrollments, or abandoned registrations. Review and remove if not needed."
            }
            
            $newNeverSignedIn = $neverSignedIn | Where-Object {
                -not $_.registrationDateTime -or
                ([DateTime]$_.registrationDateTime) -ge $warningThreshold
            }
            
            if ($newNeverSignedIn.Count -gt 0) {
                Add-ModuleFinding -Status "INFO" `
                    -Object "Recently Registered - No Sign In" `
                    -Description "$($newNeverSignedIn.Count) devices were recently registered but haven't signed in yet. This may be normal for new enrollments." `
                    -Remediation "Monitor these devices. If they don't sign in within 30 days, investigate."
            }
        }
        
        # All devices active
        if ($criticalStale.Count -eq 0 -and $stale.Count -eq 0 -and $neverSignedIn.Count -eq 0) {
            Add-ModuleFinding -Status "OK" `
                -Object "Device Activity" `
                -Description "All $($devices.Count) devices have been active within the last $script:StaleDeviceThresholdDays days." `
                -Remediation "Continue monitoring. Consider implementing automated stale device cleanup."
        }
    }
    catch {
        Add-ModuleFinding -Status "WARNING" `
            -Object "Stale Devices" `
            -Description "Unable to check for stale devices: $($_.Exception.Message)" `
            -Remediation "Check Graph permissions (Device.Read.All required)."
    }
}

<#
.SYNOPSIS
    Test-DeviceComplianceStatus - Audits Intune device compliance state.

.DESCRIPTION
    Examines the compliance status of Intune-managed devices:
    - Compliant devices
    - Non-compliant devices (with reasons)
    - Devices in grace period
    - Devices not evaluated
    - Compliance trends
    
    Graph Endpoints Used:
    - GET /deviceManagement/managedDevices
    
.OUTPUTS
    Findings based on compliance status
    
.NOTES
    Required Permissions: DeviceManagementManagedDevices.Read.All
    Minimum License: Microsoft Intune
    
.LINK
    Graph Reference: https://learn.microsoft.com/en-us/graph/api/intune-devices-manageddevice-list
#>
function Test-DeviceComplianceStatus {
    [CmdletBinding()]
    param()
    
    Write-Host "`n[+] Checking device compliance status..." -ForegroundColor Cyan
    
    try {
        # Get managed devices with compliance info
        $managedDevices = Invoke-ModuleGraphRequest -Uri "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?`$select=id,deviceName,complianceState,complianceGracePeriodExpirationDateTime,lastSyncDateTime,operatingSystem,ownerType,userPrincipalName,managementAgent" -AllPages
        
        if (-not $managedDevices -or $managedDevices.Count -eq 0) {
            Add-ModuleFinding -Status "INFO" `
                -Object "Device Compliance" `
                -Description "No Intune-managed devices found. Device compliance requires Intune enrollment." `
                -Remediation "Enroll devices in Intune to enable compliance evaluation and enforcement."
            return
        }
        
        # Categorize by compliance state
        $compliant = $managedDevices | Where-Object { $_.complianceState -eq "compliant" }
        $nonCompliant = $managedDevices | Where-Object { $_.complianceState -eq "noncompliant" }
        $inGracePeriod = $managedDevices | Where-Object { $_.complianceState -eq "inGracePeriod" }
        $unknown = $managedDevices | Where-Object { $_.complianceState -in @("unknown", "notEvaluated") }
        $conflict = $managedDevices | Where-Object { $_.complianceState -eq "conflict" }
        
        # Calculate compliance rate
        $complianceRate = if ($managedDevices.Count -gt 0) { 
            [math]::Round(($compliant.Count / $managedDevices.Count) * 100, 1) 
        } else { 0 }
        
        # Summary finding with appropriate status
        $summaryStatus = if ($complianceRate -ge 95) { "OK" }
        elseif ($complianceRate -ge 80) { "WARNING" }
        else { "FAIL" }
        
        Add-ModuleFinding -Status $summaryStatus `
            -Object "Device Compliance Summary" `
            -Description "Compliance rate: $complianceRate%. Total managed: $($managedDevices.Count). Compliant: $($compliant.Count). Non-compliant: $($nonCompliant.Count). In grace period: $($inGracePeriod.Count). Unknown/Not evaluated: $($unknown.Count)." `
            -Remediation $(if ($complianceRate -lt 95) { "Investigate non-compliant devices and remediate compliance failures. Target 95%+ compliance." } else { "Maintain current compliance posture." })
        
        # Non-compliant devices - FAIL
        if ($nonCompliant.Count -gt 0) {
            $nonCompliantByOS = $nonCompliant | Group-Object -Property operatingSystem | Sort-Object Count -Descending
            $osSummary = ($nonCompliantByOS | ForEach-Object { "$($_.Name): $($_.Count)" }) -join ", "
            
            Add-ModuleFinding -Status "FAIL" `
                -Object "Non-Compliant Devices" `
                -Description "$($nonCompliant.Count) devices are non-compliant. By OS: $osSummary. These devices may pose security risks." `
                -Remediation "Review non-compliant devices in Intune. Common issues: missing encryption, outdated OS, no passcode. Use Conditional Access to block non-compliant device access."
            
            # List up to 10 non-compliant devices
            $topNonCompliant = $nonCompliant | Select-Object -First 10
            foreach ($device in $topNonCompliant) {
                $lastSync = if ($device.lastSyncDateTime) { 
                    ([DateTime]$device.lastSyncDateTime).ToString("yyyy-MM-dd HH:mm") 
                } else { "Never" }
                
                Add-ModuleFinding -Status "FAIL" `
                    -Object "$($device.deviceName) ($($device.userPrincipalName))" `
                    -Description "Non-compliant device. OS: $($device.operatingSystem). Owner: $($device.ownerType). Last sync: $lastSync." `
                    -Remediation "Check device compliance details in Intune to identify specific compliance failures."
            }
            
            if ($nonCompliant.Count -gt 10) {
                Add-ModuleFinding -Status "INFO" `
                    -Object "Additional Non-Compliant Devices" `
                    -Description "$($nonCompliant.Count - 10) more devices are non-compliant. Review in Intune console." `
                    -Remediation "Export non-compliant device list from Intune for remediation tracking."
            }
        }
        
        # Devices in grace period - WARNING
        if ($inGracePeriod.Count -gt 0) {
            Add-ModuleFinding -Status "WARNING" `
                -Object "Devices in Grace Period" `
                -Description "$($inGracePeriod.Count) devices are in compliance grace period. These devices will become non-compliant when grace period expires." `
                -Remediation "Contact users to remediate compliance issues before grace period expires."
            
            # Check for soon-expiring grace periods
            $now = Get-Date
            $soonExpiring = $inGracePeriod | Where-Object {
                $_.complianceGracePeriodExpirationDateTime -and
                ([DateTime]$_.complianceGracePeriodExpirationDateTime) -lt $now.AddDays(7)
            }
            
            if ($soonExpiring.Count -gt 0) {
                Add-ModuleFinding -Status "WARNING" `
                    -Object "Grace Period Expiring Soon" `
                    -Description "$($soonExpiring.Count) devices have grace periods expiring within 7 days." `
                    -Remediation "Prioritize remediation for these devices to prevent access disruption."
            }
        }
        
        # Unknown/Not evaluated - INFO or WARNING
        if ($unknown.Count -gt 0) {
            $unknownPercent = [math]::Round(($unknown.Count / $managedDevices.Count) * 100, 0)
            $status = if ($unknownPercent -gt 10) { "WARNING" } else { "INFO" }
            
            Add-ModuleFinding -Status $status `
                -Object "Devices Not Evaluated" `
                -Description "$($unknown.Count) devices ($unknownPercent%) have unknown or not evaluated compliance status." `
                -Remediation "Check if compliance policies are assigned to these devices. Verify devices are syncing with Intune."
        }
        
        # Devices with conflicts
        if ($conflict.Count -gt 0) {
            Add-ModuleFinding -Status "REVIEW" `
                -Object "Compliance Policy Conflicts" `
                -Description "$($conflict.Count) devices have conflicting compliance policies." `
                -Remediation "Review policy assignments in Intune. Conflicting settings between policies can cause unexpected behavior."
        }
        
        # Check sync status
        $syncThreshold = (Get-Date).AddDays(-7)
        $notSynced = $managedDevices | Where-Object {
            -not $_.lastSyncDateTime -or
            ([DateTime]$_.lastSyncDateTime) -lt $syncThreshold
        }
        
        if ($notSynced.Count -gt 0) {
            Add-ModuleFinding -Status "REVIEW" `
                -Object "Devices Not Syncing" `
                -Description "$($notSynced.Count) devices haven't synced with Intune in over 7 days. Compliance status may be outdated." `
                -Remediation "Investigate why devices aren't syncing. May indicate network issues, device problems, or users avoiding compliance."
        }
    }
    catch {
        if ($_.Exception.Message -match "Forbidden|Authorization") {
            Add-ModuleFinding -Status "INFO" `
                -Object "Device Compliance" `
                -Description "Unable to check device compliance. Intune may not be licensed or permissions are missing." `
                -Remediation "Ensure Intune is licensed and DeviceManagementManagedDevices.Read.All permission is granted."
        }
        else {
            Add-ModuleFinding -Status "WARNING" `
                -Object "Device Compliance" `
                -Description "Unable to check device compliance: $($_.Exception.Message)" `
                -Remediation "Check Intune licensing and Graph permissions."
        }
    }
}

<#
.SYNOPSIS
    Test-DeviceCompliancePolicies - Audits compliance policy configuration and coverage.

.DESCRIPTION
    Examines Intune compliance policies:
    - Policies exist for each OS platform
    - Policy assignments (all users vs specific groups)
    - Key security settings (encryption, PIN, etc.)
    - Policy conflicts
    
    Graph Endpoints Used:
    - GET /deviceManagement/deviceCompliancePolicies
    - GET /deviceManagement/deviceCompliancePolicies/{id}/assignments
    
.OUTPUTS
    Findings based on policy configuration
    
.NOTES
    Required Permissions: DeviceManagementConfiguration.Read.All
    Minimum License: Microsoft Intune
    
.LINK
    Graph Reference: https://learn.microsoft.com/en-us/graph/api/intune-deviceconfig-devicecompliancepolicy-list
#>
function Test-DeviceCompliancePolicies {
    [CmdletBinding()]
    param()
    
    Write-Host "`n[+] Checking device compliance policies..." -ForegroundColor Cyan
    
    try {
        # Get all compliance policies
        $compliancePolicies = Invoke-ModuleGraphRequest -Uri "https://graph.microsoft.com/v1.0/deviceManagement/deviceCompliancePolicies" -AllPages
        
        if (-not $compliancePolicies -or $compliancePolicies.Count -eq 0) {
            Add-ModuleFinding -Status "FAIL" `
                -Object "Device Compliance Policies" `
                -Description "No device compliance policies configured. Without policies, all devices are considered compliant by default." `
                -Remediation "Create compliance policies for each device platform (Windows, iOS, Android, macOS). At minimum, require device encryption and a PIN/password."
            return
        }
        
        # Categorize by platform
        $windowsPolicies = $compliancePolicies | Where-Object { $_.'@odata.type' -match "windows" }
        $iosPolicies = $compliancePolicies | Where-Object { $_.'@odata.type' -match "ios" }
        $androidPolicies = $compliancePolicies | Where-Object { $_.'@odata.type' -match "android" }
        $macosPolicies = $compliancePolicies | Where-Object { $_.'@odata.type' -match "macOS" }
        
        # Summary
        Add-ModuleFinding -Status "INFO" `
            -Object "Compliance Policy Summary" `
            -Description "Total policies: $($compliancePolicies.Count). Windows: $($windowsPolicies.Count). iOS: $($iosPolicies.Count). Android: $($androidPolicies.Count). macOS: $($macosPolicies.Count)." `
            -Remediation "Ensure policies exist for all device platforms in use."
        
        # Check for missing platform coverage
        $missingPlatforms = @()
        if ($windowsPolicies.Count -eq 0) { $missingPlatforms += "Windows" }
        if ($iosPolicies.Count -eq 0) { $missingPlatforms += "iOS" }
        if ($androidPolicies.Count -eq 0) { $missingPlatforms += "Android" }
        if ($macosPolicies.Count -eq 0) { $missingPlatforms += "macOS" }
        
        if ($missingPlatforms.Count -gt 0) {
            Add-ModuleFinding -Status "WARNING" `
                -Object "Missing Platform Policies" `
                -Description "No compliance policies for: $($missingPlatforms -join ', '). Devices on these platforms won't be evaluated for compliance." `
                -Remediation "Create compliance policies for missing platforms, or ensure these platforms are blocked from accessing corporate resources."
        }
        
        # Analyze each policy
        foreach ($policy in $compliancePolicies) {
            $policyType = switch -Regex ($policy.'@odata.type') {
                "windows10" { "Windows 10/11" }
                "windows81" { "Windows 8.1" }
                "iosCompliancePolicy" { "iOS" }
                "androidCompliancePolicy" { "Android" }
                "androidWorkProfileCompliancePolicy" { "Android Work Profile" }
                "androidDeviceOwnerCompliancePolicy" { "Android Enterprise" }
                "macOSCompliancePolicy" { "macOS" }
                default { "Unknown" }
            }
            
            # Get assignments
            try {
                $assignments = Invoke-ModuleGraphRequest -Uri "https://graph.microsoft.com/v1.0/deviceManagement/deviceCompliancePolicies/$($policy.id)/assignments"
                
                $assignedToAll = $false
                $assignedGroups = @()
                
                if ($assignments) {
                    foreach ($assignment in $assignments) {
                        if ($assignment.target.'@odata.type' -eq "#microsoft.graph.allDevicesAssignmentTarget" -or
                            $assignment.target.'@odata.type' -eq "#microsoft.graph.allLicensedUsersAssignmentTarget") {
                            $assignedToAll = $true
                        }
                        elseif ($assignment.target.'@odata.type' -eq "#microsoft.graph.groupAssignmentTarget") {
                            $assignedGroups += $assignment.target.groupId
                        }
                    }
                }
                
                $assignmentSummary = if ($assignedToAll) { "All users/devices" }
                elseif ($assignedGroups.Count -gt 0) { "$($assignedGroups.Count) group(s)" }
                else { "Not assigned" }
                
                if (-not $assignedToAll -and $assignedGroups.Count -eq 0) {
                    Add-ModuleFinding -Status "WARNING" `
                        -Object "Policy: $($policy.displayName)" `
                        -Description "$policyType compliance policy is not assigned to any users or devices." `
                        -Remediation "Assign this policy to appropriate users/devices or delete if not needed."
                }
                else {
                    Add-ModuleFinding -Status "OK" `
                        -Object "Policy: $($policy.displayName)" `
                        -Description "$policyType compliance policy. Assigned to: $assignmentSummary." `
                        -Remediation "Review policy settings periodically to ensure they meet security requirements."
                }
            }
            catch {
                Add-ModuleFinding -Status "INFO" `
                    -Object "Policy: $($policy.displayName)" `
                    -Description "$policyType compliance policy. Unable to retrieve assignments." `
                    -Remediation "Verify policy assignments in Intune console."
            }
        }
    }
    catch {
        if ($_.Exception.Message -match "Forbidden|Authorization") {
            Add-ModuleFinding -Status "INFO" `
                -Object "Compliance Policies" `
                -Description "Unable to check compliance policies. Intune may not be licensed or permissions are missing." `
                -Remediation "Ensure Intune is licensed and DeviceManagementConfiguration.Read.All permission is granted."
        }
        else {
            Add-ModuleFinding -Status "WARNING" `
                -Object "Compliance Policies" `
                -Description "Unable to check compliance policies: $($_.Exception.Message)" `
                -Remediation "Check Intune licensing and Graph permissions."
        }
    }
}

<#
.SYNOPSIS
    Check-BitLockerPolicy - Audits BitLocker policy configuration and device encryption status.

.DESCRIPTION
    Examines BitLocker configuration WITHOUT reading actual recovery keys:
    - Intune device configuration policies for BitLocker/encryption
    - Windows device encryption status from Intune
    - Policy assignment coverage
    
    This check verifies that BitLocker policies are properly configured
    and that devices are reporting encrypted status. It does NOT read
    actual BitLocker recovery key values for security reasons.
    
    Graph Endpoints Used:
    - GET /deviceManagement/deviceConfigurations (for BitLocker policies)
    - GET /deviceManagement/managedDevices (for encryption status)
    
.OUTPUTS
    Findings based on BitLocker policy configuration and encryption status
    
.NOTES
    Required Permissions: DeviceManagementConfiguration.Read.All, DeviceManagementManagedDevices.Read.All
    Minimum License: Microsoft Intune
    
    Security Note: This check intentionally does NOT use BitLockerKey.Read.All
    to avoid accessing sensitive recovery key data.
    
.LINK
    Graph Reference: https://learn.microsoft.com/en-us/graph/api/intune-deviceconfig-deviceconfiguration-list
#>
function Test-BitLockerRecoveryKeys {
    [CmdletBinding()]
    param()
    
    Write-Host "`n[+] Checking BitLocker policy configuration..." -ForegroundColor Cyan
    
    try {
        $bitlockerPoliciesFound = $false
        $encryptionPoliciesFound = $false
        
        # Check for device configuration policies related to BitLocker/encryption
        try {
            $deviceConfigs = Invoke-ModuleGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations" -AllPages
            
            if ($deviceConfigs) {
                # Look for BitLocker/encryption related policies
                $bitlockerPolicies = $deviceConfigs | Where-Object {
                    $_.'@odata.type' -match "windows10EndpointProtectionConfiguration" -or
                    $_.'@odata.type' -match "windowsDeviceManagementApplicabilityRuleOsEdition" -or
                    $_.displayName -match "BitLocker|Encryption|Disk Protection" -or
                    $_.description -match "BitLocker|Encryption"
                }
                
                if ($bitlockerPolicies -and $bitlockerPolicies.Count -gt 0) {
                    $bitlockerPoliciesFound = $true
                    
                    Add-ModuleFinding -Status "OK" `
                        -Object "BitLocker Device Configuration Policies" `
                        -Description "Found $($bitlockerPolicies.Count) device configuration policy/policies related to BitLocker/encryption." `
                        -Remediation "Review policies to ensure they require BitLocker and escrow keys to Azure AD."
                    
                    foreach ($policy in $bitlockerPolicies | Select-Object -First 5) {
                        Add-ModuleFinding -Status "INFO" `
                            -Object $policy.displayName `
                            -Description "Endpoint protection/encryption policy. Type: $($_.'@odata.type' -replace '#microsoft.graph.', '')" `
                            -Remediation "Verify policy settings require encryption and key backup."
                    }
                }
            }
        }
        catch {
            Write-Verbose "Unable to check device configurations: $($_.Exception.Message)"
        }
        
        # Check for Endpoint Security disk encryption policies (Intune)
        try {
            $diskEncryptionPolicies = Invoke-ModuleGraphRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/intents?`$filter=templateId eq 'd1174162-1dd2-4976-affc-6667049ab0ae'" -AllPages
            
            if ($diskEncryptionPolicies -and $diskEncryptionPolicies.Count -gt 0) {
                $encryptionPoliciesFound = $true
                
                Add-ModuleFinding -Status "OK" `
                    -Object "Endpoint Security Disk Encryption Policies" `
                    -Description "Found $($diskEncryptionPolicies.Count) Endpoint Security disk encryption policy/policies." `
                    -Remediation "Review policies in Endpoint Security > Disk encryption."
            }
        }
        catch {
            Write-Verbose "Unable to check Endpoint Security policies: $($_.Exception.Message)"
        }
        
        # If no BitLocker policies found
        if (-not $bitlockerPoliciesFound -and -not $encryptionPoliciesFound) {
            Add-ModuleFinding -Status "WARNING" `
                -Object "BitLocker Policy Configuration" `
                -Description "No BitLocker or disk encryption policies found in Intune. Devices may not be encrypted." `
                -Remediation "Create an Endpoint Security > Disk encryption policy or Device Configuration profile to require BitLocker on Windows devices."
        }
        
        # Check managed Windows devices for encryption status
        try {
            $managedDevices = Invoke-ModuleGraphRequest -Uri "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?`$filter=operatingSystem eq 'Windows'&`$select=id,deviceName,isEncrypted,managementAgent,complianceState,lastSyncDateTime" -AllPages
            
            if ($managedDevices -and $managedDevices.Count -gt 0) {
                $encryptedDevices = $managedDevices | Where-Object { $_.isEncrypted -eq $true }
                $unencryptedDevices = $managedDevices | Where-Object { $_.isEncrypted -eq $false }
                $unknownEncryption = $managedDevices | Where-Object { $null -eq $_.isEncrypted }
                
                $encryptionRate = if ($managedDevices.Count -gt 0) {
                    [math]::Round(($encryptedDevices.Count / $managedDevices.Count) * 100, 1)
                } else { 0 }
                
                # Summary
                Add-ModuleFinding -Status "INFO" `
                    -Object "Windows Device Encryption Status" `
                    -Description "Managed Windows devices: $($managedDevices.Count). Encrypted: $($encryptedDevices.Count) ($encryptionRate%). Unencrypted: $($unencryptedDevices.Count). Unknown: $($unknownEncryption.Count)." `
                    -Remediation "Target 100% encryption for managed Windows devices."
                
                # Report on unencrypted devices
                if ($unencryptedDevices.Count -gt 0) {
                    # Filter to recently active devices
                    $recentThreshold = (Get-Date).AddDays(-30)
                    $activeUnencrypted = $unencryptedDevices | Where-Object {
                        $_.lastSyncDateTime -and
                        ([DateTime]$_.lastSyncDateTime) -gt $recentThreshold
                    }
                    
                    if ($activeUnencrypted.Count -gt 0) {
                        Add-ModuleFinding -Status "FAIL" `
                            -Object "Unencrypted Managed Devices" `
                            -Description "$($activeUnencrypted.Count) recently active Windows devices are reporting as NOT encrypted." `
                            -Remediation "Investigate why BitLocker is not enabled. Check for TPM issues, policy conflicts, or manual disablement."
                        
                        # List top unencrypted devices
                        $topUnencrypted = $activeUnencrypted | Select-Object -First 10
                        foreach ($device in $topUnencrypted) {
                            $lastSync = if ($device.lastSyncDateTime) {
                                ([DateTime]$device.lastSyncDateTime).ToString("yyyy-MM-dd")
                            } else { "Unknown" }
                            
                            Add-ModuleFinding -Status "FAIL" `
                                -Object $device.deviceName `
                                -Description "Windows device reporting NOT encrypted. Last sync: $lastSync. Compliance: $($device.complianceState)." `
                                -Remediation "Check device for BitLocker status, TPM availability, and policy application."
                        }
                        
                        if ($activeUnencrypted.Count -gt 10) {
                            Add-ModuleFinding -Status "INFO" `
                                -Object "Additional Unencrypted Devices" `
                                -Description "$($activeUnencrypted.Count - 10) more active devices are unencrypted (not listed individually)." `
                                -Remediation "Export full device list from Intune for investigation."
                        }
                    }
                }
                elseif ($encryptedDevices.Count -eq $managedDevices.Count -and $managedDevices.Count -gt 0) {
                    Add-ModuleFinding -Status "OK" `
                        -Object "Device Encryption Coverage" `
                        -Description "All $($managedDevices.Count) managed Windows devices are reporting encrypted status." `
                        -Remediation "Continue enforcing encryption policies."
                }
            }
            else {
                Add-ModuleFinding -Status "INFO" `
                    -Object "Managed Windows Devices" `
                    -Description "No Intune-managed Windows devices found. Cannot verify encryption status." `
                    -Remediation "Enroll Windows devices in Intune to manage and monitor encryption."
            }
        }
        catch {
            if ($_.Exception.Message -match "Forbidden|Authorization") {
                Add-ModuleFinding -Status "INFO" `
                    -Object "Device Encryption Status" `
                    -Description "Unable to check device encryption status. DeviceManagementManagedDevices.Read.All permission may be required." `
                    -Remediation "Grant DeviceManagementManagedDevices.Read.All permission to check device encryption status."
            }
            else {
                throw $_
            }
        }
        
        # Recommendation for key escrow verification
        Add-ModuleFinding -Status "INFO" `
            -Object "BitLocker Key Escrow Verification" `
            -Description "To verify recovery keys are being backed up to Azure AD, check: Azure Portal > Devices > All Devices > [Device] > BitLocker keys." `
            -Remediation "Ensure BitLocker policies include 'Save BitLocker recovery information to Azure Active Directory' setting."
        
    }
    catch {
        Add-ModuleFinding -Status "WARNING" `
            -Object "BitLocker Policy Check" `
            -Description "Unable to check BitLocker configuration: $($_.Exception.Message)" `
            -Remediation "Check Graph permissions (DeviceManagementConfiguration.Read.All required)."
    }
}

<#
.SYNOPSIS
    Test-DeviceRegistrationPolicy - Audits who can register and join devices.

.DESCRIPTION
    Examines device registration and join policies:
    - Who can join devices to Azure AD
    - Who can register devices (workplace join)
    - Maximum devices per user
    - MFA requirements for device registration
    
    Graph Endpoints Used:
    - GET /policies/deviceRegistrationPolicy
    
.OUTPUTS
    Findings based on device registration configuration
    
.NOTES
    Required Permissions: Policy.Read.All
    Minimum License: Azure AD Free
    
.LINK
    Graph Reference: https://learn.microsoft.com/en-us/graph/api/deviceregistrationpolicy-get
#>
function Test-DeviceRegistrationPolicy {
    [CmdletBinding()]
    param()
    
    Write-Host "`n[+] Checking device registration policy..." -ForegroundColor Cyan
    
    try {
        # Get device registration policy
        $policy = Invoke-ModuleGraphRequest -Uri "https://graph.microsoft.com/v1.0/policies/deviceRegistrationPolicy"
        
        if (-not $policy) {
            Add-ModuleFinding -Status "WARNING" `
                -Object "Device Registration Policy" `
                -Description "Unable to retrieve device registration policy." `
                -Remediation "Check permissions and verify device registration policy exists."
            return
        }
        
        # Check Azure AD Join settings
        $azureADJoinSetting = $policy.azureADJoin
        $azureADJoinAllowed = $azureADJoinSetting.isAllowed
        $azureADJoinAppliesTo = $azureADJoinSetting.appliesTo
        
        if ($azureADJoinAllowed -and $azureADJoinAppliesTo -eq "all") {
            Add-ModuleFinding -Status "REVIEW" `
                -Object "Azure AD Join - All Users" `
                -Description "All users are allowed to join devices to Azure AD. This includes personal devices that could be joined to the corporate directory." `
                -Remediation "Consider restricting Azure AD Join to specific groups (IT admins, specific user groups) to control which devices join your directory."
        }
        elseif ($azureADJoinAllowed -and $azureADJoinAppliesTo -eq "selected") {
            Add-ModuleFinding -Status "OK" `
                -Object "Azure AD Join" `
                -Description "Azure AD Join is restricted to selected groups." `
                -Remediation "Periodically review the groups allowed to join devices."
        }
        elseif (-not $azureADJoinAllowed -or $azureADJoinAppliesTo -eq "none") {
            Add-ModuleFinding -Status "INFO" `
                -Object "Azure AD Join - Disabled" `
                -Description "Azure AD Join is disabled. No users can join devices directly to Azure AD." `
                -Remediation "This is appropriate for hybrid environments. Verify this matches your device management strategy."
        }
        
        # Check Azure AD Registration settings
        $azureADRegistrationSetting = $policy.azureADRegistration
        $azureADRegistrationAllowed = $azureADRegistrationSetting.isAllowed
        $azureADRegistrationAppliesTo = $azureADRegistrationSetting.appliesTo
        
        if ($azureADRegistrationAllowed -and $azureADRegistrationAppliesTo -eq "all") {
            Add-ModuleFinding -Status "INFO" `
                -Object "Azure AD Registration - All Users" `
                -Description "All users can register personal devices (workplace join). This is common for BYOD scenarios." `
                -Remediation "If BYOD is not desired, restrict device registration to specific groups or disable entirely."
        }
        elseif ($azureADRegistrationAllowed -and $azureADRegistrationAppliesTo -eq "selected") {
            Add-ModuleFinding -Status "OK" `
                -Object "Azure AD Registration" `
                -Description "Device registration (workplace join) is restricted to selected groups." `
                -Remediation "Review groups periodically to ensure appropriate access."
        }
        
        # Check MFA requirement
        $multiFactorAuthConfiguration = $policy.multiFactorAuthConfiguration
        
        if ($multiFactorAuthConfiguration -eq "required" -or $multiFactorAuthConfiguration -eq "1") {
            Add-ModuleFinding -Status "OK" `
                -Object "MFA for Device Join" `
                -Description "MFA is required when joining devices to Azure AD. This prevents unauthorized device enrollment." `
                -Remediation "Continue requiring MFA for device join operations."
        }
        else {
            Add-ModuleFinding -Status "WARNING" `
                -Object "MFA for Device Join" `
                -Description "MFA is not required when joining devices to Azure AD. An attacker with stolen credentials could register rogue devices." `
                -Remediation "Enable MFA requirement for device join in Azure AD Device Settings or via Conditional Access."
        }
        
        # Check device limit
        $userDeviceQuota = $policy.userDeviceQuota
        
        if ($userDeviceQuota -and $userDeviceQuota -gt 0) {
            if ($userDeviceQuota -gt 20) {
                Add-ModuleFinding -Status "REVIEW" `
                    -Object "Device Limit Per User" `
                    -Description "Users can register up to $userDeviceQuota devices. A high limit increases risk of device sprawl." `
                    -Remediation "Consider reducing the device limit. Most users need 3-5 devices maximum (laptop, phone, tablet)."
            }
            elseif ($userDeviceQuota -le 5) {
                Add-ModuleFinding -Status "OK" `
                    -Object "Device Limit Per User" `
                    -Description "Users can register up to $userDeviceQuota devices. This is a reasonable limit." `
                    -Remediation "Monitor if users hit this limit legitimately."
            }
            else {
                Add-ModuleFinding -Status "INFO" `
                    -Object "Device Limit Per User" `
                    -Description "Users can register up to $userDeviceQuota devices." `
                    -Remediation "Review if this limit is appropriate for your organization."
            }
        }
        else {
            Add-ModuleFinding -Status "WARNING" `
                -Object "Device Limit Per User" `
                -Description "No device limit is configured or limit is unlimited. Users can register unlimited devices." `
                -Remediation "Set a reasonable device limit (5-10) to prevent device sprawl and potential abuse."
        }
        
        # Check local admin settings
        if ($policy.localAdminPassword) {
            $lapsSetting = $policy.localAdminPassword
            if ($lapsSetting.isEnabled) {
                Add-ModuleFinding -Status "OK" `
                    -Object "Local Admin Password Solution (LAPS)" `
                    -Description "Windows LAPS is enabled for Azure AD joined devices." `
                    -Remediation "Ensure LAPS is configured in Intune for password rotation."
            }
        }
    }
    catch {
        Add-ModuleFinding -Status "WARNING" `
            -Object "Device Registration Policy" `
            -Description "Unable to check device registration policy: $($_.Exception.Message)" `
            -Remediation "Check Graph permissions (Policy.Read.All required)."
    }
}

<#
.SYNOPSIS
    Test-ConditionalAccessDeviceControls - Audits CA policies that require device compliance.

.DESCRIPTION
    Examines Conditional Access policies for device-based controls:
    - Policies requiring compliant device
    - Policies requiring hybrid Azure AD joined device
    - Policies requiring approved client app
    - Coverage gaps for sensitive applications
    
    Graph Endpoints Used:
    - GET /identity/conditionalAccess/policies
    
.OUTPUTS
    Findings based on device controls in CA policies
    
.NOTES
    Required Permissions: Policy.Read.All
    Minimum License: Azure AD P1
    
.LINK
    Graph Reference: https://learn.microsoft.com/en-us/graph/api/conditionalaccesspolicy-list
#>
function Test-ConditionalAccessDeviceControls {
    [CmdletBinding()]
    param()
    
    Write-Host "`n[+] Checking Conditional Access device controls..." -ForegroundColor Cyan
    
    try {
        # Get all CA policies
        $caPolicies = Invoke-ModuleGraphRequest -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" -AllPages
        
        if (-not $caPolicies -or $caPolicies.Count -eq 0) {
            Add-ModuleFinding -Status "WARNING" `
                -Object "CA Device Controls" `
                -Description "No Conditional Access policies found. Device compliance cannot be enforced without CA policies." `
                -Remediation "Create Conditional Access policies that require device compliance for access to corporate resources."
            return
        }
        
        # Analyze device controls
        $policiesRequiringCompliant = @()
        $policiesRequiringHybridJoined = @()
        $policiesRequiringApprovedApp = @()
        $policiesRequiringManagedApp = @()
        $enabledPolicies = $caPolicies | Where-Object { $_.state -eq "enabled" }
        
        foreach ($policy in $caPolicies) {
            $grantControls = $policy.grantControls
            
            if ($grantControls) {
                $builtInControls = $grantControls.builtInControls
                
                if ($builtInControls -contains "compliantDevice") {
                    $policiesRequiringCompliant += $policy
                }
                if ($builtInControls -contains "domainJoinedDevice") {
                    $policiesRequiringHybridJoined += $policy
                }
                if ($builtInControls -contains "approvedApplication") {
                    $policiesRequiringApprovedApp += $policy
                }
                if ($builtInControls -contains "compliantApplication") {
                    $policiesRequiringManagedApp += $policy
                }
            }
        }
        
        # Summary
        Add-ModuleFinding -Status "INFO" `
            -Object "CA Device Controls Summary" `
            -Description "Total CA policies: $($caPolicies.Count) ($($enabledPolicies.Count) enabled). Requiring compliant device: $($policiesRequiringCompliant.Count). Requiring hybrid joined: $($policiesRequiringHybridJoined.Count). Requiring approved app: $($policiesRequiringApprovedApp.Count)." `
            -Remediation "Device controls in Conditional Access are key to Zero Trust. Review coverage below."
        
        # Check for compliant device requirement
        $enabledCompliantPolicies = $policiesRequiringCompliant | Where-Object { $_.state -eq "enabled" }
        
        if ($enabledCompliantPolicies.Count -eq 0) {
            Add-ModuleFinding -Status "FAIL" `
                -Object "No Compliant Device Requirement" `
                -Description "No enabled Conditional Access policies require a compliant device. Non-compliant devices can access corporate resources." `
                -Remediation "Create a CA policy requiring compliant device for access to Office 365, or at minimum, sensitive applications."
        }
        else {
            Add-ModuleFinding -Status "OK" `
                -Object "Compliant Device Policies" `
                -Description "$($enabledCompliantPolicies.Count) enabled polic(ies) require a compliant device." `
                -Remediation "Review policy scope to ensure adequate coverage."
            
            foreach ($policy in $enabledCompliantPolicies) {
                $targetApps = "All applications"
                if ($policy.conditions.applications.includeApplications -and 
                    $policy.conditions.applications.includeApplications[0] -ne "All") {
                    $targetApps = "$($policy.conditions.applications.includeApplications.Count) specific app(s)"
                }
                
                Add-ModuleFinding -Status "OK" `
                    -Object "Policy: $($policy.displayName)" `
                    -Description "Requires compliant device. Target: $targetApps." `
                    -Remediation "Review periodically to ensure coverage is appropriate."
            }
        }
        
        # Check for hybrid joined requirement
        $enabledHybridPolicies = $policiesRequiringHybridJoined | Where-Object { $_.state -eq "enabled" }
        
        if ($enabledHybridPolicies.Count -gt 0) {
            Add-ModuleFinding -Status "INFO" `
                -Object "Hybrid Joined Device Policies" `
                -Description "$($enabledHybridPolicies.Count) polic(ies) require Hybrid Azure AD joined devices. This is appropriate for on-premises Windows devices." `
                -Remediation "Ensure this doesn't block cloud-only or mobile devices unintentionally. Consider 'compliant OR hybrid joined' for flexibility."
        }
        
        # Check for flexible requirements
        $policiesWithFlexibleDeviceRequirement = @()
        
        foreach ($policy in $enabledPolicies) {
            if ($policy.grantControls) {
                $controls = $policy.grantControls.builtInControls
                $operator = $policy.grantControls.operator
                
                if ($controls -contains "compliantDevice" -and 
                    $controls -contains "domainJoinedDevice" -and
                    $operator -eq "OR") {
                    $policiesWithFlexibleDeviceRequirement += $policy
                }
            }
        }
        
        if ($policiesWithFlexibleDeviceRequirement.Count -gt 0) {
            Add-ModuleFinding -Status "OK" `
                -Object "Flexible Device Requirements" `
                -Description "$($policiesWithFlexibleDeviceRequirement.Count) polic(ies) accept compliant OR hybrid joined devices. This supports both cloud-managed and domain-joined scenarios." `
                -Remediation "This is a good practice for hybrid environments."
        }
        
        # Check for broad coverage
        $allAppsDevicePolicy = $enabledPolicies | Where-Object {
            $_.conditions.applications.includeApplications -contains "All" -and
            ($_.grantControls.builtInControls -contains "compliantDevice" -or
            $_.grantControls.builtInControls -contains "domainJoinedDevice")
        }
        
        if ($allAppsDevicePolicy.Count -gt 0) {
            Add-ModuleFinding -Status "OK" `
                -Object "Broad Device Requirement" `
                -Description "Device compliance/join required for all cloud apps by $($allAppsDevicePolicy.Count) polic(ies). This provides comprehensive protection." `
                -Remediation "Ensure break-glass accounts are excluded. Monitor for user impact."
        }
        else {
            Add-ModuleFinding -Status "WARNING" `
                -Object "Limited Device Requirement Scope" `
                -Description "No policy requires compliant/joined device for ALL cloud applications. Some apps may be accessible from non-compliant devices." `
                -Remediation "Consider a policy requiring device compliance for all cloud apps, or ensure all sensitive apps are individually protected."
        }
        
        # Check for mobile controls
        $enabledMobileControls = ($policiesRequiringApprovedApp + $policiesRequiringManagedApp) | 
            Where-Object { $_.state -eq "enabled" } | 
            Select-Object -Unique
        
        if ($enabledMobileControls.Count -gt 0) {
            Add-ModuleFinding -Status "OK" `
                -Object "Mobile App Protection Policies" `
                -Description "$($enabledMobileControls.Count) polic(ies) require approved or managed mobile apps. This protects data on mobile devices." `
                -Remediation "Ensure App Protection Policies are configured in Intune to complement these CA policies."
        }
        else {
            Add-ModuleFinding -Status "INFO" `
                -Object "Mobile App Protection" `
                -Description "No CA policies require approved/managed mobile apps. Consider adding for mobile device data protection." `
                -Remediation "Create CA policies requiring approved client apps or app protection policies for mobile access."
        }
    }
    catch {
        if ($_.Exception.Message -match "Forbidden|Authorization|Premium") {
            Add-ModuleFinding -Status "INFO" `
                -Object "CA Device Controls" `
                -Description "Unable to check CA policies. Azure AD Premium P1 may be required." `
                -Remediation "Upgrade to Azure AD P1 to use Conditional Access policies."
        }
        else {
            Add-ModuleFinding -Status "WARNING" `
                -Object "CA Device Controls" `
                -Description "Unable to check CA device controls: $($_.Exception.Message)" `
                -Remediation "Check Graph permissions (Policy.Read.All required)."
        }
    }
}

#endregion

#region ==================== MODULE EXPORTS ====================

<#
.SYNOPSIS
    Runs all device security checks.

.DESCRIPTION
    Convenience function to execute all checks in this module.
#>
function Invoke-DeviceChecks {
    [CmdletBinding()]
    param()
    
    Write-Host "`n" -NoNewline
    Write-Host "==========================================" -ForegroundColor Magenta
    Write-Host " Device Security Module Checks" -ForegroundColor Magenta
    Write-Host "==========================================" -ForegroundColor Magenta
    
    # Run all checks
    Test-DeviceOverview
    Test-StaleDevices
    Test-DeviceComplianceStatus
    Test-DeviceCompliancePolicies
    Test-BitLockerRecoveryKeys
    Test-DeviceRegistrationPolicy
    Test-ConditionalAccessDeviceControls
    
    Write-Host "`n[+] Device security checks complete." -ForegroundColor Magenta
}

# Export module members
Export-ModuleMember -Function @(
    'Initialize-DevicesModule',
    'Test-DeviceOverview',
    'Test-StaleDevices',
    'Test-DeviceComplianceStatus',
    'Test-DeviceCompliancePolicies',
    'Test-BitLockerRecoveryKeys',
    'Test-DeviceRegistrationPolicy',
    'Test-ConditionalAccessDeviceControls',
    'Invoke-DeviceChecks'
)

#endregion

# Auto-initialize when module is imported
$null = Initialize-DevicesModule
