<#
.SYNOPSIS
    EntraChecks-ActiveDirectory.psm1
    On-premises Active Directory security assessment module.

.DESCRIPTION
    Runs 29 read-only Active Directory security checks and emits
    schema-aligned findings that flow into the EntraChecks unified
    reporting pipeline alongside cloud findings.

    Migrated from the stand-alone ad/ActiveDirectoryv3.ps1 script.
    All Check-* functions renamed to Test-* (approved PowerShell verb).
    The duplicate Check-KerberosPreAuthDisabled definition was removed.

    Graceful degradation: if the platform is not Windows, RSAT is not
    installed, the host is not domain-joined, or the current user lacks
    Domain Admin privilege, the module emits a single INFO/WARNING
    finding and returns without running individual checks.

.NOTES
    Version: 1.0.0
    Author:  David Stells
    Requires: Windows + ActiveDirectory PowerShell module (RSAT)
    Optional: GroupPolicy PowerShell module (for GPO checks)

    Permission model:
    - Domain User       -> most read-only checks run; ACL/drift checks
                           may return incomplete results (WARNING).
    - Domain Admin      -> full check coverage.
    - Read-Only DA      -> full coverage for read-only checks.

.LINK
    Plan: plans/AD-PR1-Refactor-Plan.md
    Source: ad/ActiveDirectoryv3.ps1 (removed after migration)
#>

#Requires -Version 5.1

#region ==================== MODULE STATE ====================

$script:ModuleName = 'EntraChecks-ActiveDirectory'
$script:ModuleVersion = '1.0.0'

# Populated by Invoke-ActiveDirectoryAssessment. Accessible via
#   & (Get-Module EntraChecks-ActiveDirectory) { $script:Findings }
$script:Findings = @()

# Per-check default thresholds (overridable via parameters).
$script:DefaultUserLogonInactivityDays = 180
$script:DefaultUserPasswordAgeDays = 180
$script:DefaultRecentPrivilegedAccountDays = 30
$script:DefaultKrbTgtPasswordAgeDays = 180

# Privileged group canonical list used by multiple checks.
$script:PrivilegedGroups = @(
    'Domain Admins',
    'Enterprise Admins',
    'Administrators',
    'Schema Admins',
    'Account Operators',
    'Backup Operators'
)

# Groups + SYSTEM principal allowed to have broad rights on protected objects.
$script:AdminPrincipals = @(
    'Domain Admins',
    'Enterprise Admins',
    'Administrators',
    'SYSTEM'
)

# PR 4a: extended authorized-principals list, set per-invocation via
# Invoke-ActiveDirectoryAssessment -AuthorizedPrincipalsExtra.
$script:AuthorizedPrincipalsExtra = @()

# Per-check metadata: Category + ComplianceFrameworks. Indexed by the CheckName
# passed to Add-ADFinding. Drives unified-report grouping and SOC 2 mapping.
$script:CheckMetadata = @{}
$script:CheckMetadata['Test-ADForestAndDomain'] = @{ Category = 'Infrastructure'; Frameworks = @('CIS-AD', 'NIST-CM-8') }
$script:CheckMetadata['Test-DomainControllers'] = @{ Category = 'Infrastructure'; Frameworks = @('CIS-AD', 'NIST-CM-8', 'SOC2-CC6.1') }
$script:CheckMetadata['Test-ADPasswordPolicy'] = @{ Category = 'Authentication'; Frameworks = @('CIS-AD', 'NIST-IA-5', 'SOC2-CC6.2', 'PCI-DSS-8.3') }
$script:CheckMetadata['Test-ADStaleAccounts'] = @{ Category = 'Account Lifecycle'; Frameworks = @('CIS-AD', 'NIST-AC-2', 'SOC2-CC6.2') }
$script:CheckMetadata['Test-PrivilegedGroupMembership'] = @{ Category = 'Privileged Access'; Frameworks = @('CIS-AD', 'NIST-AC-6', 'SOC2-CC6.1') }
$script:CheckMetadata['Test-ProtectedUsersAdoption'] = @{ Category = 'Privileged Access'; Frameworks = @('CIS-AD', 'MCSB-PA-5', 'SOC2-CC6.1') }
$script:CheckMetadata['Test-DomainTrusts'] = @{ Category = 'Infrastructure'; Frameworks = @('CIS-AD', 'NIST-AC-3') }
$script:CheckMetadata['Test-ADServiceAccounts'] = @{ Category = 'Account Lifecycle'; Frameworks = @('CIS-AD', 'NIST-IA-5') }
$script:CheckMetadata['Test-KrbTgtAccountAge'] = @{ Category = 'Authentication'; Frameworks = @('CIS-AD', 'NIST-IA-5', 'SOC2-CC6.1') }
$script:CheckMetadata['Test-DelegationOverview'] = @{ Category = 'Delegation'; Frameworks = @('CIS-AD', 'MCSB-IM', 'SOC2-CC6.1') }
$script:CheckMetadata['Test-GPOInventory'] = @{ Category = 'Infrastructure'; Frameworks = @('CIS-AD') }
$script:CheckMetadata['Test-DuplicateSPNs'] = @{ Category = 'Authentication'; Frameworks = @('CIS-AD', 'MCSB-IM') }
$script:CheckMetadata['Test-PrivilegedObjectACLs'] = @{ Category = 'Privileged Access'; Frameworks = @('CIS-AD', 'NIST-AC-6', 'SOC2-CC6.1') }
$script:CheckMetadata['Test-GPPPasswords'] = @{ Category = 'Authentication'; Frameworks = @('CIS-AD', 'NIST-IA-5', 'SOC2-CC6.1', 'PCI-DSS-3.5') }
$script:CheckMetadata['Test-KerberosPreAuthDisabled'] = @{ Category = 'Authentication'; Frameworks = @('CIS-AD', 'MCSB-IM', 'SOC2-CC6.2') }
$script:CheckMetadata['Test-UnconstrainedDelegation'] = @{ Category = 'Delegation'; Frameworks = @('CIS-AD', 'MCSB-IM', 'SOC2-CC6.1') }
$script:CheckMetadata['Test-PasswordNeverExpires'] = @{ Category = 'Account Lifecycle'; Frameworks = @('CIS-AD', 'NIST-IA-5', 'SOC2-CC6.2') }
$script:CheckMetadata['Test-SIDHistory'] = @{ Category = 'Privileged Access'; Frameworks = @('CIS-AD', 'NIST-AC-6') }
$script:CheckMetadata['Test-PrivilegedSmartcardRequirement'] = @{ Category = 'Privileged Access'; Frameworks = @('CIS-AD', 'NIST-IA-2', 'SOC2-CC6.1') }
$script:CheckMetadata['Test-PrivilegedGroupCreep'] = @{ Category = 'Privileged Access'; Frameworks = @('CIS-AD', 'NIST-AC-6', 'SOC2-CC6.1') }
$script:CheckMetadata['Test-AdminSDHolderDrift'] = @{ Category = 'Privileged Access'; Frameworks = @('CIS-AD', 'NIST-AC-6', 'SOC2-CC6.1') }
$script:CheckMetadata['Test-DangerousSIDsInPrivilegedGroups'] = @{ Category = 'Privileged Access'; Frameworks = @('CIS-AD', 'NIST-AC-6', 'SOC2-CC6.1') }
$script:CheckMetadata['Test-PasswordsInDescription'] = @{ Category = 'Account Lifecycle'; Frameworks = @('CIS-AD', 'NIST-IA-5') }
$script:CheckMetadata['Test-UserAccountsWithSPN'] = @{ Category = 'Authentication'; Frameworks = @('CIS-AD', 'MCSB-IM', 'SOC2-CC6.2') }
$script:CheckMetadata['Test-OUAndGPODelegation'] = @{ Category = 'Privileged Access'; Frameworks = @('CIS-AD', 'NIST-AC-6') }
$script:CheckMetadata['Test-RecentPrivilegedAccounts'] = @{ Category = 'Privileged Access'; Frameworks = @('CIS-AD', 'NIST-AC-2', 'SOC2-CC6.1') }
$script:CheckMetadata['Test-NestedGroupPrivilegePaths'] = @{ Category = 'Privileged Access'; Frameworks = @('CIS-AD', 'NIST-AC-6') }
$script:CheckMetadata['Test-SensitiveObjectACLDrift'] = @{ Category = 'Privileged Access'; Frameworks = @('CIS-AD', 'NIST-AC-6', 'SOC2-CC6.1') }
$script:CheckMetadata['Test-ShadowGroupNames'] = @{ Category = 'Privileged Access'; Frameworks = @('CIS-AD', 'NIST-AC-6') }
# PR 2 additions — four new checks closing the highest-value coverage gaps.
$script:CheckMetadata['Test-LAPSDeployment'] = @{ Category = 'Privileged Access'; Frameworks = @('CIS-AD', 'MCSB-PA-5', 'SOC2-CC6.1') }
$script:CheckMetadata['Test-DCSecuritySettings'] = @{ Category = 'Infrastructure'; Frameworks = @('CIS-AD', 'NIST-CA-7', 'MCSB-PA-6', 'SOC2-CC6.1') }
$script:CheckMetadata['Test-KerberoastableAccounts'] = @{ Category = 'Authentication'; Frameworks = @('CIS-AD', 'MCSB-IM', 'SOC2-CC6.2') }
$script:CheckMetadata['Test-DirSyncAccountSecurity'] = @{ Category = 'Privileged Access'; Frameworks = @('MCSB-IM', 'NIST-AC-2', 'SOC2-CC6.1') }
# PR 4a Group A - credential hygiene
$script:CheckMetadata['Test-LMHashStorage'] = @{ Category = 'Authentication'; Frameworks = @('CIS-AD', 'NIST-IA-5', 'MCSB-IM-4', 'SOC2-CC6.1') }
$script:CheckMetadata['Test-NTLMv1Allowed'] = @{ Category = 'Authentication'; Frameworks = @('CIS-AD', 'NIST-IA-2', 'SOC2-CC6.2') }
$script:CheckMetadata['Test-DCLegacyEncryption'] = @{ Category = 'Authentication'; Frameworks = @('CIS-AD', 'NIST-SC-13', 'MCSB-IM-4', 'SOC2-CC6.2') }
$script:CheckMetadata['Test-NullSessionShares'] = @{ Category = 'Authentication'; Frameworks = @('CIS-AD', 'NIST-AC-3', 'SOC2-CC6.1') }
$script:CheckMetadata['Test-DomainEncryptionTypesPolicy'] = @{ Category = 'Authentication'; Frameworks = @('CIS-AD', 'NIST-SC-13', 'SOC2-CC6.2') }
# PR 4a Group B - ACL abuse paths
$script:CheckMetadata['Test-WritablePrivilegedACLs'] = @{ Category = 'Privileged Access'; Frameworks = @('CIS-AD', 'NIST-AC-6', 'MCSB-PA-5', 'SOC2-CC6.1') }
$script:CheckMetadata['Test-ShadowCredentialsVulnerable'] = @{ Category = 'Privileged Access'; Frameworks = @('CIS-AD', 'NIST-AC-6', 'MCSB-IM-3', 'SOC2-CC6.1') }
$script:CheckMetadata['Test-RBCDConfigured'] = @{ Category = 'Delegation'; Frameworks = @('CIS-AD', 'NIST-AC-6', 'MCSB-IM', 'SOC2-CC6.1') }
$script:CheckMetadata['Test-GenericWriteToSensitive'] = @{ Category = 'Privileged Access'; Frameworks = @('CIS-AD', 'NIST-AC-6', 'SOC2-CC6.1') }
# PR 4b additions
$script:CheckMetadata['Test-AuthenticatedUsersDACLReach'] = @{ Category = 'Privileged Access'; Frameworks = @('CIS-AD', 'NIST-AC-6', 'MCSB-PA-5', 'SOC2-CC6.1') }
$script:CheckMetadata['Test-DNSAdminsPrivilege'] = @{ Category = 'Privileged Access'; Frameworks = @('CIS-AD', 'NIST-AC-6', 'SOC2-CC6.1') }
$script:CheckMetadata['Test-EventAuditPolicy'] = @{ Category = 'Infrastructure'; Frameworks = @('CIS-AD', 'NIST-AU-2', 'NIST-AU-3', 'SOC2-CC7.2') }
$script:CheckMetadata['Test-DFSRSYSVOLHealth'] = @{ Category = 'Infrastructure'; Frameworks = @('CIS-AD', 'NIST-CM-2', 'SOC2-CC7.1') }

# Critical-by-nature checks — findings at FAIL status escalate to Critical severity
# regardless of the default High-for-FAIL mapping.
$script:CriticalChecks = @(
    'Test-UnconstrainedDelegation',
    'Test-KrbTgtAccountAge',
    'Test-DangerousSIDsInPrivilegedGroups',
    'Test-GPPPasswords',
    'Test-AdminSDHolderDrift',
    # PR 2: privileged SPN-bearing account with weak hash + stale password = domain-wide compromise risk.
    'Test-KerberoastableAccounts',
    # PR 2: DirSync account in Domain Admins is a serious Azure AD Connect install misconfiguration.
    'Test-DirSyncAccountSecurity',
    # PR 4a: single-step domain-compromise paths.
    'Test-WritablePrivilegedACLs',
    'Test-ShadowCredentialsVulnerable',
    'Test-GenericWriteToSensitive',
    'Test-RBCDConfigured',
    # PR 4b: DACL reach (one-hop direct exposure to DA), DnsAdmins on legacy DCs.
    'Test-AuthenticatedUsersDACLReach',
    'Test-DNSAdminsPrivilege'
)

#endregion

#region ==================== PRIVATE HELPERS ====================

<#
.SYNOPSIS
    Emits a schema-aligned finding into $script:Findings.
.DESCRIPTION
    Single helper for every Test-* function to use. Normalizes status
    vocabulary (OK -> PASS), infers Severity from status + CheckName,
    looks up Category + ComplianceFrameworks from $script:CheckMetadata,
    and derives RiskScore from Severity.
#>
function Add-ADFinding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$CheckName,
        [Parameter(Mandatory)] [ValidateSet('PASS', 'FAIL', 'WARNING', 'INFO', 'OK')] [string]$Status,
        [Parameter(Mandatory)] [string]$Object,
        [Parameter(Mandatory)] [string]$Description,
        [string]$Remediation = ''
    )

    # Normalize legacy OK -> PASS (migration from old schema).
    if ($Status -eq 'OK') { $Status = 'PASS' }

    $meta = $script:CheckMetadata[$CheckName]
    $category = if ($meta) { $meta.Category } else { 'ActiveDirectory' }
    $frameworks = if ($meta) { $meta.Frameworks } else { @() }

    $severity = switch ($Status) {
        'FAIL' { if ($script:CriticalChecks -contains $CheckName) { 'Critical' } else { 'High' } }
        'WARNING' { 'Medium' }
        'PASS' { 'Low' }
        'INFO' { 'Low' }
        default { 'Low' }
    }

    $riskScore = switch ($severity) {
        'Critical' { 90 }
        'High' { 70 }
        'Medium' { 50 }
        'Low' { 10 }
        default { 0 }
    }

    # Individual assignment to avoid PSAlignAssignmentStatement + PSUseConsistentWhitespace clash.
    $finding = [pscustomobject]@{
        Time = Get-Date
        CheckName = $CheckName
        Status = $Status
        Severity = $severity
        Category = $category
        Object = $Object
        Description = $Description
        Remediation = $Remediation
        ComplianceFrameworks = $frameworks
        ComplianceReference = ($frameworks -join ', ')
        RiskScore = $riskScore
        Type = "AD_$CheckName"
        Source = 'ActiveDirectory'
    }
    $script:Findings += $finding
}

<#
.SYNOPSIS
    Probes the runtime environment for Active Directory readiness.
.DESCRIPTION
    Returns a PSCustomObject with IsAvailable, FailureReason, IsDomainAdmin,
    DomainName, and ModulePresent fields. Invoke-ActiveDirectoryAssessment
    checks IsAvailable and returns early (emitting a single INFO finding)
    when AD queries cannot run.
#>
function Test-ADEnvironment {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    $result = [ordered]@{
        IsAvailable = $false
        FailureReason = $null
        IsDomainAdmin = $false
        DomainName = $null
        ModulePresent = $false
        Platform = $null
    }

    # Stage 1 — platform. $IsWindows isn't available on PS 5.1, so use $env:OS.
    $isWindows = ($env:OS -eq 'Windows_NT') -or ($PSVersionTable.PSEdition -eq 'Desktop')
    $result['Platform'] = if ($isWindows) { 'Windows' } else { 'Non-Windows' }
    if (-not $isWindows) {
        $result['FailureReason'] = 'Active Directory checks only run on Windows. Current platform is not Windows.'
        return [pscustomobject]$result
    }

    # Stage 2 — RSAT / ActiveDirectory module.
    $adModule = Get-Module -ListAvailable -Name ActiveDirectory -ErrorAction SilentlyContinue
    if (-not $adModule) {
        $result['FailureReason'] = "ActiveDirectory PowerShell module not installed. Install RSAT: Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0"
        return [pscustomobject]$result
    }
    $result['ModulePresent'] = $true
    Import-Module ActiveDirectory -ErrorAction SilentlyContinue | Out-Null

    # Stage 3 — domain-joined probe.
    try {
        $domain = Get-ADDomain -ErrorAction Stop
        $result['DomainName'] = $domain.DNSRoot
    }
    catch {
        $result['FailureReason'] = "Unable to query Active Directory. This is expected if the host is not domain-joined or AD connectivity is unavailable. Error: $($_.Exception.Message)"
        return [pscustomobject]$result
    }

    # Stage 4 — permission probe (soft — presence of Domain Admin membership).
    try {
        $current = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        foreach ($g in $current.Groups) {
            # S-1-5-21-*-512 = Domain Admins; S-1-5-32-544 = local Administrators.
            if ($g.Value -match '^S-1-5-21-.+-512$' -or $g.Value -eq 'S-1-5-32-544') {
                $result['IsDomainAdmin'] = $true
                break
            }
        }
    }
    catch {
        Write-Verbose "Test-ADEnvironment permission probe failed: $($_.Exception.Message)"
    }

    $result['IsAvailable'] = $true
    return [pscustomobject]$result
}

#endregion

#region ==================== INITIALIZATION ====================

function Initialize-ActiveDirectoryModule {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    Write-Host "`n[+] Loading module: $script:ModuleName v$script:ModuleVersion" -ForegroundColor Magenta
    $script:Findings = @()

    return @{
        ModuleName = $script:ModuleName
        Version = $script:ModuleVersion
        Initialized = $true
    }
}

#endregion

#region ==================== INFRASTRUCTURE CHECKS ====================

function Test-ADForestAndDomain {
    <#
    .SYNOPSIS
        Captures AD forest + domain metadata (functional levels, SID, NetBIOS).
    #>
    [CmdletBinding()]
    param()

    Write-Host "`n[+] Collecting forest and domain information..." -ForegroundColor Cyan
    try {
        $adForest = Get-ADForest
        $adDomain = Get-ADDomain
        $summary = @"
Forest Name: $($adForest.Name)
Forest Functional Level: $($adForest.ForestMode)
Domain Name: $($adDomain.DNSRoot)
Domain NetBIOS Name: $($adDomain.NetBIOSName)
Domain Functional Level: $($adDomain.DomainMode)
Forest Root Domain: $($adForest.RootDomain)
Domain SID: $($adDomain.DomainSID.Value)
"@
        Add-ADFinding -CheckName 'Test-ADForestAndDomain' -Status 'INFO' -Object 'Forest & Domain' `
            -Description "AD Forest and domain basic info: $summary" `
            -Remediation 'For reference only. Ensure forest / domain functional levels are current and supported.'
    }
    catch {
        Add-ADFinding -CheckName 'Test-ADForestAndDomain' -Status 'WARNING' -Object 'Forest & Domain' `
            -Description "Unable to collect forest / domain info: $($_.Exception.Message)" `
            -Remediation 'Check AD module installation and connectivity.'
    }
}

function Test-DomainControllers {
    <#
    .SYNOPSIS
        Enumerates all domain controllers with OS, IP, GC status, and RODC flag.
    #>
    [CmdletBinding()]
    param()

    Write-Host "`n[+] Enumerating domain controllers..." -ForegroundColor Cyan
    try {
        $dcs = Get-ADDomainController -Filter *
        $lines = foreach ($d in $dcs) {
            $role = if ($d.IsReadOnly) { 'RODC' } else { 'RWDC' }
            "DC: $($d.Name) | Site: $($d.Site) | OS: $($d.OperatingSystem) | IPv4: $($d.IPv4Address) | IPv6: $($d.IPv6Address) | GC: $($d.IsGlobalCatalog) | Role: $role"
        }
        Add-ADFinding -CheckName 'Test-DomainControllers' -Status 'INFO' -Object 'Domain Controllers' `
            -Description "Domain controllers ($($dcs.Count)): $($lines -join ' ; ')" `
            -Remediation 'Review for completeness, expected OS versions, and correct site assignments.'
    }
    catch {
        Add-ADFinding -CheckName 'Test-DomainControllers' -Status 'WARNING' -Object 'Domain Controllers' `
            -Description "Unable to enumerate domain controllers: $($_.Exception.Message)" `
            -Remediation 'Check AD module and network connectivity to a DC.'
    }
}

function Test-DomainTrusts {
    <#
    .SYNOPSIS
        Enumerates all AD domain trust relationships.
    #>
    [CmdletBinding()]
    param()

    Write-Host "`n[+] Enumerating domain trusts..." -ForegroundColor Cyan
    try {
        $trusts = @(Get-ADTrust -Filter *)
        if ($trusts.Count -eq 0) {
            Add-ADFinding -CheckName 'Test-DomainTrusts' -Status 'INFO' -Object 'Domain Trusts' `
                -Description 'No domain trusts found.' `
                -Remediation 'No action needed.'
            return
        }
        foreach ($t in $trusts) {
            $desc = "Trust: $($t.Name) | Direction: $($t.TrustDirection) | Type: $($t.TrustType) | Transitive: $($t.IsTransitive)"
            if (-not $t.IsTransitive -or $t.TrustDirection -eq 'None') {
                Add-ADFinding -CheckName 'Test-DomainTrusts' -Status 'WARNING' -Object $t.Name `
                    -Description "$desc (non-transitive or untrusted)." `
                    -Remediation 'Review this trust. Non-transitive / untrusted trusts complicate auth and can increase risk.'
            }
            else {
                Add-ADFinding -CheckName 'Test-DomainTrusts' -Status 'INFO' -Object $t.Name `
                    -Description $desc `
                    -Remediation 'Verify this trust is expected and documented.'
            }
        }
    }
    catch {
        Add-ADFinding -CheckName 'Test-DomainTrusts' -Status 'WARNING' -Object 'Domain Trusts' `
            -Description "Unable to enumerate trusts: $($_.Exception.Message)" `
            -Remediation 'Check permissions and trust relationships.'
    }
}

function Test-GPOInventory {
    <#
    .SYNOPSIS
        Enumerates all Group Policy Objects.
    #>
    [CmdletBinding()]
    param()

    Write-Host "`n[+] Enumerating Group Policy Objects..." -ForegroundColor Cyan
    try {
        if (-not (Get-Module -ListAvailable -Name GroupPolicy)) {
            Add-ADFinding -CheckName 'Test-GPOInventory' -Status 'INFO' -Object 'GPOs' `
                -Description 'GroupPolicy PowerShell module not installed. GPO inventory skipped.' `
                -Remediation 'Install RSAT GroupPolicyManagement feature to enable this check.'
            return
        }
        $gpos = @(Get-GPO -All)
        if ($gpos.Count -eq 0) {
            Add-ADFinding -CheckName 'Test-GPOInventory' -Status 'INFO' -Object 'GPOs' `
                -Description 'No GPOs found.' -Remediation 'No action needed.'
            return
        }
        Add-ADFinding -CheckName 'Test-GPOInventory' -Status 'INFO' -Object 'GPOs' `
            -Description "Total GPOs found: $($gpos.Count)." `
            -Remediation 'Review for intended purpose and scope.'
    }
    catch {
        Add-ADFinding -CheckName 'Test-GPOInventory' -Status 'WARNING' -Object 'GPOs' `
            -Description "Unable to enumerate GPOs: $($_.Exception.Message)" `
            -Remediation 'Check permissions and GroupPolicy module.'
    }
}

#endregion

#region ==================== AUTHENTICATION CHECKS ====================

function Test-ADPasswordPolicy {
    <#
    .SYNOPSIS
        Captures the default domain password policy settings.
    #>
    [CmdletBinding()]
    param()

    Write-Host "`n[+] Collecting password policy..." -ForegroundColor Cyan
    try {
        $p = Get-ADDefaultDomainPasswordPolicy
        $summary = "MinPasswordLength=$($p.MinPasswordLength); HistoryCount=$($p.PasswordHistoryCount); ComplexityEnabled=$($p.ComplexityEnabled); LockoutThreshold=$($p.LockoutThreshold); MaxPasswordAge=$($p.MaxPasswordAge); ReversibleEncryption=$($p.ReversibleEncryptionEnabled)"

        # Flag weak settings.
        if ($p.MinPasswordLength -lt 14) {
            Add-ADFinding -CheckName 'Test-ADPasswordPolicy' -Status 'WARNING' -Object 'Password Policy' `
                -Description "MinPasswordLength is $($p.MinPasswordLength). CIS benchmark recommends >=14." `
                -Remediation 'Increase MinPasswordLength to 14 or more via the Default Domain Policy.'
        }
        if (-not $p.ComplexityEnabled) {
            Add-ADFinding -CheckName 'Test-ADPasswordPolicy' -Status 'FAIL' -Object 'Password Policy' `
                -Description 'Password complexity is disabled.' `
                -Remediation 'Enable password complexity via the Default Domain Policy.'
        }
        if ($p.ReversibleEncryptionEnabled) {
            Add-ADFinding -CheckName 'Test-ADPasswordPolicy' -Status 'FAIL' -Object 'Password Policy' `
                -Description 'Reversible encryption for passwords is ENABLED at the domain level.' `
                -Remediation 'Disable reversible encryption unless a legacy protocol explicitly requires it.'
        }

        Add-ADFinding -CheckName 'Test-ADPasswordPolicy' -Status 'INFO' -Object 'Password Policy' `
            -Description "Current domain password policy: $summary" `
            -Remediation 'Review for compliance with organizational and regulatory requirements.'
    }
    catch {
        Add-ADFinding -CheckName 'Test-ADPasswordPolicy' -Status 'WARNING' -Object 'Password Policy' `
            -Description "Unable to retrieve password policy: $($_.Exception.Message)" `
            -Remediation 'Check AD module and permissions.'
    }
}

function Test-KrbTgtAccountAge {
    <#
    .SYNOPSIS
        Audits KRBTGT account state (enabled, password age, key version).
    #>
    [CmdletBinding()]
    param(
        [int]$MaxAgeDays = $script:DefaultKrbTgtPasswordAgeDays
    )

    Write-Host "`n[+] Auditing KRBTGT account..." -ForegroundColor Cyan
    try {
        $k = Get-ADUser -Identity 'krbtgt' -Properties Enabled, PasswordLastSet, 'msds-keyversionnumber', whenCreated
        $days = if ($k.PasswordLastSet) { ((Get-Date) - $k.PasswordLastSet).Days } else { -1 }

        if (-not $k.Enabled) {
            Add-ADFinding -CheckName 'Test-KrbTgtAccountAge' -Status 'FAIL' -Object 'krbtgt' `
                -Description 'KRBTGT account is disabled. Kerberos ticketing will break.' `
                -Remediation 'Re-enable the krbtgt account immediately.'
        }

        if ($days -gt $MaxAgeDays) {
            Add-ADFinding -CheckName 'Test-KrbTgtAccountAge' -Status 'FAIL' -Object 'krbtgt' `
                -Description "KRBTGT password is $days days old (threshold $MaxAgeDays). Elevated Golden Ticket risk." `
                -Remediation 'Rotate the KRBTGT password (twice, 24h apart) using the Microsoft-provided New-KrbtgtKeys.ps1 to invalidate stolen tickets.'
        }

        Add-ADFinding -CheckName 'Test-KrbTgtAccountAge' -Status 'INFO' -Object 'krbtgt' `
            -Description "Enabled=$($k.Enabled); PasswordLastSet=$($k.PasswordLastSet) ($days days ago); KeyVersion=$($k.'msds-keyversionnumber'); Created=$($k.whenCreated)" `
            -Remediation 'Rotate KRBTGT password at least every 180 days.'
    }
    catch {
        Add-ADFinding -CheckName 'Test-KrbTgtAccountAge' -Status 'WARNING' -Object 'krbtgt' `
            -Description "Unable to audit krbtgt: $($_.Exception.Message)" `
            -Remediation 'Check permissions and that the krbtgt account exists.'
    }
}

function Test-KerberosPreAuthDisabled {
    <#
    .SYNOPSIS
        Finds enabled user accounts with Kerberos Pre-Authentication disabled (AS-REP roastable).
    #>
    [CmdletBinding()]
    param()

    Write-Host "`n[+] Checking for users with Kerberos Pre-Auth disabled..." -ForegroundColor Cyan
    try {
        $users = @(Get-ADUser -Filter * -Properties DoesNotRequirePreAuth, Enabled | Where-Object { $_.DoesNotRequirePreAuth -eq $true -and $_.Enabled -eq $true })
        foreach ($u in $users) {
            Add-ADFinding -CheckName 'Test-KerberosPreAuthDisabled' -Status 'FAIL' -Object $u.SamAccountName `
                -Description "'Do not require Kerberos preauthentication' is enabled (AS-REP roasting risk)." `
                -Remediation 'Disable the flag unless strictly required for a legacy application. Review for potential compromise.'
        }
        if ($users.Count -eq 0) {
            Add-ADFinding -CheckName 'Test-KerberosPreAuthDisabled' -Status 'PASS' -Object 'All Users' `
                -Description 'No enabled users with Kerberos Pre-Auth disabled.' `
                -Remediation 'No action needed.'
        }
    }
    catch {
        Add-ADFinding -CheckName 'Test-KerberosPreAuthDisabled' -Status 'WARNING' -Object 'Users' `
            -Description "Unable to enumerate users: $($_.Exception.Message)" `
            -Remediation 'Check permissions.'
    }
}

function Test-DuplicateSPNs {
    <#
    .SYNOPSIS
        Flags SPN values assigned to more than one AD object.
    #>
    [CmdletBinding()]
    param()

    Write-Host "`n[+] Checking for duplicate SPNs..." -ForegroundColor Cyan
    try {
        $objs = Get-ADObject -LDAPFilter '(|(objectClass=user)(objectClass=computer))' -Properties ServicePrincipalName
        $map = @{}
        foreach ($o in $objs) {
            if ($o.ServicePrincipalName) {
                foreach ($spn in $o.ServicePrincipalName) {
                    if (-not $map.ContainsKey($spn)) { $map[$spn] = @() }
                    $map[$spn] += $o.DistinguishedName
                }
            }
        }
        $dupCount = 0
        foreach ($kv in $map.GetEnumerator()) {
            if ($kv.Value.Count -gt 1) {
                $dupCount++
                Add-ADFinding -CheckName 'Test-DuplicateSPNs' -Status 'FAIL' -Object $kv.Key `
                    -Description "Duplicate SPN '$($kv.Key)' on $($kv.Value.Count) objects: $($kv.Value -join '; ')" `
                    -Remediation 'Each SPN must be assigned to exactly one account. Remove duplicates.'
            }
        }
        if ($dupCount -eq 0) {
            Add-ADFinding -CheckName 'Test-DuplicateSPNs' -Status 'PASS' -Object 'SPNs' `
                -Description 'No duplicate SPNs found.' -Remediation 'No action needed.'
        }
    }
    catch {
        Add-ADFinding -CheckName 'Test-DuplicateSPNs' -Status 'WARNING' -Object 'SPNs' `
            -Description "Unable to enumerate SPNs: $($_.Exception.Message)" `
            -Remediation 'Check permissions.'
    }
}

function Test-UserAccountsWithSPN {
    <#
    .SYNOPSIS
        Flags enabled user accounts carrying SPNs (Kerberoast exposure).
    #>
    [CmdletBinding()]
    param()

    Write-Host "`n[+] Checking for user accounts with SPNs (Kerberoast exposure)..." -ForegroundColor Cyan
    try {
        $users = @(Get-ADUser -Filter * -Properties ServicePrincipalName, Enabled, ObjectClass | Where-Object { $_.Enabled -and $_.ServicePrincipalName -and $_.ServicePrincipalName.Count -gt 0 -and $_.ObjectClass -eq 'user' })
        foreach ($u in $users) {
            Add-ADFinding -CheckName 'Test-UserAccountsWithSPN' -Status 'WARNING' -Object $u.SamAccountName `
                -Description 'User account carries one or more SPNs (Kerberoastable).' `
                -Remediation 'Move to a group Managed Service Account (gMSA) where possible. PR 2 will add password-age correlation to escalate this.'
        }
        if ($users.Count -eq 0) {
            Add-ADFinding -CheckName 'Test-UserAccountsWithSPN' -Status 'PASS' -Object 'All Users' `
                -Description 'No enabled users with SPNs.' -Remediation 'No action needed.'
        }
    }
    catch {
        Add-ADFinding -CheckName 'Test-UserAccountsWithSPN' -Status 'WARNING' -Object 'Users' `
            -Description "Unable to enumerate: $($_.Exception.Message)" `
            -Remediation 'Check permissions.'
    }
}

function Test-GPPPasswords {
    <#
    .SYNOPSIS
        Scans SYSVOL for Group Policy Preferences cpassword attributes.
    #>
    [CmdletBinding()]
    param()

    Write-Host "`n[+] Scanning SYSVOL for GPP cpasswords..." -ForegroundColor Cyan
    try {
        $sysvol = "\\$((Get-ADDomain).DNSRoot)\SYSVOL"
        $xmlFiles = Get-ChildItem -Path $sysvol -Recurse -Filter '*.xml' -ErrorAction SilentlyContinue
        $hit = $false
        foreach ($f in $xmlFiles) {
            $content = Get-Content -LiteralPath $f.FullName -ErrorAction SilentlyContinue
            if ($content -match 'cpassword="[^"]+') {
                $hit = $true
                Add-ADFinding -CheckName 'Test-GPPPasswords' -Status 'FAIL' -Object $f.FullName `
                    -Description 'GPP XML file contains a cpassword attribute (reversible password in SYSVOL).' `
                    -Remediation 'Remove the GPP cpassword from SYSVOL. Reset all credentials exposed. Do not use GPP for password management.'
            }
        }
        if (-not $hit) {
            Add-ADFinding -CheckName 'Test-GPPPasswords' -Status 'PASS' -Object 'GPP Passwords' `
                -Description 'No GPP cpasswords found in SYSVOL.' -Remediation 'No action needed.'
        }
    }
    catch {
        Add-ADFinding -CheckName 'Test-GPPPasswords' -Status 'WARNING' -Object 'GPP Passwords' `
            -Description "Unable to scan SYSVOL: $($_.Exception.Message)" `
            -Remediation 'Ensure SYSVOL is reachable and you have read permission.'
    }
}

#endregion

#region ==================== DELEGATION CHECKS ====================

function Test-UnconstrainedDelegation {
    <#
    .SYNOPSIS
        Flags enabled accounts with unconstrained delegation.
    #>
    [CmdletBinding()]
    param()

    Write-Host "`n[+] Checking for unconstrained delegation..." -ForegroundColor Cyan
    try {
        $comps = @(Get-ADComputer -Filter * -Properties TrustedForDelegation, Enabled | Where-Object { $_.TrustedForDelegation -eq $true -and $_.Enabled -eq $true })
        foreach ($c in $comps) {
            Add-ADFinding -CheckName 'Test-UnconstrainedDelegation' -Status 'FAIL' -Object $c.DNSHostName `
                -Description 'Computer has unconstrained delegation enabled.' `
                -Remediation 'Remove unconstrained delegation; use constrained delegation if needed.'
        }
        $users = @(Get-ADUser -Filter * -Properties TrustedForDelegation, Enabled | Where-Object { $_.TrustedForDelegation -eq $true -and $_.Enabled -eq $true })
        foreach ($u in $users) {
            Add-ADFinding -CheckName 'Test-UnconstrainedDelegation' -Status 'FAIL' -Object $u.SamAccountName `
                -Description 'User has unconstrained delegation enabled.' `
                -Remediation 'Disable unconstrained delegation. User accounts should almost never have this.'
        }
        if ($comps.Count -eq 0 -and $users.Count -eq 0) {
            Add-ADFinding -CheckName 'Test-UnconstrainedDelegation' -Status 'PASS' -Object 'All Accounts' `
                -Description 'No accounts with unconstrained delegation.' -Remediation 'No action needed.'
        }
    }
    catch {
        Add-ADFinding -CheckName 'Test-UnconstrainedDelegation' -Status 'WARNING' -Object 'Delegation' `
            -Description "Unable to enumerate: $($_.Exception.Message)" `
            -Remediation 'Check permissions.'
    }
}

function Test-DelegationOverview {
    <#
    .SYNOPSIS
        Enumerates both constrained and unconstrained delegation assignments.
    #>
    [CmdletBinding()]
    param()

    Write-Host "`n[+] Auditing delegation overview..." -ForegroundColor Cyan
    try {
        $cComps = @(Get-ADComputer -Filter * -Properties 'msDS-AllowedToDelegateTo', Enabled | Where-Object { $_.Enabled -and $_.'msDS-AllowedToDelegateTo' -and $_.'msDS-AllowedToDelegateTo'.Count -gt 0 })
        foreach ($c in $cComps) {
            $svcs = $c.'msDS-AllowedToDelegateTo' -join '; '
            Add-ADFinding -CheckName 'Test-DelegationOverview' -Status 'INFO' -Object $c.DNSHostName `
                -Description "Constrained delegation to: $svcs" `
                -Remediation 'Review business need and that targets are scoped correctly.'
        }
        $cUsers = @(Get-ADUser -Filter * -Properties 'msDS-AllowedToDelegateTo', Enabled | Where-Object { $_.Enabled -and $_.'msDS-AllowedToDelegateTo' -and $_.'msDS-AllowedToDelegateTo'.Count -gt 0 })
        foreach ($u in $cUsers) {
            $svcs = $u.'msDS-AllowedToDelegateTo' -join '; '
            Add-ADFinding -CheckName 'Test-DelegationOverview' -Status 'INFO' -Object $u.SamAccountName `
                -Description "User has constrained delegation to: $svcs" `
                -Remediation 'Review business need and scope.'
        }
        if ($cComps.Count -eq 0 -and $cUsers.Count -eq 0) {
            Add-ADFinding -CheckName 'Test-DelegationOverview' -Status 'INFO' -Object 'Delegation' `
                -Description 'No constrained-delegation configurations detected.' `
                -Remediation 'No action needed.'
        }
    }
    catch {
        Add-ADFinding -CheckName 'Test-DelegationOverview' -Status 'WARNING' -Object 'Delegation' `
            -Description "Unable to enumerate: $($_.Exception.Message)" `
            -Remediation 'Check permissions.'
    }
}

#endregion

#region ==================== ACCOUNT LIFECYCLE CHECKS ====================

function Test-ADStaleAccounts {
    <#
    .SYNOPSIS
        Flags enabled user accounts that are inactive or have stale passwords.
    #>
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingUsernameAndPasswordParams', '',
        Justification = 'Parameters are day-count thresholds, not credentials.')]
    param(
        [int]$UserLogonInactivityDays = $script:DefaultUserLogonInactivityDays,
        [int]$UserPasswordAgeDays = $script:DefaultUserPasswordAgeDays
    )

    Write-Host "`n[+] Checking stale accounts and passwords..." -ForegroundColor Cyan
    try {
        $users = Get-ADUser -Filter * -Properties SamAccountName, Enabled, LastLogonDate, PasswordLastSet
        $now = Get-Date
        $inactive = 0; $stalePwd = 0
        foreach ($u in $users | Where-Object { $_.Enabled }) {
            if ($u.LastLogonDate -and ($now - $u.LastLogonDate).Days -gt $UserLogonInactivityDays) {
                $inactive++
                Add-ADFinding -CheckName 'Test-ADStaleAccounts' -Status 'WARNING' -Object $u.SamAccountName `
                    -Description "Inactive $((($now - $u.LastLogonDate).Days)) days (last logon $($u.LastLogonDate))." `
                    -Remediation 'Review and consider disabling or removing.'
            }
            if ($u.PasswordLastSet -and ($now - $u.PasswordLastSet).Days -gt $UserPasswordAgeDays) {
                $stalePwd++
                Add-ADFinding -CheckName 'Test-ADStaleAccounts' -Status 'WARNING' -Object $u.SamAccountName `
                    -Description "Password not changed in $((($now - $u.PasswordLastSet).Days)) days (last set $($u.PasswordLastSet))." `
                    -Remediation 'Require password change or review necessity.'
            }
        }
        Add-ADFinding -CheckName 'Test-ADStaleAccounts' -Status 'INFO' -Object 'User Accounts' `
            -Description "Checked $($users.Count) enabled users: $inactive inactive, $stalePwd with stale passwords." `
            -Remediation 'Review flagged accounts above.'
    }
    catch {
        Add-ADFinding -CheckName 'Test-ADStaleAccounts' -Status 'WARNING' -Object 'User Accounts' `
            -Description "Unable to enumerate: $($_.Exception.Message)" `
            -Remediation 'Check permissions and AD module.'
    }
}

function Test-PasswordNeverExpires {
    <#
    .SYNOPSIS
        Flags enabled accounts with PasswordNeverExpires set.
    #>
    [CmdletBinding()]
    param()

    Write-Host "`n[+] Checking for PasswordNeverExpires..." -ForegroundColor Cyan
    try {
        $users = @(Get-ADUser -Filter * -Properties PasswordNeverExpires, Enabled | Where-Object { $_.PasswordNeverExpires -eq $true -and $_.Enabled -eq $true })
        foreach ($u in $users) {
            Add-ADFinding -CheckName 'Test-PasswordNeverExpires' -Status 'FAIL' -Object $u.SamAccountName `
                -Description "'Password never expires' is enabled." `
                -Remediation 'Require password expiration. For service accounts, consider migrating to a gMSA.'
        }
        if ($users.Count -eq 0) {
            Add-ADFinding -CheckName 'Test-PasswordNeverExpires' -Status 'PASS' -Object 'All Users' `
                -Description 'No accounts with PasswordNeverExpires.' -Remediation 'No action needed.'
        }
    }
    catch {
        Add-ADFinding -CheckName 'Test-PasswordNeverExpires' -Status 'WARNING' -Object 'Users' `
            -Description "Unable to enumerate: $($_.Exception.Message)" `
            -Remediation 'Check permissions.'
    }
}

function Test-ADServiceAccounts {
    <#
    .SYNOPSIS
        Enumerates MSA / gMSA accounts.
    #>
    [CmdletBinding()]
    param()

    Write-Host "`n[+] Enumerating managed service accounts..." -ForegroundColor Cyan
    try {
        $msa = @(Get-ADServiceAccount -Filter * -Properties SamAccountName, Enabled, LastLogonDate, PasswordLastSet, ObjectClass)
        if ($msa.Count -eq 0) {
            Add-ADFinding -CheckName 'Test-ADServiceAccounts' -Status 'INFO' -Object 'Service Accounts' `
                -Description 'No managed service accounts (classic or gMSA) in the domain.' `
                -Remediation 'Consider migrating service accounts to gMSA where possible.'
            return
        }
        foreach ($a in $msa) {
            $type = if ($a.ObjectClass -eq 'msDS-GroupManagedServiceAccount') { 'gMSA' } else { 'MSA' }
            Add-ADFinding -CheckName 'Test-ADServiceAccounts' -Status 'INFO' -Object "$($a.SamAccountName) [$type]" `
                -Description "Enabled=$($a.Enabled); PasswordLastSet=$($a.PasswordLastSet)" `
                -Remediation 'Review lifecycle and rotate credentials regularly.'
        }
        Add-ADFinding -CheckName 'Test-ADServiceAccounts' -Status 'INFO' -Object 'Service Accounts' `
            -Description "Total managed service accounts: $($msa.Count)." `
            -Remediation 'Monitor for unused or risky service accounts.'
    }
    catch {
        Add-ADFinding -CheckName 'Test-ADServiceAccounts' -Status 'WARNING' -Object 'Service Accounts' `
            -Description "Unable to enumerate: $($_.Exception.Message)" `
            -Remediation 'Check permissions.'
    }
}

function Test-PasswordsInDescription {
    <#
    .SYNOPSIS
        Scans Description fields on users / groups for password-like patterns.
    #>
    [CmdletBinding()]
    param()

    Write-Host "`n[+] Checking Description fields for secrets..." -ForegroundColor Cyan
    $patterns = @('password[\s:=]+.+', 'pwd[\s:=]+.+', 'pass[\s:=]+.+', 'secret[\s:=]+.+')
    $hit = $false
    try {
        $users = Get-ADUser -Filter * -Properties Description, Enabled | Where-Object { $_.Enabled -and $_.Description }
        foreach ($u in $users) {
            foreach ($p in $patterns) {
                if ($u.Description -match $p) {
                    $hit = $true
                    Add-ADFinding -CheckName 'Test-PasswordsInDescription' -Status 'FAIL' -Object $u.SamAccountName `
                        -Description "Description contains possible secret: '$($u.Description)'" `
                        -Remediation 'Remove secrets from Description immediately. Train admins on secure credential handling.'
                    break
                }
            }
        }
        $groups = Get-ADGroup -Filter * -Properties Description | Where-Object { $_.Description }
        foreach ($g in $groups) {
            foreach ($p in $patterns) {
                if ($g.Description -match $p) {
                    $hit = $true
                    Add-ADFinding -CheckName 'Test-PasswordsInDescription' -Status 'FAIL' -Object $g.SamAccountName `
                        -Description "Group Description contains possible secret: '$($g.Description)'" `
                        -Remediation 'Remove secrets from Description immediately.'
                    break
                }
            }
        }
        if (-not $hit) {
            Add-ADFinding -CheckName 'Test-PasswordsInDescription' -Status 'PASS' -Object 'All Accounts' `
                -Description 'No password-like patterns in Description fields.' -Remediation 'No action needed.'
        }
    }
    catch {
        Add-ADFinding -CheckName 'Test-PasswordsInDescription' -Status 'WARNING' -Object 'Descriptions' `
            -Description "Unable to scan: $($_.Exception.Message)" `
            -Remediation 'Check permissions.'
    }
}

#endregion

#region ==================== PRIVILEGED ACCESS CHECKS ====================

function Test-PrivilegedGroupMembership {
    <#
    .SYNOPSIS
        Enumerates privileged group members. Flags disabled accounts in admin groups.
    #>
    [CmdletBinding()]
    param()

    Write-Host "`n[+] Enumerating privileged group membership..." -ForegroundColor Cyan
    foreach ($gname in $script:PrivilegedGroups) {
        try {
            $members = Get-ADGroupMember -Identity $gname -Recursive -ErrorAction Stop
            $mInfo = @()
            foreach ($m in $members) {
                if ($m.objectClass -eq 'user') {
                    $user = Get-ADUser -Identity $m.SamAccountName -Properties Enabled
                    if (-not $user.Enabled) {
                        Add-ADFinding -CheckName 'Test-PrivilegedGroupMembership' -Status 'WARNING' `
                            -Object "$($user.SamAccountName) ($gname)" `
                            -Description "Disabled user is a member of '$gname'." `
                            -Remediation 'Remove disabled accounts from privileged groups.'
                    }
                    $mInfo += "$($user.SamAccountName) [user] (Enabled=$($user.Enabled))"
                }
                else {
                    $mInfo += "$($m.Name) [$($m.objectClass)]"
                }
            }
            Add-ADFinding -CheckName 'Test-PrivilegedGroupMembership' -Status 'INFO' -Object $gname `
                -Description "Members: $($mInfo -join '; ')" `
                -Remediation 'Review expected membership and privilege creep.'
        }
        catch {
            Add-ADFinding -CheckName 'Test-PrivilegedGroupMembership' -Status 'WARNING' -Object $gname `
                -Description "Unable to enumerate '$gname': $($_.Exception.Message)" `
                -Remediation 'Check permissions or if group exists in this domain.'
        }
    }
}

function Test-ProtectedUsersAdoption {
    <#
    .SYNOPSIS
        Enumerates Protected Users group members.
    #>
    [CmdletBinding()]
    param()

    Write-Host "`n[+] Checking Protected Users adoption..." -ForegroundColor Cyan
    $gname = 'Protected Users'
    try {
        $members = @(Get-ADGroupMember -Identity $gname -ErrorAction Stop)
        if ($members.Count -eq 0) {
            Add-ADFinding -CheckName 'Test-ProtectedUsersAdoption' -Status 'WARNING' -Object $gname `
                -Description 'Protected Users group has no members.' `
                -Remediation 'Add high-value accounts (admins, sensitive service accounts) for enhanced credential protection.'
        }
        else {
            $list = ($members | ForEach-Object { $_.Name }) -join '; '
            Add-ADFinding -CheckName 'Test-ProtectedUsersAdoption' -Status 'INFO' -Object $gname `
                -Description "Members: $list" `
                -Remediation 'Review membership; add critical accounts where appropriate.'
        }
    }
    catch {
        Add-ADFinding -CheckName 'Test-ProtectedUsersAdoption' -Status 'WARNING' -Object $gname `
            -Description "Protected Users not accessible: $($_.Exception.Message)" `
            -Remediation 'Ensure the domain functional level supports Protected Users and the running user has read rights.'
    }
}

function Test-SIDHistory {
    <#
    .SYNOPSIS
        Flags enabled users / groups that carry SIDHistory values.
    #>
    [CmdletBinding()]
    param()

    Write-Host "`n[+] Checking for SIDHistory..." -ForegroundColor Cyan
    try {
        $users = @(Get-ADUser -Filter * -Properties SIDHistory, Enabled | Where-Object { $_.SIDHistory -and $_.SIDHistory.Count -gt 0 -and $_.Enabled -eq $true })
        foreach ($u in $users) {
            Add-ADFinding -CheckName 'Test-SIDHistory' -Status 'WARNING' -Object $u.SamAccountName `
                -Description 'User has SIDHistory values set.' `
                -Remediation 'Investigate why. Remove legacy SIDs post-migration. Monitor for unauthorized use.'
        }
        $groups = @(Get-ADGroup -Filter * -Properties SIDHistory | Where-Object { $_.SIDHistory -and $_.SIDHistory.Count -gt 0 })
        foreach ($g in $groups) {
            Add-ADFinding -CheckName 'Test-SIDHistory' -Status 'WARNING' -Object $g.SamAccountName `
                -Description 'Group has SIDHistory values set.' `
                -Remediation 'Review necessity; remove legacy SIDs if migration is complete.'
        }
        if ($users.Count -eq 0 -and $groups.Count -eq 0) {
            Add-ADFinding -CheckName 'Test-SIDHistory' -Status 'PASS' -Object 'All Users & Groups' `
                -Description 'No SIDHistory values found.' -Remediation 'No action needed.'
        }
    }
    catch {
        Add-ADFinding -CheckName 'Test-SIDHistory' -Status 'WARNING' -Object 'SIDHistory' `
            -Description "Unable to enumerate: $($_.Exception.Message)" `
            -Remediation 'Check permissions.'
    }
}

function Test-PrivilegedSmartcardRequirement {
    <#
    .SYNOPSIS
        Flags privileged users without SmartcardLogonRequired.
    #>
    [CmdletBinding()]
    param()

    Write-Host "`n[+] Checking privileged users for smartcard requirement..." -ForegroundColor Cyan
    $failHit = $false
    foreach ($gname in $script:PrivilegedGroups) {
        try {
            $members = Get-ADGroupMember -Identity $gname -Recursive -ErrorAction Stop | Where-Object { $_.objectClass -eq 'user' }
        }
        catch { continue }
        foreach ($m in $members) {
            $user = Get-ADUser -Identity $m.SamAccountName -Properties SmartcardLogonRequired, Enabled
            if ($user.Enabled -and -not $user.SmartcardLogonRequired) {
                $failHit = $true
                Add-ADFinding -CheckName 'Test-PrivilegedSmartcardRequirement' -Status 'FAIL' -Object $user.SamAccountName `
                    -Description "Privileged user '$($user.SamAccountName)' in '$gname' does NOT require smartcard logon." `
                    -Remediation 'Enforce smartcard MFA for all privileged users.'
            }
        }
    }
    if (-not $failHit) {
        Add-ADFinding -CheckName 'Test-PrivilegedSmartcardRequirement' -Status 'PASS' -Object 'Privileged Users' `
            -Description 'All privileged users require smartcard logon.' -Remediation 'No action needed.'
    }
}

function Test-PrivilegedGroupCreep {
    <#
    .SYNOPSIS
        Flags privileged-group members not on an approved whitelist.
    #>
    [CmdletBinding()]
    param(
        [hashtable]$Whitelist
    )

    Write-Host "`n[+] Checking for privilege creep in privileged groups..." -ForegroundColor Cyan
    # Default whitelist — conservative: only Administrator is allowed in any privileged group by default.
    if (-not $Whitelist) {
        $Whitelist = @{}
        foreach ($g in $script:PrivilegedGroups) { $Whitelist[$g] = @('Administrator') }
    }
    $failHit = $false
    foreach ($gname in $script:PrivilegedGroups) {
        try {
            $members = Get-ADGroupMember -Identity $gname -Recursive -ErrorAction Stop | Where-Object { $_.objectClass -eq 'user' }
        }
        catch { continue }
        $wl = $Whitelist[$gname]
        foreach ($m in $members) {
            if ($null -eq $wl -or $wl.Count -eq 0 -or $wl -notcontains $m.SamAccountName) {
                $failHit = $true
                Add-ADFinding -CheckName 'Test-PrivilegedGroupCreep' -Status 'WARNING' `
                    -Object "$($m.SamAccountName) ($gname)" `
                    -Description "User '$($m.SamAccountName)' is in privileged group '$gname' but is NOT on the approved whitelist." `
                    -Remediation "Review membership of '$gname'. Remove if unauthorized. Update whitelist as needed."
            }
        }
    }
    if (-not $failHit) {
        Add-ADFinding -CheckName 'Test-PrivilegedGroupCreep' -Status 'PASS' -Object 'Privileged Groups' `
            -Description 'No non-whitelisted members in privileged groups.' -Remediation 'No action needed.'
    }
}

function Test-AdminSDHolderDrift {
    <#
    .SYNOPSIS
        Detects ACL or owner drift on the AdminSDHolder object.
    #>
    [CmdletBinding()]
    param()

    Write-Host "`n[+] Checking AdminSDHolder ACL drift..." -ForegroundColor Cyan
    $dn = "CN=AdminSDHolder, CN=System, $((Get-ADDomain).DistinguishedName)"
    try {
        $acl = Get-Acl -Path ("AD:\$dn")
    }
    catch {
        Add-ADFinding -CheckName 'Test-AdminSDHolderDrift' -Status 'WARNING' -Object 'AdminSDHolder' `
            -Description "Unable to read AdminSDHolder ACL: $($_.Exception.Message)" `
            -Remediation 'Run with sufficient privileges (Domain Admin).'
        return
    }
    $expectedOwners = @('Domain Admins', 'Enterprise Admins')
    $ownerOK = $false
    foreach ($eo in $expectedOwners) { if ($acl.Owner -like "*$eo*") { $ownerOK = $true; break } }
    if (-not $ownerOK) {
        Add-ADFinding -CheckName 'Test-AdminSDHolderDrift' -Status 'WARNING' -Object 'AdminSDHolder' `
            -Description "Owner is not a privileged group (owner: $($acl.Owner))." `
            -Remediation 'Restore ownership to Domain Admins or Enterprise Admins.'
    }
    $flagged = @($acl.Access | Where-Object { ($_.ActiveDirectoryRights -match 'WriteProperty|GenericAll|GenericWrite|All') -and ($_.IdentityReference -notmatch 'Domain Admins|Enterprise Admins|SYSTEM|Administrators|SELF') })
    foreach ($a in $flagged) {
        Add-ADFinding -CheckName 'Test-AdminSDHolderDrift' -Status 'FAIL' -Object "AdminSDHolder ($($a.IdentityReference))" `
            -Description "Non-standard permission: '$($a.IdentityReference)' has '$($a.ActiveDirectoryRights)' on AdminSDHolder." `
            -Remediation 'Remove unauthorized ACEs from AdminSDHolder. Only privileged groups should have write rights.'
    }
    if ($flagged.Count -eq 0 -and $ownerOK) {
        Add-ADFinding -CheckName 'Test-AdminSDHolderDrift' -Status 'PASS' -Object 'AdminSDHolder' `
            -Description 'No ACL or owner drift.' -Remediation 'No action needed.'
    }
}

function Test-DangerousSIDsInPrivilegedGroups {
    <#
    .SYNOPSIS
        Flags dangerous well-known SIDs (Everyone, Anonymous Logon) in privileged groups.
    #>
    [CmdletBinding()]
    param()

    Write-Host "`n[+] Checking for dangerous SIDs in privileged groups..." -ForegroundColor Cyan
    $dangerous = @{ 'Everyone' = 'S-1-1-0'; 'Anonymous Logon' = 'S-1-5-7' }
    $failHit = $false
    foreach ($gname in $script:PrivilegedGroups) {
        try {
            $members = Get-ADGroupMember -Identity $gname -Recursive -ErrorAction Stop
        }
        catch { continue }
        foreach ($label in $dangerous.Keys) {
            $sid = $dangerous[$label]
            foreach ($m in $members) {
                if ($m.SID -and $m.SID.Value -eq $sid) {
                    $failHit = $true
                    Add-ADFinding -CheckName 'Test-DangerousSIDsInPrivilegedGroups' -Status 'FAIL' -Object $gname `
                        -Description "Privileged group '$gname' contains dangerous SID '$label' ($sid)." `
                        -Remediation 'Remove immediately. Audit for similar entries in all critical groups.'
                }
            }
        }
    }
    if (-not $failHit) {
        Add-ADFinding -CheckName 'Test-DangerousSIDsInPrivilegedGroups' -Status 'PASS' -Object 'Privileged Groups' `
            -Description 'No dangerous SIDs detected.' -Remediation 'No action needed.'
    }
}

function Test-PrivilegedObjectACLs {
    <#
    .SYNOPSIS
        Audits ACLs on privileged group containers.
    #>
    [CmdletBinding()]
    param()

    Write-Host "`n[+] Auditing ACLs on privileged objects..." -ForegroundColor Cyan
    $dn = (Get-ADDomain).DistinguishedName
    $objects = @(
        "CN=Domain Admins, CN=Users, $dn",
        "CN=Enterprise Admins, CN=Users, $dn",
        "CN=Administrators, CN=Builtin, $dn",
        "CN=Schema Admins, CN=Users, $dn",
        "CN=Account Operators, CN=Users, $dn",
        "CN=Backup Operators, CN=Users, $dn"
    )
    foreach ($o in $objects) {
        try {
            $acl = Get-Acl -Path ("AD:\$o")
            $risky = @($acl.Access | Where-Object { ($_.ActiveDirectoryRights -match 'GenericAll|GenericWrite|All|WriteProperty') -and ($script:AdminPrincipals -notcontains $_.IdentityReference.Value) })
            foreach ($r in $risky) {
                Add-ADFinding -CheckName 'Test-PrivilegedObjectACLs' -Status 'WARNING' -Object $o `
                    -Description "Non-admin '$($r.IdentityReference)' has '$($r.ActiveDirectoryRights)' on '$o'." `
                    -Remediation 'Restrict rights on privileged objects to admin teams only.'
            }
        }
        catch {
            Add-ADFinding -CheckName 'Test-PrivilegedObjectACLs' -Status 'WARNING' -Object $o `
                -Description "Unable to retrieve ACL: $($_.Exception.Message)" `
                -Remediation 'Check permissions or whether the object exists.'
        }
    }
}

function Test-OUAndGPODelegation {
    <#
    .SYNOPSIS
        Scans OUs and GPOs for non-admin write / GenericAll ACEs.
    #>
    [CmdletBinding()]
    param()

    Write-Host "`n[+] Checking OU and GPO delegation..." -ForegroundColor Cyan
    $failHit = $false
    try {
        $ous = Get-ADOrganizationalUnit -Filter * | Sort-Object DistinguishedName
        foreach ($ou in $ous) {
            try { $acl = Get-Acl -Path ("AD:\$($ou.DistinguishedName)") } catch { continue }
            $risky = @($acl.Access | Where-Object { ($_.ActiveDirectoryRights -match 'WriteProperty|GenericWrite|GenericAll|All') -and ($script:AdminPrincipals -notcontains $_.IdentityReference.Value) })
            foreach ($r in $risky) {
                $failHit = $true
                Add-ADFinding -CheckName 'Test-OUAndGPODelegation' -Status 'WARNING' -Object "OU: $($ou.Name)" `
                    -Description "OU '$($ou.Name)' grants '$($r.ActiveDirectoryRights)' to non-admin '$($r.IdentityReference)'." `
                    -Remediation 'Review and remove non-admin delegation unless business-justified.'
            }
        }
        if (Get-Module -ListAvailable -Name GroupPolicy) {
            $gpos = Get-GPO -All
            foreach ($g in $gpos) {
                $gdn = "CN={$($g.Id)}, CN=Policies, CN=System, $((Get-ADDomain).DistinguishedName)"
                try { $acl = Get-Acl -Path ("AD:\$gdn") } catch { continue }
                $risky = @($acl.Access | Where-Object { ($_.ActiveDirectoryRights -match 'WriteProperty|GenericWrite|GenericAll|All') -and ($script:AdminPrincipals -notcontains $_.IdentityReference.Value) })
                foreach ($r in $risky) {
                    $failHit = $true
                    Add-ADFinding -CheckName 'Test-OUAndGPODelegation' -Status 'WARNING' -Object "GPO: $($g.DisplayName)" `
                        -Description "GPO '$($g.DisplayName)' grants '$($r.ActiveDirectoryRights)' to non-admin '$($r.IdentityReference)'." `
                        -Remediation 'Review and remove non-admin delegation unless business-justified.'
                }
            }
        }
        if (-not $failHit) {
            Add-ADFinding -CheckName 'Test-OUAndGPODelegation' -Status 'PASS' -Object 'OUs and GPOs' `
                -Description 'No risky non-admin write permissions detected.' -Remediation 'No action needed.'
        }
    }
    catch {
        Add-ADFinding -CheckName 'Test-OUAndGPODelegation' -Status 'WARNING' -Object 'OU/GPO Delegation' `
            -Description "Unable to enumerate: $($_.Exception.Message)" `
            -Remediation 'Check permissions.'
    }
}

function Test-RecentPrivilegedAccounts {
    <#
    .SYNOPSIS
        Flags privileged-group members created in the last N days.
    #>
    [CmdletBinding()]
    param(
        [int]$RecentDays = $script:DefaultRecentPrivilegedAccountDays
    )

    Write-Host "`n[+] Checking for recently-created privileged accounts..." -ForegroundColor Cyan
    $threshold = (Get-Date).AddDays(-$RecentDays)
    $failHit = $false
    foreach ($gname in $script:PrivilegedGroups) {
        try {
            $members = Get-ADGroupMember -Identity $gname -Recursive -ErrorAction Stop | Where-Object { $_.objectClass -eq 'user' }
        }
        catch { continue }
        foreach ($m in $members) {
            $u = Get-ADUser -Identity $m.SamAccountName -Properties whenCreated, Enabled
            if ($u.Enabled -and $u.whenCreated -gt $threshold) {
                $failHit = $true
                Add-ADFinding -CheckName 'Test-RecentPrivilegedAccounts' -Status 'FAIL' `
                    -Object "$($u.SamAccountName) ($gname)" `
                    -Description "Privileged user '$($u.SamAccountName)' created $($u.whenCreated) (<$RecentDays days ago)." `
                    -Remediation 'Verify the creation was authorized. Investigate for possible persistence.'
            }
        }
    }
    if (-not $failHit) {
        Add-ADFinding -CheckName 'Test-RecentPrivilegedAccounts' -Status 'PASS' -Object 'Privileged Accounts' `
            -Description "No privileged accounts created in the last $RecentDays days." `
            -Remediation 'No action needed.'
    }
}

function Test-NestedGroupPrivilegePaths {
    <#
    .SYNOPSIS
        Flags ForeignSecurityPrincipals in privileged groups (cross-domain / trust members).
    #>
    [CmdletBinding()]
    param()

    Write-Host "`n[+] Checking for foreign-trust members in privileged groups..." -ForegroundColor Cyan
    $failHit = $false
    foreach ($gname in $script:PrivilegedGroups) {
        try {
            $members = Get-ADGroupMember -Identity $gname -Recursive -ErrorAction Stop
        }
        catch { continue }
        foreach ($m in $members) {
            if ($m.objectClass -eq 'foreignSecurityPrincipal') {
                $failHit = $true
                Add-ADFinding -CheckName 'Test-NestedGroupPrivilegePaths' -Status 'WARNING' -Object $gname `
                    -Description "Privileged group '$gname' contains a ForeignSecurityPrincipal: $($m.Name)." `
                    -Remediation 'Verify and minimize trusted-domain membership in privileged groups.'
            }
        }
    }
    if (-not $failHit) {
        Add-ADFinding -CheckName 'Test-NestedGroupPrivilegePaths' -Status 'PASS' -Object 'Privileged Groups' `
            -Description 'No ForeignSecurityPrincipals in privileged groups.' `
            -Remediation 'No action needed.'
    }
}

function Test-SensitiveObjectACLDrift {
    <#
    .SYNOPSIS
        Scans sensitive AD objects for non-admin ACEs with broad rights.
    #>
    [CmdletBinding()]
    param()

    Write-Host "`n[+] Checking ACL drift on sensitive AD objects..." -ForegroundColor Cyan
    $dn = (Get-ADDomain).DistinguishedName
    $objs = @(
        "CN=Domain Admins, CN=Users, $dn",
        "CN=Enterprise Admins, CN=Users, $dn",
        "CN=Administrators, CN=Builtin, $dn",
        "CN=Schema Admins, CN=Users, $dn",
        "CN=Account Operators, CN=Users, $dn",
        "CN=Backup Operators, CN=Users, $dn"
    )
    $failHit = $false
    foreach ($o in $objs) {
        try { $acl = Get-Acl -Path ("AD:\$o") }
        catch {
            Add-ADFinding -CheckName 'Test-SensitiveObjectACLDrift' -Status 'WARNING' -Object $o `
                -Description "Unable to read ACL for '$o'." `
                -Remediation 'Verify object exists and permissions are healthy.'
            continue
        }
        $risky = @($acl.Access | Where-Object { ($_.ActiveDirectoryRights -match 'WriteProperty|GenericWrite|GenericAll|All') -and ($script:AdminPrincipals -notcontains $_.IdentityReference.Value) })
        foreach ($r in $risky) {
            $failHit = $true
            Add-ADFinding -CheckName 'Test-SensitiveObjectACLDrift' -Status 'FAIL' -Object $o `
                -Description "Non-admin '$($r.IdentityReference)' has '$($r.ActiveDirectoryRights)' on '$o'." `
                -Remediation 'Remove unauthorized write permissions. Only admin teams should hold broad rights.'
        }
    }
    if (-not $failHit) {
        Add-ADFinding -CheckName 'Test-SensitiveObjectACLDrift' -Status 'PASS' -Object 'Sensitive Objects' `
            -Description 'No risky non-admin write permissions detected.' -Remediation 'No action needed.'
    }
}

function Test-ShadowGroupNames {
    <#
    .SYNOPSIS
        Flags groups with names that typosquat privileged groups.
    #>
    [CmdletBinding()]
    param()

    Write-Host "`n[+] Checking for shadow / lookalike group names..." -ForegroundColor Cyan
    $patterns = @(
        'Domain Admin', 'DomainAdministrator', 'Domain_Administrator', 'Domain Administrators',
        'Domian Admins', 'DomianAdmins', 'Enterprise Admin', 'EnterpriseAdministrator',
        'Enterprise Administrators', 'Schema Admin', 'SchemaAdministrator',
        'Administrat0rs', 'Adm1n', 'Account Operator', 'Backup Operator', 'Ops', 'Root'
    )
    $failHit = $false
    try {
        $all = Get-ADGroup -Filter * | Sort-Object Name
        foreach ($g in $all) {
            if ($script:PrivilegedGroups -contains $g.Name) { continue }
            foreach ($p in $patterns) {
                if ($g.Name -like "*$p*") {
                    $failHit = $true
                    Add-ADFinding -CheckName 'Test-ShadowGroupNames' -Status 'WARNING' -Object $g.Name `
                        -Description "Suspicious group name: '$($g.Name)' (possible shadow / lookalike admin group)." `
                        -Remediation 'Review this group for unnecessary privileges. Remove if not required.'
                    break
                }
            }
        }
        if (-not $failHit) {
            Add-ADFinding -CheckName 'Test-ShadowGroupNames' -Status 'PASS' -Object 'Groups' `
                -Description 'No suspicious shadow group names detected.' -Remediation 'No action needed.'
        }
    }
    catch {
        Add-ADFinding -CheckName 'Test-ShadowGroupNames' -Status 'WARNING' -Object 'Groups' `
            -Description "Unable to enumerate: $($_.Exception.Message)" `
            -Remediation 'Check permissions.'
    }
}

#endregion

#region ==================== PR 2 — HIGH-VALUE COVERAGE GAPS ====================

function Test-LAPSDeployment {
    <#
    .SYNOPSIS
        Checks Local Administrator Password Solution (LAPS) schema + coverage.
    .DESCRIPTION
        Detects whether the LAPS schema extensions are present (legacy
        ms-Mcs-AdmPwd* or Windows LAPS msLAPS-*), samples domain-joined
        computers, and reports coverage percentage. Missing schema, missing
        computer-level population, or expired passwords are flagged.
    .PARAMETER SampleSize
        Maximum number of computers to sample. Default 200.
    .PARAMETER CoverageGoalPercent
        Pass threshold. Default 90.
    #>
    [CmdletBinding()]
    param(
        [int]$SampleSize = 200,
        [int]$CoverageGoalPercent = 90
    )

    Write-Host "`n[+] Checking LAPS deployment..." -ForegroundColor Cyan
    try {
        # Schema probe — look for either legacy LAPS or Windows LAPS attributes on the computer schema.
        $schemaDN = (Get-ADRootDSE).schemaNamingContext
        $computerSchema = Get-ADObject -Identity "CN=Computer,$schemaDN" -Properties mayContain, systemMayContain -ErrorAction SilentlyContinue
        $may = @()
        if ($computerSchema.mayContain) { $may += $computerSchema.mayContain }
        if ($computerSchema.systemMayContain) { $may += $computerSchema.systemMayContain }

        $hasLegacyLAPS = $may -contains 'ms-Mcs-AdmPwd'
        $hasWindowsLAPS = $may -contains 'msLAPS-Password' -or $may -contains 'msLAPS-EncryptedPassword'

        if (-not $hasLegacyLAPS -and -not $hasWindowsLAPS) {
            Add-ADFinding -CheckName 'Test-LAPSDeployment' -Status 'FAIL' -Object 'LAPS Schema' `
                -Description 'Neither legacy LAPS (ms-Mcs-AdmPwd) nor Windows LAPS (msLAPS-Password) schema extensions are present in the domain.' `
                -Remediation 'Deploy Windows LAPS via the Windows LAPS GPO templates + Update-LapsADSchema. Legacy LAPS can be installed with Import-Module AdmPwd.PS; Update-AdmPwdADSchema.'
            return
        }

        $schemaVariant = if ($hasWindowsLAPS) { 'Windows LAPS' } else { 'Legacy LAPS (ms-Mcs-AdmPwd)' }

        # Coverage sampling. We look at an enabled-computer sample and see how many have the password attribute populated + not expired.
        $pwdAttr = if ($hasWindowsLAPS) { 'msLAPS-Password', 'msLAPS-PasswordExpirationTime' } else { 'ms-Mcs-AdmPwd', 'ms-Mcs-AdmPwdExpirationTime' }
        $computers = @(Get-ADComputer -Filter 'Enabled -eq $true' -Properties $pwdAttr -ResultSetSize $SampleSize -ErrorAction Stop)

        if ($computers.Count -eq 0) {
            Add-ADFinding -CheckName 'Test-LAPSDeployment' -Status 'INFO' -Object 'LAPS Coverage' `
                -Description 'No enabled computers found in the domain to sample.' `
                -Remediation 'No action needed.'
            return
        }

        $withPwd = @($computers | Where-Object {
                $v = $_.($pwdAttr[0])
                $null -ne $v -and $v -ne ''
            })
        $expAttr = $pwdAttr[1]
        $now = [DateTime]::UtcNow
        $expired = @($withPwd | Where-Object {
                $rawExp = $_.$expAttr
                if (-not $rawExp) { return $false }
                try {
                    $expTime = if ($rawExp -is [long] -or $rawExp -is [int64]) {
                        [DateTime]::FromFileTimeUtc([long]$rawExp)
                    }
                    elseif ($rawExp -is [DateTime]) { $rawExp }
                    else { [DateTime]$rawExp }
                    $expTime -lt $now
                }
                catch { $false }
            })

        $coverage = [math]::Round(($withPwd.Count / $computers.Count) * 100, 1)
        $summary = "Schema: $schemaVariant; coverage: $($withPwd.Count) of $($computers.Count) sampled computers have a LAPS password populated ($coverage%); $($expired.Count) expired."

        if ($coverage -ge $CoverageGoalPercent -and $expired.Count -eq 0) {
            Add-ADFinding -CheckName 'Test-LAPSDeployment' -Status 'PASS' -Object 'LAPS Coverage' `
                -Description $summary `
                -Remediation 'No action needed.'
        }
        elseif ($coverage -lt 50 -or $expired.Count -gt ($withPwd.Count * 0.25)) {
            Add-ADFinding -CheckName 'Test-LAPSDeployment' -Status 'FAIL' -Object 'LAPS Coverage' `
                -Description "$summary Coverage below 50% OR more than 25% of populated passwords are expired." `
                -Remediation 'Investigate LAPS agent deployment and the targeting GPO. Confirm the computers in scope are receiving the LAPS password-rotation policy.'
        }
        else {
            Add-ADFinding -CheckName 'Test-LAPSDeployment' -Status 'WARNING' -Object 'LAPS Coverage' `
                -Description $summary `
                -Remediation "Bring coverage above $CoverageGoalPercent%. Investigate the $($computers.Count - $withPwd.Count) computers without a populated password."
        }

        # Top missing computers, up to 20 for the remediation trail.
        $missing = @($computers | Where-Object {
                $v = $_.($pwdAttr[0])
                $null -eq $v -or $v -eq ''
            }) | Select-Object -First 20
        foreach ($m in $missing) {
            Add-ADFinding -CheckName 'Test-LAPSDeployment' -Status 'WARNING' -Object $m.DNSHostName `
                -Description "Computer does not have a populated LAPS password ($schemaVariant)." `
                -Remediation 'Verify LAPS agent installation and that the targeting GPO applies to this computer.'
        }
    }
    catch {
        Add-ADFinding -CheckName 'Test-LAPSDeployment' -Status 'WARNING' -Object 'LAPS' `
            -Description "Unable to evaluate LAPS deployment: $($_.Exception.Message)" `
            -Remediation 'Ensure the running user can read computer accounts and the LAPS schema attributes.'
    }
}

function Test-DCSecuritySettings {
    <#
    .SYNOPSIS
        Audits per-DC security settings (LDAP signing, channel binding, SMB signing, SMBv1, null sessions).
    .DESCRIPTION
        Iterates every DC and queries its registry via Invoke-Command for the
        critical hardening settings. Failures are scoped to a single DC so a
        locked-down DC doesn't poison the assessment for the rest.
    #>
    [CmdletBinding()]
    param()

    Write-Host "`n[+] Auditing DC security settings..." -ForegroundColor Cyan
    try {
        $dcs = Get-ADDomainController -Filter *
    }
    catch {
        Add-ADFinding -CheckName 'Test-DCSecuritySettings' -Status 'WARNING' -Object 'Domain Controllers' `
            -Description "Unable to enumerate DCs: $($_.Exception.Message)" `
            -Remediation 'Check permissions.'
        return
    }

    # Registry probes. Each entry: {Label; Hive; Path; Value; ExpectedValues (array of OK values); Remediation}.
    $probes = @(
        @{ Label = 'LDAP server signing'; Path = 'SYSTEM\CurrentControlSet\Services\NTDS\Parameters'; Value = 'LDAPServerIntegrity'; ExpectedValues = @(2); Remediation = 'Set HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity = 2 (Require signing). Enforce via GPO.' },
        @{ Label = 'LDAP channel binding'; Path = 'SYSTEM\CurrentControlSet\Services\NTDS\Parameters'; Value = 'LdapEnforceChannelBinding'; ExpectedValues = @(2); Remediation = 'Set HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\LdapEnforceChannelBinding = 2 (Always). See ADV190023.' },
        @{ Label = 'SMB signing required'; Path = 'SYSTEM\CurrentControlSet\Services\LanManServer\Parameters'; Value = 'RequireSecuritySignature'; ExpectedValues = @(1); Remediation = 'Set HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature = 1. Enforce via GPO: Microsoft network server: Digitally sign communications (always).' },
        @{ Label = 'SMBv1 disabled'; Path = 'SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; Value = 'SMB1'; ExpectedValues = @(0, $null); Remediation = 'Disable SMBv1: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol.' },
        @{ Label = 'Restrict anonymous'; Path = 'SYSTEM\CurrentControlSet\Control\Lsa'; Value = 'RestrictAnonymous'; ExpectedValues = @(1, 2); Remediation = 'Set HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\RestrictAnonymous = 1 (or 2). Restricts null-session access.' }
    )

    $anyFail = $false
    foreach ($dc in $dcs) {
        try {
            $result = Invoke-Command -ComputerName $dc.HostName -ScriptBlock {
                param($probes)
                $out = @{}
                foreach ($p in $probes) {
                    try {
                        $v = Get-ItemProperty -Path "HKLM:\$($p.Path)" -Name $p.Value -ErrorAction Stop
                        $out[$p.Label] = $v.($p.Value)
                    }
                    catch {
                        $out[$p.Label] = $null
                    }
                }
                return $out
            } -ArgumentList (, $probes) -ErrorAction Stop
        }
        catch {
            Add-ADFinding -CheckName 'Test-DCSecuritySettings' -Status 'WARNING' -Object $dc.HostName `
                -Description "PSRemoting / registry query unavailable on this DC: $($_.Exception.Message)" `
                -Remediation 'Enable PSRemoting (Enable-PSRemoting) or run this check directly on the DC. Check is advisory until this resolves.'
            continue
        }

        foreach ($p in $probes) {
            $actual = $result[$p.Label]
            $ok = $false
            foreach ($expected in $p.ExpectedValues) {
                if ($null -eq $expected -and $null -eq $actual) { $ok = $true; break }
                if ($actual -eq $expected) { $ok = $true; break }
            }
            if ($ok) {
                Add-ADFinding -CheckName 'Test-DCSecuritySettings' -Status 'PASS' -Object "$($dc.HostName) - $($p.Label)" `
                    -Description "$($p.Label) on $($dc.HostName) is compliant (value: $actual)." `
                    -Remediation 'No action needed.'
            }
            else {
                $anyFail = $true
                Add-ADFinding -CheckName 'Test-DCSecuritySettings' -Status 'FAIL' -Object "$($dc.HostName) - $($p.Label)" `
                    -Description "$($p.Label) on $($dc.HostName) is not compliant (value: $actual; expected: $($p.ExpectedValues -join ' or '))." `
                    -Remediation $p.Remediation
            }
        }
    }

    if (-not $anyFail) {
        # Summary PASS for the check as a whole, makes filtering easier.
        Add-ADFinding -CheckName 'Test-DCSecuritySettings' -Status 'INFO' -Object 'All DCs' `
            -Description "All $($dcs.Count) DCs passed every probed hardening setting (LDAP signing, channel binding, SMB signing, SMBv1, null sessions)." `
            -Remediation 'No action needed.'
    }
}

function Test-KerberoastableAccounts {
    <#
    .SYNOPSIS
        Extends Test-UserAccountsWithSPN with password-age + weak-hash correlation.
    .DESCRIPTION
        An account is Kerberoastable if it has an SPN, its password is
        crackable in reasonable time (old + weak hash), and ideally it is
        also privileged. Severity escalates accordingly.
    .PARAMETER PasswordAgeDays
        Flag SPN-bearing accounts whose password is older than this. Default 90.
    #>
    [CmdletBinding()]
    param(
        [int]$PasswordAgeDays = 90
    )

    Write-Host "`n[+] Checking Kerberoastable accounts (SPN + password age + hash support)..." -ForegroundColor Cyan
    try {
        $users = @(Get-ADUser -Filter { ServicePrincipalName -like '*' } `
                -Properties ServicePrincipalName, PasswordLastSet, 'msDS-SupportedEncryptionTypes', MemberOf, Enabled |
                Where-Object { $_.Enabled })
        if ($users.Count -eq 0) {
            Add-ADFinding -CheckName 'Test-KerberoastableAccounts' -Status 'PASS' -Object 'All Users' `
                -Description 'No enabled user accounts with SPNs.' -Remediation 'No action needed.'
            return
        }

        $now = Get-Date
        # AES flag constants per MS-KILE: 0x8=AES128, 0x10=AES256. 0x18 = both.
        $aesBits = 0x18
        $privilegedNames = $script:PrivilegedGroups
        $anyFail = $false

        foreach ($u in $users) {
            $days = if ($u.PasswordLastSet) { ($now - $u.PasswordLastSet).Days } else { 99999 }
            $supportedEnc = if ($null -ne $u.'msDS-SupportedEncryptionTypes') { [int]$u.'msDS-SupportedEncryptionTypes' } else { 0 }
            $aesOnly = (($supportedEnc -band $aesBits) -eq $aesBits) -and (($supportedEnc -band 0x4) -eq 0)
            $isPrivileged = $false
            if ($u.MemberOf) {
                foreach ($dn in $u.MemberOf) {
                    foreach ($p in $privilegedNames) {
                        if ($dn -like "CN=$p,*") { $isPrivileged = $true; break }
                    }
                    if ($isPrivileged) { break }
                }
            }

            $label = if ($isPrivileged) { "$($u.SamAccountName) [PRIVILEGED]" } else { $u.SamAccountName }
            $detail = "PasswordAge=${days}d; SupportedEnc=0x$([Convert]::ToString($supportedEnc, 16)); AES-only=$aesOnly; Privileged=$isPrivileged"

            if ($isPrivileged -and -not $aesOnly) {
                $anyFail = $true
                Add-ADFinding -CheckName 'Test-KerberoastableAccounts' -Status 'FAIL' -Object $label `
                    -Description "Privileged SPN-bearing account with RC4-capable hash: $detail" `
                    -Remediation 'Migrate to a gMSA. If that is impossible, set msDS-SupportedEncryptionTypes to AES-only (0x18) and rotate the password. Privileged SPN accounts are domain-wide compromise targets.'
            }
            elseif (-not $aesOnly -and $days -gt $PasswordAgeDays) {
                $anyFail = $true
                Add-ADFinding -CheckName 'Test-KerberoastableAccounts' -Status 'FAIL' -Object $label `
                    -Description "SPN-bearing account with RC4-capable hash and password age > ${PasswordAgeDays}d: $detail" `
                    -Remediation 'Rotate the password and set msDS-SupportedEncryptionTypes to AES-only (0x18). Prefer migrating to a gMSA.'
            }
            elseif (-not $aesOnly) {
                Add-ADFinding -CheckName 'Test-KerberoastableAccounts' -Status 'WARNING' -Object $label `
                    -Description "SPN-bearing account with RC4-capable hash (password is fresh): $detail" `
                    -Remediation 'Set msDS-SupportedEncryptionTypes to AES-only (0x18) to eliminate the RC4 Kerberoast surface. Prefer gMSA.'
            }
            else {
                Add-ADFinding -CheckName 'Test-KerberoastableAccounts' -Status 'INFO' -Object $label `
                    -Description "SPN-bearing account, AES-only hash: $detail" `
                    -Remediation 'Acceptable. Consider gMSA migration for additional protection.'
            }
        }

        if (-not $anyFail) {
            Add-ADFinding -CheckName 'Test-KerberoastableAccounts' -Status 'PASS' -Object 'All SPN Accounts' `
                -Description "All $($users.Count) SPN-bearing accounts are either AES-only or have fresh passwords." `
                -Remediation 'No action needed.'
        }
    }
    catch {
        Add-ADFinding -CheckName 'Test-KerberoastableAccounts' -Status 'WARNING' -Object 'Kerberoast' `
            -Description "Unable to enumerate: $($_.Exception.Message)" `
            -Remediation 'Check permissions.'
    }
}

function Test-DirSyncAccountSecurity {
    <#
    .SYNOPSIS
        Audits Azure AD Connect service account privilege and password age.
    .DESCRIPTION
        Azure AD Connect's default service account is named "MSOL_*". It must
        NOT be a member of Domain Admins, Enterprise Admins, Account Operators,
        or Backup Operators. Its password should be rotated regularly by Azure
        AD Connect; staleness is a hint the install is broken.
    #>
    [CmdletBinding()]
    param()

    Write-Host "`n[+] Checking Azure AD Connect service account..." -ForegroundColor Cyan
    try {
        $accounts = @(Get-ADUser -Filter { Name -like 'MSOL_*' } `
                -Properties MemberOf, PasswordLastSet, whenCreated, Enabled)
        if ($accounts.Count -eq 0) {
            Add-ADFinding -CheckName 'Test-DirSyncAccountSecurity' -Status 'INFO' -Object 'DirSync Account' `
                -Description 'No accounts matching "MSOL_*" found. Either Azure AD Connect is not installed, or its service account was renamed from the default.' `
                -Remediation 'If your tenant uses Azure AD Connect but the service account was renamed, manually verify its group membership + password hygiene.'
            return
        }

        $disallowedGroups = @('Domain Admins', 'Enterprise Admins', 'Account Operators', 'Backup Operators', 'Schema Admins', 'Administrators')
        $now = Get-Date
        $anyFail = $false

        foreach ($a in $accounts) {
            $days = if ($a.PasswordLastSet) { ($now - $a.PasswordLastSet).Days } else { 99999 }
            $offending = @()
            foreach ($dn in $a.MemberOf) {
                foreach ($g in $disallowedGroups) {
                    if ($dn -like "CN=$g,*") { $offending += $g }
                }
            }

            if ($offending.Count -gt 0) {
                $anyFail = $true
                Add-ADFinding -CheckName 'Test-DirSyncAccountSecurity' -Status 'FAIL' -Object $a.SamAccountName `
                    -Description "Azure AD Connect service account is a member of disallowed group(s): $($offending -join ', '). This violates the Azure AD Connect permissions model and is a significant risk." `
                    -Remediation 'Remove this account from the listed groups. The Azure AD Connect wizard only needs the Directory Synchronization Account role plus specific replication rights on the domain root.'
            }
            else {
                Add-ADFinding -CheckName 'Test-DirSyncAccountSecurity' -Status 'PASS' -Object $a.SamAccountName `
                    -Description 'Azure AD Connect service account is not a member of any disallowed privileged group.' `
                    -Remediation 'No action needed.'
            }

            if ($days -gt 365) {
                Add-ADFinding -CheckName 'Test-DirSyncAccountSecurity' -Status 'WARNING' -Object $a.SamAccountName `
                    -Description "Azure AD Connect service account password is $days days old. Azure AD Connect typically rotates this automatically; staleness suggests the install is broken." `
                    -Remediation 'Investigate the Azure AD Connect installation health. Consider running the wizard again to re-register the service account.'
            }

            Add-ADFinding -CheckName 'Test-DirSyncAccountSecurity' -Status 'INFO' -Object $a.SamAccountName `
                -Description "Enabled=$($a.Enabled); PasswordLastSet=$($a.PasswordLastSet) ($days days ago); whenCreated=$($a.whenCreated)" `
                -Remediation 'Reference only.'
        }

        if (-not $anyFail) {
            Add-ADFinding -CheckName 'Test-DirSyncAccountSecurity' -Status 'PASS' -Object 'DirSync Accounts' `
                -Description "All $($accounts.Count) MSOL_* accounts pass the disallowed-group check." `
                -Remediation 'No action needed.'
        }
    }
    catch {
        Add-ADFinding -CheckName 'Test-DirSyncAccountSecurity' -Status 'WARNING' -Object 'DirSync' `
            -Description "Unable to enumerate: $($_.Exception.Message)" `
            -Remediation 'Check permissions.'
    }
}

#endregion

#region ==================== PR 4a GROUP A - CREDENTIAL HYGIENE ====================

function Invoke-DCRegistryProbe {
    <#
    .SYNOPSIS
        Shared helper: runs a script block on every DC and returns a hashtable keyed by HostName.
    .DESCRIPTION
        Sequential by default; parallel fan-out when -Parallel is $true. Per-DC
        failures produce a hashtable entry with a __Error member instead of
        the normal probe result.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [object[]]$DCs,
        [Parameter(Mandatory)] [scriptblock]$ProbeBlock,
        [bool]$Parallel = $false
    )

    $results = @{}
    if ($Parallel -and $DCs.Count -gt 1) {
        try {
            $dcNames = $DCs | ForEach-Object { $_.HostName }
            $outputs = Invoke-Command -ComputerName $dcNames -ScriptBlock $ProbeBlock -ErrorAction Continue
            foreach ($out in $outputs) {
                $results[$out.PSComputerName] = $out
            }
        }
        catch {
            Write-Verbose "Parallel DC probe failed; falling through to sequential: $($_.Exception.Message)"
        }
    }

    foreach ($dc in $DCs) {
        if ($results.ContainsKey($dc.HostName)) { continue }
        try {
            $results[$dc.HostName] = Invoke-Command -ComputerName $dc.HostName -ScriptBlock $ProbeBlock -ErrorAction Stop
        }
        catch {
            $results[$dc.HostName] = [pscustomobject]@{ __Error = $_.Exception.Message }
        }
    }
    return $results
}

function Test-LMHashStorage {
    <#
    .SYNOPSIS
        Confirms LM hash storage is disabled (NoLMHash = 1) on every DC.
    #>
    [CmdletBinding()]
    param([bool]$Parallel = $false)

    Write-Host "`n[+] Checking LM hash storage policy (NoLMHash)..." -ForegroundColor Cyan
    try {
        $dcs = Get-ADDomainController -Filter *
    }
    catch {
        Add-ADFinding -CheckName 'Test-LMHashStorage' -Status 'WARNING' -Object 'NoLMHash' `
            -Description "Unable to enumerate DCs: $($_.Exception.Message)" -Remediation 'Check permissions.'
        return
    }

    $probe = {
        try { (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name NoLMHash -ErrorAction Stop).NoLMHash }
        catch { $null }
    }

    $results = Invoke-DCRegistryProbe -DCs $dcs -ProbeBlock $probe -Parallel:$Parallel

    $anyFail = $false
    foreach ($dc in $dcs) {
        $r = $results[$dc.HostName]
        if ($r.PSObject.Properties['__Error']) {
            Add-ADFinding -CheckName 'Test-LMHashStorage' -Status 'WARNING' -Object $dc.HostName `
                -Description "Unable to read NoLMHash: $($r.__Error)" `
                -Remediation 'Enable PSRemoting to the DC or run this check locally on the DC.'
            continue
        }
        if ($r -eq 1) {
            Add-ADFinding -CheckName 'Test-LMHashStorage' -Status 'PASS' -Object $dc.HostName `
                -Description 'LM hash storage disabled (NoLMHash = 1).' -Remediation 'No action needed.'
        }
        else {
            $anyFail = $true
            Add-ADFinding -CheckName 'Test-LMHashStorage' -Status 'FAIL' -Object $dc.HostName `
                -Description "NoLMHash on '$($dc.HostName)' is $r (expected 1). LM hashes may be stored and are cracked within minutes." `
                -Remediation "Set HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\NoLMHash = 1 via GPO (Default Domain Controllers Policy -> Security Options -> Network security: Do not store LAN Manager hash value on next password change)."
        }
    }
    if (-not $anyFail) {
        Add-ADFinding -CheckName 'Test-LMHashStorage' -Status 'INFO' -Object 'All DCs' `
            -Description "All $($dcs.Count) DCs enforce NoLMHash = 1." -Remediation 'No action needed.'
    }
}

function Test-NTLMv1Allowed {
    <#
    .SYNOPSIS
        Probes LmCompatibilityLevel on each DC. NTLMv1 must be refused (value 5).
    #>
    [CmdletBinding()]
    param([bool]$Parallel = $false)

    Write-Host "`n[+] Checking NTLMv1 acceptance (LmCompatibilityLevel)..." -ForegroundColor Cyan
    try {
        $dcs = Get-ADDomainController -Filter *
    }
    catch {
        Add-ADFinding -CheckName 'Test-NTLMv1Allowed' -Status 'WARNING' -Object 'LmCompatibilityLevel' `
            -Description "Unable to enumerate DCs: $($_.Exception.Message)" -Remediation 'Check permissions.'
        return
    }

    $probe = {
        try { (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LmCompatibilityLevel -ErrorAction Stop).LmCompatibilityLevel }
        catch { $null }
    }

    $results = Invoke-DCRegistryProbe -DCs $dcs -ProbeBlock $probe -Parallel:$Parallel

    foreach ($dc in $dcs) {
        $r = $results[$dc.HostName]
        if ($r.PSObject.Properties['__Error']) {
            Add-ADFinding -CheckName 'Test-NTLMv1Allowed' -Status 'WARNING' -Object $dc.HostName `
                -Description "Unable to read LmCompatibilityLevel: $($r.__Error)" `
                -Remediation 'Enable PSRemoting to the DC or run this check locally on the DC.'
            continue
        }

        if ($null -eq $r -or $r -lt 3) {
            Add-ADFinding -CheckName 'Test-NTLMv1Allowed' -Status 'FAIL' -Object $dc.HostName `
                -Description "LmCompatibilityLevel = $r on '$($dc.HostName)'. NTLMv1 is accepted; hash is relay-vulnerable." `
                -Remediation 'Set LmCompatibilityLevel to 5 via GPO (Network security: LAN Manager authentication level -> Send NTLMv2 response only. Refuse LM & NTLM).'
        }
        elseif ($r -in 3, 4) {
            Add-ADFinding -CheckName 'Test-NTLMv1Allowed' -Status 'WARNING' -Object $dc.HostName `
                -Description "LmCompatibilityLevel = $r on '$($dc.HostName)'. Partial NTLMv1 refusal; legacy clients can still use NTLMv1 inbound." `
                -Remediation 'Move to LmCompatibilityLevel = 5 once legacy clients are identified and remediated.'
        }
        else {
            Add-ADFinding -CheckName 'Test-NTLMv1Allowed' -Status 'PASS' -Object $dc.HostName `
                -Description "LmCompatibilityLevel = $r (NTLMv1 fully refused)." -Remediation 'No action needed.'
        }
    }
}

function Test-DCLegacyEncryption {
    <#
    .SYNOPSIS
        Flags DCs advertising DES or RC4 Kerberos encryption. AES-only is the goal.
    #>
    [CmdletBinding()]
    param([bool]$Parallel = $false)

    Write-Host "`n[+] Checking DC Kerberos encryption types..." -ForegroundColor Cyan
    try {
        $dcs = Get-ADDomainController -Filter *
    }
    catch {
        Add-ADFinding -CheckName 'Test-DCLegacyEncryption' -Status 'WARNING' -Object 'KDCEnabledEtypes' `
            -Description "Unable to enumerate DCs: $($_.Exception.Message)" -Remediation 'Check permissions.'
        return
    }

    $probe = {
        try {
            (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' -Name SupportedEncryptionTypes -ErrorAction Stop).SupportedEncryptionTypes
        }
        catch {
            try {
                (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc\Parameters' -Name KDCEnabledEtypes -ErrorAction Stop).KDCEnabledEtypes
            }
            catch { $null }
        }
    }

    $results = Invoke-DCRegistryProbe -DCs $dcs -ProbeBlock $probe -Parallel:$Parallel

    $desBits = 0x3
    $rc4Bit = 0x4
    $aesBits = 0x18

    foreach ($dc in $dcs) {
        $r = $results[$dc.HostName]
        if ($r.PSObject.Properties['__Error']) {
            Add-ADFinding -CheckName 'Test-DCLegacyEncryption' -Status 'WARNING' -Object $dc.HostName `
                -Description "Unable to read encryption-type registry values: $($r.__Error)" `
                -Remediation 'Enable PSRemoting to the DC or verify via certutil on the DC.'
            continue
        }

        if ($null -eq $r) {
            Add-ADFinding -CheckName 'Test-DCLegacyEncryption' -Status 'WARNING' -Object $dc.HostName `
                -Description "No explicit Kerberos encryption policy on '$($dc.HostName)'. Default negotiation includes RC4." `
                -Remediation "Configure SupportedEncryptionTypes via GPO to AES-only: Network security: Configure encryption types allowed for Kerberos -> AES128 + AES256."
            continue
        }

        $r = [int]$r
        $hasDes = ($r -band $desBits) -ne 0
        $hasRc4 = ($r -band $rc4Bit) -ne 0
        $hasAes = ($r -band $aesBits) -ne 0

        if ($hasDes) {
            Add-ADFinding -CheckName 'Test-DCLegacyEncryption' -Status 'FAIL' -Object $dc.HostName `
                -Description "DC '$($dc.HostName)' advertises DES Kerberos encryption (value = 0x$($r.ToString('X'))). DES is cryptographically broken." `
                -Remediation 'Remove DES bits from the encryption-types policy.'
        }
        elseif ($hasRc4 -and -not $hasAes) {
            Add-ADFinding -CheckName 'Test-DCLegacyEncryption' -Status 'FAIL' -Object $dc.HostName `
                -Description "DC '$($dc.HostName)' advertises RC4 only (value = 0x$($r.ToString('X'))). RC4 is deprecated and the Kerberoast attack surface." `
                -Remediation 'Enable AES128 + AES256 and remove RC4 in the encryption-types policy.'
        }
        elseif ($hasRc4) {
            Add-ADFinding -CheckName 'Test-DCLegacyEncryption' -Status 'WARNING' -Object $dc.HostName `
                -Description "DC '$($dc.HostName)' supports RC4 alongside AES (value = 0x$($r.ToString('X')))." `
                -Remediation 'Confirm no services require RC4; then remove RC4 from the encryption-types policy.'
        }
        else {
            Add-ADFinding -CheckName 'Test-DCLegacyEncryption' -Status 'PASS' -Object $dc.HostName `
                -Description "DC '$($dc.HostName)' uses AES-only Kerberos encryption (value = 0x$($r.ToString('X')))." `
                -Remediation 'No action needed.'
        }
    }
}

function Test-NullSessionShares {
    <#
    .SYNOPSIS
        Verifies DC anonymous-session hardening (five registry values).
    #>
    [CmdletBinding()]
    param([bool]$Parallel = $false)

    Write-Host "`n[+] Checking null-session / anonymous-access configuration..." -ForegroundColor Cyan
    try {
        $dcs = Get-ADDomainController -Filter *
    }
    catch {
        Add-ADFinding -CheckName 'Test-NullSessionShares' -Status 'WARNING' -Object 'NullSessions' `
            -Description "Unable to enumerate DCs: $($_.Exception.Message)" -Remediation 'Check permissions.'
        return
    }

    $probe = {
        $o = [ordered]@{}
        try { $o['NullSessionPipes'] = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters' -Name NullSessionPipes -ErrorAction Stop).NullSessionPipes } catch { $o['NullSessionPipes'] = $null }
        try { $o['NullSessionShares'] = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters' -Name NullSessionShares -ErrorAction Stop).NullSessionShares } catch { $o['NullSessionShares'] = $null }
        try { $o['RestrictAnonymous'] = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RestrictAnonymous -ErrorAction Stop).RestrictAnonymous } catch { $o['RestrictAnonymous'] = $null }
        try { $o['RestrictAnonymousSAM'] = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RestrictAnonymousSAM -ErrorAction Stop).RestrictAnonymousSAM } catch { $o['RestrictAnonymousSAM'] = $null }
        try { $o['EveryoneIncludesAnonymous'] = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name EveryoneIncludesAnonymous -ErrorAction Stop).EveryoneIncludesAnonymous } catch { $o['EveryoneIncludesAnonymous'] = $null }
        [pscustomobject]$o
    }

    $results = Invoke-DCRegistryProbe -DCs $dcs -ProbeBlock $probe -Parallel:$Parallel

    foreach ($dc in $dcs) {
        $r = $results[$dc.HostName]
        if ($r.PSObject.Properties['__Error']) {
            Add-ADFinding -CheckName 'Test-NullSessionShares' -Status 'WARNING' -Object $dc.HostName `
                -Description "Unable to read anonymous-session values: $($r.__Error)" `
                -Remediation 'Enable PSRemoting to the DC or run this check locally.'
            continue
        }

        $issues = @()
        if ($r.NullSessionPipes -and @($r.NullSessionPipes | Where-Object { $_ }).Count -gt 0) { $issues += "NullSessionPipes populated: $($r.NullSessionPipes -join ',')" }
        if ($r.NullSessionShares -and @($r.NullSessionShares | Where-Object { $_ }).Count -gt 0) { $issues += "NullSessionShares populated: $($r.NullSessionShares -join ',')" }
        if ($null -eq $r.RestrictAnonymous -or $r.RestrictAnonymous -lt 1) { $issues += "RestrictAnonymous = $($r.RestrictAnonymous) (expected >= 1)" }
        if ($null -eq $r.RestrictAnonymousSAM -or $r.RestrictAnonymousSAM -ne 1) { $issues += "RestrictAnonymousSAM = $($r.RestrictAnonymousSAM) (expected 1)" }
        if ($r.EveryoneIncludesAnonymous -eq 1) { $issues += 'EveryoneIncludesAnonymous = 1 (expected 0)' }

        if ($issues.Count -gt 0) {
            Add-ADFinding -CheckName 'Test-NullSessionShares' -Status 'FAIL' -Object $dc.HostName `
                -Description "Null-session misconfiguration on '$($dc.HostName)': $($issues -join '; ')" `
                -Remediation 'Enforce via GPO: Network access: Do not allow anonymous enumeration of SAM accounts and shares -> Enabled; Network access: Let Everyone permissions apply to anonymous users -> Disabled. Clear NullSessionPipes / NullSessionShares.'
        }
        else {
            Add-ADFinding -CheckName 'Test-NullSessionShares' -Status 'PASS' -Object $dc.HostName `
                -Description "Null-session configuration compliant on '$($dc.HostName)'." -Remediation 'No action needed.'
        }
    }
}

function Test-DomainEncryptionTypesPolicy {
    <#
    .SYNOPSIS
        Checks msDS-SupportedEncryptionTypes on the domain + every trust object.
    #>
    [CmdletBinding()]
    param()

    Write-Host "`n[+] Checking domain + trust encryption-types policy..." -ForegroundColor Cyan
    $aesBits = 0x18
    $desBits = 0x3
    $rc4Bit = 0x4

    try {
        $domain = Get-ADDomain -Properties 'msDS-SupportedEncryptionTypes'
        $domainEtypes = $domain.'msDS-SupportedEncryptionTypes'
    }
    catch {
        Add-ADFinding -CheckName 'Test-DomainEncryptionTypesPolicy' -Status 'WARNING' -Object 'Domain' `
            -Description "Unable to read domain encryption-types attribute: $($_.Exception.Message)" `
            -Remediation 'Check permissions.'
        return
    }

    if ($null -eq $domainEtypes) {
        Add-ADFinding -CheckName 'Test-DomainEncryptionTypesPolicy' -Status 'WARNING' -Object 'Domain' `
            -Description 'Domain msDS-SupportedEncryptionTypes is not set. Default Windows negotiation includes RC4.' `
            -Remediation 'Set msDS-SupportedEncryptionTypes = 0x18 (AES128 + AES256) on the domain object to pin AES-only.'
    }
    else {
        $v = [int]$domainEtypes
        if (($v -band $desBits) -ne 0) {
            Add-ADFinding -CheckName 'Test-DomainEncryptionTypesPolicy' -Status 'FAIL' -Object 'Domain' `
                -Description "Domain msDS-SupportedEncryptionTypes = 0x$($v.ToString('X')) includes DES." `
                -Remediation 'Remove DES bits from msDS-SupportedEncryptionTypes on the domain object.'
        }
        elseif (($v -band $rc4Bit) -ne 0 -and ($v -band $aesBits) -eq 0) {
            Add-ADFinding -CheckName 'Test-DomainEncryptionTypesPolicy' -Status 'FAIL' -Object 'Domain' `
                -Description "Domain msDS-SupportedEncryptionTypes = 0x$($v.ToString('X')) is RC4-only." `
                -Remediation 'Set msDS-SupportedEncryptionTypes = 0x18 on the domain object.'
        }
        elseif (($v -band $rc4Bit) -ne 0) {
            Add-ADFinding -CheckName 'Test-DomainEncryptionTypesPolicy' -Status 'WARNING' -Object 'Domain' `
                -Description "Domain msDS-SupportedEncryptionTypes = 0x$($v.ToString('X')) includes RC4 alongside AES." `
                -Remediation 'Move to AES-only (0x18) once no services depend on RC4.'
        }
        else {
            Add-ADFinding -CheckName 'Test-DomainEncryptionTypesPolicy' -Status 'PASS' -Object 'Domain' `
                -Description "Domain msDS-SupportedEncryptionTypes = 0x$($v.ToString('X')) (AES-only)." `
                -Remediation 'No action needed.'
        }
    }

    try {
        $trusts = @(Get-ADTrust -Filter * -Properties 'msDS-SupportedEncryptionTypes')
    }
    catch {
        return
    }
    foreach ($t in $trusts) {
        $tv = $t.'msDS-SupportedEncryptionTypes'
        if ($null -eq $tv) {
            Add-ADFinding -CheckName 'Test-DomainEncryptionTypesPolicy' -Status 'WARNING' -Object $t.Name `
                -Description "Trust '$($t.Name)' has no msDS-SupportedEncryptionTypes (defaults allow RC4)." `
                -Remediation 'Set msDS-SupportedEncryptionTypes = 0x18 on the trust object.'
            continue
        }
        $tv = [int]$tv
        if (($tv -band $rc4Bit) -ne 0 -and ($tv -band $aesBits) -eq 0) {
            Add-ADFinding -CheckName 'Test-DomainEncryptionTypesPolicy' -Status 'FAIL' -Object $t.Name `
                -Description "Trust '$($t.Name)' msDS-SupportedEncryptionTypes = 0x$($tv.ToString('X')) is RC4-only." `
                -Remediation 'Reconfigure the trust with AES-only encryption types.'
        }
    }
}

#endregion

#region ==================== PR 4a GROUP B - ACL ABUSE PATHS ====================

function Test-IsAuthorizedPrincipal {
    <#
    .SYNOPSIS
        Returns $true if the ACE's IdentityReference is in the authorized-principals allow-list.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)] [string]$IdentityReference)

    $auth = @(
        'Domain Admins', 'Enterprise Admins', 'Administrators', 'SYSTEM',
        'Schema Admins', 'BUILTIN\Administrators', 'NT AUTHORITY\SYSTEM',
        'Enterprise Read-only Domain Controllers', 'Cert Publishers',
        'Enterprise Domain Controllers'
    )
    if ($script:AuthorizedPrincipalsExtra) {
        $auth += $script:AuthorizedPrincipalsExtra
    }
    foreach ($a in $auth) {
        if ($IdentityReference -eq $a) { return $true }
        if ($IdentityReference -like "*\$a") { return $true }
    }
    return $false
}

function Test-WritablePrivilegedACLs {
    <#
    .SYNOPSIS
        Scans privileged AD objects for non-admin write-class ACEs.
    #>
    [CmdletBinding()]
    param()

    Write-Host "`n[+] Scanning privileged objects for non-admin write-class ACLs..." -ForegroundColor Cyan
    try {
        $dn = (Get-ADDomain).DistinguishedName
    }
    catch {
        Add-ADFinding -CheckName 'Test-WritablePrivilegedACLs' -Status 'WARNING' -Object 'Domain' `
            -Description "Unable to determine domain DN: $($_.Exception.Message)" -Remediation 'Check permissions.'
        return
    }

    $targets = @(
        "CN=Domain Admins,CN=Users,$dn",
        "CN=Enterprise Admins,CN=Users,$dn",
        "CN=Schema Admins,CN=Users,$dn",
        "CN=Administrators,CN=Builtin,$dn",
        "CN=Account Operators,CN=Users,$dn",
        "CN=Backup Operators,CN=Users,$dn",
        "CN=AdminSDHolder,CN=System,$dn",
        "CN=krbtgt,CN=Users,$dn",
        "OU=Domain Controllers,$dn"
    )

    try {
        $dcs = Get-ADDomainController -Filter *
        foreach ($dc in $dcs) {
            $targets += "CN=$($dc.Name),OU=Domain Controllers,$dn"
        }
    }
    catch {
        Write-Verbose "Could not enumerate DCs for additional targets: $($_.Exception.Message)"
    }

    $writeRights = 'GenericAll|GenericWrite|WriteProperty|WriteDacl|WriteOwner|AllExtendedRights'
    $anyFail = $false
    foreach ($t in $targets) {
        try {
            $acl = Get-Acl -Path ("AD:\$t") -ErrorAction Stop
        }
        catch {
            Add-ADFinding -CheckName 'Test-WritablePrivilegedACLs' -Status 'WARNING' -Object $t `
                -Description "Unable to read ACL: $($_.Exception.Message)" `
                -Remediation 'Run with Domain Admin or verify the object exists.'
            continue
        }
        foreach ($ace in $acl.Access) {
            if ($ace.ActiveDirectoryRights -match $writeRights) {
                $id = [string]$ace.IdentityReference
                if (-not (Test-IsAuthorizedPrincipal -IdentityReference $id)) {
                    $anyFail = $true
                    Add-ADFinding -CheckName 'Test-WritablePrivilegedACLs' -Status 'FAIL' -Object $t `
                        -Description "Non-admin principal '$id' holds '$($ace.ActiveDirectoryRights)' on '$t'. Direct privilege-escalation path." `
                        -Remediation 'Remove the ACE. Only Domain Admins / Enterprise Admins / SYSTEM should hold write-class rights on privileged objects.'
                }
            }
        }
    }
    if (-not $anyFail) {
        Add-ADFinding -CheckName 'Test-WritablePrivilegedACLs' -Status 'PASS' -Object 'Privileged Objects' `
            -Description "No non-admin write-class ACEs detected across $($targets.Count) sensitive objects." `
            -Remediation 'No action needed.'
    }
}

function Test-ShadowCredentialsVulnerable {
    <#
    .SYNOPSIS
        Flags non-admin WriteProperty on msDS-KeyCredentialLink for privileged accounts.
    #>
    [CmdletBinding()]
    param()

    Write-Host "`n[+] Checking for Shadow Credentials (msDS-KeyCredentialLink) exposure..." -ForegroundColor Cyan

    $targets = [System.Collections.Generic.List[string]]::new()
    foreach ($g in @('Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Account Operators')) {
        try {
            $members = Get-ADGroupMember -Identity $g -Recursive -ErrorAction Stop | Where-Object { $_.objectClass -eq 'user' }
            foreach ($m in $members) { $null = $targets.Add($m.DistinguishedName) }
        }
        catch {
            Write-Verbose "Get-ADGroupMember $g failed: $($_.Exception.Message)"
        }
    }
    try {
        $k = Get-ADUser -Identity 'krbtgt' -ErrorAction Stop
        $null = $targets.Add($k.DistinguishedName)
    }
    catch {
        Write-Verbose "krbtgt lookup failed: $($_.Exception.Message)"
    }
    try {
        $dcs = Get-ADDomainController -Filter *
        foreach ($dc in $dcs) {
            $dcComputer = Get-ADComputer -Identity $dc.Name -ErrorAction SilentlyContinue
            if ($dcComputer) { $null = $targets.Add($dcComputer.DistinguishedName) }
        }
    }
    catch {
        Write-Verbose "DC enumeration failed: $($_.Exception.Message)"
    }

    $anyFail = $false
    foreach ($t in ($targets | Select-Object -Unique)) {
        try {
            $acl = Get-Acl -Path ("AD:\$t") -ErrorAction Stop
        }
        catch {
            Write-Verbose "ACL read failed for $t"
            continue
        }

        foreach ($ace in $acl.Access) {
            $isWrite = $ace.ActiveDirectoryRights -match 'GenericAll|GenericWrite|WriteProperty'
            if (-not $isWrite) { continue }
            $objType = if ($ace.ObjectType) { [string]$ace.ObjectType } else { '' }
            $targetsKeyCred = $objType -eq '00000000-0000-0000-0000-000000000000' -or $objType -eq '5b47d60f-6090-40b2-9f37-2a4de88f3063'
            if (-not $targetsKeyCred) { continue }

            $id = [string]$ace.IdentityReference
            if (-not (Test-IsAuthorizedPrincipal -IdentityReference $id)) {
                $anyFail = $true
                Add-ADFinding -CheckName 'Test-ShadowCredentialsVulnerable' -Status 'FAIL' -Object $t `
                    -Description "Non-admin '$id' has '$($ace.ActiveDirectoryRights)' on '$t' with object-type scope including msDS-KeyCredentialLink. Can install a PKINIT public key and impersonate this account." `
                    -Remediation 'Remove the ACE. If WriteProperty on the full object is required, scope it to attributes other than msDS-KeyCredentialLink via the ObjectType GUID.'
            }
        }
    }
    if (-not $anyFail) {
        Add-ADFinding -CheckName 'Test-ShadowCredentialsVulnerable' -Status 'PASS' -Object 'Privileged Accounts' `
            -Description "No non-admin WriteProperty rights on msDS-KeyCredentialLink detected across $($targets.Count) targets." `
            -Remediation 'No action needed.'
    }
}

function Test-RBCDConfigured {
    <#
    .SYNOPSIS
        Inventory + risk audit of msDS-AllowedToActOnBehalfOfOtherIdentity (RBCD).
    #>
    [CmdletBinding()]
    param(
        [string[]]$Tier0OUDNs = @()
    )

    Write-Host "`n[+] Checking Resource-Based Constrained Delegation (RBCD)..." -ForegroundColor Cyan
    try {
        $dcs = Get-ADDomainController -Filter *
        $dcNames = $dcs | ForEach-Object { $_.Name }
    }
    catch {
        $dcNames = @()
    }

    try {
        $computersWithRBCD = @(Get-ADComputer -Filter { msDS-AllowedToActOnBehalfOfOtherIdentity -like '*' } `
                -Properties msDS-AllowedToActOnBehalfOfOtherIdentity, DistinguishedName)
    }
    catch {
        Add-ADFinding -CheckName 'Test-RBCDConfigured' -Status 'WARNING' -Object 'RBCD' `
            -Description "Unable to enumerate computers with RBCD: $($_.Exception.Message)" `
            -Remediation 'Check permissions.'
        return
    }

    foreach ($c in $computersWithRBCD) {
        $isDC = $dcNames -contains $c.Name
        $isTier0 = $false
        foreach ($ou in $Tier0OUDNs) {
            if ($c.DistinguishedName -like "*,$ou") { $isTier0 = $true; break }
        }

        $sidList = @()
        if ($c.'msDS-AllowedToActOnBehalfOfOtherIdentity') {
            try {
                $sd = [System.Security.AccessControl.RawSecurityDescriptor]::new(
                    [byte[]]$c.'msDS-AllowedToActOnBehalfOfOtherIdentity', 0)
                foreach ($ace in $sd.DiscretionaryAcl) {
                    $sidList += $ace.SecurityIdentifier.ToString()
                }
            }
            catch {
                $sidList = @('(unparseable)')
            }
        }

        if ($isDC) {
            Add-ADFinding -CheckName 'Test-RBCDConfigured' -Status 'FAIL' -Object $c.Name `
                -Description "RBCD set on DOMAIN CONTROLLER '$($c.Name)'. Any principal in the SID list can impersonate any user to this DC. Allowed SIDs: $($sidList -join ', ')" `
                -Remediation 'Clear msDS-AllowedToActOnBehalfOfOtherIdentity on this DC immediately.'
        }
        elseif ($isTier0) {
            Add-ADFinding -CheckName 'Test-RBCDConfigured' -Status 'FAIL' -Object $c.Name `
                -Description "RBCD set on Tier 0 asset '$($c.Name)'. Allowed SIDs: $($sidList -join ', ')" `
                -Remediation 'Review whether RBCD is required on this Tier 0 asset. If not, clear the attribute.'
        }
        else {
            Add-ADFinding -CheckName 'Test-RBCDConfigured' -Status 'INFO' -Object $c.Name `
                -Description "RBCD configured on '$($c.Name)'. Allowed SIDs: $($sidList -join ', ')" `
                -Remediation 'Confirm this RBCD delegation is authorized for the application running on this host.'
        }
    }

    $scanTargets = @()
    foreach ($dc in $dcs) {
        try {
            $comp = Get-ADComputer -Identity $dc.Name -ErrorAction SilentlyContinue
            if ($comp) { $scanTargets += $comp.DistinguishedName }
        }
        catch {
            Write-Verbose "DC computer object lookup failed: $($_.Exception.Message)"
        }
    }
    foreach ($ou in $Tier0OUDNs) {
        try {
            $ouComps = @(Get-ADComputer -SearchBase $ou -Filter * -ErrorAction SilentlyContinue)
            foreach ($c in $ouComps) { $scanTargets += $c.DistinguishedName }
        }
        catch {
            Write-Verbose "Tier0 OU enumeration failed: $($_.Exception.Message)"
        }
    }

    $writeRights = 'GenericAll|GenericWrite|WriteProperty'
    foreach ($dn in ($scanTargets | Select-Object -Unique)) {
        try {
            $acl = Get-Acl -Path ("AD:\$dn") -ErrorAction Stop
        }
        catch {
            Write-Verbose "ACL read failed for $dn"
            continue
        }
        foreach ($ace in $acl.Access) {
            if (-not ($ace.ActiveDirectoryRights -match $writeRights)) { continue }
            $id = [string]$ace.IdentityReference
            if (Test-IsAuthorizedPrincipal -IdentityReference $id) { continue }
            Add-ADFinding -CheckName 'Test-RBCDConfigured' -Status 'FAIL' -Object $dn `
                -Description "Non-admin '$id' has '$($ace.ActiveDirectoryRights)' on sensitive computer '$dn'. Can plant RBCD to impersonate any user." `
                -Remediation 'Remove the ACE. Only Domain Admins / Enterprise Admins should hold write rights on sensitive computer accounts.'
        }
    }

    if ($computersWithRBCD.Count -eq 0) {
        Add-ADFinding -CheckName 'Test-RBCDConfigured' -Status 'PASS' -Object 'All Computers' `
            -Description 'No RBCD configurations detected in the domain.' -Remediation 'No action needed.'
    }
}

function Test-GenericWriteToSensitive {
    <#
    .SYNOPSIS
        Flags non-admin GenericWrite on members of Domain Admins / Enterprise Admins / Schema Admins.
    #>
    [CmdletBinding()]
    param()

    Write-Host "`n[+] Scanning privileged-group MEMBERS for non-admin GenericWrite..." -ForegroundColor Cyan

    $memberDNs = @()
    foreach ($g in @('Domain Admins', 'Enterprise Admins', 'Schema Admins')) {
        try {
            $members = Get-ADGroupMember -Identity $g -Recursive -ErrorAction Stop | Where-Object { $_.objectClass -eq 'user' }
            foreach ($m in $members) { $memberDNs += $m.DistinguishedName }
        }
        catch {
            Write-Verbose "Get-ADGroupMember $g failed: $($_.Exception.Message)"
        }
    }

    $anyFail = $false
    foreach ($dn in ($memberDNs | Select-Object -Unique)) {
        try {
            $acl = Get-Acl -Path ("AD:\$dn") -ErrorAction Stop
        }
        catch {
            Write-Verbose "ACL read failed for $dn"
            continue
        }
        foreach ($ace in $acl.Access) {
            if ($ace.ActiveDirectoryRights -notmatch 'GenericWrite|GenericAll|WriteDacl|WriteOwner|AllExtendedRights') { continue }
            $id = [string]$ace.IdentityReference
            if (Test-IsAuthorizedPrincipal -IdentityReference $id) { continue }
            $anyFail = $true
            Add-ADFinding -CheckName 'Test-GenericWriteToSensitive' -Status 'FAIL' -Object $dn `
                -Description "Non-admin '$id' holds '$($ace.ActiveDirectoryRights)' directly on privileged user '$dn'. Can reset password or install shadow credentials." `
                -Remediation 'Remove the ACE. Privileged user accounts should inherit protection from AdminSDHolder only.'
        }
    }

    if (-not $anyFail -and $memberDNs.Count -gt 0) {
        Add-ADFinding -CheckName 'Test-GenericWriteToSensitive' -Status 'PASS' -Object 'Privileged Members' `
            -Description "No non-admin write rights on $((@($memberDNs | Select-Object -Unique)).Count) privileged-group user objects." `
            -Remediation 'No action needed.'
    }
}

#endregion

#region ==================== PR 4b - ATTACK PATH + DNSADMINS + AUDIT + DFSR ====================

function Test-AuthenticatedUsersDACLReach {
    <#
    .SYNOPSIS
        Bounded-depth ACL reach scan from non-admin principals to Domain Admin members.
    .DESCRIPTION
        For each user in Domain Admins / Enterprise Admins / Schema Admins:
          1. Direct: does any non-admin principal hold write-class rights on
             this user's AD object? -> Critical finding.
          2. Indirect (if MaxDepth >= 2): does any non-admin principal hold
             write-class rights on a GROUP that itself holds write-class rights
             on the DA user? -> High finding (one hop harder to exploit).
        Not a full BloodHound graph - bounded at MaxDepth to keep runtime
        sane. Catches the vast majority of real exposure in production forests.
    .PARAMETER MaxDepth
        Maximum reach depth. 1 = direct only. 2 = one-hop indirect. Default 2.
    #>
    [CmdletBinding()]
    param(
        [ValidateRange(1, 3)]
        [int]$MaxDepth = 2
    )

    Write-Host "`n[+] Scanning ACL reach paths (bounded depth = $MaxDepth)..." -ForegroundColor Cyan

    $writeRights = 'GenericAll|GenericWrite|WriteProperty|WriteDacl|WriteOwner|AllExtendedRights'

    # Collect DA / EA / SA member DNs.
    $privMembers = @()
    foreach ($g in @('Domain Admins', 'Enterprise Admins', 'Schema Admins')) {
        try {
            $members = Get-ADGroupMember -Identity $g -Recursive -ErrorAction Stop | Where-Object { $_.objectClass -eq 'user' }
            foreach ($m in $members) { $privMembers += $m.DistinguishedName }
        }
        catch {
            Write-Verbose "Get-ADGroupMember $g failed: $($_.Exception.Message)"
        }
    }
    $privMembers = @($privMembers | Select-Object -Unique)
    if ($privMembers.Count -eq 0) {
        Add-ADFinding -CheckName 'Test-AuthenticatedUsersDACLReach' -Status 'PASS' -Object 'Privileged Members' `
            -Description 'No privileged-group members enumerated (group empty or permissions blocked).' `
            -Remediation 'No action needed.'
        return
    }

    # Pass 1: direct exposure.
    $visited = @{}
    $anyDirectFail = $false
    foreach ($dn in $privMembers) {
        try {
            $acl = Get-Acl -Path ("AD:\$dn") -ErrorAction Stop
        }
        catch {
            Write-Verbose "ACL read failed for $dn"
            continue
        }
        foreach ($ace in $acl.Access) {
            if ($ace.ActiveDirectoryRights -notmatch $writeRights) { continue }
            $id = [string]$ace.IdentityReference
            if (Test-IsAuthorizedPrincipal -IdentityReference $id) { continue }
            $anyDirectFail = $true
            Add-ADFinding -CheckName 'Test-AuthenticatedUsersDACLReach' -Status 'FAIL' -Object $dn `
                -Description "DIRECT reach (1 hop): non-admin '$id' has '$($ace.ActiveDirectoryRights)' on privileged user '$dn'. Single-step compromise." `
                -Remediation 'Remove the ACE. Privileged user accounts inherit protection from AdminSDHolder; non-admin principals must not hold write rights directly.'
            $visited[$id] = $true
        }
    }

    # Pass 2: indirect exposure via groups that have rights on DA members.
    if ($MaxDepth -ge 2) {
        # First, find groups with write rights on DA members (from pass 1).
        $writableGroups = @{}
        foreach ($dn in $privMembers) {
            try {
                $acl = Get-Acl -Path ("AD:\$dn") -ErrorAction SilentlyContinue
            }
            catch { continue }
            foreach ($ace in $acl.Access) {
                if ($ace.ActiveDirectoryRights -notmatch $writeRights) { continue }
                $id = [string]$ace.IdentityReference
                # Strip domain prefix (e.g., "TEST\HRAdmins" -> "HRAdmins").
                $idShort = $id
                if ($id -match '\\(.+)$') { $idShort = $matches[1] }
                # Only interested in groups here; skip authorized principals (covered by Pass 1 exclusion) and user-looking things.
                try {
                    $grp = Get-ADGroup -Identity $idShort -ErrorAction Stop
                    if (-not $writableGroups.ContainsKey($grp.DistinguishedName)) {
                        $writableGroups[$grp.DistinguishedName] = @()
                    }
                    $writableGroups[$grp.DistinguishedName] += [pscustomobject]@{
                        TargetUser = $dn
                        Rights = $ace.ActiveDirectoryRights
                    }
                }
                catch {
                    Write-Verbose "Identity '$idShort' is not a resolvable group; skipping (likely a user)."
                }
            }
        }

        # Now for each writable group, check if it has non-admin write rights itself.
        foreach ($groupDN in $writableGroups.Keys) {
            try {
                $gAcl = Get-Acl -Path ("AD:\$groupDN") -ErrorAction Stop
            }
            catch { continue }
            foreach ($ace in $gAcl.Access) {
                if ($ace.ActiveDirectoryRights -notmatch $writeRights) { continue }
                $id = [string]$ace.IdentityReference
                if (Test-IsAuthorizedPrincipal -IdentityReference $id) { continue }
                $targets = $writableGroups[$groupDN] | ForEach-Object { "$($_.TargetUser) ($($_.Rights))" }
                Add-ADFinding -CheckName 'Test-AuthenticatedUsersDACLReach' -Status 'FAIL' -Object $groupDN `
                    -Description "INDIRECT reach (2 hops): non-admin '$id' has '$($ace.ActiveDirectoryRights)' on group '$groupDN', which has write rights on privileged user(s): $($targets -join '; '). Two-step compromise." `
                    -Remediation "Remove '$id' from the ACL on '$groupDN', OR remove the group's write rights on the privileged user(s)."
            }
        }
    }

    if (-not $anyDirectFail -and $visited.Count -eq 0) {
        Add-ADFinding -CheckName 'Test-AuthenticatedUsersDACLReach' -Status 'PASS' -Object 'DACL Reach' `
            -Description "No non-admin ACL reach paths to $($privMembers.Count) privileged member(s) within $MaxDepth hop(s)." `
            -Remediation 'No action needed.'
    }
}

function Test-DNSAdminsPrivilege {
    <#
    .SYNOPSIS
        Audits the DnsAdmins group. Legacy privilege-escalation path (pre-2019 DCs).
    .DESCRIPTION
        DnsAdmins members could historically load a DLL into the DNS Service
        (running as SYSTEM on the DC) via the ServerLevelPluginDll registry
        value - CVE-2021-40469. Microsoft hardened this in Server 2019, but
        membership is still an escalation surface (zone modification, cache
        poisoning). Severity is tiered based on whether any DC runs a
        pre-hardened OS.
    #>
    [CmdletBinding()]
    param()

    Write-Host "`n[+] Checking DnsAdmins group membership..." -ForegroundColor Cyan
    try {
        $members = @(Get-ADGroupMember -Identity 'DnsAdmins' -Recursive -ErrorAction Stop)
    }
    catch {
        Add-ADFinding -CheckName 'Test-DNSAdminsPrivilege' -Status 'INFO' -Object 'DnsAdmins' `
            -Description "DnsAdmins group not present in this domain, or unable to enumerate: $($_.Exception.Message)" `
            -Remediation 'No action needed if DnsAdmins is genuinely absent.'
        return
    }

    if ($members.Count -eq 0) {
        Add-ADFinding -CheckName 'Test-DNSAdminsPrivilege' -Status 'PASS' -Object 'DnsAdmins' `
            -Description 'DnsAdmins group has no members.' `
            -Remediation 'No action needed.'
        return
    }

    # Detect whether any DC is Server 2016 or earlier (pre-hardening for CVE-2021-40469).
    $hasLegacyDC = $false
    try {
        $dcs = Get-ADDomainController -Filter *
        foreach ($dc in $dcs) {
            if ($dc.OperatingSystem -match 'Server 2008|Server 2012|Server 2016') { $hasLegacyDC = $true; break }
        }
    }
    catch {
        Write-Verbose "DC OS enumeration failed: $($_.Exception.Message)"
    }

    $memberList = ($members | ForEach-Object { "$($_.Name) [$($_.objectClass)]" }) -join '; '

    if ($hasLegacyDC) {
        Add-ADFinding -CheckName 'Test-DNSAdminsPrivilege' -Status 'FAIL' -Object 'DnsAdmins' `
            -Description "DnsAdmins has $($members.Count) member(s): $memberList. At least one DC runs Server 2016 or earlier - DnsAdmins members can load a DLL into the DNS service (SYSTEM on DC) via ServerLevelPluginDll (CVE-2021-40469)." `
            -Remediation 'Remove all non-essential members from DnsAdmins. Patch / upgrade DCs to Server 2019+ to get the ServerLevelPluginDll hardening. Monitor DNS-server registry changes.'
    }
    else {
        Add-ADFinding -CheckName 'Test-DNSAdminsPrivilege' -Status 'WARNING' -Object 'DnsAdmins' `
            -Description "DnsAdmins has $($members.Count) member(s): $memberList. Modern DCs are hardened against the classic CVE-2021-40469 escalation, but membership is still an escalation surface (zone modification, cache poisoning)." `
            -Remediation 'Minimize DnsAdmins membership. Scope delegation to specific zones rather than group membership where possible.'
    }
}

function Test-EventAuditPolicy {
    <#
    .SYNOPSIS
        Verifies advanced audit policy on every DC covers the AD-critical subcategories.
    .DESCRIPTION
        Uses auditpol to query each DC's effective advanced audit policy.
        Required subcategories for AD forensics:
          - Kerberos Authentication Service (S+F)
          - Kerberos Service Ticket Operations (S+F)
          - Credential Validation (S+F)
          - Directory Service Access (S+F)
          - Directory Service Changes (S)
          - Account Management subcategories (S)
    .PARAMETER Subcategories
        Optional override. Default is a reasonable baseline.
    #>
    [CmdletBinding()]
    param(
        [hashtable]$Subcategories
    )

    Write-Host "`n[+] Checking advanced audit policy on DCs..." -ForegroundColor Cyan

    if (-not $Subcategories) {
        # Default: subcategory name -> required inclusion flags (S = success, F = failure, SF = both).
        $Subcategories = @{
            'Kerberos Authentication Service' = 'SF'
            'Kerberos Service Ticket Operations' = 'SF'
            'Credential Validation' = 'SF'
            'Directory Service Access' = 'SF'
            'Directory Service Changes' = 'S'
            'User Account Management' = 'S'
            'Security Group Management' = 'S'
        }
    }

    try {
        $dcs = Get-ADDomainController -Filter *
    }
    catch {
        Add-ADFinding -CheckName 'Test-EventAuditPolicy' -Status 'WARNING' -Object 'Audit Policy' `
            -Description "Unable to enumerate DCs: $($_.Exception.Message)" -Remediation 'Check permissions.'
        return
    }

    foreach ($dc in $dcs) {
        try {
            $policy = Invoke-Command -ComputerName $dc.HostName -ScriptBlock {
                # auditpol CSV output: "Machine Name","Policy Target","Subcategory","Subcategory GUID","Inclusion Setting","Exclusion Setting"
                auditpol /get /category:* /r 2>&1
            } -ErrorAction Stop
        }
        catch {
            Add-ADFinding -CheckName 'Test-EventAuditPolicy' -Status 'WARNING' -Object $dc.HostName `
                -Description "Unable to read audit policy on '$($dc.HostName)': $($_.Exception.Message)" `
                -Remediation 'Enable PSRemoting or verify locally: auditpol /get /category:*'
            continue
        }

        # Parse CSV output; skip lines that aren't actual policy rows.
        $csvRows = @()
        try {
            $csvText = $policy -join "`r`n"
            $csvRows = $csvText | ConvertFrom-Csv -ErrorAction Stop
        }
        catch {
            Add-ADFinding -CheckName 'Test-EventAuditPolicy' -Status 'WARNING' -Object $dc.HostName `
                -Description "Unable to parse auditpol CSV on '$($dc.HostName)'. auditpol output may be locale-specific (non-English Windows). Manual verification required." `
                -Remediation 'Review auditpol /get /category:* output on the DC directly.'
            continue
        }

        $missing = @()
        foreach ($sub in $Subcategories.Keys) {
            $want = $Subcategories[$sub]
            $row = $csvRows | Where-Object { $_.Subcategory -eq $sub } | Select-Object -First 1
            if (-not $row) {
                $missing += "$sub (not found)"
                continue
            }
            $setting = [string]$row.'Inclusion Setting'
            $ok = $true
            if ($want -match 'S' -and $setting -notmatch 'Success') { $ok = $false }
            if ($want -match 'F' -and $setting -notmatch 'Failure') { $ok = $false }
            if (-not $ok) {
                $missing += "$sub (current: '$setting', required: $want)"
            }
        }

        if ($missing.Count -gt 0) {
            Add-ADFinding -CheckName 'Test-EventAuditPolicy' -Status 'FAIL' -Object $dc.HostName `
                -Description "DC '$($dc.HostName)' has audit-policy gaps: $($missing -join '; '). These gaps mean no forensic trail for the most common AD attack surfaces." `
                -Remediation 'Configure advanced audit policy via GPO: Computer Configuration -> Policies -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration. Enable Success + Failure for each missing subcategory.'
        }
        else {
            Add-ADFinding -CheckName 'Test-EventAuditPolicy' -Status 'PASS' -Object $dc.HostName `
                -Description "DC '$($dc.HostName)' audit policy covers all $($Subcategories.Count) required subcategories." `
                -Remediation 'No action needed.'
        }
    }
}

function Test-DFSRSYSVOLHealth {
    <#
    .SYNOPSIS
        Verifies SYSVOL replicates via DFS-R (not legacy FRS) and no recent critical errors.
    .DESCRIPTION
        SYSVOL replication failures cause Group Policy drift: LAPS password
        rotation fails to propagate, GPP cpassword remediation doesn't apply
        consistently, security policy converges unevenly. Checks that every
        DC is in the DFSR SYSVOL replication group and that no critical DFSR
        events (4012 "journal wrap", 5002 "content set", 5014 "connection
        failure") have fired in the last 24 hours.
    #>
    [CmdletBinding()]
    param()

    Write-Host "`n[+] Checking DFSR SYSVOL replication health..." -ForegroundColor Cyan

    if (-not (Get-Module -ListAvailable -Name DFSR)) {
        Add-ADFinding -CheckName 'Test-DFSRSYSVOLHealth' -Status 'INFO' -Object 'DFSR' `
            -Description 'DFSR PowerShell module not available on this host. Install RSAT DFS-R Management tools or run this check from a DC.' `
            -Remediation 'Add-WindowsCapability -Online -Name Rsat.FileServices.Tools~~~~0.0.1.0'
        return
    }

    Import-Module DFSR -ErrorAction SilentlyContinue | Out-Null

    try {
        $dcs = Get-ADDomainController -Filter *
    }
    catch {
        Add-ADFinding -CheckName 'Test-DFSRSYSVOLHealth' -Status 'WARNING' -Object 'DFSR' `
            -Description "Unable to enumerate DCs: $($_.Exception.Message)" -Remediation 'Check permissions.'
        return
    }

    # Check DFSR membership for the Domain System Volume replication group.
    try {
        $members = @(Get-DfsrMembership -GroupName 'Domain System Volume' -ErrorAction Stop)
    }
    catch {
        Add-ADFinding -CheckName 'Test-DFSRSYSVOLHealth' -Status 'INFO' -Object 'DFSR' `
            -Description "Unable to query the 'Domain System Volume' DFSR group. SYSVOL may still be on legacy FRS (Get-DfsrMembership failed: $($_.Exception.Message))." `
            -Remediation 'If SYSVOL is on FRS, migrate to DFSR: https://learn.microsoft.com/en-us/troubleshoot/windows-server/group-policy/migrate-sysvol-replication-to-dfsr'
        return
    }

    $dcNames = $dcs | ForEach-Object { $_.Name }
    foreach ($dcName in $dcNames) {
        $m = $members | Where-Object { $_.ComputerName -eq $dcName } | Select-Object -First 1
        if (-not $m) {
            Add-ADFinding -CheckName 'Test-DFSRSYSVOLHealth' -Status 'FAIL' -Object $dcName `
                -Description "DC '$dcName' is not a member of the 'Domain System Volume' DFSR replication group. SYSVOL is not replicating to this DC." `
                -Remediation 'Investigate the DC''s DFSR configuration. Use dfsrdiag to diagnose. Policies originating elsewhere will not converge on this DC.'
            continue
        }
        if (-not $m.Enabled) {
            Add-ADFinding -CheckName 'Test-DFSRSYSVOLHealth' -Status 'FAIL' -Object $dcName `
                -Description "DC '$dcName' DFSR membership is DISABLED. SYSVOL replication is not active." `
                -Remediation "Enable DFSR membership via: Set-DfsrMembership -GroupName 'Domain System Volume' -ContentPath <path> -ComputerName '$dcName' -FolderName SYSVOL_DFSR -Enabled `$true"
            continue
        }

        # Check for critical DFSR events in the last 24h.
        try {
            $criticalIds = @(4012, 5002, 5014)
            $evts = Invoke-Command -ComputerName $dcName -ScriptBlock {
                param($ids)
                Get-WinEvent -FilterHashtable @{ LogName = 'DFS Replication'; Id = $ids; StartTime = (Get-Date).AddHours(-24) } -ErrorAction SilentlyContinue -MaxEvents 20
            } -ArgumentList (, $criticalIds) -ErrorAction Stop
        }
        catch {
            Add-ADFinding -CheckName 'Test-DFSRSYSVOLHealth' -Status 'WARNING' -Object $dcName `
                -Description "Unable to scan DFSR event log on '$dcName': $($_.Exception.Message)" `
                -Remediation 'Enable PSRemoting or check the DFS Replication event log directly on the DC.'
            continue
        }

        if ($evts -and @($evts).Count -gt 0) {
            $eventSummary = ($evts | Group-Object Id | ForEach-Object { "ID $($_.Name) x$($_.Count)" }) -join '; '
            Add-ADFinding -CheckName 'Test-DFSRSYSVOLHealth' -Status 'FAIL' -Object $dcName `
                -Description "DC '$dcName' has DFSR critical events in the last 24h: $eventSummary. SYSVOL replication is likely impaired." `
                -Remediation 'Investigate per event ID: 4012 = journal wrap (serious, requires non-authoritative restore); 5002 = content set disabled; 5014 = connection failure. Use dfsrdiag backlog / dfsrdiag replicationstate.'
        }
        else {
            Add-ADFinding -CheckName 'Test-DFSRSYSVOLHealth' -Status 'PASS' -Object $dcName `
                -Description "DC '$dcName' DFSR SYSVOL replication enabled, no critical events in last 24h." `
                -Remediation 'No action needed.'
        }
    }
}

#endregion

#region ==================== MAIN ENTRY POINT ====================

<#
.SYNOPSIS
    Runs the full Active Directory assessment.
.DESCRIPTION
    Verifies the environment via Test-ADEnvironment, then invokes all (or a
    selected subset of) Test-* functions. Returns the accumulated findings array.
.PARAMETER UserLogonInactivityDays
    Threshold for flagging stale user logons. Default 180.
.PARAMETER UserPasswordAgeDays
    Threshold for flagging stale passwords. Default 180.
.PARAMETER IncludeChecks
    Optional list of specific Test-* function names to run. Default: all.
.PARAMETER ExcludeChecks
    Optional list of Test-* function names to skip.
#>
function Invoke-ActiveDirectoryAssessment {
    [CmdletBinding()]
    [OutputType([array])]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingUsernameAndPasswordParams', '',
        Justification = 'Parameters are day-count thresholds, not credentials.')]
    param(
        [int]$UserLogonInactivityDays = $script:DefaultUserLogonInactivityDays,
        [int]$UserPasswordAgeDays = $script:DefaultUserPasswordAgeDays,
        [int]$RecentPrivilegedAccountDays = $script:DefaultRecentPrivilegedAccountDays,
        [int]$KrbTgtPasswordAgeDays = $script:DefaultKrbTgtPasswordAgeDays,
        [int]$KerberoastPasswordAgeDays = 90,
        # PR 4a knobs
        [bool]$ParallelDCProbing = $false,
        [string[]]$Tier0OUDNs = @(),
        [string[]]$AuthorizedPrincipalsExtra = @(),
        # PR 4b knobs
        [ValidateRange(1, 3)]
        [int]$DACLReachMaxDepth = 2,
        [hashtable]$AuditSubcategoryOverrides,
        [string[]]$IncludeChecks,
        [string[]]$ExcludeChecks
    )

    $script:AuthorizedPrincipalsExtra = $AuthorizedPrincipalsExtra

    $script:Findings = @()

    $env = Test-ADEnvironment
    if (-not $env.IsAvailable) {
        Add-ADFinding -CheckName 'Test-ADForestAndDomain' -Status 'INFO' -Object 'Active Directory Module' `
            -Description "Active Directory checks skipped. $($env.FailureReason)" `
            -Remediation 'Run on a domain-joined Windows host with RSAT installed. Cloud-only environments can ignore this finding.'
        return , $script:Findings
    }

    if (-not $env.IsDomainAdmin) {
        Add-ADFinding -CheckName 'Test-ADForestAndDomain' -Status 'WARNING' -Object 'Active Directory Permissions' `
            -Description 'Running without Domain Admin privileges. ACL / drift checks may return incomplete results.' `
            -Remediation 'Re-run as a Domain Admin or Read-Only Domain Admin for full coverage.'
    }

    $allChecks = @(
        'Test-ADForestAndDomain', 'Test-DomainControllers', 'Test-ADPasswordPolicy',
        'Test-ADStaleAccounts', 'Test-PrivilegedGroupMembership', 'Test-ProtectedUsersAdoption',
        'Test-DomainTrusts', 'Test-ADServiceAccounts', 'Test-KrbTgtAccountAge',
        'Test-DelegationOverview', 'Test-GPOInventory', 'Test-DuplicateSPNs',
        'Test-PrivilegedObjectACLs', 'Test-GPPPasswords', 'Test-KerberosPreAuthDisabled',
        'Test-UnconstrainedDelegation', 'Test-PasswordNeverExpires', 'Test-SIDHistory',
        'Test-PrivilegedSmartcardRequirement', 'Test-PrivilegedGroupCreep', 'Test-AdminSDHolderDrift',
        'Test-DangerousSIDsInPrivilegedGroups', 'Test-PasswordsInDescription', 'Test-UserAccountsWithSPN',
        'Test-OUAndGPODelegation', 'Test-RecentPrivilegedAccounts', 'Test-NestedGroupPrivilegePaths',
        'Test-SensitiveObjectACLDrift', 'Test-ShadowGroupNames',
        # PR 2 additions
        'Test-LAPSDeployment', 'Test-DCSecuritySettings', 'Test-KerberoastableAccounts',
        'Test-DirSyncAccountSecurity',
        # PR 4a - credential hygiene (Group A)
        'Test-LMHashStorage', 'Test-NTLMv1Allowed', 'Test-DCLegacyEncryption',
        'Test-NullSessionShares', 'Test-DomainEncryptionTypesPolicy',
        # PR 4a - ACL abuse paths (Group B)
        'Test-WritablePrivilegedACLs', 'Test-ShadowCredentialsVulnerable',
        'Test-RBCDConfigured', 'Test-GenericWriteToSensitive',
        # PR 4b - attack path + DNSAdmins + audit + DFSR
        'Test-AuthenticatedUsersDACLReach', 'Test-DNSAdminsPrivilege',
        'Test-EventAuditPolicy', 'Test-DFSRSYSVOLHealth'
    )

    $toRun = if ($IncludeChecks) {
        $allChecks | Where-Object { $IncludeChecks -contains $_ }
    }
    else {
        $allChecks
    }
    if ($ExcludeChecks) {
        $toRun = $toRun | Where-Object { $ExcludeChecks -notcontains $_ }
    }

    # PR 3: import the ADCS submodule if present. ADCS checks run at the end of
    # the AD assessment and gracefully no-op when no Enterprise CA is deployed.
    $adcsModulePath = Join-Path (Split-Path -Parent $PSCommandPath) 'EntraChecks-ADCS.psm1'
    $adcsAvailable = $false
    if (Test-Path -LiteralPath $adcsModulePath) {
        try {
            Import-Module -Name $adcsModulePath -Force -ErrorAction Stop
            $adcsAvailable = $true
        }
        catch {
            Write-Verbose "AD CS submodule import failed: $($_.Exception.Message)"
        }
    }

    foreach ($check in $toRun) {
        try {
            switch ($check) {
                'Test-ADStaleAccounts' {
                    & $check -UserLogonInactivityDays $UserLogonInactivityDays -UserPasswordAgeDays $UserPasswordAgeDays
                }
                'Test-KrbTgtAccountAge' {
                    & $check -MaxAgeDays $KrbTgtPasswordAgeDays
                }
                'Test-RecentPrivilegedAccounts' {
                    & $check -RecentDays $RecentPrivilegedAccountDays
                }
                'Test-KerberoastableAccounts' {
                    & $check -PasswordAgeDays $KerberoastPasswordAgeDays
                }
                'Test-LMHashStorage' { & $check -Parallel:$ParallelDCProbing }
                'Test-NTLMv1Allowed' { & $check -Parallel:$ParallelDCProbing }
                'Test-DCLegacyEncryption' { & $check -Parallel:$ParallelDCProbing }
                'Test-NullSessionShares' { & $check -Parallel:$ParallelDCProbing }
                'Test-RBCDConfigured' { & $check -Tier0OUDNs $Tier0OUDNs }
                'Test-AuthenticatedUsersDACLReach' { & $check -MaxDepth $DACLReachMaxDepth }
                'Test-EventAuditPolicy' {
                    if ($AuditSubcategoryOverrides) { & $check -Subcategories $AuditSubcategoryOverrides }
                    else { & $check }
                }
                default {
                    & $check
                }
            }
        }
        catch {
            Add-ADFinding -CheckName $check -Status 'WARNING' -Object $check `
                -Description "Check failed unexpectedly: $($_.Exception.Message)" `
                -Remediation 'Inspect the module source or report this failure; the assessment continued with the remaining checks.'
        }
    }

    # PR 3: run ADCS checks as the final phase. Appends to $script:Findings of
    # the ADCS module, which we then merge back into this module's findings.
    if ($adcsAvailable) {
        try {
            $adcsFindings = Invoke-ADCSAssessment
            if ($adcsFindings) {
                $script:Findings += $adcsFindings
            }
        }
        catch {
            Write-Verbose "Invoke-ADCSAssessment failed: $($_.Exception.Message)"
        }
    }

    return , $script:Findings
}

#endregion

#region ==================== MODULE EXPORTS ====================

Export-ModuleMember -Function @(
    'Initialize-ActiveDirectoryModule',
    'Test-ADEnvironment',
    'Invoke-ActiveDirectoryAssessment',
    'Test-ADForestAndDomain',
    'Test-DomainControllers',
    'Test-ADPasswordPolicy',
    'Test-ADStaleAccounts',
    'Test-PrivilegedGroupMembership',
    'Test-ProtectedUsersAdoption',
    'Test-DomainTrusts',
    'Test-ADServiceAccounts',
    'Test-KrbTgtAccountAge',
    'Test-DelegationOverview',
    'Test-GPOInventory',
    'Test-DuplicateSPNs',
    'Test-PrivilegedObjectACLs',
    'Test-GPPPasswords',
    'Test-KerberosPreAuthDisabled',
    'Test-UnconstrainedDelegation',
    'Test-PasswordNeverExpires',
    'Test-SIDHistory',
    'Test-PrivilegedSmartcardRequirement',
    'Test-PrivilegedGroupCreep',
    'Test-AdminSDHolderDrift',
    'Test-DangerousSIDsInPrivilegedGroups',
    'Test-PasswordsInDescription',
    'Test-UserAccountsWithSPN',
    'Test-OUAndGPODelegation',
    'Test-RecentPrivilegedAccounts',
    'Test-NestedGroupPrivilegePaths',
    'Test-SensitiveObjectACLDrift',
    'Test-ShadowGroupNames',
    # PR 2 additions
    'Test-LAPSDeployment',
    'Test-DCSecuritySettings',
    'Test-KerberoastableAccounts',
    'Test-DirSyncAccountSecurity',
    # PR 4a - credential hygiene (Group A)
    'Test-LMHashStorage',
    'Test-NTLMv1Allowed',
    'Test-DCLegacyEncryption',
    'Test-NullSessionShares',
    'Test-DomainEncryptionTypesPolicy',
    # PR 4a - ACL abuse paths (Group B)
    'Test-WritablePrivilegedACLs',
    'Test-ShadowCredentialsVulnerable',
    'Test-RBCDConfigured',
    'Test-GenericWriteToSensitive',
    # PR 4b - attack path + DNSAdmins + audit + DFSR
    'Test-AuthenticatedUsersDACLReach',
    'Test-DNSAdminsPrivilege',
    'Test-EventAuditPolicy',
    'Test-DFSRSYSVOLHealth'
)

#endregion
