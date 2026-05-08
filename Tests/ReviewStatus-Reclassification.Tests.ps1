<#
.SYNOPSIS
    Pester 5 regression test for the WARNING -> REVIEW reclassifications
    (PR 3 of Review-Status-Plan).

.DESCRIPTION
    Static source-text assertions: verify each function listed below contains
    at least one `-Status "REVIEW"` emission. Lightweight — doesn't require
    mocking Graph. The point is to catch reverts: if someone changes a REVIEW
    back to WARNING in any of these functions, this test fails loudly.

    The reclassification audit moved 26 emissions across 3 files:
      - Scripts/Invoke-EntraChecks.ps1                   (13 emissions)
      - Modules/EntraChecks-IdentityProtection.psm1      (6 emissions)
      - Modules/EntraChecks-Devices.psm1                 (6 emissions)

    All 26 share the same criterion: remediation language begins with
    "Review" / "Investigate" / "Consider", indicating human-judgment
    intent rather than a deterministic policy violation.

    Run: Invoke-Pester -Path Tests/ReviewStatus-Reclassification.Tests.ps1
#>

#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeAll {
    $repoRoot = Split-Path -Parent $PSScriptRoot
    $script:OrchestratorSrc = Get-Content (Join-Path $repoRoot 'Scripts/Invoke-EntraChecks.ps1') -Raw
    $script:IdentityProtectionSrc = Get-Content (Join-Path $repoRoot 'Modules/EntraChecks-IdentityProtection.psm1') -Raw
    $script:DevicesSrc = Get-Content (Join-Path $repoRoot 'Modules/EntraChecks-Devices.psm1') -Raw

    # Helper: extract the body of a named function from a source string. Returns
    # the substring from `function <Name>` to the next top-level closing brace
    # at column 1 (best-effort heuristic — works for the conventionally-formatted
    # functions in this codebase).
    function Get-FunctionBody {
        param(
            [string]$Src,
            [string]$Name
        )
        $pattern = "(?ms)^function\s+$([regex]::Escape($Name))[\s\(]+.*?^\}"
        $m = [regex]::Match($Src, $pattern)
        if ($m.Success) { return $m.Value }
        return ''
    }

    function Get-ReviewCount {
        param([string]$Body)
        ([regex]::Matches($Body, '-Status\s+"REVIEW"')).Count
    }
}

Describe 'PR 3 reclassifications — Scripts/Invoke-EntraChecks.ps1' {

    It 'Test-OAuthConsentGrants emits at least 2 REVIEW findings (high-risk scope + third-party admin consent)' {
        $body = Get-FunctionBody -Src $script:OrchestratorSrc -Name 'Test-OAuthConsentGrants'
        $body | Should -Not -BeNullOrEmpty
        Get-ReviewCount -Body $body | Should -BeGreaterOrEqual 2
    }

    It 'Test-DirectoryRolesAndMembers emits at least 1 REVIEW (servicePrincipal with privileged role)' {
        $body = Get-FunctionBody -Src $script:OrchestratorSrc -Name 'Test-DirectoryRolesAndMembers'
        Get-ReviewCount -Body $body | Should -BeGreaterOrEqual 1
    }

    It 'Test-DirectoryRoleAssignmentPaths emits at least 2 REVIEW findings (5+ assignments + SP-with-role)' {
        $body = Get-FunctionBody -Src $script:OrchestratorSrc -Name 'Test-DirectoryRoleAssignmentPaths'
        Get-ReviewCount -Body $body | Should -BeGreaterOrEqual 2
    }

    It 'Test-UserAccountsAndInactivity emits at least 2 REVIEW findings (inactive user + never-signed-in)' {
        $body = Get-FunctionBody -Src $script:OrchestratorSrc -Name 'Test-UserAccountsAndInactivity'
        Get-ReviewCount -Body $body | Should -BeGreaterOrEqual 2
    }

    It 'Test-RoleAssignableGroupOwnership emits at least 1 REVIEW (servicePrincipal owner)' {
        $body = Get-FunctionBody -Src $script:OrchestratorSrc -Name 'Test-RoleAssignableGroupOwnership'
        Get-ReviewCount -Body $body | Should -BeGreaterOrEqual 1
    }

    It 'Test-ApplicationCredentials emits at least 2 REVIEW findings (long-lived secret + multiple credentials)' {
        $body = Get-FunctionBody -Src $script:OrchestratorSrc -Name 'Test-ApplicationCredentials'
        Get-ReviewCount -Body $body | Should -BeGreaterOrEqual 2
    }

    It 'Test-AppRoleAssignments emits at least 1 REVIEW (app with 10+ Graph permissions)' {
        $body = Get-FunctionBody -Src $script:OrchestratorSrc -Name 'Test-AppRoleAssignments'
        Get-ReviewCount -Body $body | Should -BeGreaterOrEqual 1
    }

    It 'Test-NamedLocation emits at least 2 REVIEW findings (broad-IP-trusted + unknown-countries-trusted)' {
        $body = Get-FunctionBody -Src $script:OrchestratorSrc -Name 'Test-NamedLocation'
        Get-ReviewCount -Body $body | Should -BeGreaterOrEqual 2
    }
}

Describe 'PR 3 reclassifications — Modules/EntraChecks-IdentityProtection.psm1' {

    It 'Test-RiskyUsers emits at least 2 REVIEW findings (medium risk + stale risks)' {
        $body = Get-FunctionBody -Src $script:IdentityProtectionSrc -Name 'Test-RiskyUsers'
        Get-ReviewCount -Body $body | Should -BeGreaterOrEqual 2
    }

    It 'Test-RiskySignIns emits at least 2 REVIEW findings (medium-risk + impossible-travel)' {
        $body = Get-FunctionBody -Src $script:IdentityProtectionSrc -Name 'Test-RiskySignIns'
        Get-ReviewCount -Body $body | Should -BeGreaterOrEqual 2
    }

    It 'Test-RiskDetections emits at least 2 REVIEW findings (unexpected geo + trend increase)' {
        $body = Get-FunctionBody -Src $script:IdentityProtectionSrc -Name 'Test-RiskDetections'
        Get-ReviewCount -Body $body | Should -BeGreaterOrEqual 2
    }
}

Describe 'PR 3 reclassifications — Modules/EntraChecks-Devices.psm1' {

    It 'Test-DeviceOverview emits at least 1 REVIEW (non-compliant devices)' {
        $body = Get-FunctionBody -Src $script:DevicesSrc -Name 'Test-DeviceOverview'
        Get-ReviewCount -Body $body | Should -BeGreaterOrEqual 1
    }

    It 'Test-StaleDevices emits at least 2 REVIEW findings (stale + never-signed-in)' {
        $body = Get-FunctionBody -Src $script:DevicesSrc -Name 'Test-StaleDevices'
        Get-ReviewCount -Body $body | Should -BeGreaterOrEqual 2
    }

    It 'Test-DeviceComplianceStatus emits at least 2 REVIEW findings (policy conflicts + not-syncing)' {
        $body = Get-FunctionBody -Src $script:DevicesSrc -Name 'Test-DeviceComplianceStatus'
        Get-ReviewCount -Body $body | Should -BeGreaterOrEqual 2
    }

    It 'Test-DeviceRegistrationPolicy emits at least 2 REVIEW findings (Azure AD Join all users + 20+ device limit)' {
        $body = Get-FunctionBody -Src $script:DevicesSrc -Name 'Test-DeviceRegistrationPolicy'
        Get-ReviewCount -Body $body | Should -BeGreaterOrEqual 2
    }
}

Describe 'PR 3 reclassifications — total emission count' {

    It 'has at least 26 REVIEW emissions across the 3 audited files (regression guard)' {
        $totalReview = (Get-ReviewCount -Body $script:OrchestratorSrc) +
                       (Get-ReviewCount -Body $script:IdentityProtectionSrc) +
                       (Get-ReviewCount -Body $script:DevicesSrc)
        $totalReview | Should -BeGreaterOrEqual 26
    }
}
