<#
.SYNOPSIS
    Pester 5 suite for EntraChecks-HybridCorrelation.psm1.

.DESCRIPTION
    Synthetic finding arrays. Verifies the correlation logic matches
    principals across cloud and on-prem findings by UPN (Exact) and by
    sAMAccountName (Inferred), and correctly excludes infrastructure /
    INFO / PASS findings.

    Run:
      Invoke-Pester -Path Tests/EntraChecks-HybridCorrelation.Tests.ps1
#>

#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeAll {
    $repoRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $repoRoot 'Modules\EntraChecks-HybridCorrelation.psm1') -Force

    function New-CloudFinding {
        param(
            [string]$Upn,
            [string]$Status = 'FAIL',
            [string]$Severity = 'High',
            [string]$Category = 'Identity',
            [string]$Source = 'IdentityProtection'
        )
        [pscustomobject]@{
            Time = Get-Date
            Status = $Status
            Severity = $Severity
            Category = $Category
            Object = $Upn
            Description = "Synthetic cloud finding for $Upn"
            Remediation = 'Synthetic'
            Source = $Source
        }
    }

    function New-OnPremFinding {
        param(
            [string]$Sam,
            [string]$Status = 'WARNING',
            [string]$Severity = 'Medium',
            [string]$Category = 'Privileged Access',
            [string]$CheckName = 'Test-Synthetic',
            [string]$Description
        )
        if (-not $PSBoundParameters.ContainsKey('Description')) {
            $Description = "Synthetic on-prem finding for $Sam"
        }
        [pscustomobject]@{
            Time = Get-Date
            CheckName = $CheckName
            Status = $Status
            Severity = $Severity
            Category = $Category
            Object = $Sam
            Description = $Description
            Remediation = 'Synthetic'
            Source = 'ActiveDirectory'
        }
    }

    # PR 5 - helper for the PrivilegedRoleMember INFO marker emitted by
    # Check-DirectoryRolesAndMembers.
    function New-RoleMemberMarker {
        param(
            [string]$Upn,
            [string]$Role = 'Global Administrator'
        )
        [pscustomobject]@{
            Time = Get-Date
            CheckName = 'Check-DirectoryRolesAndMembers'
            Status = 'INFO'
            Severity = 'Info'
            Category = 'Identity'
            Object = "$Upn ($Role)"
            Description = "PrivilegedRoleMember: '$Upn' holds cloud role '$Role'. Inventory marker for hybrid correlation."
            Remediation = 'No action required.'
        }
    }
}

Describe 'Get-HybridIdentityCorrelation — empty input' {

    It 'returns zero counts for an empty findings array' {
        $result = Get-HybridIdentityCorrelation -Findings @()
        $result.CorrelationCount | Should -Be 0
        $result.CorrelatedPrincipals.Count | Should -Be 0
        $result.CloudOnlyPrincipals.Count | Should -Be 0
        $result.OnPremOnlyPrincipals.Count | Should -Be 0
    }

    It 'returns zero counts for null input without crashing' {
        $result = Get-HybridIdentityCorrelation -Findings $null
        $result.CorrelationCount | Should -Be 0
    }
}

Describe 'Get-HybridIdentityCorrelation — UPN exact matching' {

    It 'correlates a principal flagged in both planes by UPN' {
        $findings = @(
            (New-CloudFinding -Upn 'alice@contoso.com' -Source 'IdentityProtection' -Severity 'High'),
            (New-OnPremFinding -Sam 'alice@contoso.com' -Severity 'Medium')
        )
        $result = Get-HybridIdentityCorrelation -Findings $findings
        $result.CorrelationCount | Should -Be 1
        $result.CorrelatedPrincipals[0].Confidence | Should -Be 'Exact'
        $result.CorrelatedPrincipals[0].Principal | Should -Be 'alice@contoso.com'
    }

    It 'surfaces the maximum severity per plane' {
        $findings = @(
            (New-CloudFinding -Upn 'bob@contoso.com' -Severity 'Medium'),
            (New-CloudFinding -Upn 'bob@contoso.com' -Severity 'Critical'),
            (New-OnPremFinding -Sam 'bob@contoso.com' -Severity 'Low'),
            (New-OnPremFinding -Sam 'bob@contoso.com' -Severity 'High')
        )
        $result = Get-HybridIdentityCorrelation -Findings $findings
        $result.CorrelatedPrincipals[0].MaxCloudSeverity | Should -Be 'Critical'
        $result.CorrelatedPrincipals[0].MaxOnPremSeverity | Should -Be 'High'
    }
}

Describe 'Get-HybridIdentityCorrelation — sAMAccountName inferred matching' {

    It 'correlates when cloud has UPN and on-prem has only sAMAccountName' {
        $findings = @(
            (New-CloudFinding -Upn 'carol@contoso.com' -Severity 'High'),
            (New-OnPremFinding -Sam 'carol' -Severity 'Medium')
        )
        $result = Get-HybridIdentityCorrelation -Findings $findings
        $result.CorrelationCount | Should -Be 1
        $result.CorrelatedPrincipals[0].Confidence | Should -Be 'Inferred'
        $result.CorrelatedPrincipals[0].MatchKey | Should -Be 'sAMAccountName'
    }

    It 'does not double-count when a UPN match and a SAM match both exist' {
        $findings = @(
            (New-CloudFinding -Upn 'dave@contoso.com' -Severity 'High'),
            (New-OnPremFinding -Sam 'dave@contoso.com' -Severity 'Medium'),
            (New-OnPremFinding -Sam 'dave' -Severity 'Low')
        )
        $result = Get-HybridIdentityCorrelation -Findings $findings
        $result.CorrelationCount | Should -Be 1
        $result.CorrelatedPrincipals[0].Confidence | Should -Be 'Exact'
    }
}

Describe 'Get-HybridIdentityCorrelation — buckets' {

    It 'separates cloud-only and on-prem-only principals' {
        $findings = @(
            (New-CloudFinding -Upn 'cloudonly@contoso.com' -Severity 'High'),
            (New-OnPremFinding -Sam 'onpremonly' -Severity 'Medium')
        )
        $result = Get-HybridIdentityCorrelation -Findings $findings
        $result.CorrelationCount | Should -Be 0
        @($result.CloudOnlyPrincipals | Where-Object { $_.Principal -eq 'cloudonly@contoso.com' }).Count | Should -Be 1
    }
}

Describe 'Get-HybridIdentityCorrelation — exclusion filters' {

    It 'excludes Infrastructure-category findings' {
        $findings = @(
            (New-CloudFinding -Upn 'eve@contoso.com' -Category 'Infrastructure'),
            (New-OnPremFinding -Sam 'eve@contoso.com' -Category 'Infrastructure')
        )
        $result = Get-HybridIdentityCorrelation -Findings $findings
        $result.CorrelationCount | Should -Be 0
    }

    It 'excludes INFO and PASS status findings' {
        $findings = @(
            (New-CloudFinding -Upn 'frank@contoso.com' -Status 'INFO'),
            (New-OnPremFinding -Sam 'frank@contoso.com' -Status 'PASS')
        )
        $result = Get-HybridIdentityCorrelation -Findings $findings
        $result.CorrelationCount | Should -Be 0
    }

    It 'includes WARNING findings' {
        $findings = @(
            (New-CloudFinding -Upn 'grace@contoso.com' -Status 'WARNING' -Severity 'Medium'),
            (New-OnPremFinding -Sam 'grace@contoso.com' -Status 'WARNING' -Severity 'Medium')
        )
        $result = Get-HybridIdentityCorrelation -Findings $findings
        $result.CorrelationCount | Should -Be 1
    }
}

Describe 'Get-HybridIdentityCorrelation — totals' {

    It 'tracks total identity-bearing findings per plane' {
        $findings = @(
            (New-CloudFinding -Upn 'a@contoso.com'),
            (New-CloudFinding -Upn 'b@contoso.com'),
            (New-OnPremFinding -Sam 'a@contoso.com'),
            (New-OnPremFinding -Sam 'c'),
            (New-OnPremFinding -Sam 'd')
        )
        $result = Get-HybridIdentityCorrelation -Findings $findings
        $result.TotalCloudFindings | Should -Be 2
        $result.TotalOnPremFindings | Should -Be 3
    }
}

# ---------------------------------------------------------------------------
# PR 5 - Cross-surface correlators
# ---------------------------------------------------------------------------

Describe 'New-PrincipalIndex' {

    It 'extracts privileged role names from Check-DirectoryRolesAndMembers markers' {
        $findings = @(
            (New-RoleMemberMarker -Upn 'alice@contoso.com' -Role 'Global Administrator'),
            (New-RoleMemberMarker -Upn 'alice@contoso.com' -Role 'User Administrator')
        )
        $idx = New-PrincipalIndex -Findings $findings
        $idx.ContainsKey('alice@contoso.com') | Should -Be $true
        @($idx['alice@contoso.com'].PrivilegedRoles) | Should -Contain 'Global Administrator'
        @($idx['alice@contoso.com'].PrivilegedRoles) | Should -Contain 'User Administrator'
    }

    It 'handles empty and null input without crashing' {
        (New-PrincipalIndex -Findings @()).Keys.Count | Should -Be 0
        (New-PrincipalIndex -Findings $null).Keys.Count | Should -Be 0
    }
}

Describe 'Find-DAExposureToCloudAdmin' {

    It 'emits a Critical finding when DIRECT DACL reach intersects cloud admin role' {
        $marker = New-RoleMemberMarker -Upn 'alice@contoso.com' -Role 'Global Administrator'
        $onPrem = New-OnPremFinding -Sam 'alice@contoso.com' -Status 'FAIL' -Severity 'Critical' -CheckName 'Test-AuthenticatedUsersDACLReach' -Description "DIRECT reach (1 hop): non-admin 'TEST\helpdesk' has 'GenericAll' on privileged user 'alice'."
        $result = Get-HybridIdentityCorrelation -Findings @($marker, $onPrem)
        $cross = @($result.CrossSurfaceFindings | Where-Object { $_.Type -eq 'HybridCrossSurface_DAExposureToCloudAdmin' })
        $cross.Count | Should -Be 1
        $cross[0].Severity | Should -Be 'Critical'
        $cross[0].Principal | Should -Be 'alice@contoso.com'
    }

    It 'stays silent when DACL reach targets a non-cloud-admin principal' {
        $onPrem = New-OnPremFinding -Sam 'alice@contoso.com' -Status 'FAIL' -Severity 'Critical' -CheckName 'Test-AuthenticatedUsersDACLReach' -Description "DIRECT reach: non-admin has 'GenericAll' on 'alice'."
        $result = Get-HybridIdentityCorrelation -Findings @($onPrem)
        @($result.CrossSurfaceFindings | Where-Object { $_.Type -eq 'HybridCrossSurface_DAExposureToCloudAdmin' }).Count | Should -Be 0
    }
}

Describe 'Find-DnsAdminsWithCloudPrivilege' {

    It 'emits Critical when legacy DC language is present + cloud admin overlap' {
        $marker = New-RoleMemberMarker -Upn 'bob@contoso.com' -Role 'Privileged Role Administrator'
        $onPrem = New-OnPremFinding -Sam 'DnsAdmins' -Status 'FAIL' -Severity 'Critical' -CheckName 'Test-DNSAdminsPrivilege' -Description "DnsAdmins has 1 member(s): bob [user]. At least one DC runs Server 2016 or earlier - legacy DC."
        $result = Get-HybridIdentityCorrelation -Findings @($marker, $onPrem)
        $cross = @($result.CrossSurfaceFindings | Where-Object { $_.Type -eq 'HybridCrossSurface_DnsAdminsWithCloudPrivilege' })
        $cross.Count | Should -Be 1
        $cross[0].Severity | Should -Be 'Critical'
    }

    It 'emits High when only modern DCs (no legacy language in description)' {
        $marker = New-RoleMemberMarker -Upn 'bob@contoso.com' -Role 'User Administrator'
        $onPrem = New-OnPremFinding -Sam 'DnsAdmins' -Status 'WARNING' -Severity 'High' -CheckName 'Test-DNSAdminsPrivilege' -Description "DnsAdmins has 1 member(s): bob [user]. Modern DCs are hardened but membership is still an escalation surface."
        $result = Get-HybridIdentityCorrelation -Findings @($marker, $onPrem)
        $cross = @($result.CrossSurfaceFindings | Where-Object { $_.Type -eq 'HybridCrossSurface_DnsAdminsWithCloudPrivilege' })
        $cross.Count | Should -Be 1
        $cross[0].Severity | Should -Be 'High'
    }
}

Describe 'Find-ShadowCredentialsOnCloudSyncedAdmin' {

    It 'emits Critical when shadow-creds target also holds a cloud role' {
        $marker = New-RoleMemberMarker -Upn 'carol@contoso.com' -Role 'Global Administrator'
        $onPrem = New-OnPremFinding -Sam 'carol@contoso.com' -Status 'FAIL' -Severity 'High' -CheckName 'Test-ShadowCredentialsVulnerable' -Description 'msDS-KeyCredentialLink write exposure on carol.'
        $result = Get-HybridIdentityCorrelation -Findings @($marker, $onPrem)
        $cross = @($result.CrossSurfaceFindings | Where-Object { $_.Type -eq 'HybridCrossSurface_ShadowCredentialsOnCloudSyncedAdmin' })
        $cross.Count | Should -Be 1
        $cross[0].Severity | Should -Be 'Critical'
    }
}

Describe 'Find-RBCDOnPrivilegedTier0Targeting' {

    It 'emits High when RBCD source principal is cloud-privileged' {
        $marker = New-RoleMemberMarker -Upn 'svc@contoso.com' -Role 'Application Administrator'
        $onPrem = New-OnPremFinding -Sam 'DC01' -Status 'FAIL' -Severity 'Critical' -CheckName 'Test-RBCDConfigured' -Description "RBCD configured on Tier 0 target 'DC01', allowing impersonation by: svc@contoso.com. High risk."
        $result = Get-HybridIdentityCorrelation -Findings @($marker, $onPrem)
        $cross = @($result.CrossSurfaceFindings | Where-Object { $_.Type -eq 'HybridCrossSurface_RBCDOnPrivilegedTier0Targeting' })
        $cross.Count | Should -Be 1
        $cross[0].Severity | Should -Be 'High'
    }

    It 'skips gracefully when RBCD source is not extractable' {
        $marker = New-RoleMemberMarker -Upn 'svc@contoso.com' -Role 'Application Administrator'
        $onPrem = New-OnPremFinding -Sam 'DC01' -Status 'FAIL' -Severity 'Critical' -CheckName 'Test-RBCDConfigured' -Description 'RBCD configured but description does not match pattern.'
        $result = Get-HybridIdentityCorrelation -Findings @($marker, $onPrem)
        @($result.CrossSurfaceFindings | Where-Object { $_.Type -eq 'HybridCrossSurface_RBCDOnPrivilegedTier0Targeting' }).Count | Should -Be 0
    }
}

Describe 'Find-RiskyUserWithOnPremPrivilege' {

    It 'emits High when a risky user is also on-prem Tier 0 member' {
        $cloud = New-CloudFinding -Upn 'dave@contoso.com' -Status 'FAIL' -Severity 'High' -Source 'IdentityProtection'
        $cloud | Add-Member -MemberType NoteProperty -Name CheckName -Value 'Test-RiskyUsers' -Force
        $onPrem = New-OnPremFinding -Sam 'dave@contoso.com' -Status 'FAIL' -Severity 'High' -CheckName 'Test-PrivilegedGroupMembership' -Description "User 'dave' is a member of Domain Admins."
        $result = Get-HybridIdentityCorrelation -Findings @($cloud, $onPrem)
        $cross = @($result.CrossSurfaceFindings | Where-Object { $_.Type -eq 'HybridCrossSurface_RiskyUserWithOnPremPrivilege' })
        $cross.Count | Should -Be 1
        $cross[0].Severity | Should -BeIn @('High', 'Critical')
    }

    It 'stays silent when risky user has no on-prem privileged group finding' {
        $cloud = New-CloudFinding -Upn 'dave@contoso.com' -Status 'FAIL' -Severity 'High' -Source 'IdentityProtection'
        $cloud | Add-Member -MemberType NoteProperty -Name CheckName -Value 'Test-RiskyUsers' -Force
        $result = Get-HybridIdentityCorrelation -Findings @($cloud)
        @($result.CrossSurfaceFindings | Where-Object { $_.Type -eq 'HybridCrossSurface_RiskyUserWithOnPremPrivilege' }).Count | Should -Be 0
    }
}

Describe 'CrossSurfaceFindings output shape' {

    It 'exposes CrossSurfaceFindings + CrossSurfaceCount fields' {
        $result = Get-HybridIdentityCorrelation -Findings @()
        $result.PSObject.Properties.Name | Should -Contain 'CrossSurfaceFindings'
        $result.PSObject.Properties.Name | Should -Contain 'CrossSurfaceCount'
        $result.CrossSurfaceCount | Should -Be 0
    }
}
