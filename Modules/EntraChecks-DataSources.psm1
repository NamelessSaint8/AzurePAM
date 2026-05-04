<#
.SYNOPSIS
    EntraChecks-DataSources.psm1
    Authoritative provenance catalog for every data source EntraChecks ingests.

.DESCRIPTION
    Single source of truth that maps each data source bucket
    (Internal, SecureScore, DefenderCompliance, AzurePolicy, PurviewCompliance)
    to the API endpoints, cmdlets, scopes, and reference documentation that
    produced it. Reports use this catalog to surface auditor-grade provenance.

    Adding a new data source = one new entry in $script:DataSourceCatalog.

.NOTES
    Static fields (Description, Provider, Endpoints, Cmdlets, Scopes, ReferenceUrl)
    are declarative. Runtime fields (AuthMethod, Upn, Tenant, Subscriptions,
    QueriedAt) are populated by Update-DataSourceContext at the call site that
    just produced the data.

.LINK
    Used by:
    - Modules/EntraChecks-Compliance.psm1 (Export-UnifiedComplianceReport)
    - Modules/EntraChecks-ExcelReporting.psm1 (Data Sources sheet)
    - Scripts/Invoke-EntraChecks.ps1 (Add-Finding: per-finding source tagging)
#>

#Requires -Version 5.1

$script:ModuleVersion = "1.0.0"
$script:ModuleName = "EntraChecks-DataSources"

#region ==================== CATALOG ====================

$script:DataSourceCatalog = @{
    Internal = @{
        Description = "EntraChecks internal compliance assessment"
        Provider = "Local engine"
        Endpoints = @()
        Cmdlets = @("Invoke-EntraChecks")
        Scopes = @()
        AuthMethod = $null
        Upn = $null
        Tenant = $null
        Subscriptions = @()
        QueriedAt = $null
        ReferenceUrl = "https://github.com/f8l124/AzurePAM"
    }
    SecureScore = @{
        Description = "Microsoft Secure Score"
        Provider = "Microsoft Graph (security)"
        Endpoints = @(
            "GET https://graph.microsoft.com/v1.0/security/secureScores",
            "GET https://graph.microsoft.com/v1.0/security/secureScoreControlProfiles"
        )
        Cmdlets = @("Get-SecureScore", "Get-SecureScoreImprovementActions", "Invoke-MgGraphRequest")
        Scopes = @("SecurityEvents.Read.All")
        AuthMethod = $null
        Upn = $null
        Tenant = $null
        Subscriptions = @()
        QueriedAt = $null
        ReferenceUrl = "https://learn.microsoft.com/en-us/graph/api/resources/securescore"
    }
    DefenderCompliance = @{
        Description = "Defender for Cloud regulatory compliance"
        Provider = "Azure Resource Manager (Microsoft.Security)"
        Endpoints = @(
            "GET /subscriptions/{id}/providers/Microsoft.Security/regulatoryComplianceStandards",
            "GET /subscriptions/{id}/providers/Microsoft.Security/regulatoryComplianceStandards/{name}/regulatoryComplianceControls"
        )
        Cmdlets = @("Get-DefenderComplianceAssessment", "Get-AzSubscription", "Invoke-AzRestMethod")
        Scopes = @("RBAC: Reader on each subscription")
        AuthMethod = $null
        Upn = $null
        Tenant = $null
        Subscriptions = @()
        QueriedAt = $null
        ReferenceUrl = "https://learn.microsoft.com/en-us/azure/defender-for-cloud/regulatory-compliance-dashboard"
    }
    AzurePolicy = @{
        Description = "Azure Policy compliance"
        Provider = "Azure Resource Manager (Microsoft.PolicyInsights)"
        Endpoints = @(
            "Get-AzPolicyState",
            "Get-AzPolicyAssignment",
            "Get-AzPolicyStateSummary"
        )
        Cmdlets = @("Get-AzurePolicyComplianceAssessment", "Get-AzPolicyState", "Get-AzPolicyAssignment", "Get-AzPolicyStateSummary")
        Scopes = @("RBAC: Reader on each subscription")
        AuthMethod = $null
        Upn = $null
        Tenant = $null
        Subscriptions = @()
        QueriedAt = $null
        ReferenceUrl = "https://learn.microsoft.com/en-us/azure/governance/policy/how-to/get-compliance-data"
    }
    PurviewCompliance = @{
        Description = "Purview Compliance Manager"
        Provider = "Microsoft Graph (compliance)"
        Endpoints = @(
            "GET https://graph.microsoft.com/beta/compliance/complianceManager/...",
            "GET https://graph.microsoft.com/v1.0/security/labels/..."
        )
        Cmdlets = @("Get-PurviewComplianceAssessment", "Invoke-MgGraphRequest")
        Scopes = @("ComplianceManager.Read.All", "InformationProtectionPolicy.Read")
        AuthMethod = $null
        Upn = $null
        Tenant = $null
        Subscriptions = @()
        QueriedAt = $null
        ReferenceUrl = "https://learn.microsoft.com/en-us/purview/compliance-manager"
    }
}

# Maps a module file name (case-insensitive) to its data source key.
# Anything not listed defaults to 'Internal'.
$script:ModuleToSource = @{
    'EntraChecks-SecureScore.psm1' = 'SecureScore'
    'EntraChecks-DefenderCompliance.psm1' = 'DefenderCompliance'
    'EntraChecks-AzurePolicy.psm1' = 'AzurePolicy'
    'EntraChecks-PurviewCompliance.psm1' = 'PurviewCompliance'
}

#endregion

#region ==================== PRIVATE HELPERS ====================

function ConvertTo-DataSourceClone {
    <#
    .SYNOPSIS
        Returns a deep-enough clone of a catalog descriptor so callers cannot
        mutate the master entry by reference.
    #>
    [OutputType([hashtable])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Descriptor
    )

    $clone = @{}
    foreach ($key in $Descriptor.Keys) {
        $value = $Descriptor[$key]
        if ($value -is [array]) {
            $clone[$key] = @($value)
        }
        else {
            $clone[$key] = $value
        }
    }
    return $clone
}

#endregion

#region ==================== PUBLIC FUNCTIONS ====================

function Get-DataSourceCatalog {
    <#
    .SYNOPSIS
        Returns a fresh copy of the full data source catalog.

    .DESCRIPTION
        Each call returns independent clones so the caller can populate runtime
        fields without affecting the master catalog or other consumers.

    .EXAMPLE
        $catalog = Get-DataSourceCatalog
        $catalog.SecureScore.QueriedAt = (Get-Date).ToUniversalTime()
    #>
    [OutputType([hashtable])]
    [CmdletBinding()]
    param()

    $result = @{}
    foreach ($key in $script:DataSourceCatalog.Keys) {
        $result[$key] = ConvertTo-DataSourceClone -Descriptor $script:DataSourceCatalog[$key]
    }
    return $result
}

function Get-DataSourceDescriptor {
    <#
    .SYNOPSIS
        Returns a clone of a single named descriptor from the catalog.

    .PARAMETER Key
        Catalog key (e.g., 'SecureScore').

    .EXAMPLE
        $d = Get-DataSourceDescriptor -Key 'SecureScore'
    #>
    [OutputType([hashtable])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Key
    )

    if (-not $script:DataSourceCatalog.ContainsKey($Key)) {
        throw "Unknown data source key: '$Key'. Known keys: $($script:DataSourceCatalog.Keys -join ', ')"
    }
    return ConvertTo-DataSourceClone -Descriptor $script:DataSourceCatalog[$Key]
}

function Update-DataSourceContext {
    <#
    .SYNOPSIS
        Stamps runtime context (Auth, Tenant, Subscriptions, QueriedAt) onto a
        descriptor at the moment data is ingested.

    .DESCRIPTION
        Call this once per source bucket after the data has been gathered, so
        the report can show *who* queried *what tenant/subscriptions* *when*.

        The descriptor is mutated in place. Pass either the live runtime context
        (UPN, AuthMethod, etc.) or rely on the function to derive it from
        Get-MgContext / Get-AzContext.

    .PARAMETER Descriptor
        Hashtable from Get-DataSourceDescriptor or a slot in Get-DataSourceCatalog.

    .PARAMETER AuthMethod
        Optional override (e.g., 'Delegated · interactive', 'App-only · client credentials').

    .PARAMETER Upn
        Optional signed-in user principal name. If omitted, derived from Get-MgContext.

    .PARAMETER Tenant
        Optional tenant identifier. If omitted, derived from Get-MgContext / Get-AzContext.

    .PARAMETER Subscriptions
        Optional list of subscription names/IDs queried.

    .PARAMETER QueriedAt
        Optional ISO-8601 timestamp. Defaults to UTC now.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Descriptor,

        [string]$AuthMethod,
        [string]$Upn,
        [string]$Tenant,
        [string[]]$Subscriptions,
        [datetime]$QueriedAt = (Get-Date).ToUniversalTime()
    )

    # Auto-derive from Microsoft Graph context if not supplied
    $mgContext = $null
    if (Get-Command -Name Get-MgContext -ErrorAction SilentlyContinue) {
        $mgContext = Get-MgContext -ErrorAction SilentlyContinue
    }

    # Auto-derive from Azure context if not supplied
    $azContext = $null
    if (Get-Command -Name Get-AzContext -ErrorAction SilentlyContinue) {
        $azContext = Get-AzContext -ErrorAction SilentlyContinue
    }

    if (-not $AuthMethod) {
        if ($mgContext -and $mgContext.AuthType) {
            $AuthMethod = "$($mgContext.AuthType) · Microsoft Graph"
        }
        elseif ($azContext) {
            $AuthMethod = "Azure RM · $($azContext.Account.Type)"
        }
        else {
            $AuthMethod = "Unknown"
        }
    }

    if (-not $Upn) {
        if ($mgContext -and $mgContext.Account) {
            $Upn = $mgContext.Account
        }
        elseif ($azContext -and $azContext.Account) {
            $Upn = $azContext.Account.Id
        }
    }

    if (-not $Tenant) {
        if ($mgContext -and $mgContext.TenantId) {
            $Tenant = $mgContext.TenantId
        }
        elseif ($azContext -and $azContext.Tenant) {
            $Tenant = $azContext.Tenant.Id
        }
    }

    $Descriptor['AuthMethod'] = $AuthMethod
    $Descriptor['Upn'] = $Upn
    $Descriptor['Tenant'] = $Tenant
    $Descriptor['QueriedAt'] = $QueriedAt
    if ($PSBoundParameters.ContainsKey('Subscriptions') -and $Subscriptions) {
        $Descriptor['Subscriptions'] = @($Subscriptions)
    }
}

function Resolve-FindingSource {
    <#
    .SYNOPSIS
        Resolves the data source key that produced a finding.

    .DESCRIPTION
        Walks the call stack until it finds a frame whose script path lives
        under Modules/, then maps that .psm1 filename to a data source key via
        $script:ModuleToSource. Returns 'Internal' when nothing else matches.

        Used by Add-Finding for auto-derivation when no explicit -Source is
        provided.

    .PARAMETER ExplicitSource
        If supplied, returned as-is (after validation against the catalog).
        This is the override path used by source-specific modules.
    #>
    [OutputType([string])]
    [CmdletBinding()]
    param(
        [string]$ExplicitSource
    )

    if ($ExplicitSource) {
        if ($script:DataSourceCatalog.ContainsKey($ExplicitSource)) {
            return $ExplicitSource
        }
        Write-Warning "Resolve-FindingSource: '$ExplicitSource' is not a known data source key. Falling back to auto-derive."
    }

    $stack = Get-PSCallStack
    foreach ($frame in $stack) {
        $scriptName = $frame.ScriptName
        if (-not $scriptName) { continue }
        $fileName = Split-Path -Leaf $scriptName
        if ($script:ModuleToSource.ContainsKey($fileName)) {
            return $script:ModuleToSource[$fileName]
        }
    }

    return 'Internal'
}

function Get-DataSourceKeys {
    <#
    .SYNOPSIS
        Returns the list of catalog keys.
    #>
    [OutputType([string[]])]
    [CmdletBinding()]
    param()
    return [string[]]@($script:DataSourceCatalog.Keys | Sort-Object)
}

function ConvertTo-DataSourceRows {
    <#
    .SYNOPSIS
        Flattens a catalog into one row per source for Excel/CSV/table rendering.

    .DESCRIPTION
        One row per source in canonical order. Multi-value cells (Endpoints,
        Cmdlets, Scopes, Subscriptions) are joined with '; ' to keep the table
        compact. Used by both the Excel and CSV output paths and by the unified
        report's accordion reference table.

    .PARAMETER Catalog
        Hashtable from Get-DataSourceCatalog. Must contain at least one of the
        canonical keys.
    #>
    [OutputType([System.Collections.Generic.List[object]])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Catalog
    )

    $orderedKeys = @('Internal', 'SecureScore', 'DefenderCompliance', 'AzurePolicy', 'PurviewCompliance')
    $titleMap = @{
        'Internal' = 'EntraChecks Internal'
        'SecureScore' = 'Microsoft Secure Score'
        'DefenderCompliance' = 'Defender for Cloud Compliance'
        'AzurePolicy' = 'Azure Policy'
        'PurviewCompliance' = 'Purview Compliance Manager'
    }
    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($key in $orderedKeys) {
        if (-not $Catalog.ContainsKey($key)) { continue }
        $s = $Catalog[$key]
        $auth = if ($s.AuthMethod) {
            if ($s.Upn) { "$($s.AuthMethod) | $($s.Upn)" } else { [string]$s.AuthMethod }
        } else { '' }
        $queriedAt = if ($s.QueriedAt) { (Get-Date $s.QueriedAt -Format 'yyyy-MM-dd HH:mm:ss') + ' UTC' } else { '' }
        [void]$rows.Add([PSCustomObject]@{
                Source = $titleMap[$key]
                Status = if ($s.Available) { 'Active' } else { 'Not Available' }
                Provider = $s.Provider
                Endpoints = if ($s.Endpoints) { (@($s.Endpoints) -join '; ') } else { '' }
                Cmdlets = if ($s.Cmdlets) { (@($s.Cmdlets) -join '; ') } else { '' }
                Scopes = if ($s.Scopes) { (@($s.Scopes) -join '; ') } else { '' }
                Auth = $auth
                Tenant = [string]$s.Tenant
                Subscriptions = if ($s.Subscriptions) { (@($s.Subscriptions) -join '; ') } else { '' }
                QueriedAt = $queriedAt
                Reference = [string]$s.ReferenceUrl
            })
    }
    return $rows
}

#endregion

#region ==================== MODULE EXPORTS ====================

Export-ModuleMember -Function @(
    'Get-DataSourceCatalog',
    'Get-DataSourceDescriptor',
    'Get-DataSourceKeys',
    'Update-DataSourceContext',
    'Resolve-FindingSource',
    'ConvertTo-DataSourceRows'
)

#endregion
