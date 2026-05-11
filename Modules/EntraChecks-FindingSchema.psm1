<#
.SYNOPSIS
    Central finding schema (v2.0) normalizer for EntraChecks GRC workflow.

.DESCRIPTION
    Implements PR 1 of plans/Central-Finding-Schema-GRC-Plan.md.

    Provides the additive schema-v2 surface that turns every legacy
    EntraChecks finding into a stable GRC record. Legacy fields
    (Time, CheckName, Type, Status, Object, Description, Remediation,
    Source, RiskScore, RiskLevel, ComplianceMappings) are preserved
    untouched; v2 fields (FindingId, ControlMappings, Evidence, Owner,
    Exception, ReviewStatus, RemediationDetail, Disposition, Tags,
    Links, SchemaVersion) are appended.

    The module is read-only with respect to assessment results: analyst
    workflow state (Owner / Exception / ReviewStatus) is merged in via
    Merge-FindingState but can never overwrite raw status, risk score,
    description, or source.

.NOTES
    Author: David Stells
    Version: 2.0.0
    Schema: 2.0
#>

#Requires -Version 5.1

# Pull in optional enrichment modules so ConvertTo-EntraFindingV2 can call
# Add-RiskScoring / Add-ComplianceMapping / Add-RemediationGuidance from
# this module's scope. Without these explicit imports, PowerShell's
# module-scoped Get-Command lookups silently miss the cmdlets even when
# they're registered in the global session.
$script:SchemaModulePath = Split-Path -Parent $PSCommandPath
foreach ($dep in @('EntraChecks-RiskScoring.psm1', 'EntraChecks-ComplianceMapping.psm1', 'EntraChecks-RemediationGuidance.psm1')) {
    $depPath = Join-Path $script:SchemaModulePath $dep
    if (Test-Path $depPath) {
        Import-Module $depPath -Force -ErrorAction SilentlyContinue
    }
}

#region Module constants

$Script:SchemaVersion = '2.0'

# Allowed enum values. Validation in Test-EntraFindingV2 keys off these.
$Script:Enum_Status = @('OK', 'INFO', 'WARNING', 'FAIL', 'REVIEW')
$Script:Enum_OwnerType = @('User', 'Group', 'Team', 'Application', 'Subscription', 'ResourceGroup', 'Unknown')
$Script:Enum_OwnerSource = @('StateOverride', 'OwnerHint', 'AzureTag', 'EntraOwner', 'Subscription', 'ResourceGroup', 'Unknown')
$Script:Enum_Confidence = @('High', 'Medium', 'Low', 'Unknown')
$Script:Enum_ExceptionStatus = @('None', 'Requested', 'Approved', 'Rejected', 'Expired', 'Revoked')
$Script:Enum_ExceptionType = @('AcceptedRisk', 'FalsePositive', 'CompensatingControl', 'OutOfScope', '')
$Script:Enum_ReviewState = @('New', 'NeedsReview', 'InReview', 'ActionRequired', 'Accepted', 'Resolved', 'Suppressed')
$Script:Enum_AssessmentRole = @('Automated', 'Manual', 'Inherited', 'Advisory')
$Script:Enum_MappingSource = @('EntraChecks', 'DefenderForCloud', 'AzurePolicy', 'Purview', 'Manual')
$Script:Enum_DataClassification = @('Public', 'Internal', 'Confidential', 'Restricted')
$Script:Enum_RedactionStatus = @('NotRequired', 'Redacted', 'RawPayloadExcluded')
$Script:Enum_AutomationSafety = @('ManualOnly', 'DryRunRecommended', 'SafeToAutomate', 'Destructive')
$Script:Enum_Disposition = @(
    'Open', 'Review', 'ActionRequired', 'AcceptedRisk', 'CompensatingControl',
    'FalsePositive', 'OutOfScope', 'Resolved', 'Suppressed', 'ExpiredException',
    'Informational', 'Passing'
)

# Legacy ComplianceMappings keys -> normalized framework names.
$Script:FrameworkAlias = @{
    'CIS_M365' = 'CIS_M365'
    'NIST_CSF' = 'NIST_CSF'
    'SOC2' = 'SOC2'
    'PCI_DSS_4' = 'PCI_DSS_4'
}

# Per-framework field that holds the control list, used when normalizing.
$Script:FrameworkControlField = @{
    'CIS_M365' = 'Controls'
    'NIST_CSF' = 'Functions'
    'SOC2' = 'Criteria'
    'PCI_DSS_4' = 'Requirements'
}

# Fields that local analyst state is NEVER allowed to overwrite. These are
# raw assessment facts and must remain immutable across runs (the audit trail
# would be meaningless otherwise).
$Script:ImmutableFields = @(
    'Time', 'CheckName', 'Type', 'Status', 'Object', 'ObjectType', 'ObjectId',
    'ResourceId', 'TenantId', 'SubscriptionId', 'Source', 'Description',
    'Remediation', 'RiskScore', 'RiskLevel', 'PriorityScore',
    'RemediationEffort', 'ComplianceMappings', 'ControlMappings', 'Evidence',
    'FindingId', 'FindingKey', 'SchemaVersion'
)

# Patterns we treat as secret-like during evidence redaction. Conservative
# regex: each match flips the evidence row's RedactionStatus to 'Redacted'.
# Order matters — more specific tokens first.
$Script:SecretPatterns = @(
    @{ Name = 'BearerToken'; Pattern = '(?i)bearer\s+[a-z0-9._\-]{20,}' }
    @{ Name = 'JwtToken'; Pattern = '(?i)eyJ[a-z0-9_\-]+\.eyJ[a-z0-9_\-]+\.[a-z0-9_\-]+' }
    @{ Name = 'PrivateKeyBlock'; Pattern = '-----BEGIN [A-Z ]+PRIVATE KEY-----' }
    @{ Name = 'AzureSasToken'; Pattern = '(?i)\bsig=[a-z0-9%]{20,}' }
    @{ Name = 'StorageAccountKey'; Pattern = '(?i)accountkey=[a-z0-9+/=]{60,}' }
    @{ Name = 'ConnectionString'; Pattern = '(?i)(server|host|data source|account)=[^;]+;.*?(password|pwd|key)=[^;]+' }
    @{ Name = 'ClientSecret'; Pattern = '(?i)(client_secret|clientsecret)["''=:\s]+[^"''\s,;]{12,}' }
    @{ Name = 'PasswordEquals'; Pattern = '(?i)(password|pwd)["''=:\s]+[^"''\s,;]{6,}' }
    @{ Name = 'AuthorizationHeader'; Pattern = '(?i)authorization:\s*[a-z]+\s+[a-z0-9._\-=/+]{20,}' }
)

#endregion

#region Private helpers

function Get-EcfNormalizedString {
    <#
    Trim + lowercase + collapse whitespace. Used inside the FindingId hash
    so trivial casing/whitespace differences in object names don't fragment
    analyst state across runs.
    #>
    param([Parameter(Mandatory)][AllowEmptyString()][AllowNull()][string]$Value)
    if (-not $Value) { return '' }
    return ($Value.Trim() -replace '\s+', ' ').ToLowerInvariant()
}

function Get-EcfFindingProperty {
    <#
    Read an arbitrary property off a finding regardless of whether it's a
    PSCustomObject, hashtable, or PSObject. Returns $null when absent.
    #>
    param(
        [Parameter(Mandatory)] $Finding,
        [Parameter(Mandatory)][string]$Name
    )
    if ($null -eq $Finding) { return $null }
    if ($Finding -is [hashtable]) {
        if ($Finding.ContainsKey($Name)) { return $Finding[$Name] }
        return $null
    }
    if ($Finding.PSObject -and $Finding.PSObject.Properties[$Name]) {
        return $Finding.$Name
    }
    return $null
}

function Set-EcfFindingProperty {
    <#
    Idempotent property setter. Adds via Add-Member -Force when missing,
    otherwise direct assignment. Always returns the finding so callers can
    pipe through the merge chain.
    #>
    param(
        [Parameter(Mandatory)] $Finding,
        [Parameter(Mandatory)][string]$Name,
        [AllowNull()] $Value
    )
    if ($Finding -is [hashtable]) {
        $Finding[$Name] = $Value
        return $Finding
    }
    if ($Finding.PSObject.Properties[$Name]) {
        $Finding.$Name = $Value
    }
    else {
        $Finding | Add-Member -NotePropertyName $Name -NotePropertyValue $Value -Force
    }
    return $Finding
}

function ConvertTo-EcfSha256Hex {
    # Parameter MUST NOT be named 'Input' — that's a PS automatic variable
    # that holds the pipeline iterator and cannot be used as a parameter
    # name without bizarre binding behavior.
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
        $hash = $sha.ComputeHash($bytes)
        return -join ($hash | ForEach-Object { $_.ToString('x2') })
    }
    finally {
        $sha.Dispose()
    }
}

function Test-EcfIsExpired {
    param([AllowNull()][string]$IsoDate)
    if (-not $IsoDate) { return $false }
    # [ref] needs a strongly-typed [datetime], otherwise the TryParse
    # overload resolution fails ("argument count: 2" — ironic given there
    # ARE 2 args, but the second one isn't typed correctly).
    [datetime]$parsed = [datetime]::MinValue
    if (-not [datetime]::TryParse($IsoDate, [ref]$parsed)) { return $false }
    return $parsed.ToUniversalTime() -lt (Get-Date).ToUniversalTime()
}

function Get-EcfDefaultEvidenceRow {
    [pscustomobject]@{
        EvidenceId = ''
        Source = ''
        Provider = ''
        Endpoint = ''
        Cmdlet = ''
        TenantId = ''
        SubscriptionId = ''
        ResourceId = ''
        CapturedAtUtc = ''
        QueryScope = ''
        DataClassification = 'Internal'
        Reference = ''
        HashAlgorithm = 'SHA256'
        Hash = ''
        RedactionStatus = 'RawPayloadExcluded'
    }
}

function Get-EcfDefaultOwner {
    [pscustomobject]@{
        OwnerType = 'Unknown'
        DisplayName = ''
        UserPrincipalName = ''
        Email = ''
        Team = ''
        Source = 'Unknown'
        Confidence = 'Unknown'
        DueDate = ''
    }
}

function Get-EcfDefaultException {
    [pscustomobject]@{
        Status = 'None'
        Type = ''
        Justification = ''
        Approver = ''
        RequestedBy = ''
        RequestedAt = ''
        ApprovedAt = ''
        ExpiresAt = ''
        EvidenceRefs = @()
    }
}

function Get-EcfDefaultReviewStatus {
    param([string]$RawStatus)
    $defaultState = if ($RawStatus -eq 'REVIEW') { 'NeedsReview' } else { 'New' }
    [pscustomobject]@{
        State = $defaultState
        Reviewer = ''
        Notes = ''
        FirstSeenUtc = ''
        LastSeenUtc = ''
        ReviewedAtUtc = ''
        NextReviewDate = ''
    }
}

function Get-EcfDefaultRemediationDetail {
    [pscustomobject]@{
        Summary = ''
        PortalSteps = @()
        PowerShell = ''
        AzureCli = ''
        ValidationSteps = @()
        RollbackSteps = @()
        Impact = ''
        Considerations = ''
        Effort = ''
        RequiresApproval = $false
        AutomationSafety = 'ManualOnly'
        DocumentationLinks = @()
    }
}

#endregion

#region Public — identity

function New-EntraFindingId {
    <#
    .SYNOPSIS
        Returns a deterministic ECF-... finding identifier.
    .DESCRIPTION
        SHA256 of a normalized identity string built from tenant, source,
        check name, type, object type, and the most stable object ID
        available (preferring ObjectId, then ResourceId, then Object).
        FindingKey is appended last and lets a single check emit multiple
        findings for the same target without colliding.

        Identity inputs are lowercased and whitespace-collapsed before
        hashing so trivial casing differences in object names (e.g. Graph
        sometimes returning UPNs in mixed case) don't fragment analyst
        state across runs.

        Hash inputs deliberately exclude: timestamps, risk score,
        remediation text, owner, review state, exception state. Those
        change run-to-run and must not affect identity.
    .OUTPUTS
        String of the form ECF-<20 lowercase hex chars>.
    #>
    [OutputType([string])]
    [CmdletBinding()]
    param(
        [AllowEmptyString()][AllowNull()][string]$TenantId,
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$CheckName,
        [AllowEmptyString()][AllowNull()][string]$Type,
        [AllowEmptyString()][AllowNull()][string]$ObjectType,
        [AllowEmptyString()][AllowNull()][string]$ObjectId,
        [AllowEmptyString()][AllowNull()][string]$ResourceId,
        [AllowEmptyString()][AllowNull()][string]$Object,
        [AllowEmptyString()][AllowNull()][string]$FindingKey
    )

    # Pick the most stable object identifier available. Object (display) is
    # the last fallback because Graph display names can change without the
    # underlying resource changing.
    $stableObject = ''
    if ($ObjectId) { $stableObject = $ObjectId }
    elseif ($ResourceId) { $stableObject = $ResourceId }
    else { $stableObject = $Object }

    $parts = @(
        Get-EcfNormalizedString -Value $TenantId
        Get-EcfNormalizedString -Value $Source
        Get-EcfNormalizedString -Value $CheckName
        Get-EcfNormalizedString -Value $Type
        Get-EcfNormalizedString -Value $ObjectType
        Get-EcfNormalizedString -Value $stableObject
        Get-EcfNormalizedString -Value $FindingKey
    )

    $canonical = ($parts -join '|')
    $hex = ConvertTo-EcfSha256Hex -Text $canonical
    return 'ECF-' + $hex.Substring(0, 20)
}

#endregion

#region Public — control-mapping conversion

function ConvertTo-ControlMappings {
    <#
    .SYNOPSIS
        Normalizes legacy ComplianceMappings hashtable into a flat array of
        ControlMappings rows.
    .DESCRIPTION
        Existing assessment code populates Finding.ComplianceMappings as
        @{ CIS_M365 = @{ Controls = @('1.1.3'); Title=...; Description=... }; ... }.
        That shape is opaque to consumers that want a flat list of
        (Framework, ControlId, Title) rows.

        This function explodes the hashtable into one row per (framework,
        control) pair. Unmapped findings produce an empty array, never $null
        — schema-v2 contract.
    .OUTPUTS
        Array of [pscustomobject] rows. Empty when no mappings.
    #>
    [OutputType([object[]])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowNull()] $ComplianceMappings,
        [string]$MappingSource = 'EntraChecks'
    )

    $rows = New-Object System.Collections.Generic.List[object]
    # Write-Output -NoEnumerate is the only PS idiom that reliably returns
    # a 0-or-N element array as a single pipeline value. Plain `return $arr`
    # collapses 0-element to $null and unwraps 1-element to a scalar; the
    # leading-comma trick fights with caller-side @() wrappers. -NoEnumerate
    # emits the array as one item, callers do `$x = func` (no @()) and
    # always get an array.
    if ($null -eq $ComplianceMappings) { return , ([object[]]$rows.ToArray()) }

    # Tolerate both [hashtable] and [pscustomobject] inputs — JSON round-trips
    # turn hashtables into PSCustomObjects.
    $frameworkKeys = if ($ComplianceMappings -is [hashtable]) {
        $ComplianceMappings.Keys
    }
    elseif ($ComplianceMappings.PSObject) {
        $ComplianceMappings.PSObject.Properties.Name
    }
    else { @() }

    foreach ($fw in $frameworkKeys) {
        $framework = if ($Script:FrameworkAlias.ContainsKey($fw)) { $Script:FrameworkAlias[$fw] } else { $fw }
        $entry = if ($ComplianceMappings -is [hashtable]) { $ComplianceMappings[$fw] } else { $ComplianceMappings.$fw }
        if ($null -eq $entry) { continue }

        $controlField = if ($Script:FrameworkControlField.ContainsKey($framework)) { $Script:FrameworkControlField[$framework] } else { 'Controls' }

        $controls = @()
        if ($entry -is [hashtable]) {
            if ($entry.ContainsKey($controlField)) { $controls = @($entry[$controlField]) }
        }
        elseif ($entry.PSObject -and $entry.PSObject.Properties[$controlField]) {
            $controls = @($entry.$controlField)
        }

        $title = if ($entry -is [hashtable] -and $entry.ContainsKey('Title')) { $entry['Title'] } elseif ($entry.PSObject -and $entry.PSObject.Properties['Title']) { $entry.Title } else { '' }
        $description = if ($entry -is [hashtable] -and $entry.ContainsKey('Description')) { $entry['Description'] } elseif ($entry.PSObject -and $entry.PSObject.Properties['Description']) { $entry.Description } else { '' }
        $family = if ($entry -is [hashtable] -and $entry.ContainsKey('Family')) { $entry['Family'] } elseif ($entry.PSObject -and $entry.PSObject.Properties['Family']) { $entry.Family } else { '' }

        # If the framework provides only a description and no title, lift it
        # into Requirement so analysts always see *something* descriptive.
        $requirement = if ($description) { $description } else { $title }

        if (-not $controls -or $controls.Count -eq 0) {
            # Some legacy entries have a Title with no Controls list.
            # Emit a single descriptive row so the analyst still sees the
            # framework reference.
            if ($title -or $description) {
                $row = [pscustomobject]@{
                    Framework = $framework
                    ControlId = ''
                    ControlTitle = $title
                    Requirement = $requirement
                    Family = $family
                    AssessmentRole = 'Automated'
                    MappingSource = $MappingSource
                    MappingConfidence = 'Medium'
                }
                $rows.Add($row)
            }
            continue
        }

        foreach ($control in $controls) {
            if (-not $control) { continue }
            $row = [pscustomobject]@{
                Framework = $framework
                ControlId = [string]$control
                ControlTitle = $title
                Requirement = $requirement
                Family = $family
                AssessmentRole = 'Automated'
                MappingSource = $MappingSource
                MappingConfidence = 'High'
            }
            $rows.Add($row)
        }
    }

    # Single-item emission of the array (see comment above for why).
    return , ([object[]]$rows.ToArray())
}

#endregion

#region Public — evidence

function ConvertTo-EvidenceReference {
    <#
    .SYNOPSIS
        Builds an Evidence row from source metadata.
    .DESCRIPTION
        Evidence rows are *references* — they describe where the assessor
        looked, with what tool, scoped to which tenant/subscription, and
        whether the underlying artifact was redacted. They never embed raw
        protected payloads.

        When -RawSample is provided AND -AllowRawSample is set, the sample
        is scanned for secret-like patterns. Any hit flips RedactionStatus
        to 'Redacted'. Without -AllowRawSample the sample is discarded and
        RedactionStatus stays 'RawPayloadExcluded' (the default and safe
        choice for v1).
    .OUTPUTS
        Single Evidence pscustomobject row.
    #>
    [OutputType([pscustomobject])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Source,
        [string]$Provider = '',
        [string]$Endpoint = '',
        [string]$Cmdlet = '',
        [string]$TenantId = '',
        [string]$SubscriptionId = '',
        [string]$ResourceId = '',
        [string]$QueryScope = '',
        [ValidateSet('Public', 'Internal', 'Confidential', 'Restricted')]
        [string]$DataClassification = 'Internal',
        [string]$Reference = '',
        [string]$RawSample = '',
        [switch]$AllowRawSample
    )

    $row = Get-EcfDefaultEvidenceRow
    $row.Source = $Source
    $row.Provider = $Provider
    $row.Endpoint = $Endpoint
    $row.Cmdlet = $Cmdlet
    $row.TenantId = $TenantId
    $row.SubscriptionId = $SubscriptionId
    $row.ResourceId = $ResourceId
    $row.CapturedAtUtc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    $row.QueryScope = $QueryScope
    $row.DataClassification = $DataClassification
    $row.Reference = $Reference

    # Hash basis: prefer the referenced artifact (Reference or RawSample);
    # fall back to a canonical descriptor so every evidence row is uniquely
    # addressable even when no artifact exists.
    $hashBasis = ''
    if ($Reference) { $hashBasis = $Reference }
    elseif ($RawSample -and $AllowRawSample) { $hashBasis = $RawSample }
    else { $hashBasis = "$Source|$Provider|$Cmdlet|$TenantId|$SubscriptionId|$ResourceId|$QueryScope" }
    $row.Hash = ConvertTo-EcfSha256Hex -Text $hashBasis

    if ($RawSample) {
        if (-not $AllowRawSample) {
            $row.RedactionStatus = 'RawPayloadExcluded'
        }
        else {
            $matched = $false
            foreach ($p in $Script:SecretPatterns) {
                if ($RawSample -match $p.Pattern) { $matched = $true; break }
            }
            $row.RedactionStatus = if ($matched) { 'Redacted' } else { 'NotRequired' }
        }
    }

    # EvidenceId is the first 16 hex chars of the hash — short enough for
    # display, long enough to remain unique within a single report.
    $row.EvidenceId = 'EVID-' + $row.Hash.Substring(0, 16)
    return $row
}

function Test-EvidenceContainsSecret {
    <#
    .SYNOPSIS
        Internal helper exposed for tests. Returns $true if the supplied
        text matches any of the secret regex patterns.
    #>
    [OutputType([bool])]
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)
    if (-not $Text) { return $false }
    foreach ($p in $Script:SecretPatterns) {
        if ($Text -match $p.Pattern) { return $true }
    }
    return $false
}

#endregion

#region Public — owner

function Resolve-FindingOwner {
    <#
    .SYNOPSIS
        Resolves the Owner block for a finding using the documented
        precedence order.
    .DESCRIPTION
        Order:
          1. -StateOverride (analyst-supplied)
          2. -OwnerHint    (assessment-supplied)
          3. -ResourceTags (Owner / ServiceOwner / ApplicationOwner / CostCenter / BusinessUnit)
          4. -EntraOwners  (app/SP owners list)
          5. -SubscriptionOwner / -ResourceGroupOwner
          6. Default Unknown owner

        Each tier carries a distinct OwnerSource value so downstream
        consumers can tell whether the owner was authored by an analyst
        or auto-derived.
    .OUTPUTS
        Owner pscustomobject row.
    #>
    [OutputType([pscustomobject])]
    [CmdletBinding()]
    param(
        [hashtable]$StateOverride,
        $OwnerHint,
        [hashtable]$ResourceTags,
        [object[]]$EntraOwners,
        $SubscriptionOwner,
        $ResourceGroupOwner
    )

    function New-EcfOwnerFromHashtable {
        param([hashtable]$Source, [string]$DefaultSource)
        $owner = Get-EcfDefaultOwner
        foreach ($k in 'OwnerType', 'DisplayName', 'UserPrincipalName', 'Email', 'Team', 'DueDate') {
            if ($Source.ContainsKey($k) -and $Source[$k]) { $owner.$k = [string]$Source[$k] }
        }
        $owner.Source = if ($Source.ContainsKey('Source') -and $Source['Source']) { [string]$Source['Source'] } else { $DefaultSource }
        $owner.Confidence = if ($Source.ContainsKey('Confidence') -and $Source['Confidence']) { [string]$Source['Confidence'] } else { 'High' }
        return $owner
    }

    if ($StateOverride -and $StateOverride.Count -gt 0) {
        $o = New-EcfOwnerFromHashtable -Source $StateOverride -DefaultSource 'StateOverride'
        $o.Source = 'StateOverride'
        $o.Confidence = if ($StateOverride.ContainsKey('Confidence') -and $StateOverride['Confidence']) { [string]$StateOverride['Confidence'] } else { 'High' }
        return $o
    }

    if ($OwnerHint) {
        if ($OwnerHint -is [hashtable]) {
            $o = New-EcfOwnerFromHashtable -Source $OwnerHint -DefaultSource 'OwnerHint'
            $o.Source = 'OwnerHint'
            return $o
        }
        elseif ($OwnerHint -is [string] -and $OwnerHint) {
            $o = Get-EcfDefaultOwner
            $o.OwnerType = 'User'
            $o.DisplayName = $OwnerHint
            $o.Source = 'OwnerHint'
            $o.Confidence = 'Medium'
            return $o
        }
    }

    if ($ResourceTags -and $ResourceTags.Count -gt 0) {
        foreach ($tagKey in @('Owner', 'ServiceOwner', 'ApplicationOwner', 'CostCenter', 'BusinessUnit')) {
            if ($ResourceTags.ContainsKey($tagKey) -and $ResourceTags[$tagKey]) {
                $o = Get-EcfDefaultOwner
                $o.OwnerType = if ($tagKey -in @('CostCenter', 'BusinessUnit')) { 'Team' } else { 'User' }
                $o.DisplayName = [string]$ResourceTags[$tagKey]
                $o.Team = if ($tagKey -in @('CostCenter', 'BusinessUnit')) { [string]$ResourceTags[$tagKey] } else { '' }
                $o.Source = 'AzureTag'
                $o.Confidence = 'Medium'
                return $o
            }
        }
    }

    if ($EntraOwners -and $EntraOwners.Count -gt 0) {
        $first = $EntraOwners[0]
        $o = Get-EcfDefaultOwner
        $o.OwnerType = 'User'
        $o.DisplayName = [string](Get-EcfFindingProperty -Finding $first -Name 'DisplayName')
        $o.UserPrincipalName = [string](Get-EcfFindingProperty -Finding $first -Name 'UserPrincipalName')
        $o.Email = [string](Get-EcfFindingProperty -Finding $first -Name 'Mail')
        $o.Source = 'EntraOwner'
        $o.Confidence = 'Medium'
        return $o
    }

    if ($SubscriptionOwner) {
        $o = Get-EcfDefaultOwner
        $o.OwnerType = 'Subscription'
        $o.DisplayName = [string]$SubscriptionOwner
        $o.Source = 'Subscription'
        $o.Confidence = 'Low'
        return $o
    }

    if ($ResourceGroupOwner) {
        $o = Get-EcfDefaultOwner
        $o.OwnerType = 'ResourceGroup'
        $o.DisplayName = [string]$ResourceGroupOwner
        $o.Source = 'ResourceGroup'
        $o.Confidence = 'Low'
        return $o
    }

    return Get-EcfDefaultOwner
}

#endregion

#region Public — disposition

function Get-FindingDisposition {
    <#
    .SYNOPSIS
        Computes a finding's Disposition from raw Status, ReviewStatus, and
        Exception state.
    .DESCRIPTION
        Derivation order (first match wins):
          1. Status='OK'                                 -> Passing
          2. Status='INFO'                               -> Informational
          3. Exception expired                           -> ExpiredException
          4. Exception approved                          -> exception type
          5. ReviewStatus.State='Resolved'               -> Resolved
          6. ReviewStatus.State='Suppressed'             -> Suppressed
          7. Status='REVIEW' or NeedsReview/InReview     -> Review
          8. Status in (FAIL, WARNING)                   -> ActionRequired
          9. fallback                                    -> Open

        Disposition is derived, never authored. Analyst state controls only
        the inputs (ReviewStatus, Exception); this function decides the
        bucket.
    .OUTPUTS
        String — one of $Script:Enum_Disposition.
    #>
    [OutputType([string])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Status,
        [pscustomobject]$ReviewStatus,
        [pscustomobject]$Exception
    )

    if ($Status -eq 'OK') { return 'Passing' }
    if ($Status -eq 'INFO') { return 'Informational' }

    if ($Exception) {
        $expStatus = [string](Get-EcfFindingProperty -Finding $Exception -Name 'Status')
        $expType = [string](Get-EcfFindingProperty -Finding $Exception -Name 'Type')
        $expiresAt = [string](Get-EcfFindingProperty -Finding $Exception -Name 'ExpiresAt')

        # Expired covers both 'still says Approved but past expiry' AND
        # 'state file already has Status=Expired'. Either way the bucket is
        # ExpiredException so the action queue picks it back up.
        if ($expStatus -eq 'Expired') { return 'ExpiredException' }
        if ($expStatus -eq 'Approved' -and (Test-EcfIsExpired -IsoDate $expiresAt)) {
            return 'ExpiredException'
        }
        if ($expStatus -eq 'Approved') {
            switch ($expType) {
                'AcceptedRisk' { return 'AcceptedRisk' }
                'CompensatingControl' { return 'CompensatingControl' }
                'FalsePositive' { return 'FalsePositive' }
                'OutOfScope' { return 'OutOfScope' }
                default { return 'AcceptedRisk' }
            }
        }
    }

    if ($ReviewStatus) {
        $rs = [string](Get-EcfFindingProperty -Finding $ReviewStatus -Name 'State')
        if ($rs -eq 'Resolved') { return 'Resolved' }
        if ($rs -eq 'Suppressed') { return 'Suppressed' }
        if ($rs -in @('NeedsReview', 'InReview')) { return 'Review' }
    }

    if ($Status -eq 'REVIEW') { return 'Review' }
    if ($Status -in @('FAIL', 'WARNING')) { return 'ActionRequired' }

    return 'Open'
}

#endregion

#region Public — state merge

function Merge-FindingState {
    <#
    .SYNOPSIS
        Applies local analyst state (Owner / Exception / ReviewStatus /
        Tags / Links) to a finding by FindingId.
    .DESCRIPTION
        Local state is allowlisted. Only Owner, Exception, ReviewStatus,
        Tags, and Links can come from state. Raw assessment facts (status,
        risk score, source, description, etc.) are immutable and any state
        attempt to set them is silently ignored.

        State shape:
          @{ Findings = @{ 'ECF-...' = @{ Owner=@{...}; Exception=@{...}; ReviewStatus=@{...}; Tags=@(); Links=@() } } }

        Returns the finding (mutated in place + returned for piping).
    .OUTPUTS
        The finding, with state merged.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Finding,
        [Parameter(Mandatory)][hashtable]$State
    )

    $findingId = [string](Get-EcfFindingProperty -Finding $Finding -Name 'FindingId')
    if (-not $findingId) { return $Finding }
    if (-not $State.ContainsKey('Findings')) { return $Finding }

    $bucket = $State['Findings']
    $entry = $null
    if ($bucket -is [hashtable] -and $bucket.ContainsKey($findingId)) {
        $entry = $bucket[$findingId]
    }
    elseif ($bucket.PSObject -and $bucket.PSObject.Properties[$findingId]) {
        $entry = $bucket.$findingId
    }
    if (-not $entry) { return $Finding }

    # Helper: pull a sub-hashtable off the state entry, regardless of whether
    # the entry is a hashtable or a PSCustomObject (post-JSON-roundtrip).
    function Get-EcfStateSection {
        param($Entry, [string]$Section)
        if ($Entry -is [hashtable]) {
            if ($Entry.ContainsKey($Section)) { return $Entry[$Section] } else { return $null }
        }
        if ($Entry.PSObject -and $Entry.PSObject.Properties[$Section]) {
            return $Entry.$Section
        }
        return $null
    }

    # Owner
    $ownerState = Get-EcfStateSection -Entry $entry -Section 'Owner'
    if ($ownerState) {
        $hash = if ($ownerState -is [hashtable]) { $ownerState } else {
            $h = @{}; foreach ($p in $ownerState.PSObject.Properties) { $h[$p.Name] = $p.Value }; $h
        }
        $owner = Resolve-FindingOwner -StateOverride $hash
        Set-EcfFindingProperty -Finding $Finding -Name 'Owner' -Value $owner | Out-Null
    }

    # Exception
    $exState = Get-EcfStateSection -Entry $entry -Section 'Exception'
    if ($exState) {
        $current = Get-EcfFindingProperty -Finding $Finding -Name 'Exception'
        if (-not $current) { $current = Get-EcfDefaultException }
        $sourceProps = if ($exState -is [hashtable]) { $exState.Keys } else { $exState.PSObject.Properties.Name }
        foreach ($k in $sourceProps) {
            if ($current.PSObject.Properties[$k]) {
                $val = if ($exState -is [hashtable]) { $exState[$k] } else { $exState.$k }
                $current.$k = $val
            }
        }
        # If an approved exception has a past ExpiresAt, normalize Status to
        # 'Expired' so derived disposition reflects reality without anyone
        # having to update the state file the moment it lapses.
        if ($current.Status -eq 'Approved' -and (Test-EcfIsExpired -IsoDate $current.ExpiresAt)) {
            $current.Status = 'Expired'
        }
        Set-EcfFindingProperty -Finding $Finding -Name 'Exception' -Value $current | Out-Null
    }

    # ReviewStatus
    $rsState = Get-EcfStateSection -Entry $entry -Section 'ReviewStatus'
    if ($rsState) {
        $rawStatus = [string](Get-EcfFindingProperty -Finding $Finding -Name 'Status')
        $current = Get-EcfFindingProperty -Finding $Finding -Name 'ReviewStatus'
        if (-not $current) { $current = Get-EcfDefaultReviewStatus -RawStatus $rawStatus }
        $sourceProps = if ($rsState -is [hashtable]) { $rsState.Keys } else { $rsState.PSObject.Properties.Name }
        foreach ($k in $sourceProps) {
            if ($current.PSObject.Properties[$k]) {
                $val = if ($rsState -is [hashtable]) { $rsState[$k] } else { $rsState.$k }
                $current.$k = $val
            }
        }
        Set-EcfFindingProperty -Finding $Finding -Name 'ReviewStatus' -Value $current | Out-Null
    }

    # Tags / Links — merged additively, deduped case-insensitively
    foreach ($listField in @('Tags', 'Links')) {
        $stateList = Get-EcfStateSection -Entry $entry -Section $listField
        if ($null -ne $stateList) {
            $existing = @(Get-EcfFindingProperty -Finding $Finding -Name $listField)
            if ($null -eq $existing) { $existing = @() }
            $merged = New-Object System.Collections.Generic.List[object]
            $seen = New-Object System.Collections.Generic.HashSet[string] ([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($item in @($existing) + @($stateList)) {
                if ($null -eq $item) { continue }
                $key = [string]$item
                if ($seen.Add($key)) { $merged.Add($item) }
            }
            Set-EcfFindingProperty -Finding $Finding -Name $listField -Value $merged.ToArray() | Out-Null
        }
    }

    # Recompute disposition with the new state.
    $disposition = Get-FindingDisposition `
        -Status (Get-EcfFindingProperty -Finding $Finding -Name 'Status') `
        -ReviewStatus (Get-EcfFindingProperty -Finding $Finding -Name 'ReviewStatus') `
        -Exception (Get-EcfFindingProperty -Finding $Finding -Name 'Exception')
    Set-EcfFindingProperty -Finding $Finding -Name 'Disposition' -Value $disposition | Out-Null

    return $Finding
}

#endregion

#region Public — normalization (orchestrator)

function ConvertTo-EntraFindingV2 {
    <#
    .SYNOPSIS
        Normalizes a legacy or partial finding to schema v2.0.
    .DESCRIPTION
        Idempotent: calling this on an already-v2 finding leaves existing
        v2 fields intact; only missing fields are added.

        Calls available enrichment modules (RiskScoring, ComplianceMapping,
        RemediationGuidance) when present, but does not require them — a
        finding can be normalized in a minimal environment for testing.
    .OUTPUTS
        The finding, with v2 fields populated.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)] $Finding,
        [string]$DefaultTenantId = '',
        [string]$DefaultSource = 'Internal'
    )

    process {
        if ($null -eq $Finding) { return $null }

        # Always write SchemaVersion last, after every other field has been
        # populated, so partially-failed normalizations don't claim v2.

        # Fill source/tenant first since FindingId depends on them.
        $existingSource = Get-EcfFindingProperty -Finding $Finding -Name 'Source'
        if (-not $existingSource) {
            Set-EcfFindingProperty -Finding $Finding -Name 'Source' -Value $DefaultSource | Out-Null
        }
        $existingTenant = Get-EcfFindingProperty -Finding $Finding -Name 'TenantId'
        if (-not $existingTenant -and $DefaultTenantId) {
            Set-EcfFindingProperty -Finding $Finding -Name 'TenantId' -Value $DefaultTenantId | Out-Null
        }

        foreach ($field in @('ObjectType', 'ObjectId', 'ResourceId', 'SubscriptionId', 'FindingKey')) {
            if ($null -eq (Get-EcfFindingProperty -Finding $Finding -Name $field)) {
                Set-EcfFindingProperty -Finding $Finding -Name $field -Value '' | Out-Null
            }
        }

        # FindingId — only generate if absent. Re-runs over the same finding
        # must produce the same ID.
        if (-not (Get-EcfFindingProperty -Finding $Finding -Name 'FindingId')) {
            $newId = New-EntraFindingId `
                -TenantId   ([string](Get-EcfFindingProperty -Finding $Finding -Name 'TenantId')) `
                -Source     ([string](Get-EcfFindingProperty -Finding $Finding -Name 'Source')) `
                -CheckName  ([string](Get-EcfFindingProperty -Finding $Finding -Name 'CheckName')) `
                -Type       ([string](Get-EcfFindingProperty -Finding $Finding -Name 'Type')) `
                -ObjectType ([string](Get-EcfFindingProperty -Finding $Finding -Name 'ObjectType')) `
                -ObjectId   ([string](Get-EcfFindingProperty -Finding $Finding -Name 'ObjectId')) `
                -ResourceId ([string](Get-EcfFindingProperty -Finding $Finding -Name 'ResourceId')) `
                -Object     ([string](Get-EcfFindingProperty -Finding $Finding -Name 'Object')) `
                -FindingKey ([string](Get-EcfFindingProperty -Finding $Finding -Name 'FindingKey'))
            Set-EcfFindingProperty -Finding $Finding -Name 'FindingId' -Value $newId | Out-Null
        }

        # Risk scoring — only call if module loaded AND finding lacks RiskScore.
        if ((-not (Get-EcfFindingProperty -Finding $Finding -Name 'RiskScore')) -and (Get-Command Add-RiskScoring -ErrorAction SilentlyContinue)) {
            try { $Finding = $Finding | Add-RiskScoring } catch { Write-Verbose "Add-RiskScoring failed: $_" }
        }

        # Compliance mapping — only call if module loaded AND finding lacks ComplianceMappings.
        if ((-not (Get-EcfFindingProperty -Finding $Finding -Name 'ComplianceMappings')) -and (Get-Command Add-ComplianceMapping -ErrorAction SilentlyContinue)) {
            try { $Finding = $Finding | Add-ComplianceMapping } catch { Write-Verbose "Add-ComplianceMapping failed: $_" }
        }

        # Remediation guidance — populate RemediationGuidance only if module loaded.
        if ((-not (Get-EcfFindingProperty -Finding $Finding -Name 'RemediationGuidance')) -and (Get-Command Add-RemediationGuidance -ErrorAction SilentlyContinue)) {
            try { $Finding = $Finding | Add-RemediationGuidance } catch { Write-Verbose "Add-RemediationGuidance failed: $_" }
        }

        # ControlMappings — derive from ComplianceMappings each time. Cheap,
        # and lets us re-derive if a future PR changes the framework data.
        $cm = Get-EcfFindingProperty -Finding $Finding -Name 'ComplianceMappings'
        $controlMappings = ConvertTo-ControlMappings -ComplianceMappings $cm
        Set-EcfFindingProperty -Finding $Finding -Name 'ControlMappings' -Value $controlMappings | Out-Null

        # Evidence — build a minimal default row from Source if no Evidence
        # has been populated yet. Modules can replace this later by setting
        # the Evidence property explicitly before normalization.
        $existingEvidence = Get-EcfFindingProperty -Finding $Finding -Name 'Evidence'
        if ($null -eq $existingEvidence) {
            $defaultEvidence = ConvertTo-EvidenceReference `
                -Source ([string](Get-EcfFindingProperty -Finding $Finding -Name 'Source')) `
                -TenantId ([string](Get-EcfFindingProperty -Finding $Finding -Name 'TenantId')) `
                -SubscriptionId ([string](Get-EcfFindingProperty -Finding $Finding -Name 'SubscriptionId')) `
                -ResourceId ([string](Get-EcfFindingProperty -Finding $Finding -Name 'ResourceId')) `
                -QueryScope ([string](Get-EcfFindingProperty -Finding $Finding -Name 'CheckName'))
            Set-EcfFindingProperty -Finding $Finding -Name 'Evidence' -Value @($defaultEvidence) | Out-Null
        }

        # Owner — initialize to Unknown if absent. State merge upgrades later.
        if (-not (Get-EcfFindingProperty -Finding $Finding -Name 'Owner')) {
            $ownerHint = Get-EcfFindingProperty -Finding $Finding -Name 'OwnerHint'
            $owner = Resolve-FindingOwner -OwnerHint $ownerHint
            Set-EcfFindingProperty -Finding $Finding -Name 'Owner' -Value $owner | Out-Null
        }

        # Exception / ReviewStatus — defaults
        if (-not (Get-EcfFindingProperty -Finding $Finding -Name 'Exception')) {
            Set-EcfFindingProperty -Finding $Finding -Name 'Exception' -Value (Get-EcfDefaultException) | Out-Null
        }
        if (-not (Get-EcfFindingProperty -Finding $Finding -Name 'ReviewStatus')) {
            $rs = Get-EcfDefaultReviewStatus -RawStatus ([string](Get-EcfFindingProperty -Finding $Finding -Name 'Status'))
            Set-EcfFindingProperty -Finding $Finding -Name 'ReviewStatus' -Value $rs | Out-Null
        }

        # RemediationDetail — populate from RemediationGuidance if available
        if (-not (Get-EcfFindingProperty -Finding $Finding -Name 'RemediationDetail')) {
            $rd = Get-EcfDefaultRemediationDetail
            $shortRem = [string](Get-EcfFindingProperty -Finding $Finding -Name 'Remediation')
            if ($shortRem) { $rd.Summary = $shortRem }
            $rg = Get-EcfFindingProperty -Finding $Finding -Name 'RemediationGuidance'
            if ($rg) {
                $portal = Get-EcfFindingProperty -Finding $rg -Name 'StepsPortal'
                if ($portal) { $rd.PortalSteps = @($portal) }
                $ps = Get-EcfFindingProperty -Finding $rg -Name 'StepsPowerShell'
                if ($ps) { $rd.PowerShell = [string]$ps }
                $impact = Get-EcfFindingProperty -Finding $rg -Name 'Impact'
                if ($impact) {
                    $rd.Impact = [string](Get-EcfFindingProperty -Finding $impact -Name 'Positive')
                    $rd.Considerations = [string](Get-EcfFindingProperty -Finding $impact -Name 'Negative')
                }
            }
            Set-EcfFindingProperty -Finding $Finding -Name 'RemediationDetail' -Value $rd | Out-Null
        }

        # Tags / Links — default empty arrays
        foreach ($f in @('Tags', 'Links')) {
            if ($null -eq (Get-EcfFindingProperty -Finding $Finding -Name $f)) {
                Set-EcfFindingProperty -Finding $Finding -Name $f -Value @() | Out-Null
            }
        }

        # Disposition — derived
        $disposition = Get-FindingDisposition `
            -Status ([string](Get-EcfFindingProperty -Finding $Finding -Name 'Status')) `
            -ReviewStatus (Get-EcfFindingProperty -Finding $Finding -Name 'ReviewStatus') `
            -Exception (Get-EcfFindingProperty -Finding $Finding -Name 'Exception')
        Set-EcfFindingProperty -Finding $Finding -Name 'Disposition' -Value $disposition | Out-Null

        # Schema version last
        Set-EcfFindingProperty -Finding $Finding -Name 'SchemaVersion' -Value $Script:SchemaVersion | Out-Null

        return $Finding
    }
}

#endregion

#region Public — validation

function Test-EntraFindingV2 {
    <#
    .SYNOPSIS
        Validates a v2 finding's required fields and enum values.
    .DESCRIPTION
        Returns a structured result, not just $true/$false:

          @{ IsValid = $bool; Errors = @(); Warnings = @() }

        Errors block schema-v2 conformance. Warnings flag suspicious but
        tolerable issues (e.g. empty TenantId, missing optional fields).
    .OUTPUTS
        Hashtable with IsValid / Errors / Warnings.
    #>
    [OutputType([hashtable])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Finding
    )

    $errors = New-Object System.Collections.Generic.List[string]
    $warnings = New-Object System.Collections.Generic.List[string]

    if ($null -eq $Finding) {
        $errors.Add('Finding is null')
        return @{ IsValid = $false; Errors = $errors.ToArray(); Warnings = $warnings.ToArray() }
    }

    $schema = Get-EcfFindingProperty -Finding $Finding -Name 'SchemaVersion'
    if ($schema -ne $Script:SchemaVersion) {
        $errors.Add("SchemaVersion '$schema' != expected '$Script:SchemaVersion'")
    }

    foreach ($req in @('FindingId', 'CheckName', 'Status', 'Source')) {
        if (-not (Get-EcfFindingProperty -Finding $Finding -Name $req)) {
            $errors.Add("Required field '$req' is empty")
        }
    }

    $findingId = [string](Get-EcfFindingProperty -Finding $Finding -Name 'FindingId')
    if ($findingId -and $findingId -notmatch '^ECF-[0-9a-f]{20}$') {
        $errors.Add("FindingId '$findingId' does not match ECF-<20 hex> format")
    }

    $status = [string](Get-EcfFindingProperty -Finding $Finding -Name 'Status')
    if ($status -and $status -notin $Script:Enum_Status) {
        $errors.Add("Status '$status' not in allowed set: $($Script:Enum_Status -join ', ')")
    }

    $disposition = [string](Get-EcfFindingProperty -Finding $Finding -Name 'Disposition')
    if ($disposition -and $disposition -notin $Script:Enum_Disposition) {
        $errors.Add("Disposition '$disposition' not in allowed set")
    }

    $owner = Get-EcfFindingProperty -Finding $Finding -Name 'Owner'
    if ($owner) {
        $ot = [string](Get-EcfFindingProperty -Finding $owner -Name 'OwnerType')
        if ($ot -and $ot -notin $Script:Enum_OwnerType) {
            $errors.Add("Owner.OwnerType '$ot' not in allowed set")
        }
    }

    $ex = Get-EcfFindingProperty -Finding $Finding -Name 'Exception'
    if ($ex) {
        $exs = [string](Get-EcfFindingProperty -Finding $ex -Name 'Status')
        if ($exs -and $exs -notin $Script:Enum_ExceptionStatus) {
            $errors.Add("Exception.Status '$exs' not in allowed set")
        }
    }

    $rs = Get-EcfFindingProperty -Finding $Finding -Name 'ReviewStatus'
    if ($rs) {
        $rss = [string](Get-EcfFindingProperty -Finding $rs -Name 'State')
        if ($rss -and $rss -notin $Script:Enum_ReviewState) {
            $errors.Add("ReviewStatus.State '$rss' not in allowed set")
        }
    }

    if (-not (Get-EcfFindingProperty -Finding $Finding -Name 'TenantId')) {
        $warnings.Add('TenantId is empty — FindingId stability across tenants is not guaranteed')
    }

    return @{
        IsValid = ($errors.Count -eq 0)
        Errors = $errors.ToArray()
        Warnings = $warnings.ToArray()
    }
}

#endregion

#region Public — batch normalization + state load (PR 2 integration helper)

function Import-FindingState {
    <#
    .SYNOPSIS
        Loads a local analyst state file from disk.
    .DESCRIPTION
        State file is JSON with shape:
          { "Version": "1.0", "Findings": { "ECF-...": { Owner=..., Exception=..., ReviewStatus=... } } }

        Returns $null when the file is missing — callers treat that as
        "no state, run with defaults". When the file exists but is malformed,
        a Warning is written and $null is returned (an unparseable state file
        must NOT abort the assessment — analyst workflow is advisory).

        Findings is converted to a hashtable keyed by FindingId so
        Merge-FindingState can do constant-time lookups.
    .OUTPUTS
        Hashtable { Findings = @{ <FindingId> = <state-entry-pscustomobject> } }
        or $null when no state.
    #>
    [OutputType([hashtable])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][AllowNull()][string]$Path
    )

    if (-not $Path) { return $null }
    if (-not (Test-Path -LiteralPath $Path)) { return $null }

    try {
        $raw = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
        $parsed = $raw | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        Write-Warning ("Failed to load finding state file '{0}': {1}" -f $Path, $_.Exception.Message)
        return $null
    }

    # Normalize Findings into a hashtable keyed by FindingId. JSON parsed via
    # ConvertFrom-Json yields PSCustomObject; we reshape to hashtable here so
    # downstream Merge-FindingState gets a uniform input.
    $findingsBucket = @{}
    if ($parsed.PSObject -and $parsed.PSObject.Properties['Findings'] -and $parsed.Findings) {
        foreach ($prop in $parsed.Findings.PSObject.Properties) {
            $findingsBucket[$prop.Name] = $prop.Value
        }
    }

    return @{ Findings = $findingsBucket }
}

function Initialize-FindingsForReport {
    <#
    .SYNOPSIS
        Batch-normalizes a collection of legacy or partial findings into
        v2 schema, optionally applying analyst state from a JSON file.
    .DESCRIPTION
        This is the single integration point for orchestrator code paths.
        Idempotent: findings that already have SchemaVersion='2.0' are still
        run through the merger (so re-running with updated state picks up
        new entries) but their FindingId is preserved.

        State file precedence:
          1. Explicit -StateFilePath (always wins)
          2. -ConfigGrc hashtable's FindingStatePath property
          3. None — defaults applied

        Failures during normalization are logged via Write-Warning but never
        abort the report — analyst workflow is advisory.
    .OUTPUTS
        Array of v2-normalized findings. Same length as input.
    #>
    [OutputType([object[]])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowNull()][AllowEmptyCollection()][object[]]$Findings,
        [string]$DefaultTenantId = '',
        [string]$DefaultSource = 'Internal',
        [string]$StateFilePath = '',
        $ConfigGrc
    )

    if ($null -eq $Findings -or $Findings.Count -eq 0) {
        return , ([object[]]@())
    }

    # Resolve the effective state path. Explicit param wins; otherwise read
    # GRC.FindingStatePath from the supplied config block.
    $effectivePath = $StateFilePath
    if (-not $effectivePath -and $ConfigGrc) {
        $cfgPath = Get-EcfFindingProperty -Finding $ConfigGrc -Name 'FindingStatePath'
        if ($cfgPath) { $effectivePath = [string]$cfgPath }
    }

    $state = Import-FindingState -Path $effectivePath

    $output = New-Object System.Collections.Generic.List[object]
    foreach ($f in $Findings) {
        if ($null -eq $f) { continue }

        $normalized = $null
        try {
            $normalized = $f | ConvertTo-EntraFindingV2 -DefaultTenantId $DefaultTenantId -DefaultSource $DefaultSource
        }
        catch {
            Write-Warning ("ConvertTo-EntraFindingV2 failed on finding (Object={0}): {1}" -f (Get-EcfFindingProperty -Finding $f -Name 'Object'), $_.Exception.Message)
            $output.Add($f)
            continue
        }

        if ($state) {
            try {
                $normalized = Merge-FindingState -Finding $normalized -State $state
            }
            catch {
                Write-Warning ("Merge-FindingState failed on finding (FindingId={0}): {1}" -f (Get-EcfFindingProperty -Finding $normalized -Name 'FindingId'), $_.Exception.Message)
            }
        }

        $output.Add($normalized)
    }

    return , ([object[]]$output.ToArray())
}

#endregion

#region Public — flat-row export (PR 5 of Central-Finding-Schema-GRC-Plan)

function ConvertTo-FindingFlatRow {
    <#
    .SYNOPSIS
        Flattens a v2 finding's nested objects (Owner, Exception, ReviewStatus,
        ControlMappings, Evidence) into scalar columns suitable for CSV export.
    .DESCRIPTION
        Export-Csv's default behavior on a finding with nested objects renders
        cells as `@{Status=Approved; Type=...}` strings — analyst-hostile and
        unfilterable in Excel.

        This helper produces a single [pscustomobject] with one column per
        atomic value plus a few semicolon-joined arrays:
          - ControlMappingsFlat  = 'CIS_M365:1.1.1;NIST_CSF:PR.AC-1;...'
          - EvidenceIds          = 'EVID-...;EVID-...'
          - EvidenceSources      = 'Internal;Internal'
          - TagsFlat             = 'tier-1;quarterly-review'
          - LinksFlat            = 'https://...;https://...'

        Legacy findings (no v2 fields) produce flat rows with empty cells in
        the v2 columns — Export-Csv still emits a uniform header.
    .OUTPUTS
        Single [pscustomobject] with stable column ordering.
    #>
    [OutputType([pscustomobject])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)] $Finding
    )

    process {
        if ($null -eq $Finding) { return $null }

        $owner = Get-EcfFindingProperty -Finding $Finding -Name 'Owner'
        $exception = Get-EcfFindingProperty -Finding $Finding -Name 'Exception'
        $reviewStatus = Get-EcfFindingProperty -Finding $Finding -Name 'ReviewStatus'
        # Wrap-then-strip-nulls: PowerShell's @(...) on $null yields a
        # 1-element array containing $null, which would re-enter the foreach
        # below with a $null pipeline item — and Get-EcfFindingProperty's
        # -Finding parameter is Mandatory, so $null fails binding.
        $controlMappings = @(Get-EcfFindingProperty -Finding $Finding -Name 'ControlMappings') | Where-Object { $null -ne $_ }
        $evidence = @(Get-EcfFindingProperty -Finding $Finding -Name 'Evidence') | Where-Object { $null -ne $_ }
        $tags = @(Get-EcfFindingProperty -Finding $Finding -Name 'Tags') | Where-Object { $null -ne $_ }
        $links = @(Get-EcfFindingProperty -Finding $Finding -Name 'Links') | Where-Object { $null -ne $_ }
        # Re-wrap so .Count works uniformly on 0/1/many.
        $controlMappings = @($controlMappings)
        $evidence = @($evidence)
        $tags = @($tags)
        $links = @($links)

        $controlMappingsFlat = ''
        if ($controlMappings.Count -gt 0) {
            $controlMappingsFlat = (($controlMappings | ForEach-Object {
                        $fw = [string](Get-EcfFindingProperty -Finding $_ -Name 'Framework')
                        $cid = [string](Get-EcfFindingProperty -Finding $_ -Name 'ControlId')
                        if ($fw -and $cid) { "${fw}:${cid}" } elseif ($fw) { $fw } else { $cid }
                    }) -join ';')
        }

        $evidenceIds = ''
        $evidenceSources = ''
        $evidenceRedactionStatuses = ''
        if ($evidence.Count -gt 0) {
            $evidenceIds = (($evidence | ForEach-Object { [string](Get-EcfFindingProperty -Finding $_ -Name 'EvidenceId') }) -join ';')
            $evidenceSources = (($evidence | ForEach-Object { [string](Get-EcfFindingProperty -Finding $_ -Name 'Source') }) -join ';')
            $evidenceRedactionStatuses = (($evidence | ForEach-Object { [string](Get-EcfFindingProperty -Finding $_ -Name 'RedactionStatus') }) -join ';')
        }

        $tagsFlat = if ($tags.Count -gt 0) { ($tags -join ';') } else { '' }
        $linksFlat = if ($links.Count -gt 0) { ($links -join ';') } else { '' }

        # Build the flat row. Column ordering is stable across runs so CSVs
        # diff cleanly across snapshots — analyst tools (Excel, Pandas, jq
        # via csv-to-json) all benefit.
        [pscustomobject]@{
            FindingId = [string](Get-EcfFindingProperty -Finding $Finding -Name 'FindingId')
            SchemaVersion = [string](Get-EcfFindingProperty -Finding $Finding -Name 'SchemaVersion')
            Time = Get-EcfFindingProperty -Finding $Finding -Name 'Time'
            Status = [string](Get-EcfFindingProperty -Finding $Finding -Name 'Status')
            Disposition = [string](Get-EcfFindingProperty -Finding $Finding -Name 'Disposition')
            CheckName = [string](Get-EcfFindingProperty -Finding $Finding -Name 'CheckName')
            Type = [string](Get-EcfFindingProperty -Finding $Finding -Name 'Type')
            Object = [string](Get-EcfFindingProperty -Finding $Finding -Name 'Object')
            ObjectType = [string](Get-EcfFindingProperty -Finding $Finding -Name 'ObjectType')
            ObjectId = [string](Get-EcfFindingProperty -Finding $Finding -Name 'ObjectId')
            ResourceId = [string](Get-EcfFindingProperty -Finding $Finding -Name 'ResourceId')
            TenantId = [string](Get-EcfFindingProperty -Finding $Finding -Name 'TenantId')
            SubscriptionId = [string](Get-EcfFindingProperty -Finding $Finding -Name 'SubscriptionId')
            Source = [string](Get-EcfFindingProperty -Finding $Finding -Name 'Source')
            Description = [string](Get-EcfFindingProperty -Finding $Finding -Name 'Description')
            Remediation = [string](Get-EcfFindingProperty -Finding $Finding -Name 'Remediation')

            RiskScore = Get-EcfFindingProperty -Finding $Finding -Name 'RiskScore'
            RiskLevel = [string](Get-EcfFindingProperty -Finding $Finding -Name 'RiskLevel')
            PriorityScore = Get-EcfFindingProperty -Finding $Finding -Name 'PriorityScore'
            RemediationEffort = Get-EcfFindingProperty -Finding $Finding -Name 'RemediationEffort'

            OwnerType = if ($owner) { [string](Get-EcfFindingProperty -Finding $owner -Name 'OwnerType') } else { '' }
            OwnerDisplayName = if ($owner) { [string](Get-EcfFindingProperty -Finding $owner -Name 'DisplayName') } else { '' }
            OwnerEmail = if ($owner) { [string](Get-EcfFindingProperty -Finding $owner -Name 'Email') } else { '' }
            OwnerUPN = if ($owner) { [string](Get-EcfFindingProperty -Finding $owner -Name 'UserPrincipalName') } else { '' }
            OwnerSource = if ($owner) { [string](Get-EcfFindingProperty -Finding $owner -Name 'Source') } else { '' }
            OwnerDueDate = if ($owner) { [string](Get-EcfFindingProperty -Finding $owner -Name 'DueDate') } else { '' }

            ExceptionStatus = if ($exception) { [string](Get-EcfFindingProperty -Finding $exception -Name 'Status') } else { '' }
            ExceptionType = if ($exception) { [string](Get-EcfFindingProperty -Finding $exception -Name 'Type') } else { '' }
            ExceptionApprover = if ($exception) { [string](Get-EcfFindingProperty -Finding $exception -Name 'Approver') } else { '' }
            ExceptionApprovedAt = if ($exception) { [string](Get-EcfFindingProperty -Finding $exception -Name 'ApprovedAt') } else { '' }
            ExceptionExpiresAt = if ($exception) { [string](Get-EcfFindingProperty -Finding $exception -Name 'ExpiresAt') } else { '' }
            ExceptionJustification = if ($exception) { [string](Get-EcfFindingProperty -Finding $exception -Name 'Justification') } else { '' }

            ReviewState = if ($reviewStatus) { [string](Get-EcfFindingProperty -Finding $reviewStatus -Name 'State') } else { '' }
            Reviewer = if ($reviewStatus) { [string](Get-EcfFindingProperty -Finding $reviewStatus -Name 'Reviewer') } else { '' }
            ReviewNotes = if ($reviewStatus) { [string](Get-EcfFindingProperty -Finding $reviewStatus -Name 'Notes') } else { '' }
            NextReviewDate = if ($reviewStatus) { [string](Get-EcfFindingProperty -Finding $reviewStatus -Name 'NextReviewDate') } else { '' }

            ControlMappingsFlat = $controlMappingsFlat
            EvidenceIds = $evidenceIds
            EvidenceSources = $evidenceSources
            EvidenceRedactionStatuses = $evidenceRedactionStatuses
            TagsFlat = $tagsFlat
            LinksFlat = $linksFlat
        }
    }
}

#endregion

#region Module exports

Export-ModuleMember -Function @(
    'New-EntraFindingId',
    'ConvertTo-EntraFindingV2',
    'Test-EntraFindingV2',
    'Merge-FindingState',
    'Get-FindingDisposition',
    'Initialize-FindingsForReport',
    'Import-FindingState',
    'ConvertTo-FindingFlatRow',
    'ConvertTo-ControlMappings',
    'ConvertTo-EvidenceReference',
    'Resolve-FindingOwner',
    'Test-EvidenceContainsSecret'
)

#endregion
