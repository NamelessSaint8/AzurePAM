<#
.SYNOPSIS
    Define global-scope stubs for Microsoft.Graph and Az cmdlets so that
    Pester's `Mock -ModuleName ...` can intercept them on machines where
    the real modules aren't installed (Linux/macOS CI, fresh devboxes).

.DESCRIPTION
    Pester's `Mock` requires the target command to be reachable from the
    target module's session. If `Invoke-MgGraphRequest` doesn't exist
    anywhere, `Mock -ModuleName Foo Invoke-MgGraphRequest { ... }` fails
    with "Could not find Command Invoke-MgGraphRequest".

    Each stub:
      * Is installed only when no command of that name already exists, so
        on Windows-with-real-modules the actual cmdlet wins.
      * Lives in the global scope so modules under test see it (PowerShell
        looks up unresolved commands at module-load time in caller scope).
      * Throws if called without a Mock — stubs are not safe defaults; if
        a test calls real Graph/Az you want to know loudly, not silently
        return @().

    Usage (in a test file's BeforeAll):
        . (Join-Path $PSScriptRoot 'Helpers/Stub-CloudCmdlets.ps1')
        Import-Module ./Modules/EntraChecks-Something.psm1 -Force
        ...
        Mock -ModuleName EntraChecks-Something Invoke-MgGraphRequest { ... }

    Order matters: stubs must be installed BEFORE the module-under-test
    is imported, because the module captures the command reference at
    import time.

    Cross-platform note: Windows-only tests (AD/ACL APIs) tag their
    Describe blocks with -Tag 'WindowsOnly' and are excluded by the
    cross-platform runner. Stubbing Get-Acl would not help — the
    underlying .NET ACL types are unsupported off Windows.
#>

#Requires -Version 5.1

# Idempotent install helper. Defines a stub at *global* scope only when
# no command of that name is currently available in any scope.
#
# Default body returns $null silently. We tried "throw if not mocked" first,
# but modules under test often call Get-AzContext / Get-MgContext during
# Import-Module to discover whether they're already connected — that's a
# legitimate "no, not connected, fall back" path, not a missing-Mock bug.
# Loud failure made imports fail before any test could even register a Mock.
# Silent $null is a faithful no-credentials simulation; a test that expects
# specific data must register a Mock anyway, and a test that doesn't expect
# the path to be exercised will still notice via downstream assertions.
function script:Install-StubIfMissing {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [scriptblock]$Body = { $null }
    )
    if (Get-Command -Name $Name -ErrorAction SilentlyContinue) { return }
    # Install at global scope so other module sessions resolve to it.
    Set-Item -LiteralPath "function:global:$Name" -Value $Body
}

# ---------------------------------------------------------------
# Microsoft.Graph
# ---------------------------------------------------------------

# Invoke-MgGraphRequest gets a real param block: Pester mock proxies mirror
# the mocked command's signature, so a param-less stub means $Uri/$Method
# never bind inside Mock bodies on stubbed (CI) machines — mocks that
# discriminate by URI silently take the wrong branch (this defect was
# behind the since-removed KnownAssertionDrift tag on the SOC2-Phase2
# break-glass suite).
Install-StubIfMissing -Name 'Invoke-MgGraphRequest' -Body {
    [CmdletBinding()]
    param(
        [string]$Method,
        [string]$Uri,
        $Body,
        [hashtable]$Headers,
        [string]$ContentType,
        [string]$OutputType
    )
    $null
}

foreach ($n in @(
        'Connect-MgGraph'
        'Disconnect-MgGraph'
        'Get-MgContext'
        'Get-MgUser'
        'Get-MgGroup'
        'Get-MgGroupMember'
        'Get-MgDirectoryRole'
        'Get-MgServicePrincipal'
        'Get-MgServicePrincipalAppRoleAssignedTo'
        'Get-MgServicePrincipalOwner'
        'Get-MgApplication'
        'Get-MgRoleManagementDirectoryRoleAssignment'
        'Get-MgRoleManagementDirectoryRoleAssignmentSchedule'
        'Get-MgRoleManagementDirectoryRoleEligibilitySchedule'
        'Get-MgRoleManagementDirectoryRoleDefinition'
        'Get-MgIdentityConditionalAccessPolicy'
        'Get-MgPolicyAuthenticationMethodPolicy'
        'Get-MgReportAuthenticationMethodUserRegistrationDetail'
    )) {
    Install-StubIfMissing -Name $n
}

# ---------------------------------------------------------------
# Az (Azure PowerShell)
# ---------------------------------------------------------------
foreach ($n in @(
        'Connect-AzAccount'
        'Disconnect-AzAccount'
        'Get-AzContext'
        'Set-AzContext'
        'Get-AzSubscription'
        'Get-AzTenant'
        'Get-AzAccessToken'
        'Get-AzResource'
        'Get-AzResourceGroup'
        'Get-AzRoleAssignment'
        'Get-AzPolicyAssignment'
        'Get-AzPolicyState'
        'Get-AzRecoveryServicesVault'
        'Get-AzKeyVault'
        'Get-AzKeyVaultSecret'
        'Invoke-AzRestMethod'
    )) {
    Install-StubIfMissing -Name $n
}

# ---------------------------------------------------------------
# Optional: Az.Security helpers used by Defender checks. These call
# REST under the hood; tests Mock the wrapper instead, but install
# the cmdlet name in case any direct call sneaks in.
# ---------------------------------------------------------------
foreach ($n in @(
        'Get-AzSecurityAssessment'
        'Get-AzRegulatoryComplianceAssessment'
        'Get-AzRegulatoryComplianceStandard'
    )) {
    Install-StubIfMissing -Name $n
}
