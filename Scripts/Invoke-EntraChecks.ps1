<#
.SYNOPSIS
    Invoke-EntraChecks.ps1
    Comprehensive Microsoft Entra ID Security Check Script

.DESCRIPTION
    Cloud-native equivalent of ADChecks_Pro.ps1 for Microsoft Entra ID (Azure AD).
    Performs security assessments using Microsoft Graph API without requiring Sentinel.
    
    Features:
    - Modular, extensible check functions
    - Standardized findings with status/severity, object, description, and remediation
    - Support for both interactive and application (service principal) authentication
    - Capability detection for license-dependent features
    - CSV, HTML, and JSON report export
    - Non-interactive mode for automation
    - Configuration file support
    - Previous assessment comparison
    - Remediation script generation
    
.PARAMETER ReportDir
    Directory to save reports. Default: C:\temp\EntraChecks

.PARAMETER UserInactivityDays
    Days threshold for inactive user detection. Default: 90

.PARAMETER PasswordAgeDays
    Days threshold for stale password detection. Default: 180

.PARAMETER RecentDays
    Days threshold for "recently created" checks. Default: 30

.PARAMETER AuthMode
    Authentication mode: "Interactive" or "Application". Default: Interactive

.PARAMETER TenantId
    Tenant ID (required for Application auth mode)

.PARAMETER ClientId
    Application (client) ID (required for Application auth mode)

.PARAMETER ClientSecret
    Client secret as SecureString (for Application auth mode, alternative to ClientCertificate).
    Create with: $secret = Read-Host -AsSecureString

.PARAMETER ClientCertificateThumbprint
    Certificate thumbprint (for Application auth mode, alternative to ClientSecret)

.PARAMETER NonInteractive
    Run all checks without menu interaction. Ideal for scheduled/automated runs.

.PARAMETER OutputFormat
    Output format(s): CSV, HTML, JSON, or All. Default: CSV,HTML
    Can specify multiple: -OutputFormat CSV,HTML,JSON

.PARAMETER ConfigFile
    Path to configuration JSON file. If not specified, looks for EntraChecks-Config.json in script directory.

.PARAMETER CompareTo
    Path to previous assessment JSON file for comparison/trend analysis.

.PARAMETER GenerateRemediationScript
    Generate a PowerShell script with remediation commands for all findings.

.PARAMETER ChecksToRun
    Specific checks to run (by function name). If not specified, runs all checks.
    Example: -ChecksToRun "Test-PasswordNeverExpires","Test-GuestUsers"

.PARAMETER ExcludeChecks
    Checks to exclude from the run.
    Example: -ExcludeChecks "Test-PIMConfiguration"

.EXAMPLE
    # Interactive authentication (admin runs manually)
    .\Invoke-EntraChecks.ps1
    
.EXAMPLE
    # Application authentication with client secret
    $secret = ConvertTo-SecureString "your-secret" -AsPlainText -Force
    .\Invoke-EntraChecks.ps1 -AuthMode Application -TenantId "contoso.onmicrosoft.com" `
        -ClientId "00000000-0000-0000-0000-000000000000" -ClientSecret $secret

.EXAMPLE
    # Non-interactive with all output formats
    .\Invoke-EntraChecks.ps1 -NonInteractive -OutputFormat All

.EXAMPLE
    # Compare to previous assessment
    .\Invoke-EntraChecks.ps1 -NonInteractive -CompareTo "C:\Reports\previous-assessment.json"

.EXAMPLE
    # Generate remediation script
    .\Invoke-EntraChecks.ps1 -NonInteractive -GenerateRemediationScript

.EXAMPLE
    # Run specific checks only
    .\Invoke-EntraChecks.ps1 -NonInteractive -ChecksToRun "Test-PasswordNeverExpires","Test-GuestUsers"

.NOTES
    Version: 1.5.0
    Author: David Stells
    Requires: Microsoft.Graph PowerShell SDK
    
    Required Graph Permissions (Read-Only):
    - Directory.Read.All
    - User.Read.All
    - Group.Read.All
    - Application.Read.All
    - RoleManagement.Read.Directory
    - Policy.Read.All
    - AuditLog.Read.All
    - UserAuthenticationMethod.Read.All (for MFA checks)

.LINK
    AD Equivalent: ActiveDirectoryCheckv3_2.ps1
    Graph API Reference: https://learn.microsoft.com/en-us/graph/api/overview
#>

[CmdletBinding()]
param(
    [string]$ReportDir = "C:\temp\EntraChecks",
    [int]$UserInactivityDays = 90,
    [int]$PasswordAgeDays = 180,
    [int]$RecentDays = 30,
    
    [ValidateSet("Interactive", "Application")]
    [string]$AuthMode = "Interactive",
    
    [string]$TenantId,
    [string]$ClientId,
    [SecureString]$ClientSecret,
    [string]$ClientCertificateThumbprint,
    
    # Phase A Enhancement Parameters
    [switch]$NonInteractive,
    
    [ValidateSet("CSV", "HTML", "JSON", "All")]
    [string[]]$OutputFormat = @("CSV", "HTML"),
    
    [string]$ConfigFile,
    
    [string]$CompareTo,
    
    [switch]$GenerateRemediationScript,
    
    [string[]]$ChecksToRun,
    
    [string[]]$ExcludeChecks
)

#region ==================== INITIALIZATION ====================

# Create report directory if it doesn't exist
if (!(Test-Path $ReportDir)) {
    New-Item -Type Directory -Path $ReportDir | Out-Null
}

# Timestamp for file naming
$script:TimeVal = Get-Date -UFormat "%Y-%m-%d-%H-%M"
$LogFile = Join-Path $ReportDir "InvokeEntraChecks-LogFile-$script:TimeVal.log"

# Import and initialize logging module
$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$modulesPath = Join-Path $scriptRoot "Modules"
$loggingModule = Join-Path $modulesPath "EntraChecks-Logging.psm1"

if (Test-Path $loggingModule) {
    Import-Module $loggingModule -Force -ErrorAction SilentlyContinue

    # Initialize logging subsystem
    $logDir = Join-Path $ReportDir "Logs"
    $logLevel = if ($NonInteractive) { 'INFO' } else { 'DEBUG' }
    Initialize-LoggingSubsystem -LogDirectory $logDir -MinimumLevel $logLevel -RetentionDays 90 -StructuredLogging | Out-Null

    Write-Log -Level INFO -Message "EntraChecks assessment started" -Category "System" -Properties @{
        Version = "1.5.0"
        ReportDirectory = $ReportDir
        NonInteractive = $NonInteractive.IsPresent
    }
    Write-AuditLog -EventType "SessionStarted" -Description "EntraChecks assessment session started" -Details @{
        ReportDirectory = $ReportDir
        OutputFormat = ($OutputFormat -join ', ')
    }
}

# Start transcript as fallback (suppress output to avoid polluting stream)
Start-Transcript $LogFile -ErrorAction SilentlyContinue | Out-Null

# Initialize findings collection
$script:Findings = @()

# Previous assessment data (for comparison)
$script:PreviousFindings = $null

# Mapping from check function names to risk/compliance type keys
# These keys match the BaseRiskScores table in EntraChecks-RiskScoring.psm1
# and the framework mapping tables in EntraChecks-ComplianceMapping.psm1
$script:CheckNameToType = @{}
$script:CheckNameToType['Check-ConditionalAccessPolicies'] = 'ConditionalAccess_Missing'
$script:CheckNameToType['Check-PasswordNeverExpires'] = 'PasswordExpiry_Disabled'
$script:CheckNameToType['Check-DirectoryRolesAndMembers'] = 'AdminRoles_Excessive'
$script:CheckNameToType['Check-PrivilegedRoleCreep'] = 'GlobalAdmin_Multiple'
$script:CheckNameToType['Check-RecentPrivilegedAccounts'] = 'AdminRoles_Excessive'
$script:CheckNameToType['Check-UserAccountsAndInactivity'] = 'PasswordPolicy_Weak'
$script:CheckNameToType['Check-GuestUsers'] = 'GuestAccess_Unrestricted'
$script:CheckNameToType['Check-PasswordsInProfileFields'] = 'PasswordPolicy_Weak'
$script:CheckNameToType['Check-ShadowGroups'] = 'AdminRoles_Excessive'
$script:CheckNameToType['Check-RoleAssignableGroupOwnership'] = 'AdminRoles_Excessive'
$script:CheckNameToType['Check-ApplicationCredentials'] = 'AppPermissions_Excessive'
$script:CheckNameToType['Check-ServicePrincipalPermissions'] = 'AppPermissions_Excessive'
$script:CheckNameToType['Check-OAuthConsentGrants'] = 'AppConsent_UserAllowed'
$script:CheckNameToType['Check-AppRoleAssignments'] = 'AppPermissions_Excessive'
$script:CheckNameToType['Check-DuplicateAppIdentifiers'] = 'AppPermissions_Excessive'
$script:CheckNameToType['Check-AuthenticationMethodsPolicy'] = 'MFA_Disabled'
$script:CheckNameToType['Check-PrivilegedUserMFACoverage'] = 'MFA_AdminDisabled'
$script:CheckNameToType['Check-CrossTenantAccessPolicy'] = 'GuestAccess_Unrestricted'
$script:CheckNameToType['Check-AuthorizationPolicy'] = 'SecurityDefaults_Disabled'
$script:CheckNameToType['Check-AdminUnitDelegation'] = 'AdminRoles_Excessive'
$script:CheckNameToType['Check-PIMConfiguration'] = 'AdminRoles_Excessive'
$script:CheckNameToType['Check-AuditLogRetention'] = 'AuditLog_NotEnabled'
$script:CheckNameToType['Check-DirectoryRoleAssignmentPaths'] = 'AdminRoles_Excessive'
$script:CheckNameToType['Check-NamedLocations'] = 'ConditionalAccess_Missing'
$script:CheckNameToType['Check-TenantAndDomainInfo'] = 'Default'

#region ==================== ERROR KNOWLEDGE BASE ====================
# Maps error patterns to meaningful codes, causes, and resolutions
# Used by Write-CheckError to classify errors for analyst-friendly logging
$script:ErrorKnowledge = @{}
$entry = @{}
$entry['Pattern'] = 'AADSTS|authentication failed|token.*expir|login required|InteractiveBrowser'
$entry['Cause'] = 'Authentication session expired or failed'
$entry['Resolution'] = 'Re-run the script and sign in again. If using scheduled mode, check service principal credentials.'
$script:ErrorKnowledge['EC-AUTH'] = $entry
$entry = @{}
$entry['Pattern'] = 'Forbidden|403|Insufficient privileges|Authorization_RequestDenied|insufficient.*scope'
$entry['Cause'] = 'Missing Graph API permissions'
$entry['Resolution'] = 'Have a Global Admin run .\Grant-AdminConsent.ps1 to grant required scopes, or sign in with Global Reader role.'
$script:ErrorKnowledge['EC-PERM'] = $entry
$entry = @{}
$entry['Pattern'] = 'Premium|P2.*required|license.*required|IdentityProtection|AAD_Premium'
$entry['Cause'] = 'Requires Azure AD Premium P2 license'
$entry['Resolution'] = 'This check requires an Azure AD Premium P2 license. Skip it with -ExcludeChecks or upgrade your license.'
$script:ErrorKnowledge['EC-LIC'] = $entry
$entry = @{}
$entry['Pattern'] = '429|throttl|Too Many Requests|rate.*limit'
$entry['Cause'] = 'Graph API rate limiting'
$entry['Resolution'] = 'Too many API requests. Wait a few minutes and re-run, or run fewer modules at once.'
$script:ErrorKnowledge['EC-THROT'] = $entry
$entry = @{}
$entry['Pattern'] = 'Not connected|no.*graph.*session|Connect-MgGraph|network|timeout|socket'
$entry['Cause'] = 'Graph/Azure connection lost'
$entry['Resolution'] = 'Network issue or session timeout. Check connectivity and re-run the script.'
$script:ErrorKnowledge['EC-CONN'] = $entry
$entry = @{}
$entry['Pattern'] = '404|Not Found|does not exist|resource.*not.*found'
$entry['Cause'] = 'Requested resource not found'
$entry['Resolution'] = 'The API endpoint or resource does not exist in this tenant. This may be expected if the feature is not configured.'
$script:ErrorKnowledge['EC-NOTFOUND'] = $entry
$entry = @{}
$entry['Pattern'] = 'Azure\.Identity\.Broker|WAM|Az\.Accounts|AzContext|subscription'
$entry['Cause'] = 'Azure module or authentication issue'
$entry['Resolution'] = 'Check Az module installation (Install-Module Az.Accounts). If WAM errors persist, restart PowerShell.'
$script:ErrorKnowledge['EC-AZ'] = $entry
$entry = @{}
$entry['Pattern'] = 'not recognized|CommandNotFound|Import-Module|module.*not.*found'
$entry['Cause'] = 'Required PowerShell module not installed'
$entry['Resolution'] = 'Run .\Install-Prerequisites.ps1 to install all required modules.'
$script:ErrorKnowledge['EC-MOD'] = $entry

# Collects errors during the run for the end-of-run summary
$script:ErrorSummary = [System.Collections.ArrayList]::new()

function Write-CheckError {
    <#
    .SYNOPSIS
        Logs a check/module error with classification, writes to log file, and tracks for summary.
    .DESCRIPTION
        Matches the error against the ErrorKnowledge base to assign a meaningful error code,
        cause, and resolution. Logs to the structured log file via Write-Log, writes to the
        console for real-time visibility, and adds to ErrorSummary for the end-of-run report.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$CheckName,

        [Parameter(Mandatory)]
        [string]$Message,

        [System.Management.Automation.ErrorRecord]$ErrorRecord,

        [string]$Category = "CheckExecution"
    )

    # Match error against knowledge base
    $errorCode = 'EC-UNKNOWN'
    $cause = 'Unexpected error'
    $resolution = 'Check the log file for full error details and contact the administrator.'
    $errorText = if ($ErrorRecord) { $ErrorRecord.Exception.Message } else { $Message }

    foreach ($code in $script:ErrorKnowledge.Keys) {
        $entry = $script:ErrorKnowledge[$code]
        if ($errorText -match $entry.Pattern) {
            $errorCode = $code
            $cause = $entry.Cause
            $resolution = $entry.Resolution
            break
        }
    }

    # Log to structured log file (persistent)
    if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
        $logProps = @{}
        $logProps['ErrorCode'] = $errorCode
        $logProps['CheckName'] = $CheckName
        $logProps['Cause'] = $cause
        $logProps['Resolution'] = $resolution
        Write-Log -Level ERROR -Message "[$errorCode] $CheckName - $Message" `
            -Category $Category `
            -ErrorRecord $ErrorRecord `
            -Properties $logProps
    }

    # Write to console (real-time visibility for analyst)
    Write-Host "[!] [$errorCode] $CheckName : $Message" -ForegroundColor Red
    Write-Host "    Cause: $cause" -ForegroundColor DarkYellow
    Write-Host "    Fix: $resolution" -ForegroundColor DarkGray

    # Track for end-of-run summary
    $errorEntry = New-Object PSObject
    $errorEntry | Add-Member -NotePropertyName Time -NotePropertyValue (Get-Date)
    $errorEntry | Add-Member -NotePropertyName ErrorCode -NotePropertyValue $errorCode
    $errorEntry | Add-Member -NotePropertyName CheckName -NotePropertyValue $CheckName
    $errorEntry | Add-Member -NotePropertyName Message -NotePropertyValue $Message
    $errorEntry | Add-Member -NotePropertyName Cause -NotePropertyValue $cause
    $errorEntry | Add-Member -NotePropertyName Resolution -NotePropertyValue $resolution
    $exceptionMsg = if ($ErrorRecord) { $ErrorRecord.Exception.Message } else { $null }
    $errorEntry | Add-Member -NotePropertyName Exception -NotePropertyValue $exceptionMsg
    $null = $script:ErrorSummary.Add($errorEntry)
}

function Show-ErrorSummary {
    <#
    .SYNOPSIS
        Displays a grouped error summary at the end of the assessment run.
    #>
    if ($script:ErrorSummary.Count -eq 0) {
        Write-Host "`n[OK] Assessment completed with no errors." -ForegroundColor Green
        if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
            Write-Log -Level INFO -Message "Assessment completed with no errors" -Category "Summary"
        }
        return
    }

    $grouped = $script:ErrorSummary | Group-Object -Property ErrorCode

    Write-Host ""
    Write-Host "========================================" -ForegroundColor Yellow
    Write-Host "  ASSESSMENT ERROR SUMMARY" -ForegroundColor Yellow
    Write-Host "  $($script:ErrorSummary.Count) error(s) during execution" -ForegroundColor Yellow
    Write-Host "========================================" -ForegroundColor Yellow

    foreach ($group in $grouped) {
        $code = $group.Name
        $items = $group.Group
        $cause = $items[0].Cause
        $resolution = $items[0].Resolution

        Write-Host "`n  [$code] $cause ($($items.Count)x)" -ForegroundColor Red
        foreach ($item in $items) {
            Write-Host "    - $($item.CheckName): $($item.Message)" -ForegroundColor DarkGray
        }
        Write-Host "    Fix: $resolution" -ForegroundColor DarkYellow
    }

    # Show log file path
    $logPath = $null
    if (Get-Command Get-LogFilePath -ErrorAction SilentlyContinue) {
        $logPath = Get-LogFilePath
    }
    if ($logPath) {
        Write-Host "`n  Full error log: $logPath" -ForegroundColor Cyan
    }
    else {
        Write-Host "`n  Check .\Logs\ folder for detailed error logs." -ForegroundColor Cyan
    }
    Write-Host "========================================" -ForegroundColor Yellow

    # Log the summary itself
    if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
        $summaryText = ($grouped | ForEach-Object { "[$($_.Name)] $($_.Count)x: $($_.Group[0].Cause)" }) -join '; '
        $summaryProps = @{}
        $summaryProps['TotalErrors'] = $script:ErrorSummary.Count
        $summaryProps['ErrorCodes'] = ($grouped | ForEach-Object { $_.Name }) -join ','
        Write-Log -Level WARN -Message "Assessment completed with $($script:ErrorSummary.Count) error(s): $summaryText" `
            -Category "Summary" `
            -Properties $summaryProps
    }
}
#endregion

# Configuration from file
$script:Config = $null

# Load configuration file if specified or auto-detect
function Import-Configuration {
    $configPath = $ConfigFile
    
    # Auto-detect config file in script directory if not specified
    if (-not $configPath) {
        $scriptDir = Split-Path -Parent $MyInvocation.ScriptName
        if ($scriptDir) {
            $autoConfigPath = Join-Path $scriptDir "EntraChecks-Config.json"
            if (Test-Path $autoConfigPath) {
                $configPath = $autoConfigPath
                Write-Host "[*] Auto-detected configuration file: $configPath" -ForegroundColor Gray
            }
        }
    }
    
    if ($configPath -and (Test-Path $configPath)) {
        try {
            $script:Config = Get-Content $configPath -Raw | ConvertFrom-Json
            Write-Host "[+] Loaded configuration from: $configPath" -ForegroundColor Green
            
            # Apply configuration values to parameters if not explicitly specified
            if ($script:Config.Thresholds) {
                if ($script:Config.Thresholds.UserInactivityDays -and $UserInactivityDays -eq 90) {
                    $script:UserInactivityDays = $script:Config.Thresholds.UserInactivityDays
                }
                if ($script:Config.Thresholds.PasswordAgeDays -and $PasswordAgeDays -eq 180) {
                    $script:PasswordAgeDays = $script:Config.Thresholds.PasswordAgeDays
                }
                if ($script:Config.Thresholds.RecentDays -and $RecentDays -eq 30) {
                    $script:RecentDays = $script:Config.Thresholds.RecentDays
                }
            }
        }
        catch {
            Write-Host "[!] Failed to load configuration file: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
}

# Load previous assessment for comparison
function Import-PreviousAssessment {
    if ($CompareTo -and (Test-Path $CompareTo)) {
        try {
            $script:PreviousFindings = Get-Content $CompareTo -Raw | ConvertFrom-Json
            Write-Host "[+] Loaded previous assessment for comparison: $CompareTo" -ForegroundColor Green
            Write-Host "    Previous assessment date: $($script:PreviousFindings.Metadata.Timestamp)" -ForegroundColor Gray
            Write-Host "    Previous findings count: $($script:PreviousFindings.Findings.Count)" -ForegroundColor Gray
        }
        catch {
            Write-Host "[!] Failed to load previous assessment: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
}

# Initialize configuration and previous assessment
Import-Configuration
Import-PreviousAssessment

# Store parameters in script scope for access in functions
$script:UserInactivityDays = $UserInactivityDays
$script:PasswordAgeDays = $PasswordAgeDays
$script:RecentDays = $RecentDays

# Tenant capabilities (populated during connection)
$script:TenantCapabilities = @{
    TenantId = $null
    TenantName = $null
    HasP1License = $false
    HasP2License = $false
    HasPIM = $false
    HasConditionalAccess = $false
    HasSignInLogs = $false
}

#endregion

#region ==================== CORE FUNCTIONS ====================

<#
.SYNOPSIS
    Adds a finding to the global findings collection.

.DESCRIPTION
    Standardized function for recording security findings.
    Mirrors the Add-Finding function from the AD script.

.PARAMETER Status
    Finding status: OK, INFO, WARNING, or FAIL

.PARAMETER Object
    The object or entity the finding relates to

.PARAMETER Description
    Detailed description of the finding

.PARAMETER Remediation
    Recommended remediation steps
#>
function Add-Finding {
    param(
        [Parameter(Mandatory)]
        # REVIEW = human-judgment item. Distinct from WARNING (clear-policy
        # violation) and INFO (advisory). Surfaces in the Review Queue
        # section, not the main Findings list. RiskScore is still computed;
        # only the RiskLevel band is overridden to 'Review'.
        [ValidateSet("OK", "INFO", "WARNING", "FAIL", "REVIEW")]
        [string]$Status,

        [Parameter(Mandatory)]
        [string]$Object,

        [Parameter(Mandatory)]
        [string]$Description,

        [string]$Remediation = "Review and address as appropriate.",

        # Provenance: which data source produced this finding. Optional —
        # auto-derived from the call stack when omitted (sources are mapped
        # by .psm1 file name in EntraChecks-DataSources.psm1).
        [string]$Source
    )

    # Auto-capture calling function name for CIS/NIST compliance mapping
    $callerName = (Get-PSCallStack)[1].FunctionName
    # Normalize Test- prefix to Check- for compatibility with MappedChecks arrays
    $checkName = $callerName -replace '^Test-', 'Check-'

    # Resolve finding type for risk scoring and compliance framework mapping
    $findingType = if ($script:CheckNameToType.ContainsKey($checkName)) {
        $script:CheckNameToType[$checkName]
    }
    else {
        'Default'
    }

    # Resolve data source key. Prefers explicit -Source if given; otherwise
    # falls back to call-stack auto-derive via Resolve-FindingSource. When the
    # DataSources module isn't loaded (legacy invocation path), we default to
    # 'Internal'.
    $resolvedSource = if (Get-Command Resolve-FindingSource -ErrorAction SilentlyContinue) {
        if ($PSBoundParameters.ContainsKey('Source')) {
            Resolve-FindingSource -ExplicitSource $Source -WarningAction SilentlyContinue
        }
        else {
            Resolve-FindingSource
        }
    }
    elseif ($Source) {
        $Source
    }
    else {
        'Internal'
    }

    $finding = [PSCustomObject]@{
        Time = (Get-Date)
        CheckName = $checkName
        Type = $findingType
        Status = $Status
        Object = $Object
        Description = $Description
        Remediation = $Remediation
        Source = $resolvedSource
    }

    $script:Findings += $finding

    # Log the finding
    $logLevel = switch ($Status) {
        "OK" { "INFO" }
        "INFO" { "INFO" }
        "REVIEW" { "INFO" }
        "WARNING" { "WARN" }
        "FAIL" { "ERROR" }
    }

    if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
        Write-Log -Level $logLevel -Message "Finding: $Description" -Category "Finding" -Properties @{
            Status = $Status
            Object = $Object
            Remediation = $Remediation
        }

        # Write audit log for FAIL and WARNING findings
        if ($Status -in @('FAIL', 'WARNING')) {
            $auditResult = if ($Status -eq 'FAIL') { 'Failure' } else { 'Warning' }
            Write-AuditLog -EventType "FindingDetected" -Description $Description -TargetObject $Object -Result $auditResult
        }
    }

    # Also write to console with color coding
    $color = switch ($Status) {
        "OK" { "Green" }
        "INFO" { "Cyan" }
        "REVIEW" { "Magenta" }
        "WARNING" { "Yellow" }
        "FAIL" { "Red" }
    }
    Write-Host "[$Status] $Object" -ForegroundColor $color
}

# Remove the Microsoft.Graph.Authentication alias 'Invoke-GraphRequest' which conflicts
# with our custom function below. The alias points to Invoke-MgGraphRequest which does
# NOT have an -AllPages parameter, causing all checks to fail.
if (Get-Alias Invoke-GraphRequest -ErrorAction SilentlyContinue) {
    Remove-Item alias:Invoke-GraphRequest -Force -ErrorAction SilentlyContinue
}

<#
.SYNOPSIS
    Makes a request to Microsoft Graph API with error handling and pagination support.

.DESCRIPTION
    Wrapper function for Graph API calls with automatic pagination,
    error handling, and retry logic.

.PARAMETER Uri
    The Graph API endpoint URI

.PARAMETER Method
    HTTP method (default: GET)

.PARAMETER AllPages
    If true, automatically handles pagination to retrieve all results
#>
function Invoke-GraphRequest {
    param(
        [Parameter(Mandatory)]
        [string]$Uri,
        
        [string]$Method = "GET",
        
        [switch]$AllPages
    )
    
    try {
        if ($AllPages) {
            $results = @()
            $response = Invoke-MgGraphRequest -Uri $Uri -Method $Method
            
            if ($response.value) {
                $results += $response.value
            } else {
                return $response
            }
            
            # Handle pagination
            while ($response.'@odata.nextLink') {
                $response = Invoke-MgGraphRequest -Uri $response.'@odata.nextLink' -Method $Method
                if ($response.value) {
                    $results += $response.value
                }
            }
            
            return $results
        } else {
            return Invoke-MgGraphRequest -Uri $Uri -Method $Method
        }
    }
    catch {
        Write-Warning "Graph API request failed: $($_.Exception.Message)"
        Write-Warning "URI: $Uri"
        return $null
    }
}

#endregion

#region ==================== AUTHENTICATION ====================

<#
.SYNOPSIS
    Connects to Microsoft Graph with the specified authentication mode.

.DESCRIPTION
    Supports both interactive (delegated) and application (client credentials) authentication.
    Validates required parameters and establishes the Graph connection.
#>
function Connect-EntraChecks {
    Write-Host "`n[*] Connecting to Microsoft Graph..." -ForegroundColor Cyan

    # Check if already connected (e.g. when called from Start-EntraChecks.ps1 which authenticates first)
    $existingContext = Get-MgContext -ErrorAction SilentlyContinue
    if ($existingContext) {
        Write-Host "[+] Already connected to Microsoft Graph" -ForegroundColor Green
        Write-Host "    Account: $($existingContext.Account)" -ForegroundColor Gray
        Write-Host "    Tenant ID: $($existingContext.TenantId)" -ForegroundColor Gray
        $script:TenantCapabilities.TenantId = $existingContext.TenantId
        return $true
    }

    # Check if Microsoft.Graph module is installed
    if (!(Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
        Write-Host "[!] Microsoft.Graph module not found. Installing..." -ForegroundColor Yellow
        try {
            Install-Module Microsoft.Graph -Scope CurrentUser -Force -AllowClobber
        }
        catch {
            Write-Error "Failed to install Microsoft.Graph module. Please install manually: Install-Module Microsoft.Graph -Scope CurrentUser"
            return $false
        }
    }
    
    # Import required modules
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop

    # Remove the alias that Microsoft.Graph.Authentication creates (Invoke-GraphRequest -> Invoke-MgGraphRequest)
    # This alias shadows our custom Invoke-GraphRequest function which supports -AllPages pagination
    if (Get-Alias Invoke-GraphRequest -ErrorAction SilentlyContinue) {
        Remove-Item alias:Invoke-GraphRequest -Force -ErrorAction SilentlyContinue
    }

    # Define required scopes — kept in sync with $script:AllGraphScopes in
    # Start-EntraChecks.ps1. Requesting the same union here means a stand-alone
    # invocation does not trigger an incremental-consent re-prompt the next
    # time the user runs through the menu.
    $requiredScopes = @(
        "Directory.Read.All",
        "Policy.Read.All",
        "SecurityEvents.Read.All",
        "AuditLog.Read.All",
        "IdentityRiskEvent.Read.All",
        "IdentityRiskyUser.Read.All",
        "Device.Read.All",
        "DeviceManagementManagedDevices.Read.All",
        "DeviceManagementConfiguration.Read.All",
        "InformationProtectionPolicy.Read",
        "BitLockerKey.ReadBasic.All"
    )
    
    try {
        if ($AuthMode -eq "Interactive") {
            Write-Host "[*] Using interactive authentication..." -ForegroundColor Cyan
            
            # Interactive login
            if ($TenantId) {
                Connect-MgGraph -Scopes $requiredScopes -TenantId $TenantId -NoWelcome
            } else {
                Connect-MgGraph -Scopes $requiredScopes -NoWelcome
            }
        }
        else {
            # Application authentication
            Write-Host "[*] Using application authentication..." -ForegroundColor Cyan
            
            # Validate required parameters
            if (-not $TenantId -or -not $ClientId) {
                Write-Error "Application authentication requires -TenantId and -ClientId parameters."
                return $false
            }
            
            if ($ClientSecret) {
                # Client secret authentication
                $credential = New-Object System.Management.Automation.PSCredential($ClientId, $ClientSecret)
                Connect-MgGraph -TenantId $TenantId -ClientSecretCredential $credential -NoWelcome
            }
            elseif ($ClientCertificateThumbprint) {
                # Certificate authentication
                Connect-MgGraph -TenantId $TenantId -ClientId $ClientId -CertificateThumbprint $ClientCertificateThumbprint -NoWelcome
            }
            else {
                Write-Error "Application authentication requires either -ClientSecret or -ClientCertificateThumbprint."
                return $false
            }
        }
        
        # Verify connection
        $context = Get-MgContext
        if ($context) {
            Write-Host "[+] Successfully connected to Microsoft Graph" -ForegroundColor Green
            Write-Host "    Tenant ID: $($context.TenantId)" -ForegroundColor Gray
            Write-Host "    Auth Type: $($context.AuthType)" -ForegroundColor Gray
            Write-Host "    Scopes: $($context.Scopes -join ', ')" -ForegroundColor Gray
            
            $script:TenantCapabilities.TenantId = $context.TenantId
            return $true
        }
        else {
            Write-Error "Failed to establish Graph connection."
            return $false
        }
    }
    catch {
        Write-Error "Authentication failed: $($_.Exception.Message)"
        return $false
    }
}

<#
.SYNOPSIS
    Disconnects from Microsoft Graph.
#>
function Disconnect-EntraChecks {
    Write-Host "`n[*] Disconnecting from Microsoft Graph..." -ForegroundColor Cyan
    Disconnect-MgGraph -ErrorAction SilentlyContinue
    Write-Host "[+] Disconnected." -ForegroundColor Green
}

#endregion

#region ==================== CAPABILITY DETECTION ====================

<#
.SYNOPSIS
    Detects tenant capabilities and license features.

.DESCRIPTION
    Probes various Graph endpoints to determine what features are available.
    This enables graceful degradation when certain licenses aren't present.
    
    Detects:
    - Azure AD P1 license (Conditional Access)
    - Azure AD P2 license (PIM)
    - Sign-in log availability
    - Audit log availability
#>
function Get-TenantCapabilities {
    Write-Host "`n[*] Detecting tenant capabilities..." -ForegroundColor Cyan
    
    # Get organization info
    try {
        $org = Invoke-GraphRequest -Uri "https://graph.microsoft.com/v1.0/organization"
        if ($org.value) {
            $script:TenantCapabilities.TenantName = $org.value[0].displayName
            Write-Host "    Tenant Name: $($script:TenantCapabilities.TenantName)" -ForegroundColor Gray
        }
    }
    catch {
        Write-Warning "Could not retrieve organization info."
    }
    
    # Check for Conditional Access (P1 indicator)
    try {
        Invoke-GraphRequest -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" | Out-Null
        $script:TenantCapabilities.HasConditionalAccess = $true
        $script:TenantCapabilities.HasP1License = $true
        Write-Host "    [+] Conditional Access: Available (P1+)" -ForegroundColor Green
    }
    catch {
        Write-Host "    [-] Conditional Access: Not available or not licensed" -ForegroundColor Yellow
    }
    
    # Check for PIM (P2 indicator)
    try {
        $null = Invoke-GraphRequest -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilitySchedules?`$top=1"
        $script:TenantCapabilities.HasPIM = $true
        $script:TenantCapabilities.HasP2License = $true
        Write-Host "    [+] Privileged Identity Management: Available (P2)" -ForegroundColor Green
    }
    catch {
        Write-Host "    [-] Privileged Identity Management: Not available or not licensed" -ForegroundColor Yellow
    }
    
    # Check sign-in logs availability
    try {
        $null = Invoke-GraphRequest -Uri "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$top=1"
        $script:TenantCapabilities.HasSignInLogs = $true
        Write-Host "    [+] Sign-in Logs: Available" -ForegroundColor Green
    }
    catch {
        Write-Host "    [-] Sign-in Logs: Not available (may require P1+ license)" -ForegroundColor Yellow
    }
    
    Write-Host ""
    return $script:TenantCapabilities
}

#endregion

#region ==================== CHECK FUNCTIONS ====================

<#
.SYNOPSIS
    Test-TenantAndDomainInfo - Gathers tenant and domain information.

.DESCRIPTION
    Equivalent to: Check-ForestAndDomainInfo (AD version)
    
    Collects and reports basic information about the Microsoft Entra ID tenant,
    including tenant name, ID, verified domains, and configuration details.
    
    Graph Endpoints Used:
    - GET /organization
    - GET /domains
    
.OUTPUTS
    Findings with Status: INFO
    
.NOTES
    Required Permissions: Directory.Read.All
    Minimum License: Azure AD Free
    
.LINK
    AD Equivalent: Check-ForestAndDomainInfo
    Graph Reference: https://learn.microsoft.com/en-us/graph/api/organization-get
#>
function Test-TenantAndDomainInfo {
    Write-Host "`n[+] Collecting tenant and domain information..." -ForegroundColor Cyan
    
    try {
        # Get organization (tenant) details
        $org = Invoke-GraphRequest -Uri "https://graph.microsoft.com/v1.0/organization"
        $tenant = $org.value[0]
        
        # Get verified domains
        $domains = Invoke-GraphRequest -Uri "https://graph.microsoft.com/v1.0/domains" -AllPages
        
        # Build domain list
        $domainList = $domains | ForEach-Object {
            $flags = @()
            if ($_.isDefault) { $flags += "Default" }
            if ($_.isInitial) { $flags += "Initial" }
            if ($_.isVerified) { $flags += "Verified" }
            "$($_.id) [$($flags -join ', ')]"
        }
        
        # Create summary
        $summary = @"
Tenant Display Name:    $($tenant.displayName)
Tenant ID:              $($tenant.id)
Country:                $($tenant.countryLetterCode)
Created:                $($tenant.createdDateTime)
On-Premises Sync:       $(if ($tenant.onPremisesSyncEnabled) { "Enabled (Hybrid)" } else { "Disabled (Cloud-Only)" })
Verified Domains:
$($domainList | ForEach-Object { "  - $_" } | Out-String)
"@
        
        Add-Finding -Status "INFO" `
            -Object "Tenant and Domains" `
            -Description "Entra ID tenant basic info:`n$summary" `
            -Remediation "No action needed. For reference only."
        
        # Flag if hybrid (might need AD checks too)
        if ($tenant.onPremisesSyncEnabled) {
            Add-Finding -Status "INFO" `
                -Object "Hybrid Configuration" `
                -Description "This tenant has on-premises sync enabled (Azure AD Connect). Some security controls may need to be checked in on-premises AD as well." `
                -Remediation "Run AD security checks on the on-premises environment in addition to these Entra checks."
        }
    }
    catch {
        Add-Finding -Status "WARNING" `
            -Object "Tenant and Domains" `
            -Description "Unable to collect tenant/domain info: $($_.Exception.Message)" `
            -Remediation "Check connectivity and Graph permissions (Directory.Read.All required)."
    }
}

<#
.SYNOPSIS
    Test-PasswordNeverExpires - Finds users with password set to never expire.

.DESCRIPTION
    Equivalent to: Test-PasswordNeverExpires (AD version)
    
    Finds all enabled user accounts with the "Password never expires" setting.
    This is controlled by the passwordPolicies attribute containing 
    "DisablePasswordExpiration".
    
    These accounts are at higher risk for password-related attacks and should
    be reviewed, especially if they have elevated privileges.
    
    Graph Endpoints Used:
    - GET /users?$select=id,displayName,userPrincipalName,accountEnabled,passwordPolicies
    
.OUTPUTS
    Findings with Status: FAIL for each affected user, OK if none found
    
.NOTES
    Required Permissions: User.Read.All
    Minimum License: Azure AD Free
    This is a DIRECT PORT - cleanest 1:1 mapping from AD check
    
.LINK
    AD Equivalent: Test-PasswordNeverExpires
    Graph Reference: https://learn.microsoft.com/en-us/graph/api/user-list
#>
function Test-PasswordNeverExpires {
    Write-Host "`n[+] Checking for enabled user accounts with 'Password Never Expires' set..." -ForegroundColor Cyan
    
    try {
        # Query all users with relevant properties
        $users = Invoke-GraphRequest -Uri "https://graph.microsoft.com/v1.0/users?`$select=id,displayName,userPrincipalName,accountEnabled,passwordPolicies&`$top=999" -AllPages
        
        $flaggedCount = 0
        
        foreach ($user in $users) {
            # Check if enabled and has DisablePasswordExpiration in passwordPolicies
            if ($user.accountEnabled -eq $true -and 
                $user.passwordPolicies -and 
                $user.passwordPolicies -match "DisablePasswordExpiration") {
                
                $flaggedCount++
                Add-Finding -Status "FAIL" `
                    -Object $user.userPrincipalName `
                    -Description "User account has 'Password never expires' enabled (passwordPolicies: $($user.passwordPolicies)). This increases the risk of credential compromise over time." `
                    -Remediation "Remove the 'DisablePasswordExpiration' policy for this user. If this is a service account, consider using a managed identity or workload identity instead."
            }
        }
        
        if ($flaggedCount -eq 0) {
            Add-Finding -Status "OK" `
                -Object "All Users" `
                -Description "No enabled users found with 'Password never expires' set." `
                -Remediation "No action needed."
        }
        else {
            Add-Finding -Status "INFO" `
                -Object "Password Never Expires Summary" `
                -Description "Found $flaggedCount enabled user(s) with 'Password never expires' set." `
                -Remediation "Review each flagged account above and remediate as appropriate."
        }
    }
    catch {
        Add-Finding -Status "WARNING" `
            -Object "Password Never Expires" `
            -Description "Unable to check password expiration settings: $($_.Exception.Message)" `
            -Remediation "Check Graph permissions (User.Read.All required)."
    }
}

<#
.SYNOPSIS
    Test-DirectoryRolesAndMembers - Enumerates privileged directory role members.

.DESCRIPTION
    Equivalent to: Check-AdminGroupsAndMembers (AD version)
    
    Enumerates members of key privileged Azure AD directory roles.
    Flags:
    - Disabled users in privileged roles (should be removed)
    - Guest users in privileged roles (high risk)
    - Service principals with directory roles (may be overprivileged)
    
    Graph Endpoints Used:
    - GET /directoryRoles
    - GET /directoryRoles/{id}/members
    
.OUTPUTS
    Findings with Status: INFO for role membership, WARNING/FAIL for issues
    
.NOTES
    Required Permissions: Directory.Read.All, RoleManagement.Read.Directory
    Minimum License: Azure AD Free
    
.LINK
    AD Equivalent: Check-AdminGroupsAndMembers
    Graph Reference: https://learn.microsoft.com/en-us/graph/api/directoryrole-list-members
#>
function Test-DirectoryRolesAndMembers {
    Write-Host "`n[+] Enumerating privileged directory role members..." -ForegroundColor Cyan
    
    # Key privileged roles to check (by display name)
    # These are the cloud equivalents of AD privileged groups
    $PrivilegedRoles = @(
        "Global Administrator",
        "Privileged Role Administrator",
        "Privileged Authentication Administrator",
        "Security Administrator",
        "User Administrator",
        "Exchange Administrator",
        "SharePoint Administrator",
        "Application Administrator",
        "Cloud Application Administrator",
        "Authentication Administrator",
        "Helpdesk Administrator",
        "Password Administrator",
        "Groups Administrator"
    )
    
    try {
        # Get all activated directory roles
        $directoryRoles = Invoke-GraphRequest -Uri "https://graph.microsoft.com/v1.0/directoryRoles" -AllPages
        
        foreach ($role in $directoryRoles) {
            # Only check our target privileged roles
            if ($PrivilegedRoles -contains $role.displayName) {
                
                # Get members of this role
                $members = Invoke-GraphRequest -Uri "https://graph.microsoft.com/v1.0/directoryRoles/$($role.id)/members" -AllPages
                
                if ($members.Count -eq 0) {
                    Add-Finding -Status "INFO" `
                        -Object $role.displayName `
                        -Description "Role '$($role.displayName)' has no members assigned." `
                        -Remediation "No action needed unless this role should have members."
                    continue
                }
                
                $memberInfo = @()
                
                foreach ($member in $members) {
                    $memberType = $member.'@odata.type' -replace '#microsoft.graph.', ''
                    
                    switch ($memberType) {
                        "user" {
                            # Check for disabled users
                            if ($member.accountEnabled -eq $false) {
                                Add-Finding -Status "WARNING" `
                                    -Object "$($member.userPrincipalName) ($($role.displayName))" `
                                    -Description "Disabled user '$($member.displayName)' is a member of privileged role '$($role.displayName)'." `
                                    -Remediation "Remove this disabled account from the role immediately."
                            }
                            
                            # Check for guest users
                            if ($member.userType -eq "Guest") {
                                Add-Finding -Status "FAIL" `
                                    -Object "$($member.userPrincipalName) ($($role.displayName))" `
                                    -Description "Guest user '$($member.displayName)' has privileged role '$($role.displayName)'. External users with admin roles represent significant risk." `
                                    -Remediation "Remove guest users from privileged roles. If external admin access is required, use B2B with strict conditional access and regular access reviews."
                            }
                            
                            $enabled = if ($member.accountEnabled) { "Enabled" } else { "DISABLED" }
                            $userType = if ($member.userType) { $member.userType } else { "Member" }
                            $memberInfo += "$($member.userPrincipalName) [User, $enabled, $userType]"

                            # PR 5: per-member INFO finding enables hybrid cross-surface correlation.
                            # The correlators (Find-DAExposureToCloudAdmin, etc.) scan for findings with
                            # this shape to link on-prem AD exposure to cloud privilege.
                            if ($member.accountEnabled -ne $false -and $member.userType -ne "Guest" -and $member.userPrincipalName) {
                                Add-Finding -Status "INFO" `
                                    -Object "$($member.userPrincipalName) ($($role.displayName))" `
                                    -Description "PrivilegedRoleMember: '$($member.userPrincipalName)' holds cloud role '$($role.displayName)'. Inventory marker for hybrid correlation — see the role summary finding for full context." `
                                    -Remediation "No action required — this informational finding exists to support hybrid cross-surface correlation against on-prem AD findings."
                            }
                        }
                        "servicePrincipal" {
                            Add-Finding -Status "REVIEW" `
                                -Object "$($member.displayName) ($($role.displayName))" `
                                -Description "Service principal '$($member.displayName)' has privileged directory role '$($role.displayName)'. Applications with admin roles should be carefully reviewed." `
                                -Remediation "Review if this service principal truly requires this role. Consider using more granular app permissions instead of directory roles."
                            
                            $memberInfo += "$($member.displayName) [ServicePrincipal, AppId: $($member.appId)]"
                        }
                        "group" {
                            $memberInfo += "$($member.displayName) [Group - role-assignable]"
                        }
                        default {
                            $memberInfo += "$($member.displayName) [$memberType]"
                        }
                    }
                }
                
                # Summary finding for the role
                $summary = $memberInfo -join "; "
                Add-Finding -Status "INFO" `
                    -Object $role.displayName `
                    -Description "Members ($($members.Count)): $summary" `
                    -Remediation "Review for expected membership and privilege creep. Ensure all members have business justification."
            }
        }
    }
    catch {
        Add-Finding -Status "WARNING" `
            -Object "Directory Roles" `
            -Description "Unable to enumerate directory roles: $($_.Exception.Message)" `
            -Remediation "Check Graph permissions (Directory.Read.All, RoleManagement.Read.Directory required)."
    }
}

<#
.SYNOPSIS
    Test-PrivilegedRoleCreep - Flags unexpected members in privileged roles.

.DESCRIPTION
    Equivalent to: Check-PrivilegedGroupCreep (AD version)
    
    Compares actual privileged role members against a configurable allowlist.
    Flags any members not on the expected list as potential privilege creep
    or unauthorized elevation.
    
    Customize the $RoleAllowlists hashtable for each client environment.
    
    Graph Endpoints Used:
    - GET /directoryRoles
    - GET /directoryRoles/{id}/members
    
.OUTPUTS
    Findings with Status: WARNING for non-allowlisted members, OK if clean
    
.NOTES
    Required Permissions: Directory.Read.All, RoleManagement.Read.Directory
    Minimum License: Azure AD Free
    
.LINK
    AD Equivalent: Check-PrivilegedGroupCreep
    Graph Reference: https://learn.microsoft.com/en-us/graph/api/directoryrole-list-members
#>
function Test-PrivilegedRoleCreep {
    Write-Host "`n[+] Checking for non-standard members in privileged roles (privilege creep)..." -ForegroundColor Cyan
    
    # Define allowlisted/expected members for each role
    # Key: role display name, Value: array of UPNs or display names (case-insensitive)
    # CUSTOMIZE THIS FOR EACH CLIENT
    $RoleAllowlists = @{
        "Global Administrator" = @(
            # Add expected Global Admins here
            # Example: "admin@contoso.com", "breakglass@contoso.com"
        )
        "Privileged Role Administrator" = @()
        "Privileged Authentication Administrator" = @()
        "Security Administrator" = @()
        "User Administrator" = @()
    }
    
    # Roles to check
    $RolesToCheck = $RoleAllowlists.Keys
    
    try {
        # Get all activated directory roles
        $directoryRoles = Invoke-GraphRequest -Uri "https://graph.microsoft.com/v1.0/directoryRoles" -AllPages
        
        $creepFound = $false
        
        foreach ($role in $directoryRoles) {
            if ($RolesToCheck -contains $role.displayName) {
                
                $allowlist = $RoleAllowlists[$role.displayName]
                
                # Get members
                $members = Invoke-GraphRequest -Uri "https://graph.microsoft.com/v1.0/directoryRoles/$($role.id)/members" -AllPages
                
                foreach ($member in $members) {
                    $memberIdentifier = if ($member.userPrincipalName) { 
                        $member.userPrincipalName 
                    } else { 
                        $member.displayName 
                    }
                    
                    # Check if member is in allowlist (case-insensitive)
                    $isAllowed = $false
                    foreach ($allowed in $allowlist) {
                        if ($memberIdentifier -ieq $allowed -or $member.displayName -ieq $allowed) {
                            $isAllowed = $true
                            break
                        }
                    }
                    
                    if (-not $isAllowed) {
                        $creepFound = $true
                        
                        # Determine severity based on role
                        $status = if ($role.displayName -eq "Global Administrator") { "FAIL" } else { "WARNING" }
                        
                        Add-Finding -Status $status `
                            -Object "$memberIdentifier ($($role.displayName))" `
                            -Description "Member '$memberIdentifier' has privileged role '$($role.displayName)' but is NOT on the approved allowlist. Possible privilege creep or unauthorized elevation." `
                            -Remediation "Review this role assignment. If not authorized, remove immediately. If authorized, add to the allowlist in the script configuration."
                    }
                }
            }
        }
        
        if (-not $creepFound) {
            Add-Finding -Status "OK" `
                -Object "Privileged Roles" `
                -Description "No non-allowlisted members detected in privileged roles (or allowlists are empty - configure for your environment)." `
                -Remediation "No action needed. Note: Configure `$RoleAllowlists in the script for meaningful detection."
        }
    }
    catch {
        Add-Finding -Status "WARNING" `
            -Object "Privileged Role Creep" `
            -Description "Unable to check privileged role membership: $($_.Exception.Message)" `
            -Remediation "Check Graph permissions (Directory.Read.All, RoleManagement.Read.Directory required)."
    }
}

<#
.SYNOPSIS
    Test-RecentPrivilegedAccounts - Finds recently created accounts with privileged roles.

.DESCRIPTION
    Equivalent to: Test-RecentPrivilegedAccounts (AD version)
    
    Scans privileged roles for user accounts created within the last N days
    (controlled by $RecentDays parameter). This helps identify potential
    persistence or "stealth admin" attacks.
    
    Graph Endpoints Used:
    - GET /directoryRoles
    - GET /directoryRoles/{id}/members
    - GET /users/{id} (for createdDateTime)
    
.OUTPUTS
    Findings with Status: FAIL for recent privileged accounts, OK if none found
    
.NOTES
    Required Permissions: Directory.Read.All, RoleManagement.Read.Directory, User.Read.All
    Minimum License: Azure AD Free
    
.LINK
    AD Equivalent: Test-RecentPrivilegedAccounts
    Graph Reference: https://learn.microsoft.com/en-us/graph/api/user-get
#>
function Test-RecentPrivilegedAccounts {
    Write-Host "`n[+] Checking for recently created privileged accounts (last $RecentDays days)..." -ForegroundColor Cyan
    
    $thresholdDate = (Get-Date).AddDays(-$RecentDays)
    
    # Roles to check
    $PrivilegedRoles = @(
        "Global Administrator",
        "Privileged Role Administrator",
        "Privileged Authentication Administrator",
        "Security Administrator",
        "User Administrator",
        "Exchange Administrator",
        "SharePoint Administrator",
        "Application Administrator",
        "Cloud Application Administrator"
    )
    
    try {
        # Get all activated directory roles
        $directoryRoles = Invoke-GraphRequest -Uri "https://graph.microsoft.com/v1.0/directoryRoles" -AllPages
        
        $recentFound = $false
        $checkedUsers = @{}  # Avoid checking same user multiple times
        
        foreach ($role in $directoryRoles) {
            if ($PrivilegedRoles -contains $role.displayName) {
                
                # Get members
                $members = Invoke-GraphRequest -Uri "https://graph.microsoft.com/v1.0/directoryRoles/$($role.id)/members" -AllPages
                
                foreach ($member in $members) {
                    # Only check users
                    if ($member.'@odata.type' -ne '#microsoft.graph.user') { continue }
                    
                    # Skip if already checked
                    if ($checkedUsers.ContainsKey($member.id)) { continue }
                    $checkedUsers[$member.id] = $true
                    
                    # Get full user details including createdDateTime
                    $user = Invoke-GraphRequest -Uri "https://graph.microsoft.com/v1.0/users/$($member.id)?`$select=id,displayName,userPrincipalName,createdDateTime,accountEnabled"
                    
                    if ($user.createdDateTime) {
                        $createdDate = [DateTime]$user.createdDateTime
                        
                        if ($user.accountEnabled -and $createdDate -gt $thresholdDate) {
                            $recentFound = $true
                            $daysAgo = [math]::Round(((Get-Date) - $createdDate).TotalDays, 0)
                            
                            Add-Finding -Status "FAIL" `
                                -Object "$($user.userPrincipalName) ($($role.displayName))" `
                                -Description "Privileged user '$($user.userPrincipalName)' was created $daysAgo days ago (created: $($user.createdDateTime)) and has role '$($role.displayName)'." `
                                -Remediation "Verify this account creation was authorized. If not expected, investigate immediately for possible persistence or privilege escalation attack."
                        }
                    }
                }
            }
        }
        
        if (-not $recentFound) {
            Add-Finding -Status "OK" `
                -Object "Privileged Accounts" `
                -Description "No privileged accounts created in the last $RecentDays days." `
                -Remediation "No action needed."
        }
    }
    catch {
        Add-Finding -Status "WARNING" `
            -Object "Recent Privileged Accounts" `
            -Description "Unable to check for recent privileged accounts: $($_.Exception.Message)" `
            -Remediation "Check Graph permissions (Directory.Read.All, RoleManagement.Read.Directory, User.Read.All required)."
    }
}

#endregion

#region ==================== PHASE 2: USER & IDENTITY CHECKS ====================

<#
.SYNOPSIS
    Test-UserAccountsAndInactivity - Finds stale user accounts and passwords.

.DESCRIPTION
    Equivalent to: Test-UserAccountsAndInactivity (AD version)
    
    Enumerates all enabled user accounts and flags:
    - Accounts that have not signed in within $UserInactivityDays
    - Accounts whose password hasn't changed in $PasswordAgeDays
    
    Uses signInActivity (requires P1 license) with fallback to createdDateTime.
    
    Graph Endpoints Used:
    - GET /users (with signInActivity via beta endpoint)
    
.OUTPUTS
    Findings with Status: WARNING for stale accounts, INFO for summary
    
.NOTES
    Required Permissions: User.Read.All, AuditLog.Read.All
    Minimum License: Azure AD Free (limited), P1 for signInActivity
    
.LINK
    AD Equivalent: Test-UserAccountsAndInactivity
    Graph Reference: https://learn.microsoft.com/en-us/graph/api/user-list
#>
function Test-UserAccountsAndInactivity {
    Write-Host "`n[+] Checking user accounts for inactivity and password age..." -ForegroundColor Cyan
    
    $inactiveDays = $UserInactivityDays
    $passwordDays = $PasswordAgeDays
    $now = Get-Date
    $inactiveThreshold = $now.AddDays(-$inactiveDays)
    $passwordThreshold = $now.AddDays(-$passwordDays)
    
    try {
        # Try beta endpoint first for signInActivity (requires P1)
        $useSignInActivity = $script:TenantCapabilities.HasSignInLogs
        
        if ($useSignInActivity) {
            Write-Host "    Using signInActivity data (P1 feature)..." -ForegroundColor Gray
            $users = Invoke-GraphRequest -Uri "https://graph.microsoft.com/beta/users?`$select=id,displayName,userPrincipalName,accountEnabled,userType,createdDateTime,signInActivity,lastPasswordChangeDateTime&`$filter=accountEnabled eq true&`$top=999" -AllPages
        }
        else {
            Write-Host "    signInActivity not available, using limited data..." -ForegroundColor Yellow
            $users = Invoke-GraphRequest -Uri "https://graph.microsoft.com/v1.0/users?`$select=id,displayName,userPrincipalName,accountEnabled,userType,createdDateTime&`$filter=accountEnabled eq true&`$top=999" -AllPages
        }
        
        $inactiveCount = 0
        $stalePwdCount = 0
        $totalUsers = 0
        
        foreach ($user in $users) {
            # Skip guest users (they're handled separately)
            if ($user.userType -eq "Guest") { continue }
            
            $totalUsers++
            
            # Check for inactivity
            if ($useSignInActivity -and $user.signInActivity) {
                $lastSignIn = $null
                
                # Check both interactive and non-interactive sign-ins
                if ($user.signInActivity.lastSignInDateTime) {
                    $lastSignIn = [DateTime]$user.signInActivity.lastSignInDateTime
                }
                elseif ($user.signInActivity.lastNonInteractiveSignInDateTime) {
                    $lastSignIn = [DateTime]$user.signInActivity.lastNonInteractiveSignInDateTime
                }
                
                if ($lastSignIn -and $lastSignIn -lt $inactiveThreshold) {
                    $inactiveCount++
                    $daysSinceSignIn = [math]::Round(($now - $lastSignIn).TotalDays, 0)
                    
                    Add-Finding -Status "REVIEW" `
                        -Object $user.userPrincipalName `
                        -Description "User account inactive for $daysSinceSignIn days (last sign-in: $($lastSignIn.ToString('yyyy-MM-dd'))). Threshold: $inactiveDays days." `
                        -Remediation "Review this account. Consider disabling if no longer needed, or verify the user still requires access."
                }
                elseif (-not $lastSignIn) {
                    # User has never signed in
                    $createdDate = if ($user.createdDateTime) { [DateTime]$user.createdDateTime } else { $null }
                    if ($createdDate -and $createdDate -lt $inactiveThreshold) {
                        $inactiveCount++
                        $daysSinceCreated = [math]::Round(($now - $createdDate).TotalDays, 0)
                        
                        Add-Finding -Status "REVIEW" `
                            -Object $user.userPrincipalName `
                            -Description "User account created $daysSinceCreated days ago but has NEVER signed in." `
                            -Remediation "Investigate why this account exists but has never been used. Consider disabling or removing."
                    }
                }
            }
            
            # Check for stale password
            if ($user.lastPasswordChangeDateTime) {
                $lastPwdChange = [DateTime]$user.lastPasswordChangeDateTime
                
                if ($lastPwdChange -lt $passwordThreshold) {
                    $stalePwdCount++
                    $daysSincePwdChange = [math]::Round(($now - $lastPwdChange).TotalDays, 0)
                    
                    Add-Finding -Status "WARNING" `
                        -Object $user.userPrincipalName `
                        -Description "User password not changed in $daysSincePwdChange days (last changed: $($lastPwdChange.ToString('yyyy-MM-dd'))). Threshold: $passwordDays days." `
                        -Remediation "Require password change or review if this account is still actively needed."
                }
            }
        }
        
        # Summary finding
        $summaryMsg = "Checked $totalUsers enabled member users."
        if ($useSignInActivity) {
            $summaryMsg += " Found $inactiveCount inactive (>$inactiveDays days), $stalePwdCount with stale passwords (>$passwordDays days)."
        }
        else {
            $summaryMsg += " Note: Sign-in activity data not available (requires P1 license). Stale password check: $stalePwdCount found."
        }
        
        Add-Finding -Status "INFO" `
            -Object "User Accounts Summary" `
            -Description $summaryMsg `
            -Remediation "Review flagged accounts above. Consider implementing automated lifecycle management."
    }
    catch {
        Add-Finding -Status "WARNING" `
            -Object "User Accounts" `
            -Description "Unable to enumerate user accounts: $($_.Exception.Message)" `
            -Remediation "Check permissions (User.Read.All, AuditLog.Read.All required)."
    }
}

<#
.SYNOPSIS
    Test-GuestUsers - Inventories and analyzes external/guest users.

.DESCRIPTION
    Equivalent to: Check-NestedGroupTrusts (AD version - cross-domain members)
    
    Enumerates all guest users in the tenant and flags:
    - Total guest count (for awareness)
    - Guests with privileged role assignments
    - Stale guests (not signed in recently)
    - Guests from specific external domains
    
    Graph Endpoints Used:
    - GET /users?$filter=userType eq 'Guest'
    - GET /directoryRoles/{id}/members
    
.OUTPUTS
    Findings with Status: INFO for inventory, WARNING/FAIL for issues
    
.NOTES
    Required Permissions: User.Read.All, Directory.Read.All
    Minimum License: Azure AD Free
    
.LINK
    AD Equivalent: Check-NestedGroupTrusts (ForeignSecurityPrincipal detection)
    Graph Reference: https://learn.microsoft.com/en-us/graph/api/user-list
#>
function Test-GuestUsers {
    Write-Host "`n[+] Checking guest (external) users..." -ForegroundColor Cyan
    
    try {
        # Get all guest users
        $guests = Invoke-GraphRequest -Uri "https://graph.microsoft.com/v1.0/users?`$filter=userType eq 'Guest'&`$select=id,displayName,userPrincipalName,mail,createdDateTime,accountEnabled,externalUserState&`$top=999" -AllPages
        
        if (-not $guests -or $guests.Count -eq 0) {
            Add-Finding -Status "OK" `
                -Object "Guest Users" `
                -Description "No guest (external) users found in the tenant." `
                -Remediation "No action needed."
            return
        }
        
        # Count by state
        $totalGuests = $guests.Count
        $enabledGuests = ($guests | Where-Object { $_.accountEnabled -eq $true }).Count
        $pendingGuests = ($guests | Where-Object { $_.externalUserState -eq "PendingAcceptance" }).Count
        
        # Group by domain
        $domainCounts = @{}
        foreach ($guest in $guests) {
            $email = if ($guest.mail) { $guest.mail } else { $guest.userPrincipalName }
            if ($email -match "@(.+)$") {
                $domain = $matches[1].ToLower()
                if (-not $domainCounts.ContainsKey($domain)) {
                    $domainCounts[$domain] = 0
                }
                $domainCounts[$domain]++
            }
        }
        
        # Summary finding
        $topDomains = ($domainCounts.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 5 | ForEach-Object { "$($_.Key): $($_.Value)" }) -join ", "
        
        Add-Finding -Status "INFO" `
            -Object "Guest Users Summary" `
            -Description "Total guest users: $totalGuests (Enabled: $enabledGuests, Pending: $pendingGuests). Top domains: $topDomains" `
            -Remediation "Review guest access regularly. Implement access reviews for external users."
        
        # Check for pending invitations older than 30 days
        $now = Get-Date
        $pendingThreshold = $now.AddDays(-30)
        
        foreach ($guest in $guests) {
            if ($guest.externalUserState -eq "PendingAcceptance" -and $guest.createdDateTime) {
                $createdDate = [DateTime]$guest.createdDateTime
                if ($createdDate -lt $pendingThreshold) {
                    $daysOld = [math]::Round(($now - $createdDate).TotalDays, 0)
                    Add-Finding -Status "WARNING" `
                        -Object $guest.userPrincipalName `
                        -Description "Guest invitation pending for $daysOld days (invited: $($createdDate.ToString('yyyy-MM-dd'))). User has never accepted." `
                        -Remediation "Resend invitation or remove this guest if no longer needed."
                }
            }
        }
        
        # Check if any guests have privileged roles (cross-reference with directory roles)
        $privilegedRoles = @(
            "Global Administrator", "Privileged Role Administrator", "Security Administrator",
            "User Administrator", "Exchange Administrator", "SharePoint Administrator",
            "Application Administrator", "Cloud Application Administrator"
        )
        
        $directoryRoles = Invoke-GraphRequest -Uri "https://graph.microsoft.com/v1.0/directoryRoles" -AllPages
        $guestIds = $guests | ForEach-Object { $_.id }
        
        foreach ($role in $directoryRoles) {
            if ($privilegedRoles -contains $role.displayName) {
                $members = Invoke-GraphRequest -Uri "https://graph.microsoft.com/v1.0/directoryRoles/$($role.id)/members" -AllPages
                
                foreach ($member in $members) {
                    if ($guestIds -contains $member.id) {
                        Add-Finding -Status "FAIL" `
                            -Object "$($member.userPrincipalName) ($($role.displayName))" `
                            -Description "Guest user '$($member.displayName)' has privileged role '$($role.displayName)'. External users with admin rights represent significant security risk." `
                            -Remediation "Remove guest from privileged role immediately. If external admin is required, use dedicated B2B accounts with strict Conditional Access and regular access reviews."
                    }
                }
            }
        }
    }
    catch {
        Add-Finding -Status "WARNING" `
            -Object "Guest Users" `
            -Description "Unable to enumerate guest users: $($_.Exception.Message)" `
            -Remediation "Check Graph permissions (User.Read.All required)."
    }
}

<#
.SYNOPSIS
    Test-PasswordsInProfileFields - Searches for credentials in user profile fields.

.DESCRIPTION
    Equivalent to: Check-PasswordsInDescription (AD version)
    
    Scans user profile fields, group descriptions, and application descriptions
    for patterns that might indicate stored passwords or secrets.
    
    Fields Checked:
    - User: jobTitle, department, officeLocation, aboutMe, onPremisesExtensionAttributes
    - Groups: description
    - Applications: description, notes
    
    Graph Endpoints Used:
    - GET /users
    - GET /groups
    - GET /applications
    
.OUTPUTS
    Findings with Status: FAIL for potential secrets found, OK if clean
    
.NOTES
    Required Permissions: User.Read.All, Group.Read.All, Application.Read.All
    Minimum License: Azure AD Free
    
.LINK
    AD Equivalent: Check-PasswordsInDescription
    Graph Reference: https://learn.microsoft.com/en-us/graph/api/user-list
#>
function Test-PasswordsInProfileFields {
    Write-Host "`n[+] Checking for passwords/secrets in profile and description fields..." -ForegroundColor Cyan
    
    # Patterns that might indicate passwords or secrets
    $passwordPatterns = @(
        'password\s*[:=]\s*\S+',
        'pwd\s*[:=]\s*\S+',
        'pass\s*[:=]\s*\S+',
        'secret\s*[:=]\s*\S+',
        'key\s*[:=]\s*\S+',
        'token\s*[:=]\s*\S+',
        'credential\s*[:=]\s*\S+',
        'apikey\s*[:=]\s*\S+',
        'api[_-]?key\s*[:=]\s*\S+',
        'connectionstring\s*[:=]\s*\S+',
        'conn[_-]?str\s*[:=]\s*\S+'
    )
    
    $combinedPattern = $passwordPatterns -join '|'
    $foundSecrets = $false
    
    try {
        # Check users
        Write-Host "    Checking user profile fields..." -ForegroundColor Gray
        $users = Invoke-GraphRequest -Uri "https://graph.microsoft.com/v1.0/users?`$select=id,displayName,userPrincipalName,jobTitle,department,officeLocation,aboutMe&`$top=999" -AllPages
        
        foreach ($user in $users) {
            $fieldsToCheck = @(
                @{ Name = "jobTitle"; Value = $user.jobTitle },
                @{ Name = "department"; Value = $user.department },
                @{ Name = "officeLocation"; Value = $user.officeLocation },
                @{ Name = "aboutMe"; Value = $user.aboutMe }
            )
            
            foreach ($field in $fieldsToCheck) {
                if ($field.Value -and $field.Value -match $combinedPattern) {
                    $foundSecrets = $true
                    Add-Finding -Status "FAIL" `
                        -Object "$($user.userPrincipalName) ($($field.Name))" `
                        -Description "User '$($user.displayName)' has possible password/secret in $($field.Name) field: '$($field.Value)'" `
                        -Remediation "Immediately remove passwords or secrets from profile fields. Reset any exposed credentials. Educate users on secure credential handling."
                }
            }
        }
        
        # Check groups
        Write-Host "    Checking group descriptions..." -ForegroundColor Gray
        $groups = Invoke-GraphRequest -Uri "https://graph.microsoft.com/v1.0/groups?`$select=id,displayName,description&`$top=999" -AllPages
        
        foreach ($group in $groups) {
            if ($group.description -and $group.description -match $combinedPattern) {
                $foundSecrets = $true
                Add-Finding -Status "FAIL" `
                    -Object "Group: $($group.displayName)" `
                    -Description "Group '$($group.displayName)' has possible password/secret in description: '$($group.description)'" `
                    -Remediation "Immediately remove passwords or secrets from group descriptions. Reset any exposed credentials."
            }
        }
        
        # Check applications
        Write-Host "    Checking application descriptions..." -ForegroundColor Gray
        $apps = Invoke-GraphRequest -Uri "https://graph.microsoft.com/v1.0/applications?`$select=id,displayName,description,notes&`$top=999" -AllPages
        
        foreach ($app in $apps) {
            $fieldsToCheck = @(
                @{ Name = "description"; Value = $app.description },
                @{ Name = "notes"; Value = $app.notes }
            )
            
            foreach ($field in $fieldsToCheck) {
                if ($field.Value -and $field.Value -match $combinedPattern) {
                    $foundSecrets = $true
                    Add-Finding -Status "FAIL" `
                        -Object "Application: $($app.displayName) ($($field.Name))" `
                        -Description "Application '$($app.displayName)' has possible password/secret in $($field.Name): '$($field.Value)'" `
                        -Remediation "Immediately remove passwords or secrets from application metadata. Use Azure Key Vault for secret storage. Reset any exposed credentials."
                }
            }
        }
        
        if (-not $foundSecrets) {
            Add-Finding -Status "OK" `
                -Object "Profile Fields" `
                -Description "No passwords or secrets found in user profiles, group descriptions, or application metadata." `
                -Remediation "No action needed. Continue to educate users about secure credential handling."
        }
    }
    catch {
        Add-Finding -Status "WARNING" `
            -Object "Password in Fields Check" `
            -Description "Unable to complete password-in-fields check: $($_.Exception.Message)" `
            -Remediation "Check Graph permissions (User.Read.All, Group.Read.All, Application.Read.All required)."
    }
}

<#
.SYNOPSIS
    Test-ShadowGroups - Detects groups with names similar to privileged roles/groups.

.DESCRIPTION
    Equivalent to: Test-ShadowGroups (AD version)
    
    Scans all groups for names that might be typosquatting or mimicking
    legitimate privileged groups or Azure AD roles. Also checks for
    role-assignable groups with suspicious configurations.
    
    Graph Endpoints Used:
    - GET /groups
    
.OUTPUTS
    Findings with Status: WARNING/FAIL for suspicious groups, OK if clean
    
.NOTES
    Required Permissions: Group.Read.All
    Minimum License: Azure AD Free
    
.LINK
    AD Equivalent: Test-ShadowGroups
    Graph Reference: https://learn.microsoft.com/en-us/graph/api/group-list
#>
function Test-ShadowGroups {
    Write-Host "`n[+] Checking for shadow groups (lookalike privileged groups)..." -ForegroundColor Cyan
    
    # Patterns to catch typosquatting of privileged roles/groups
    $shadowPatterns = @(
        "Global Admin",
        "GlobalAdministrator",
        "Global_Administrator",
        "Globa1 Administrator",
        "G1obal Administrator",
        "Privileged Role Admin",
        "PrivilegedRoleAdministrator",
        "Security Admin",
        "SecurityAdministrator",
        "User Admin",
        "UserAdministrator",
        "Exchange Admin",
        "SharePoint Admin",
        "Application Admin",
        "Cloud Admin",
        "Tenant Admin",
        "Azure Admin",
        "Administrat0r",
        "Adm1n",
        "Admin_",
        "_Admin",
        "Root",
        "Superuser",
        "Super User"
    )
    
    # Legitimate role names to exclude
    $legitimateRoles = @(
        "Global Administrator",
        "Privileged Role Administrator",
        "Security Administrator",
        "User Administrator",
        "Exchange Administrator",
        "SharePoint Administrator",
        "Application Administrator",
        "Cloud Application Administrator",
        "Helpdesk Administrator",
        "Authentication Administrator"
    )
    
    try {
        $groups = Invoke-GraphRequest -Uri "https://graph.microsoft.com/v1.0/groups?`$select=id,displayName,description,groupTypes,securityEnabled,isAssignableToRole&`$top=999" -AllPages
        
        $shadowFound = $false
        
        foreach ($group in $groups) {
            # Skip if this matches a legitimate role name exactly
            if ($legitimateRoles -contains $group.displayName) { continue }
            
            # Check against shadow patterns
            foreach ($pattern in $shadowPatterns) {
                if ($group.displayName -like "*$pattern*") {
                    $shadowFound = $true
                    
                    $severity = if ($group.isAssignableToRole) { "FAIL" } else { "WARNING" }
                    $roleAssignable = if ($group.isAssignableToRole) { " [ROLE-ASSIGNABLE]" } else { "" }
                    
                    Add-Finding -Status $severity `
                        -Object "$($group.displayName)$roleAssignable" `
                        -Description "Suspicious group name detected: '$($group.displayName)' matches shadow pattern '$pattern'. This could be an attempt to create a lookalike privileged group." `
                        -Remediation "Investigate this group. If not legitimate, remove it. If legitimate, consider renaming to avoid confusion with privileged roles."
                    break
                }
            }
        }
        
        # Also check for role-assignable groups that might be suspicious
        $roleAssignableGroups = $groups | Where-Object { $_.isAssignableToRole -eq $true }
        
        if ($roleAssignableGroups.Count -gt 0) {
            Add-Finding -Status "INFO" `
                -Object "Role-Assignable Groups" `
                -Description "Found $($roleAssignableGroups.Count) role-assignable groups: $(($roleAssignableGroups | ForEach-Object { $_.displayName }) -join ', ')" `
                -Remediation "Role-assignable groups can be assigned to Azure AD roles. Review these groups carefully and ensure their membership is strictly controlled."
        }
        
        if (-not $shadowFound) {
            Add-Finding -Status "OK" `
                -Object "Groups" `
                -Description "No suspicious shadow/lookalike admin groups detected." `
                -Remediation "No action needed."
        }
    }
    catch {
        Add-Finding -Status "WARNING" `
            -Object "Shadow Groups" `
            -Description "Unable to check for shadow groups: $($_.Exception.Message)" `
            -Remediation "Check Graph permissions (Group.Read.All required)."
    }
}

<#
.SYNOPSIS
    Test-RoleAssignableGroupOwnership - Audits owners of role-assignable groups.

.DESCRIPTION
    Equivalent to: Check-AdminSDHolderDrift (AD version - privilege persistence)
    
    Role-assignable groups can be assigned to Azure AD directory roles.
    Whoever owns these groups can add members, effectively granting themselves
    privileged access. This check identifies:
    - All role-assignable groups and their owners
    - Non-privileged users who own role-assignable groups
    - Service principals as owners (potential persistence mechanism)
    
    Graph Endpoints Used:
    - GET /groups?$filter=isAssignableToRole eq true
    - GET /groups/{id}/owners
    - GET /groups/{id}/members
    
.OUTPUTS
    Findings with Status: FAIL for risky ownership, INFO for inventory
    
.NOTES
    Required Permissions: Group.Read.All, Directory.Read.All
    Minimum License: Azure AD P1 (role-assignable groups require P1)
    
.LINK
    AD Equivalent: Check-AdminSDHolderDrift, Check-SensitiveObjectACLDrift
    Graph Reference: https://learn.microsoft.com/en-us/graph/api/group-list-owners
#>
function Test-RoleAssignableGroupOwnership {
    Write-Host "`n[+] Checking role-assignable group ownership (privilege escalation paths)..." -ForegroundColor Cyan
    
    try {
        # Get all role-assignable groups
        $roleAssignableGroups = Invoke-GraphRequest -Uri "https://graph.microsoft.com/v1.0/groups?`$filter=isAssignableToRole eq true&`$select=id,displayName,description&`$top=999" -AllPages
        
        if (-not $roleAssignableGroups -or $roleAssignableGroups.Count -eq 0) {
            Add-Finding -Status "INFO" `
                -Object "Role-Assignable Groups" `
                -Description "No role-assignable groups found in the tenant." `
                -Remediation "No action needed. Role-assignable groups require Azure AD P1 license."
            return
        }
        
        # Get privileged users for comparison (Global Admins, Privileged Role Admins)
        $privilegedUserIds = @()
        $privilegedRoles = @("Global Administrator", "Privileged Role Administrator")
        
        $directoryRoles = Invoke-GraphRequest -Uri "https://graph.microsoft.com/v1.0/directoryRoles" -AllPages
        foreach ($role in $directoryRoles) {
            if ($privilegedRoles -contains $role.displayName) {
                $members = Invoke-GraphRequest -Uri "https://graph.microsoft.com/v1.0/directoryRoles/$($role.id)/members" -AllPages
                foreach ($member in $members) {
                    if ($member.'@odata.type' -eq '#microsoft.graph.user') {
                        $privilegedUserIds += $member.id
                    }
                }
            }
        }
        
        foreach ($group in $roleAssignableGroups) {
            # Get owners
            $owners = Invoke-GraphRequest -Uri "https://graph.microsoft.com/v1.0/groups/$($group.id)/owners" -AllPages
            
            # Get members for context
            $members = Invoke-GraphRequest -Uri "https://graph.microsoft.com/v1.0/groups/$($group.id)/members" -AllPages
            
            if (-not $owners -or $owners.Count -eq 0) {
                Add-Finding -Status "WARNING" `
                    -Object "Group: $($group.displayName)" `
                    -Description "Role-assignable group '$($group.displayName)' has NO owners. This may indicate orphaned privileged access." `
                    -Remediation "Assign appropriate owners to this group or consider removing it if unused."
                continue
            }
            
            $ownerList = @()
            
            foreach ($owner in $owners) {
                $ownerType = $owner.'@odata.type' -replace '#microsoft.graph.', ''
                $ownerName = if ($owner.userPrincipalName) { $owner.userPrincipalName } else { $owner.displayName }
                
                switch ($ownerType) {
                    "user" {
                        # Check if owner is a privileged user
                        if ($privilegedUserIds -notcontains $owner.id) {
                            Add-Finding -Status "FAIL" `
                                -Object "$ownerName (Owner of $($group.displayName))" `
                                -Description "Non-privileged user '$ownerName' is an owner of role-assignable group '$($group.displayName)'. This user can add members to this group, potentially granting themselves privileged access." `
                                -Remediation "Remove non-privileged users as owners of role-assignable groups. Only Global Administrators or Privileged Role Administrators should own these groups."
                        }
                        $ownerList += "$ownerName [User]"
                    }
                    "servicePrincipal" {
                        Add-Finding -Status "REVIEW" `
                            -Object "$($owner.displayName) (Owner of $($group.displayName))" `
                            -Description "Service principal '$($owner.displayName)' is an owner of role-assignable group '$($group.displayName)'. This could be a persistence mechanism." `
                            -Remediation "Review if this service principal should own a role-assignable group. Remove if not explicitly required."
                        $ownerList += "$($owner.displayName) [ServicePrincipal]"
                    }
                    default {
                        $ownerList += "$ownerName [$ownerType]"
                    }
                }
            }
            
            # Info finding for the group
            $memberCount = if ($members) { $members.Count } else { 0 }
            Add-Finding -Status "INFO" `
                -Object "Group: $($group.displayName)" `
                -Description "Role-assignable group with $memberCount members. Owners: $($ownerList -join ', ')" `
                -Remediation "Ensure ownership is restricted to appropriate administrators."
        }
    }
    catch {
        Add-Finding -Status "WARNING" `
            -Object "Role-Assignable Groups" `
            -Description "Unable to check role-assignable group ownership: $($_.Exception.Message)" `
            -Remediation "Check Graph permissions (Group.Read.All, Directory.Read.All required)."
    }
}

#endregion

#region ==================== PHASE 3: APPLICATION & SERVICE PRINCIPAL CHECKS ====================

<#
.SYNOPSIS
    Test-ApplicationCredentials - Audits application credential hygiene.

.DESCRIPTION
    Equivalent to: Check-ServiceAccounts, Check-UserSPNs (AD version - credential analysis)
    
    Examines all application registrations for credential-related security issues:
    - Applications using password (secret) credentials vs certificates
    - Credentials expiring soon or already expired
    - Long-lived credentials (>2 years)
    - Applications with multiple credentials (rotation concerns)
    - Applications with no credentials (unused?)
    
    Graph Endpoints Used:
    - GET /applications
    
.OUTPUTS
    Findings with Status: WARNING/FAIL for credential issues, INFO for inventory
    
.NOTES
    Required Permissions: Application.Read.All
    Minimum License: Azure AD Free
    
.LINK
    AD Equivalent: Check-ServiceAccounts, Check-UserSPNs
    Graph Reference: https://learn.microsoft.com/en-us/graph/api/application-list
#>
function Test-ApplicationCredentials {
    Write-Host "`n[+] Checking application credential hygiene..." -ForegroundColor Cyan
    
    $now = Get-Date
    $expiringThreshold = $now.AddDays(30)  # Credentials expiring within 30 days
    $longLivedThreshold = $now.AddYears(2) # Credentials valid for more than 2 years
    
    try {
        # Get all applications with credential info
        $apps = Invoke-GraphRequest -Uri "https://graph.microsoft.com/v1.0/applications?`$select=id,appId,displayName,passwordCredentials,keyCredentials,createdDateTime&`$top=999" -AllPages
        
        if (-not $apps -or $apps.Count -eq 0) {
            Add-Finding -Status "INFO" `
                -Object "Applications" `
                -Description "No application registrations found in the tenant." `
                -Remediation "No action needed."
            return
        }
        
        $totalApps = $apps.Count
        $appsWithPasswords = 0
        $appsWithCerts = 0
        $appsWithBoth = 0
        $appsWithNone = 0
        $expiredCreds = 0
        $expiringSoonCreds = 0
        $longLivedCreds = 0
        
        foreach ($app in $apps) {
            $hasPassword = $app.passwordCredentials -and $app.passwordCredentials.Count -gt 0
            $hasCert = $app.keyCredentials -and $app.keyCredentials.Count -gt 0
            
            # Categorize apps by credential type
            if ($hasPassword -and $hasCert) {
                $appsWithBoth++
            }
            elseif ($hasPassword) {
                $appsWithPasswords++
            }
            elseif ($hasCert) {
                $appsWithCerts++
            }
            else {
                $appsWithNone++
            }
            
            # Check password credentials
            if ($hasPassword) {
                foreach ($cred in $app.passwordCredentials) {
                    $endDate = if ($cred.endDateTime) { [DateTime]$cred.endDateTime } else { $null }
                    $credName = if ($cred.displayName) { $cred.displayName } else { "Unnamed" }
                    
                    if ($endDate) {
                        # Check for expired
                        if ($endDate -lt $now) {
                            $expiredCreds++
                            Add-Finding -Status "WARNING" `
                                -Object "$($app.displayName) (Secret: $credName)" `
                                -Description "Application '$($app.displayName)' has EXPIRED password credential '$credName' (expired: $($endDate.ToString('yyyy-MM-dd'))). Expired credentials should be removed." `
                                -Remediation "Remove the expired credential from this application registration."
                        }
                        # Check for expiring soon
                        elseif ($endDate -lt $expiringThreshold) {
                            $expiringSoonCreds++
                            $daysUntilExpiry = [math]::Round(($endDate - $now).TotalDays, 0)
                            Add-Finding -Status "WARNING" `
                                -Object "$($app.displayName) (Secret: $credName)" `
                                -Description "Application '$($app.displayName)' has password credential '$credName' expiring in $daysUntilExpiry days ($($endDate.ToString('yyyy-MM-dd')))." `
                                -Remediation "Rotate this credential before expiration to prevent service disruption."
                        }
                        # Check for long-lived
                        elseif ($endDate -gt $longLivedThreshold) {
                            $longLivedCreds++
                            $yearsValid = [math]::Round(($endDate - $now).TotalDays / 365, 1)
                            Add-Finding -Status "REVIEW" `
                                -Object "$($app.displayName) (Secret: $credName)" `
                                -Description "Application '$($app.displayName)' has long-lived password credential '$credName' valid for $yearsValid more years (expires: $($endDate.ToString('yyyy-MM-dd'))). Long-lived secrets increase risk." `
                                -Remediation "Consider shorter credential lifetimes (1 year max recommended) or migrate to certificate-based authentication."
                        }
                    }
                }
                
                # Multiple password credentials warning
                if ($app.passwordCredentials.Count -gt 2) {
                    Add-Finding -Status "REVIEW" `
                        -Object "$($app.displayName)" `
                        -Description "Application '$($app.displayName)' has $($app.passwordCredentials.Count) password credentials. Multiple credentials may indicate poor rotation practices." `
                        -Remediation "Review credential usage and remove unused credentials. Implement proper credential rotation."
                }
            }
            
            # Check certificate credentials
            if ($hasCert) {
                foreach ($cred in $app.keyCredentials) {
                    $endDate = if ($cred.endDateTime) { [DateTime]$cred.endDateTime } else { $null }
                    $credName = if ($cred.displayName) { $cred.displayName } else { "Unnamed" }
                    
                    if ($endDate) {
                        # Check for expired certificates
                        if ($endDate -lt $now) {
                            $expiredCreds++
                            Add-Finding -Status "WARNING" `
                                -Object "$($app.displayName) (Cert: $credName)" `
                                -Description "Application '$($app.displayName)' has EXPIRED certificate '$credName' (expired: $($endDate.ToString('yyyy-MM-dd')))." `
                                -Remediation "Remove the expired certificate and upload a new one if still needed."
                        }
                        # Check for expiring soon
                        elseif ($endDate -lt $expiringThreshold) {
                            $expiringSoonCreds++
                            $daysUntilExpiry = [math]::Round(($endDate - $now).TotalDays, 0)
                            Add-Finding -Status "WARNING" `
                                -Object "$($app.displayName) (Cert: $credName)" `
                                -Description "Application '$($app.displayName)' has certificate '$credName' expiring in $daysUntilExpiry days ($($endDate.ToString('yyyy-MM-dd')))." `
                                -Remediation "Renew and upload new certificate before expiration."
                        }
                    }
                }
            }
        }
        
        # Summary finding
        Add-Finding -Status "INFO" `
            -Object "Application Credentials Summary" `
            -Description "Total apps: $totalApps. With secrets only: $appsWithPasswords. With certs only: $appsWithCerts. With both: $appsWithBoth. No credentials: $appsWithNone. Expired: $expiredCreds. Expiring soon: $expiringSoonCreds. Long-lived: $longLivedCreds." `
            -Remediation "Prefer certificate authentication over secrets. Implement credential rotation policies. Remove expired credentials."
        
        # Flag if too many apps use passwords vs certificates
        if ($appsWithPasswords -gt $appsWithCerts -and $appsWithPasswords -gt 5) {
            Add-Finding -Status "INFO" `
                -Object "Credential Type Distribution" `
                -Description "More applications use password credentials ($appsWithPasswords) than certificates ($appsWithCerts). Certificates are more secure than secrets." `
                -Remediation "Consider migrating applications from password credentials to certificate-based authentication where possible."
        }
    }
    catch {
        Add-Finding -Status "WARNING" `
            -Object "Application Credentials" `
            -Description "Unable to check application credentials: $($_.Exception.Message)" `
            -Remediation "Check Graph permissions (Application.Read.All required)."
    }
}

<#
.SYNOPSIS
    Test-ServicePrincipalPermissions - Identifies overprivileged service principals.

.DESCRIPTION
    Equivalent to: Check-UnconstrainedDelegation (AD version - broad access)
    
    Examines service principals for dangerous permission configurations:
    - Service principals with directory role assignments
    - Applications with high-risk Graph API permissions
    - First-party vs third-party app classification
    
    Graph Endpoints Used:
    - GET /servicePrincipals
    - GET /servicePrincipals/{id}/appRoleAssignments
    
.OUTPUTS
    Findings with Status: FAIL for dangerous permissions, WARNING for elevated access
    
.NOTES
    Required Permissions: Application.Read.All, Directory.Read.All
    Minimum License: Azure AD Free
    
.LINK
    AD Equivalent: Check-UnconstrainedDelegation
    Graph Reference: https://learn.microsoft.com/en-us/graph/api/serviceprincipal-list-approleassignments
#>
function Test-ServicePrincipalPermissions {
    Write-Host "`n[+] Checking service principal permissions for overprivileged apps..." -ForegroundColor Cyan
    
    # High-risk Graph API permissions (application permissions)
    $highRiskPermissions = @{
        # Directory
        "Directory.ReadWrite.All" = "Can read and write all directory data"
        "RoleManagement.ReadWrite.Directory" = "Can manage role assignments - CRITICAL"
        "Application.ReadWrite.All" = "Can create/modify any application"
        "AppRoleAssignment.ReadWrite.All" = "Can grant any app permission"
        "DelegatedPermissionGrant.ReadWrite.All" = "Can grant delegated permissions"
        "Policy.ReadWrite.All" = "Can modify policies including Conditional Access"
        
        # Mail
        "Mail.ReadWrite" = "Can read/write all users' mail"
        "Mail.Send" = "Can send mail as any user"
        "MailboxSettings.ReadWrite" = "Can modify mailbox settings"
        
        # Files
        "Files.ReadWrite.All" = "Can read/write all files in all site collections"
        "Sites.FullControl.All" = "Full control of all SharePoint sites"
        "Sites.ReadWrite.All" = "Can read/write items in all site collections"
        
        # Users
        "User.ReadWrite.All" = "Can read/write all user profiles"
        "User.ManageIdentities.All" = "Can manage user identities"
        "User.EnableDisableAccount.All" = "Can enable/disable accounts"
        "User.Export.All" = "Can export user data"
        
        # Groups
        "Group.ReadWrite.All" = "Can read/write all groups"
        "GroupMember.ReadWrite.All" = "Can manage group membership"
        
        # Other dangerous
        "AuditLog.Read.All" = "Can read all audit logs"
        "SecurityEvents.ReadWrite.All" = "Can read/write security events"
        "ThreatIndicators.ReadWrite.OwnedBy" = "Can manage threat indicators"
    }
    
    # Microsoft's first-party app IDs (partial list of common ones)
    $microsoftAppIds = @(
        "00000003-0000-0000-c000-000000000000", # Microsoft Graph
        "00000002-0000-0000-c000-000000000000", # Azure AD Graph (legacy)
        "00000001-0000-0000-c000-000000000000", # Azure ESTS
        "00000003-0000-0ff1-ce00-000000000000", # SharePoint Online
        "00000002-0000-0ff1-ce00-000000000000", # Exchange Online
        "00000007-0000-0000-c000-000000000000"  # Azure Portal
    )
    
    try {
        # Get all service principals (enterprise applications)
        $servicePrincipals = Invoke-GraphRequest -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$select=id,appId,displayName,servicePrincipalType,appOwnerOrganizationId,accountEnabled&`$top=999" -AllPages

        if (-not $servicePrincipals -or $servicePrincipals.Count -eq 0) {
            Add-Finding -Status "INFO" `
                -Object "Service Principals" `
                -Description "No service principals found in the tenant." `
                -Remediation "No action needed."
            return
        }

        # Get tenant ID for comparison
        $tenantId = $script:TenantCapabilities.TenantId

        $totalSPs = $servicePrincipals.Count
        $thirdPartySPs = 0
        $highRiskSPs = 0

        # Cache for resource SP lookups - most assignments point to the same resource
        # (e.g., Microsoft Graph), so caching avoids thousands of redundant API calls
        $resourceSPCache = @{}

        # Filter to enabled SPs only and count third-party up front
        $enabledSPs = @($servicePrincipals | Where-Object { $_.accountEnabled -ne $false })
        foreach ($sp in $enabledSPs) {
            $isThirdParty = $sp.appOwnerOrganizationId -and $sp.appOwnerOrganizationId -ne $tenantId
            $isMicrosoft = $microsoftAppIds -contains $sp.appId
            if ($isThirdParty -and -not $isMicrosoft) {
                $thirdPartySPs++
            }
        }

        # Batch-fetch all appRoleAssignments in one call instead of per-SP
        # This returns all assignments across the tenant in a single paginated request
        $allAssignments = $null
        try {
            $allAssignments = Invoke-GraphRequest -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$select=id,appId,displayName,appOwnerOrganizationId,accountEnabled&`$expand=appRoleAssignments&`$top=999" -AllPages
        }
        catch {
            Write-Verbose "Batch expand query not supported, falling back to per-SP queries: $($_.Exception.Message)"
            $allAssignments = $null
        }

        if ($allAssignments) {
            # Fast path: expanded query returned assignments inline
            foreach ($sp in $allAssignments) {
                if ($sp.accountEnabled -eq $false) { continue }
                if (-not $sp.appRoleAssignments -or $sp.appRoleAssignments.Count -eq 0) { continue }

                $isThirdParty = $sp.appOwnerOrganizationId -and $sp.appOwnerOrganizationId -ne $tenantId
                $isMicrosoft = $microsoftAppIds -contains $sp.appId

                $dangerousPermissions = @()
                foreach ($assignment in $sp.appRoleAssignments) {
                    $resourceSP = $null
                    if ($resourceSPCache.ContainsKey($assignment.resourceId)) {
                        $resourceSP = $resourceSPCache[$assignment.resourceId]
                    }
                    else {
                        try {
                            $resourceSP = Invoke-GraphRequest -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($assignment.resourceId)?`$select=id,displayName,appRoles"
                            $resourceSPCache[$assignment.resourceId] = $resourceSP
                        }
                        catch {
                            Write-Verbose "Could not resolve resource SP '$($assignment.resourceId)': $($_.Exception.Message)"
                            $resourceSPCache[$assignment.resourceId] = $null
                        }
                    }

                    if ($resourceSP -and $resourceSP.appRoles) {
                        $appRole = $resourceSP.appRoles | Where-Object { $_.id -eq $assignment.appRoleId }
                        if ($appRole -and $highRiskPermissions.ContainsKey($appRole.value)) {
                            $dangerousPermissions += "$($appRole.value) ($($highRiskPermissions[$appRole.value]))"
                        }
                    }
                }

                if ($dangerousPermissions.Count -gt 0) {
                    $highRiskSPs++
                    $severity = if ($dangerousPermissions -match "RoleManagement|Directory.ReadWrite|AppRoleAssignment") { "FAIL" } else { "WARNING" }
                    $partyType = if ($isThirdParty -and -not $isMicrosoft) { "THIRD-PARTY" } elseif ($isMicrosoft) { "Microsoft" } else { "First-party" }

                    Add-Finding -Status $severity `
                        -Object "$($sp.displayName) [$partyType]" `
                        -Description "Service principal '$($sp.displayName)' has high-risk permissions: $($dangerousPermissions -join '; ')" `
                        -Remediation "Review if this application truly requires these permissions. Apply principle of least privilege. Third-party apps with these permissions are especially risky."
                }
            }
        }
        else {
            # Fallback path: per-SP queries with resource SP caching
            $spCount = 0
            foreach ($sp in $enabledSPs) {
                $spCount++
                if ($spCount % 100 -eq 0) {
                    Write-Host "    Processing service principal $spCount of $($enabledSPs.Count)..." -ForegroundColor DarkGray
                }

                $isThirdParty = $sp.appOwnerOrganizationId -and $sp.appOwnerOrganizationId -ne $tenantId
                $isMicrosoft = $microsoftAppIds -contains $sp.appId

                try {
                    $appRoleAssignments = Invoke-GraphRequest -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($sp.id)/appRoleAssignments" -AllPages

                    if ($appRoleAssignments -and $appRoleAssignments.Count -gt 0) {
                        $dangerousPermissions = @()

                        foreach ($assignment in $appRoleAssignments) {
                            # Use cached resource SP lookup to avoid redundant API calls
                            $resourceSP = $null
                            if ($resourceSPCache.ContainsKey($assignment.resourceId)) {
                                $resourceSP = $resourceSPCache[$assignment.resourceId]
                            }
                            else {
                                try {
                                    $resourceSP = Invoke-GraphRequest -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($assignment.resourceId)?`$select=id,displayName,appRoles"
                                    $resourceSPCache[$assignment.resourceId] = $resourceSP
                                }
                                catch {
                                    Write-Verbose "Could not resolve resource SP '$($assignment.resourceId)': $($_.Exception.Message)"
                                    $resourceSPCache[$assignment.resourceId] = $null
                                }
                            }

                            if ($resourceSP -and $resourceSP.appRoles) {
                                $appRole = $resourceSP.appRoles | Where-Object { $_.id -eq $assignment.appRoleId }
                                if ($appRole -and $highRiskPermissions.ContainsKey($appRole.value)) {
                                    $dangerousPermissions += "$($appRole.value) ($($highRiskPermissions[$appRole.value]))"
                                }
                            }
                        }

                        if ($dangerousPermissions.Count -gt 0) {
                            $highRiskSPs++
                            $severity = if ($dangerousPermissions -match "RoleManagement|Directory.ReadWrite|AppRoleAssignment") { "FAIL" } else { "WARNING" }
                            $partyType = if ($isThirdParty -and -not $isMicrosoft) { "THIRD-PARTY" } elseif ($isMicrosoft) { "Microsoft" } else { "First-party" }

                            Add-Finding -Status $severity `
                                -Object "$($sp.displayName) [$partyType]" `
                                -Description "Service principal '$($sp.displayName)' has high-risk permissions: $($dangerousPermissions -join '; ')" `
                                -Remediation "Review if this application truly requires these permissions. Apply principle of least privilege. Third-party apps with these permissions are especially risky."
                        }
                    }
                }
                catch {
                    Write-Verbose "Could not query appRoleAssignments for SP '$($sp.displayName)': $($_.Exception.Message)"
                }
            }
        }
        
        # Summary finding
        Add-Finding -Status "INFO" `
            -Object "Service Principal Summary" `
            -Description "Total service principals: $totalSPs. Third-party apps: $thirdPartySPs. Apps with high-risk permissions: $highRiskSPs." `
            -Remediation "Regularly review third-party applications and their permissions. Remove unused applications."
        
        if ($thirdPartySPs -gt 20) {
            Add-Finding -Status "INFO" `
                -Object "Third-Party Apps" `
                -Description "Tenant has $thirdPartySPs third-party applications with access. Large numbers of third-party apps increase attack surface." `
                -Remediation "Implement app governance policies. Regularly review and remove unused third-party applications."
        }
    }
    catch {
        Add-Finding -Status "WARNING" `
            -Object "Service Principal Permissions" `
            -Description "Unable to check service principal permissions: $($_.Exception.Message)" `
            -Remediation "Check Graph permissions (Application.Read.All required)."
    }
}

<#
.SYNOPSIS
    Test-OAuthConsentGrants - Audits delegated permission grants.

.DESCRIPTION
    Equivalent to: Check-DelegationOverview (AD version - delegation analysis)
    
    Examines OAuth2 permission grants (user consent and admin consent):
    - Admin-consented permissions (tenant-wide)
    - User-consented permissions (individual grants)
    - Grants for high-risk scopes
    - Grants to third-party applications
    
    Graph Endpoints Used:
    - GET /oauth2PermissionGrants
    
.OUTPUTS
    Findings with Status: WARNING/FAIL for risky grants, INFO for inventory
    
.NOTES
    Required Permissions: Directory.Read.All
    Minimum License: Azure AD Free
    
.LINK
    AD Equivalent: Check-DelegationOverview
    Graph Reference: https://learn.microsoft.com/en-us/graph/api/oauth2permissiongrant-list
#>
function Test-OAuthConsentGrants {
    Write-Host "`n[+] Checking OAuth consent grants (delegated permissions)..." -ForegroundColor Cyan
    
    # High-risk delegated scopes
    $highRiskScopes = @(
        "Directory.ReadWrite.All",
        "Directory.AccessAsUser.All",
        "User.ReadWrite.All",
        "Group.ReadWrite.All",
        "Mail.ReadWrite",
        "Mail.Send",
        "Files.ReadWrite.All",
        "Sites.FullControl.All",
        "Calendars.ReadWrite",
        "Contacts.ReadWrite",
        "MailboxSettings.ReadWrite"
    )
    
    try {
        # Get all OAuth2 permission grants
        $grants = Invoke-GraphRequest -Uri "https://graph.microsoft.com/v1.0/oauth2PermissionGrants?`$top=999" -AllPages
        
        if (-not $grants -or $grants.Count -eq 0) {
            Add-Finding -Status "OK" `
                -Object "OAuth Consent Grants" `
                -Description "No OAuth consent grants found in the tenant." `
                -Remediation "No action needed."
            return
        }
        
        $totalGrants = $grants.Count
        $adminConsentGrants = 0
        $userConsentGrants = 0
        $highRiskGrants = 0
        
        # Cache service principal lookups
        $spCache = @{}
        
        foreach ($grant in $grants) {
            $isAdminConsent = $grant.consentType -eq "AllPrincipals"
            
            if ($isAdminConsent) {
                $adminConsentGrants++
            }
            else {
                $userConsentGrants++
            }
            
            # Get the client service principal name
            $clientName = "Unknown"
            if ($grant.clientId) {
                if (-not $spCache.ContainsKey($grant.clientId)) {
                    try {
                        $sp = Invoke-GraphRequest -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($grant.clientId)?`$select=id,displayName,appOwnerOrganizationId"
                        $spCache[$grant.clientId] = $sp
                    }
                    catch {
                        $spCache[$grant.clientId] = $null
                    }
                }
                if ($spCache[$grant.clientId]) {
                    $clientName = $spCache[$grant.clientId].displayName
                }
            }
            
            # Parse scopes
            $scopes = if ($grant.scope) { $grant.scope -split ' ' } else { @() }
            $riskyScopes = $scopes | Where-Object { $highRiskScopes -contains $_ }
            
            if ($riskyScopes.Count -gt 0) {
                $highRiskGrants++
                $consentType = if ($isAdminConsent) { "Admin consent (ALL USERS)" } else { "User consent" }
                
                Add-Finding -Status "REVIEW" `
                    -Object "$clientName" `
                    -Description "Application '$clientName' has $consentType for high-risk scopes: $($riskyScopes -join ', '). These permissions allow broad data access." `
                    -Remediation "Review if this application requires these permissions. Consider revoking and re-granting with minimal scopes."
            }
            
            # Flag admin consent grants to third-party apps
            if ($isAdminConsent -and $spCache[$grant.clientId]) {
                $sp = $spCache[$grant.clientId]
                $tenantId = $script:TenantCapabilities.TenantId
                
                if ($sp.appOwnerOrganizationId -and $sp.appOwnerOrganizationId -ne $tenantId) {
                    # This is a third-party app with admin consent
                    if ($scopes.Count -gt 5) {
                        Add-Finding -Status "REVIEW" `
                            -Object "$clientName (Third-Party)" `
                            -Description "Third-party application '$clientName' has admin consent for $($scopes.Count) permissions: $($grant.scope). Large permission grants to external apps increase risk." `
                            -Remediation "Review all permissions granted to this third-party application. Apply principle of least privilege."
                    }
                }
            }
        }
        
        # Summary finding
        Add-Finding -Status "INFO" `
            -Object "OAuth Consent Summary" `
            -Description "Total consent grants: $totalGrants. Admin consent (tenant-wide): $adminConsentGrants. User consent (individual): $userConsentGrants. Grants with high-risk scopes: $highRiskGrants." `
            -Remediation "Implement consent workflow requiring admin approval. Regularly review consent grants."
        
        if ($userConsentGrants -gt 50) {
            Add-Finding -Status "INFO" `
                -Object "User Consent Volume" `
                -Description "High volume of user consent grants ($userConsentGrants). This may indicate users are consenting to many applications without oversight." `
                -Remediation "Consider restricting user consent and implementing an admin consent workflow. Review authorization policy settings."
        }
    }
    catch {
        Add-Finding -Status "WARNING" `
            -Object "OAuth Consent Grants" `
            -Description "Unable to check OAuth consent grants: $($_.Exception.Message)" `
            -Remediation "Check Graph permissions (Directory.Read.All required)."
    }
}

<#
.SYNOPSIS
    Test-AppRoleAssignments - Audits application permission assignments.

.DESCRIPTION
    Equivalent to: Check-ObjectPermissionsAudit (AD version - permission analysis)
    
    Examines app role assignments to identify:
    - Which service principals have which application permissions
    - Permissions to Microsoft Graph and other APIs
    - Unusual permission patterns
    
    Note: This complements Test-ServicePrincipalPermissions by providing
    a different view (by resource rather than by client).
    
    Graph Endpoints Used:
    - GET /servicePrincipals (filtered for Microsoft Graph)
    - GET /servicePrincipals/{id}/appRoleAssignedTo
    
.OUTPUTS
    Findings with Status: INFO for inventory, WARNING for concerning patterns
    
.NOTES
    Required Permissions: Application.Read.All
    Minimum License: Azure AD Free
    
.LINK
    AD Equivalent: Check-ObjectPermissionsAudit
    Graph Reference: https://learn.microsoft.com/en-us/graph/api/serviceprincipal-list-approleassignedto
#>
function Test-AppRoleAssignments {
    Write-Host "`n[+] Checking application permission assignments to Microsoft Graph..." -ForegroundColor Cyan
    
    try {
        # Find Microsoft Graph service principal
        $graphSP = Invoke-GraphRequest -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '00000003-0000-0000-c000-000000000000'&`$select=id,displayName,appRoles"
        
        if (-not $graphSP -or -not $graphSP.value -or $graphSP.value.Count -eq 0) {
            Add-Finding -Status "WARNING" `
                -Object "Microsoft Graph" `
                -Description "Could not find Microsoft Graph service principal in tenant." `
                -Remediation "This is unexpected. Check tenant configuration."
            return
        }
        
        $graphId = $graphSP.value[0].id
        $appRoles = $graphSP.value[0].appRoles
        
        # Build a lookup for app role IDs to names
        $roleIdToName = @{}
        foreach ($role in $appRoles) {
            $roleIdToName[$role.id] = $role.value
        }
        
        # Get all assignments to Microsoft Graph
        $assignments = Invoke-GraphRequest -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$graphId/appRoleAssignedTo?`$top=999" -AllPages
        
        if (-not $assignments -or $assignments.Count -eq 0) {
            Add-Finding -Status "INFO" `
                -Object "Graph API Permissions" `
                -Description "No applications have been granted Microsoft Graph application permissions." `
                -Remediation "No action needed."
            return
        }
        
        # Group assignments by principal
        $permissionsByApp = @{}
        
        foreach ($assignment in $assignments) {
            $principalId = $assignment.principalId
            $principalName = $assignment.principalDisplayName
            $roleName = $roleIdToName[$assignment.appRoleId]
            
            if (-not $roleName) { $roleName = "Unknown Role" }
            
            if (-not $permissionsByApp.ContainsKey($principalId)) {
                $permissionsByApp[$principalId] = @{
                    Name = $principalName
                    Permissions = @()
                }
            }
            $permissionsByApp[$principalId].Permissions += $roleName
        }
        
        # Analyze each app's permissions
        $criticalPermissions = @("Directory.ReadWrite.All", "RoleManagement.ReadWrite.Directory", "Application.ReadWrite.All", "AppRoleAssignment.ReadWrite.All")
        $appsWithCritical = 0
        
        foreach ($appId in $permissionsByApp.Keys) {
            $app = $permissionsByApp[$appId]
            $hasCritical = $app.Permissions | Where-Object { $criticalPermissions -contains $_ }
            
            if ($hasCritical) {
                $appsWithCritical++
                Add-Finding -Status "FAIL" `
                    -Object $app.Name `
                    -Description "Application '$($app.Name)' has CRITICAL Graph permissions: $($hasCritical -join ', '). These permissions allow full control over directory objects." `
                    -Remediation "Verify this application absolutely requires these permissions. Consider using more granular permissions if possible."
            }
            elseif ($app.Permissions.Count -gt 10) {
                Add-Finding -Status "REVIEW" `
                    -Object $app.Name `
                    -Description "Application '$($app.Name)' has $($app.Permissions.Count) Microsoft Graph permissions. Large permission grants may indicate over-privileged configuration." `
                    -Remediation "Review all permissions and remove any that are not actively required."
            }
        }
        
        # Summary
        Add-Finding -Status "INFO" `
            -Object "Graph Permission Summary" `
            -Description "Total apps with Graph permissions: $($permissionsByApp.Count). Apps with critical permissions: $appsWithCritical." `
            -Remediation "Regularly audit application permissions. Implement approval workflows for new permission grants."
    }
    catch {
        Add-Finding -Status "WARNING" `
            -Object "App Role Assignments" `
            -Description "Unable to check app role assignments: $($_.Exception.Message)" `
            -Remediation "Check Graph permissions (Application.Read.All required)."
    }
}

<#
.SYNOPSIS
    Test-DuplicateAppIdentifiers - Finds applications with duplicate identifiers.

.DESCRIPTION
    Equivalent to: Check-DuplicateSPNs (AD version)
    
    Scans applications for duplicate or conflicting identifiers:
    - Duplicate identifierUris across applications
    - Duplicate servicePrincipalNames on service principals
    
    Duplicate identifiers can cause authentication issues and may indicate
    configuration problems or potential security issues.
    
    Graph Endpoints Used:
    - GET /applications
    - GET /servicePrincipals
    
.OUTPUTS
    Findings with Status: FAIL for duplicates found, OK if clean
    
.NOTES
    Required Permissions: Application.Read.All
    Minimum License: Azure AD Free
    
.LINK
    AD Equivalent: Check-DuplicateSPNs
    Graph Reference: https://learn.microsoft.com/en-us/graph/api/application-list
#>
function Test-DuplicateAppIdentifiers {
    Write-Host "`n[+] Checking for duplicate application identifiers..." -ForegroundColor Cyan
    
    try {
        # Get all applications with identifierUris
        $apps = Invoke-GraphRequest -Uri "https://graph.microsoft.com/v1.0/applications?`$select=id,appId,displayName,identifierUris&`$top=999" -AllPages
        
        # Build a map of identifierUris to applications
        $uriMap = @{}
        
        foreach ($app in $apps) {
            if ($app.identifierUris -and $app.identifierUris.Count -gt 0) {
                foreach ($uri in $app.identifierUris) {
                    if (-not $uriMap.ContainsKey($uri)) {
                        $uriMap[$uri] = @()
                    }
                    $uriMap[$uri] += @{
                        Id = $app.id
                        AppId = $app.appId
                        DisplayName = $app.displayName
                    }
                }
            }
        }
        
        # Find duplicates
        $duplicateUris = $uriMap.GetEnumerator() | Where-Object { $_.Value.Count -gt 1 }
        
        if ($duplicateUris) {
            foreach ($dup in $duplicateUris) {
                $appList = ($dup.Value | ForEach-Object { "$($_.DisplayName) ($($_.AppId))" }) -join "; "
                
                Add-Finding -Status "FAIL" `
                    -Object "Duplicate URI: $($dup.Key)" `
                    -Description "Identifier URI '$($dup.Key)' is used by multiple applications: $appList. This can cause authentication failures and token confusion." `
                    -Remediation "Each identifier URI should be unique to a single application. Remove the duplicate from one of the applications."
            }
        }
        
        # Get service principals and check servicePrincipalNames
        $servicePrincipals = Invoke-GraphRequest -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$select=id,appId,displayName,servicePrincipalNames&`$top=999" -AllPages
        
        # Build a map of SPNs
        $spnMap = @{}
        
        foreach ($sp in $servicePrincipals) {
            if ($sp.servicePrincipalNames -and $sp.servicePrincipalNames.Count -gt 0) {
                foreach ($spn in $sp.servicePrincipalNames) {
                    # Skip the appId-based SPN as that's expected to be unique
                    if ($spn -match "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$") {
                        continue
                    }
                    
                    if (-not $spnMap.ContainsKey($spn)) {
                        $spnMap[$spn] = @()
                    }
                    $spnMap[$spn] += @{
                        Id = $sp.id
                        AppId = $sp.appId
                        DisplayName = $sp.displayName
                    }
                }
            }
        }
        
        # Find duplicate SPNs
        $duplicateSpns = $spnMap.GetEnumerator() | Where-Object { $_.Value.Count -gt 1 }
        
        if ($duplicateSpns) {
            foreach ($dup in $duplicateSpns) {
                $spList = ($dup.Value | ForEach-Object { "$($_.DisplayName) ($($_.AppId))" }) -join "; "
                
                Add-Finding -Status "FAIL" `
                    -Object "Duplicate SPN: $($dup.Key)" `
                    -Description "Service Principal Name '$($dup.Key)' is used by multiple service principals: $spList. This can cause authentication issues." `
                    -Remediation "Each SPN should be unique. Remove the duplicate from one of the service principals."
            }
        }
        
        if (-not $duplicateUris -and -not $duplicateSpns) {
            Add-Finding -Status "OK" `
                -Object "Application Identifiers" `
                -Description "No duplicate identifier URIs or service principal names found." `
                -Remediation "No action needed."
        }
        
        # Summary
        $totalApps = if ($apps) { $apps.Count } else { 0 }
        $totalSPs = if ($servicePrincipals) { $servicePrincipals.Count } else { 0 }
        $dupUriCount = if ($duplicateUris) { @($duplicateUris).Count } else { 0 }
        $dupSpnCount = if ($duplicateSpns) { @($duplicateSpns).Count } else { 0 }
        
        Add-Finding -Status "INFO" `
            -Object "Identifier Summary" `
            -Description "Checked $totalApps applications and $totalSPs service principals. Found $dupUriCount duplicate URIs and $dupSpnCount duplicate SPNs." `
            -Remediation "Maintain unique identifiers for all applications."
    }
    catch {
        Add-Finding -Status "WARNING" `
            -Object "Duplicate Identifiers" `
            -Description "Unable to check for duplicate identifiers: $($_.Exception.Message)" `
            -Remediation "Check Graph permissions (Application.Read.All required)."
    }
}

#endregion

#region ==================== PHASE 4: AUTHENTICATION & POLICY CHECKS ====================

<#
.SYNOPSIS
    Test-ConditionalAccessPolicies - Inventories and analyzes Conditional Access policies.

.DESCRIPTION
    Equivalent to: Check-GPOOverview (AD version - policy inventory)
    
    Examines Conditional Access policies for:
    - Policy inventory (enabled, disabled, report-only)
    - Policies targeting privileged users/roles
    - Legacy authentication blocks
    - MFA requirements
    - Gaps in coverage (e.g., no policy for admins)
    
    Graph Endpoints Used:
    - GET /identity/conditionalAccess/policies
    
.OUTPUTS
    Findings with Status: INFO for inventory, WARNING/FAIL for gaps
    
.NOTES
    Required Permissions: Policy.Read.All
    Minimum License: Azure AD P1 (Conditional Access requires P1)
    
.LINK
    AD Equivalent: Check-GPOOverview
    Graph Reference: https://learn.microsoft.com/en-us/graph/api/conditionalaccessroot-list-policies
#>
function Test-ConditionalAccessPolicies {
    Write-Host "`n[+] Checking Conditional Access policies..." -ForegroundColor Cyan
    
    # Check if CA is available
    if (-not $script:TenantCapabilities.HasConditionalAccess) {
        Add-Finding -Status "WARNING" `
            -Object "Conditional Access" `
            -Description "Conditional Access policies are not available. This typically means the tenant does not have Azure AD P1 or higher licensing." `
            -Remediation "Consider upgrading to Azure AD P1 to enable Conditional Access for improved security posture."
        return
    }
    
    try {
        # Get all CA policies
        $policies = Invoke-GraphRequest -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" -AllPages
        
        if (-not $policies -or $policies.Count -eq 0) {
            Add-Finding -Status "FAIL" `
                -Object "Conditional Access" `
                -Description "No Conditional Access policies found despite P1 licensing. The tenant has no policy-based access controls." `
                -Remediation "Implement Conditional Access policies immediately. Start with requiring MFA for all administrators."
            return
        }
        
        $totalPolicies = $policies.Count
        $enabledPolicies = ($policies | Where-Object { $_.state -eq "enabled" }).Count
        $disabledPolicies = ($policies | Where-Object { $_.state -eq "disabled" }).Count
        $reportOnlyPolicies = ($policies | Where-Object { $_.state -eq "enabledForReportingButNotEnforced" }).Count
        
        # Track key policy types
        $hasMFAForAdmins = $false
        $hasBlockLegacyAuth = $false
        $hasMFAForAllUsers = $false

        foreach ($policy in $policies) {
            # Skip disabled policies for analysis
            if ($policy.state -eq "disabled") { continue }

            # Analyze conditions
            $conditions = $policy.conditions
            $grantControls = $policy.grantControls
            
            # Check if policy targets admins
            $targetsAdmins = $false
            if ($conditions.users) {
                $includeRoles = $conditions.users.includeRoles
                if ($includeRoles) {
                    # Common admin role IDs
                    $adminRoleIds = @(
                        "62e90394-69f5-4237-9190-012177145e10", # Global Administrator
                        "e8611ab8-c189-46e8-94e1-60213ab1f814", # Privileged Role Administrator
                        "194ae4cb-b126-40b2-bd5b-6091b380977d", # Security Administrator
                        "f28a1f50-f6e7-4571-818b-6a12f2af6b6c", # SharePoint Administrator
                        "29232cdf-9323-42fd-ade2-1d097af3e4de", # Exchange Administrator
                        "fe930be7-5e62-47db-91af-98c3a49a38b1"  # User Administrator
                    )
                    foreach ($roleId in $includeRoles) {
                        if ($adminRoleIds -contains $roleId) {
                            $targetsAdmins = $true
                            break
                        }
                    }
                }
                # Also check if it includes "All" users
                if ($conditions.users.includeUsers -contains "All") {
                    $targetsAdmins = $true
                }
            }
            
            # Check grant controls
            $requiresMFA = $false
            $blocksAccess = $false

            if ($grantControls) {
                if ($grantControls.builtInControls -contains "mfa") {
                    $requiresMFA = $true
                }
                if ($grantControls.builtInControls -contains "block") {
                    $blocksAccess = $true
                }
            }
            
            # Check for legacy auth block
            if ($conditions.clientAppTypes) {
                $legacyTypes = @("exchangeActiveSync", "other")
                $hasLegacyCondition = $conditions.clientAppTypes | Where-Object { $legacyTypes -contains $_ }
                if ($hasLegacyCondition -and $blocksAccess) {
                    $hasBlockLegacyAuth = $true
                }
            }
            
            # Track key policy coverage
            if ($targetsAdmins -and $requiresMFA) {
                $hasMFAForAdmins = $true
            }
            if ($conditions.users.includeUsers -contains "All" -and $requiresMFA) {
                $hasMFAForAllUsers = $true
            }
        }
        
        # Summary finding
        Add-Finding -Status "INFO" `
            -Object "Conditional Access Summary" `
            -Description "Total policies: $totalPolicies (Enabled: $enabledPolicies, Disabled: $disabledPolicies, Report-Only: $reportOnlyPolicies)" `
            -Remediation "Review all policies regularly. Test new policies in report-only mode before enabling."
        
        # Check for critical gaps
        if (-not $hasMFAForAdmins) {
            Add-Finding -Status "FAIL" `
                -Object "CA Gap: Admin MFA" `
                -Description "No Conditional Access policy found that requires MFA for administrative roles. Admins are not protected by policy-enforced MFA." `
                -Remediation "Create a Conditional Access policy requiring MFA for all administrative directory roles immediately. This is a critical security control."
        }
        else {
            Add-Finding -Status "OK" `
                -Object "CA: Admin MFA" `
                -Description "Conditional Access policy requiring MFA for administrators is in place." `
                -Remediation "No action needed. Continue to monitor policy effectiveness."
        }
        
        if (-not $hasBlockLegacyAuth) {
            Add-Finding -Status "WARNING" `
                -Object "CA Gap: Legacy Auth" `
                -Description "No Conditional Access policy found that blocks legacy authentication. Legacy auth protocols bypass MFA and are frequently exploited." `
                -Remediation "Create a Conditional Access policy to block legacy authentication for all users. Legacy auth includes POP, IMAP, SMTP AUTH, and older Office clients."
        }
        else {
            Add-Finding -Status "OK" `
                -Object "CA: Legacy Auth Block" `
                -Description "Conditional Access policy blocking legacy authentication is in place." `
                -Remediation "No action needed."
        }
        
        if (-not $hasMFAForAllUsers) {
            Add-Finding -Status "INFO" `
                -Object "CA: All User MFA" `
                -Description "No Conditional Access policy requires MFA for all users. Consider implementing MFA for all users, not just administrators." `
                -Remediation "Implement MFA for all users via Conditional Access. Start with report-only mode to assess impact."
        }
        
        # List all enabled policies for reference
        $enabledPolicyList = $policies | Where-Object { $_.state -eq "enabled" } | ForEach-Object { $_.displayName }
        if ($enabledPolicyList.Count -gt 0) {
            Add-Finding -Status "INFO" `
                -Object "Enabled CA Policies" `
                -Description "Active policies: $($enabledPolicyList -join '; ')" `
                -Remediation "Review each policy for appropriate scope and controls."
        }
    }
    catch {
        Add-Finding -Status "WARNING" `
            -Object "Conditional Access" `
            -Description "Unable to check Conditional Access policies: $($_.Exception.Message)" `
            -Remediation "Check Graph permissions (Policy.Read.All required) and Azure AD P1 licensing."
    }
}

<#
.SYNOPSIS
    Test-AuthenticationMethodsPolicy - Analyzes authentication methods configuration.

.DESCRIPTION
    Equivalent to: Check-PasswordPolicy (AD version - auth configuration)
    
    Examines the authentication methods policy to understand:
    - Which authentication methods are enabled tenant-wide
    - FIDO2, Microsoft Authenticator, SMS, Email OTP settings
    - Method-specific configurations
    
    Graph Endpoints Used:
    - GET /policies/authenticationMethodsPolicy
    - GET /policies/authenticationMethodsPolicy/authenticationMethodConfigurations
    
.OUTPUTS
    Findings with Status: INFO for inventory, WARNING for weak methods
    
.NOTES
    Required Permissions: Policy.Read.All
    Minimum License: Azure AD Free (basic), P1 for full features
    
.LINK
    AD Equivalent: Check-PasswordPolicy
    Graph Reference: https://learn.microsoft.com/en-us/graph/api/authenticationmethodspolicy-get
#>
function Test-AuthenticationMethodsPolicy {
    Write-Host "`n[+] Checking authentication methods policy..." -ForegroundColor Cyan
    
    try {
        # Get authentication methods policy
        $authMethodsPolicy = Invoke-GraphRequest -Uri "https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy"
        
        if (-not $authMethodsPolicy) {
            Add-Finding -Status "WARNING" `
                -Object "Authentication Methods" `
                -Description "Unable to retrieve authentication methods policy." `
                -Remediation "Check permissions and try again."
            return
        }
        
        $methodConfigs = $authMethodsPolicy.authenticationMethodConfigurations
        
        # Analyze each method
        $enabledMethods = @()
        $weakMethodsEnabled = @()
        $strongMethodsEnabled = @()
        
        # Define method strength
        $strongMethods = @("fido2", "microsoftAuthenticator", "windowsHelloForBusiness", "x509Certificate")
        $weakMethods = @("sms", "voice", "email")
        
        foreach ($method in $methodConfigs) {
            $methodType = $method.'@odata.type' -replace '#microsoft.graph.', '' -replace 'AuthenticationMethodConfiguration', ''
            $state = $method.state
            
            if ($state -eq "enabled") {
                $enabledMethods += $methodType
                
                if ($strongMethods -contains $methodType) {
                    $strongMethodsEnabled += $methodType
                }
                elseif ($weakMethods -contains $methodType) {
                    $weakMethodsEnabled += $methodType
                }
            }
        }
        
        # Summary finding
        Add-Finding -Status "INFO" `
            -Object "Authentication Methods Summary" `
            -Description "Enabled methods: $($enabledMethods -join ', '). Strong (phishing-resistant): $($strongMethodsEnabled.Count). Weaker methods: $($weakMethodsEnabled.Count)." `
            -Remediation "Enable phishing-resistant methods (FIDO2, Windows Hello). Consider disabling weaker methods for privileged users."
        
        # Check for phishing-resistant methods
        if ($strongMethodsEnabled.Count -eq 0) {
            Add-Finding -Status "WARNING" `
                -Object "Phishing-Resistant MFA" `
                -Description "No phishing-resistant authentication methods are enabled (FIDO2, Windows Hello, Certificate). These methods provide the strongest protection against credential theft." `
                -Remediation "Enable FIDO2 security keys or Windows Hello for Business, especially for privileged users."
        }
        else {
            Add-Finding -Status "OK" `
                -Object "Phishing-Resistant MFA" `
                -Description "Phishing-resistant methods enabled: $($strongMethodsEnabled -join ', ')" `
                -Remediation "Continue to promote adoption of these methods, especially for administrators."
        }
        
        # Check for weak methods
        if ($weakMethodsEnabled.Count -gt 0) {
            Add-Finding -Status "INFO" `
                -Object "Weaker Auth Methods" `
                -Description "Weaker authentication methods are enabled: $($weakMethodsEnabled -join ', '). SMS and voice can be intercepted. Email OTP is less secure than app-based methods." `
                -Remediation "Consider restricting weaker methods to non-privileged users only. Disable SMS/Voice for administrators via Authentication Strengths."
        }
        
        # Check specific method configurations
        foreach ($method in $methodConfigs) {
            $methodType = $method.'@odata.type' -replace '#microsoft.graph.', '' -replace 'AuthenticationMethodConfiguration', ''
            
            # Check Microsoft Authenticator settings
            if ($methodType -eq "microsoftAuthenticator" -and $method.state -eq "enabled") {
                $featureSettings = $method.featureSettings
                if ($featureSettings) {
                    $numberMatching = $featureSettings.numberMatchingRequiredState
                    if ($numberMatching -and $numberMatching.state -ne "enabled") {
                        Add-Finding -Status "WARNING" `
                            -Object "Authenticator: Number Matching" `
                            -Description "Number matching is not enabled for Microsoft Authenticator. Number matching helps prevent MFA fatigue attacks." `
                            -Remediation "Enable number matching in Microsoft Authenticator settings to improve security."
                    }
                }
            }
            
            # Check FIDO2 settings
            if ($methodType -eq "fido2" -and $method.state -eq "enabled") {
                $isSelfServiceAllowed = $method.isSelfServiceRegistrationAllowed
                Add-Finding -Status "INFO" `
                    -Object "FIDO2 Configuration" `
                    -Description "FIDO2 security keys enabled. Self-service registration: $(if ($isSelfServiceAllowed) { 'Allowed' } else { 'Not allowed' })" `
                    -Remediation "Ensure FIDO2 keys are deployed to privileged users. Consider allowing self-service registration for broader adoption."
            }
        }
    }
    catch {
        Add-Finding -Status "WARNING" `
            -Object "Authentication Methods" `
            -Description "Unable to check authentication methods policy: $($_.Exception.Message)" `
            -Remediation "Check Graph permissions (Policy.Read.All required)."
    }
}

<#
.SYNOPSIS
    Test-PrivilegedUserMFACoverage - Verifies MFA registration for privileged users.

.DESCRIPTION
    Equivalent to: Check-PrivilegedAccountsSmartcard (AD version - strong auth)
    
    Checks if users with privileged directory roles have MFA methods registered:
    - Identifies privileged users without any MFA method
    - Reports MFA method types registered by admins
    - Flags admins using only weak MFA methods
    
    Graph Endpoints Used:
    - GET /directoryRoles
    - GET /directoryRoles/{id}/members
    - GET /reports/authenticationMethods/userRegistrationDetails (or per-user methods)
    
.OUTPUTS
    Findings with Status: FAIL for admins without MFA, WARNING for weak MFA
    
.NOTES
    Required Permissions: UserAuthenticationMethod.Read.All, Directory.Read.All
    Minimum License: Azure AD P1 (for registration reports)
    
.LINK
    AD Equivalent: Check-PrivilegedAccountsSmartcard
    Graph Reference: https://learn.microsoft.com/en-us/graph/api/reportroot-list-credentialuserregistrationdetails
#>
function Test-PrivilegedUserMFACoverage {
    Write-Host "`n[+] Checking MFA registration for privileged users..." -ForegroundColor Cyan
    
    # Privileged roles to check
    $privilegedRoleNames = @(
        "Global Administrator",
        "Privileged Role Administrator",
        "Privileged Authentication Administrator",
        "Security Administrator",
        "User Administrator",
        "Exchange Administrator",
        "SharePoint Administrator",
        "Application Administrator",
        "Cloud Application Administrator",
        "Authentication Administrator"
    )
    
    try {
        # Get directory roles
        $directoryRoles = Invoke-GraphRequest -Uri "https://graph.microsoft.com/v1.0/directoryRoles" -AllPages
        
        $privilegedUsers = @{}
        
        # Collect all privileged users
        foreach ($role in $directoryRoles) {
            if ($privilegedRoleNames -contains $role.displayName) {
                $members = Invoke-GraphRequest -Uri "https://graph.microsoft.com/v1.0/directoryRoles/$($role.id)/members" -AllPages
                
                foreach ($member in $members) {
                    if ($member.'@odata.type' -eq '#microsoft.graph.user') {
                        if (-not $privilegedUsers.ContainsKey($member.id)) {
                            $privilegedUsers[$member.id] = @{
                                Id = $member.id
                                UPN = $member.userPrincipalName
                                DisplayName = $member.displayName
                                Roles = @()
                            }
                        }
                        $privilegedUsers[$member.id].Roles += $role.displayName
                    }
                }
            }
        }
        
        if ($privilegedUsers.Count -eq 0) {
            Add-Finding -Status "INFO" `
                -Object "Privileged User MFA" `
                -Description "No users found in privileged directory roles." `
                -Remediation "No action needed."
            return
        }
        
        # Try to get MFA registration details
        $usersWithoutMFA = @()
        $usersWithWeakMFA = @()
        $usersWithStrongMFA = @()

        # First try the userRegistrationDetails endpoint (most reliable, requires AuditLog.Read.All)
        $registrationDetails = @{}
        $useRegistrationApi = $false
        try {
            $regData = Invoke-GraphRequest -Uri "https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails" -AllPages
            if ($regData) {
                foreach ($reg in $regData) {
                    if ($reg.id) {
                        $registrationDetails[$reg.id] = $reg
                    }
                }
                $useRegistrationApi = $true
                Write-Host "    [i] Using userRegistrationDetails API for MFA status" -ForegroundColor Gray
            }
        }
        catch {
            Write-Verbose "userRegistrationDetails not available: $($_.Exception.Message). Falling back to per-user method check."
        }

        $strongMethods = @("fido2", "microsoftAuthenticator", "windowsHelloForBusiness", "softwareOath")
        $weakMethods = @("mobilePhone", "alternateMobilePhone", "email")

        foreach ($userId in $privilegedUsers.Keys) {
            $user = $privilegedUsers[$userId]

            # Method 1: Use registration details API (preferred - more accurate)
            if ($useRegistrationApi -and $registrationDetails.ContainsKey($userId)) {
                $regDetail = $registrationDetails[$userId]
                $isMfaRegistered = $regDetail.isMfaRegistered
                $isMfaCapable = $regDetail.isMfaCapable
                $methodsRegistered = @($regDetail.methodsRegistered)

                if ($isMfaRegistered -or $isMfaCapable) {
                    # Check method strength
                    $hasStrong = $false
                    foreach ($m in $methodsRegistered) {
                        if ($m -in @("fido2", "microsoftAuthenticator", "windowsHelloForBusiness", "softwareOath", "passKeyDeviceBound", "passKeyDeviceBoundAuthenticator")) {
                            $hasStrong = $true
                            break
                        }
                    }
                    if ($hasStrong) {
                        $usersWithStrongMFA += @{
                            User = $user
                            Methods = $methodsRegistered
                        }
                    }
                    else {
                        $usersWithWeakMFA += @{
                            User = $user
                            Methods = $methodsRegistered
                        }
                    }
                }
                else {
                    $usersWithoutMFA += $user
                }
                continue
            }

            # Method 2: Fall back to per-user authentication methods endpoint
            try {
                $methods = Invoke-GraphRequest -Uri "https://graph.microsoft.com/v1.0/users/$userId/authentication/methods" -AllPages

                if (-not $methods -or $methods.Count -eq 0) {
                    $usersWithoutMFA += $user
                    continue
                }

                # Analyze methods
                $userStrongMethods = @()
                $userWeakMethods = @()

                foreach ($method in $methods) {
                    $methodType = $method.'@odata.type' -replace '#microsoft.graph.', '' -replace 'AuthenticationMethod', ''

                    if ($methodType -eq "password") {
                        continue  # Password doesn't count as MFA
                    }

                    if ($strongMethods -contains $methodType) {
                        $userStrongMethods += $methodType
                    }
                    elseif ($weakMethods -contains $methodType -or $methodType -eq "phone") {
                        $userWeakMethods += $methodType
                    }
                    else {
                        # Unknown method type - treat as weak MFA (at least it's something)
                        $userWeakMethods += $methodType
                    }
                }

                if ($userStrongMethods.Count -eq 0 -and $userWeakMethods.Count -eq 0) {
                    $usersWithoutMFA += $user
                }
                elseif ($userStrongMethods.Count -gt 0) {
                    $usersWithStrongMFA += @{
                        User = $user
                        Methods = $userStrongMethods
                    }
                }
                else {
                    $usersWithWeakMFA += @{
                        User = $user
                        Methods = $userWeakMethods
                    }
                }
            }
            catch {
                Add-Finding -Status "WARNING" `
                    -Object $user.UPN `
                    -Description "Unable to retrieve MFA methods for privileged user '$($user.DisplayName)' ($($user.UPN)). Roles: $($user.Roles -join ', ')" `
                    -Remediation "Ensure UserAuthenticationMethod.Read.All permission is granted to check MFA status."
            }
        }
        
        # Report findings
        foreach ($user in $usersWithoutMFA) {
            Add-Finding -Status "FAIL" `
                -Object "$($user.UPN)" `
                -Description "Privileged user '$($user.DisplayName)' has NO MFA methods registered. Roles: $($user.Roles -join ', '). This account is vulnerable to credential theft." `
                -Remediation "Immediately require this user to register MFA. Consider blocking sign-in until MFA is registered."
        }
        
        foreach ($item in $usersWithWeakMFA) {
            $user = $item.User
            $methods = $item.Methods
            Add-Finding -Status "WARNING" `
                -Object "$($user.UPN)" `
                -Description "Privileged user '$($user.DisplayName)' only has weak MFA methods: $($methods -join ', '). Roles: $($user.Roles -join ', '). SMS/Phone can be intercepted." `
                -Remediation "Encourage this user to register stronger MFA methods (Microsoft Authenticator, FIDO2 security key)."
        }
        
        # Summary
        $totalPrivileged = $privilegedUsers.Count
        $withoutMFA = $usersWithoutMFA.Count
        $withWeak = $usersWithWeakMFA.Count
        $withStrong = $usersWithStrongMFA.Count
        
        Add-Finding -Status "INFO" `
            -Object "Privileged User MFA Summary" `
            -Description "Total privileged users: $totalPrivileged. Without MFA: $withoutMFA. Weak MFA only: $withWeak. Strong MFA: $withStrong." `
            -Remediation "Ensure all privileged users have strong MFA methods registered."
        
        if ($withoutMFA -eq 0 -and $withWeak -eq 0) {
            Add-Finding -Status "OK" `
                -Object "Privileged User MFA Coverage" `
                -Description "All privileged users have MFA methods registered." `
                -Remediation "No action needed. Continue to monitor MFA registration."
        }
    }
    catch {
        Add-Finding -Status "WARNING" `
            -Object "Privileged User MFA" `
            -Description "Unable to check privileged user MFA coverage: $($_.Exception.Message)" `
            -Remediation "Check Graph permissions (UserAuthenticationMethod.Read.All, Directory.Read.All required)."
    }
}

<#
.SYNOPSIS
    Test-CrossTenantAccessPolicy - Audits B2B collaboration and cross-tenant trust.

.DESCRIPTION
    Equivalent to: Check-DomainTrusts (AD version - trust relationships)
    
    Examines cross-tenant access settings:
    - Default inbound/outbound access settings
    - Partner-specific configurations
    - B2B collaboration restrictions
    - B2B direct connect settings
    
    Graph Endpoints Used:
    - GET /policies/crossTenantAccessPolicy
    - GET /policies/crossTenantAccessPolicy/default
    - GET /policies/crossTenantAccessPolicy/partners
    
.OUTPUTS
    Findings with Status: INFO for inventory, WARNING for permissive settings
    
.NOTES
    Required Permissions: Policy.Read.All
    Minimum License: Azure AD Free (basic), P1/P2 for advanced settings
    
.LINK
    AD Equivalent: Check-DomainTrusts
    Graph Reference: https://learn.microsoft.com/en-us/graph/api/crosstenantaccesspolicy-get
#>
function Test-CrossTenantAccessPolicy {
    Write-Host "`n[+] Checking cross-tenant access policy (B2B trust)..." -ForegroundColor Cyan
    
    try {
        # Get default cross-tenant access settings
        $defaultPolicy = Invoke-GraphRequest -Uri "https://graph.microsoft.com/v1.0/policies/crossTenantAccessPolicy/default"
        
        # Get partner-specific configurations
        $partners = $null
        try {
            $partners = Invoke-GraphRequest -Uri "https://graph.microsoft.com/v1.0/policies/crossTenantAccessPolicy/partners" -AllPages
        }
        catch {
            Write-Verbose "No partner configurations found or access denied: $_"
        }
        
        # Analyze default inbound settings (how external users access this tenant)
        $inboundDefaults = $defaultPolicy.b2bCollaborationInbound
        $outboundDefaults = $defaultPolicy.b2bCollaborationOutbound
        
        # Check inbound defaults
        $inboundSummary = @()
        if ($inboundDefaults) {
            if ($inboundDefaults.usersAndGroups.accessType -eq "allowed") {
                $inboundSummary += "Users: Allowed"
            }
            else {
                $inboundSummary += "Users: Blocked"
            }
            if ($inboundDefaults.applications.accessType -eq "allowed") {
                $inboundSummary += "Apps: Allowed"
            }
            else {
                $inboundSummary += "Apps: Blocked"
            }
        }
        
        # Check outbound defaults
        $outboundSummary = @()
        if ($outboundDefaults) {
            if ($outboundDefaults.usersAndGroups.accessType -eq "allowed") {
                $outboundSummary += "Users: Allowed"
            }
            else {
                $outboundSummary += "Users: Blocked"
            }
            if ($outboundDefaults.applications.accessType -eq "allowed") {
                $outboundSummary += "Apps: Allowed"
            }
            else {
                $outboundSummary += "Apps: Blocked"
            }
        }
        
        # Summary finding
        Add-Finding -Status "INFO" `
            -Object "Cross-Tenant Access Defaults" `
            -Description "Default B2B Inbound: $($inboundSummary -join ', '). Default B2B Outbound: $($outboundSummary -join ', ')." `
            -Remediation "Review default settings. Consider restricting inbound/outbound access to specific trusted organizations."
        
        # Check if inbound is wide open
        if ($inboundDefaults.usersAndGroups.accessType -eq "allowed" -and 
            (-not $inboundDefaults.usersAndGroups.targets -or $inboundDefaults.usersAndGroups.targets.Count -eq 0)) {
            Add-Finding -Status "INFO" `
                -Object "B2B Inbound Access" `
                -Description "Default inbound B2B collaboration allows users from any external Azure AD tenant. This is common but may be more permissive than needed." `
                -Remediation "Consider restricting inbound B2B to specific partner organizations if you have a defined list of trusted partners."
        }
        
        # Check trust settings (MFA and device trust)
        if ($inboundDefaults) {
            $trustMFA = $defaultPolicy.inboundTrust.isMfaAccepted
            $trustCompliantDevice = $defaultPolicy.inboundTrust.isCompliantDeviceAccepted
            $trustHybridDevice = $defaultPolicy.inboundTrust.isHybridAzureADJoinedDeviceAccepted
            
            $trustSettings = @()
            if ($trustMFA) { $trustSettings += "MFA claims" }
            if ($trustCompliantDevice) { $trustSettings += "Compliant device claims" }
            if ($trustHybridDevice) { $trustSettings += "Hybrid Azure AD join claims" }
            
            if ($trustSettings.Count -gt 0) {
                Add-Finding -Status "INFO" `
                    -Object "Inbound Trust Settings" `
                    -Description "This tenant trusts the following claims from external tenants by default: $($trustSettings -join ', ')." `
                    -Remediation "Trusting external MFA/device claims can improve user experience but relies on partner security. Evaluate based on your security requirements."
            }
            else {
                Add-Finding -Status "INFO" `
                    -Object "Inbound Trust Settings" `
                    -Description "This tenant does not trust MFA or device claims from external tenants by default. External users will need to satisfy this tenant's MFA requirements." `
                    -Remediation "This is a more secure default. Consider enabling trust for specific partner organizations if needed."
            }
        }
        
        # Check partner-specific configurations
        if ($partners -and $partners.Count -gt 0) {
            Add-Finding -Status "INFO" `
                -Object "Partner Configurations" `
                -Description "Found $($partners.Count) partner-specific cross-tenant access configurations. These override the default settings for specific organizations." `
                -Remediation "Review each partner configuration to ensure appropriate access levels."
            
            foreach ($partner in $partners) {
                $tenantId = $partner.tenantId
                
                # Check if this partner has elevated trust
                $partnerTrust = @()
                if ($partner.inboundTrust) {
                    if ($partner.inboundTrust.isMfaAccepted) { $partnerTrust += "MFA" }
                    if ($partner.inboundTrust.isCompliantDeviceAccepted) { $partnerTrust += "Compliant Device" }
                }
                
                if ($partnerTrust.Count -gt 0) {
                    Add-Finding -Status "INFO" `
                        -Object "Partner: $tenantId" `
                        -Description "Partner tenant '$tenantId' has elevated trust: $($partnerTrust -join ', ')." `
                        -Remediation "Verify this partner's security posture justifies the elevated trust."
                }
            }
        }
        else {
            Add-Finding -Status "INFO" `
                -Object "Partner Configurations" `
                -Description "No partner-specific cross-tenant access configurations found. All external access uses default settings." `
                -Remediation "Consider adding partner-specific configurations for trusted organizations to customize access."
        }
    }
    catch {
        Add-Finding -Status "WARNING" `
            -Object "Cross-Tenant Access" `
            -Description "Unable to check cross-tenant access policy: $($_.Exception.Message)" `
            -Remediation "Check Graph permissions (Policy.Read.All required)."
    }
}

<#
.SYNOPSIS
    Test-AuthorizationPolicy - Audits tenant-wide authorization settings.

.DESCRIPTION
    Examines the authorization policy for security-relevant settings:
    - Whether users can consent to apps
    - Whether users can invite guests
    - Whether users can create security groups
    - Whether users can read other users
    - Default user role permissions
    
    Graph Endpoints Used:
    - GET /policies/authorizationPolicy
    
.OUTPUTS
    Findings with Status: INFO for settings, WARNING for permissive configurations
    
.NOTES
    Required Permissions: Policy.Read.All
    Minimum License: Azure AD Free
    
.LINK
    Graph Reference: https://learn.microsoft.com/en-us/graph/api/authorizationpolicy-get
#>
function Test-AuthorizationPolicy {
    Write-Host "`n[+] Checking authorization policy settings..." -ForegroundColor Cyan
    
    try {
        # Get authorization policy
        $authzPolicy = Invoke-GraphRequest -Uri "https://graph.microsoft.com/v1.0/policies/authorizationPolicy"
        
        if (-not $authzPolicy) {
            Add-Finding -Status "WARNING" `
                -Object "Authorization Policy" `
                -Description "Unable to retrieve authorization policy." `
                -Remediation "Check permissions and try again."
            return
        }
        
        # Check user consent settings
        $defaultUserRolePermissions = $authzPolicy.defaultUserRolePermissions
        
        # Can users consent to apps?
        $permissionGrantPolicies = $authzPolicy.permissionGrantPolicyIdsAssignedToDefaultUserRole
        $canUserConsent = $permissionGrantPolicies -and $permissionGrantPolicies.Count -gt 0
        
        if ($canUserConsent) {
            # Check what kind of consent is allowed
            $consentPolicies = $permissionGrantPolicies -join ', '
            
            if ($permissionGrantPolicies -contains "microsoft-user-default-legacy") {
                Add-Finding -Status "WARNING" `
                    -Object "User App Consent" `
                    -Description "Users can consent to third-party applications accessing company data on their behalf (legacy policy). This can lead to data exfiltration via malicious apps." `
                    -Remediation "Restrict user consent. Implement an admin consent workflow so IT can review app requests."
            }
            elseif ($permissionGrantPolicies -contains "microsoft-user-default-low") {
                Add-Finding -Status "INFO" `
                    -Object "User App Consent" `
                    -Description "Users can consent to apps from verified publishers for low-risk permissions only. This is a reasonable balance of usability and security." `
                    -Remediation "Monitor consent grants regularly. Consider further restrictions if consent abuse is observed."
            }
            else {
                Add-Finding -Status "INFO" `
                    -Object "User App Consent" `
                    -Description "User consent policy: $consentPolicies" `
                    -Remediation "Review the consent policy to ensure it meets security requirements."
            }
        }
        else {
            Add-Finding -Status "OK" `
                -Object "User App Consent" `
                -Description "Users cannot consent to applications. All app consent requires administrator approval." `
                -Remediation "This is the most secure setting. Ensure an admin consent workflow is in place."
        }
        
        # Check guest invite settings
        $allowInvitesFrom = $authzPolicy.allowInvitesFrom
        
        switch ($allowInvitesFrom) {
            "everyone" {
                Add-Finding -Status "WARNING" `
                    -Object "Guest Invitations" `
                    -Description "Anyone, including guests, can invite external users. This is the most permissive setting." `
                    -Remediation "Restrict guest invitations to admins only or specific roles to prevent uncontrolled external access."
            }
            "adminsAndGuestInviters" {
                Add-Finding -Status "INFO" `
                    -Object "Guest Invitations" `
                    -Description "Admins and users in the Guest Inviter role can invite guests." `
                    -Remediation "Review who has the Guest Inviter role. Consider restricting further if needed."
            }
            "adminsGuestInvitersAndAllMembers" {
                Add-Finding -Status "INFO" `
                    -Object "Guest Invitations" `
                    -Description "All member users can invite guests. Guests cannot invite other guests." `
                    -Remediation "Consider restricting to admins/guest inviters only for tighter control."
            }
            "none" {
                Add-Finding -Status "OK" `
                    -Object "Guest Invitations" `
                    -Description "Only admins can invite guests. This is the most restrictive setting." `
                    -Remediation "No action needed. This provides maximum control over external access."
            }
            default {
                Add-Finding -Status "INFO" `
                    -Object "Guest Invitations" `
                    -Description "Guest invitation setting: $allowInvitesFrom" `
                    -Remediation "Review this setting to ensure it meets security requirements."
            }
        }
        
        # Check if users can create security groups
        if ($defaultUserRolePermissions) {
            $canCreateSecurityGroups = $defaultUserRolePermissions.allowedToCreateSecurityGroups
            
            if ($canCreateSecurityGroups) {
                Add-Finding -Status "INFO" `
                    -Object "Security Group Creation" `
                    -Description "Users can create security groups. This can lead to group sprawl and unmanaged access." `
                    -Remediation "Consider restricting security group creation to administrators to maintain governance."
            }
            else {
                Add-Finding -Status "OK" `
                    -Object "Security Group Creation" `
                    -Description "Users cannot create security groups. Only administrators can create groups." `
                    -Remediation "No action needed."
            }
            
            # Check if users can create tenants
            $canCreateTenants = $defaultUserRolePermissions.allowedToCreateTenants
            
            if ($canCreateTenants) {
                Add-Finding -Status "WARNING" `
                    -Object "Tenant Creation" `
                    -Description "Users can create new Azure AD tenants. This can lead to shadow IT and unmanaged environments." `
                    -Remediation "Disable tenant creation by regular users to prevent shadow IT."
            }
            else {
                Add-Finding -Status "OK" `
                    -Object "Tenant Creation" `
                    -Description "Users cannot create new Azure AD tenants." `
                    -Remediation "No action needed."
            }
            
            # Check if users can read other users
            $canReadOtherUsers = $defaultUserRolePermissions.allowedToReadOtherUsers
            
            if ($canReadOtherUsers -eq $false) {
                Add-Finding -Status "INFO" `
                    -Object "User Directory Visibility" `
                    -Description "Users cannot read other users' directory information. This improves privacy but may impact collaboration features." `
                    -Remediation "This is appropriate for highly sensitive environments. Verify it doesn't break required functionality."
            }
        }

        # Summary
        Add-Finding -Status "INFO" `
            -Object "Authorization Policy Summary" `
            -Description "Guest invites: $allowInvitesFrom. User consent: $(if ($canUserConsent) { 'Allowed (with restrictions)' } else { 'Blocked' })." `
            -Remediation "Review these settings annually or when security requirements change."
    }
    catch {
        Add-Finding -Status "WARNING" `
            -Object "Authorization Policy" `
            -Description "Unable to check authorization policy: $($_.Exception.Message)" `
            -Remediation "Check Graph permissions (Policy.Read.All required)."
    }
}

#endregion

#region ==================== PHASE 5: GOVERNANCE & AUDIT CHECKS ====================

<#
.SYNOPSIS
    Test-AdminUnitDelegation - Audits administrative unit configurations.

.DESCRIPTION
    Equivalent to: Check-OUDelegation (AD version)
    
    Examines administrative units and their delegated management:
    - Lists all administrative units
    - Identifies scoped role assignments
    - Checks for restricted management AU configurations
    - Reviews AU membership
    
    Graph Endpoints Used:
    - GET /directory/administrativeUnits
    - GET /directory/administrativeUnits/{id}/scopedRoleMembers
    
.OUTPUTS
    Findings with Status: INFO for inventory, WARNING for potential issues
    
.NOTES
    Required Permissions: AdministrativeUnit.Read.All, RoleManagement.Read.Directory
    Minimum License: Azure AD P1
    
.LINK
    AD Equivalent: Check-OUDelegation
    Graph Reference: https://learn.microsoft.com/en-us/graph/api/directory-list-administrativeunits
#>
function Test-AdminUnitDelegation {
    Write-Host "`n[+] Checking administrative unit delegation..." -ForegroundColor Cyan
    
    try {
        # Get all administrative units
        $adminUnits = Invoke-GraphRequest -Uri "https://graph.microsoft.com/v1.0/directory/administrativeUnits?`$select=id,displayName,description,membershipType,membershipRule,visibility&`$top=999" -AllPages
        
        if (-not $adminUnits -or $adminUnits.Count -eq 0) {
            Add-Finding -Status "INFO" `
                -Object "Administrative Units" `
                -Description "No administrative units found in the tenant. Administrative units are used for delegated administration of subsets of users/groups." `
                -Remediation "Consider using administrative units if you need to delegate administration to specific departments or regions."
            return
        }
        
        $totalAUs = $adminUnits.Count
        $restrictedAUs = 0
        $dynamicAUs = 0
        $totalScopedAssignments = 0
        
        foreach ($au in $adminUnits) {
            # Check for restricted management
            $isRestricted = $au.visibility -eq "HiddenMembership"
            if ($isRestricted) { $restrictedAUs++ }
            
            # Check for dynamic membership
            $isDynamic = $au.membershipType -eq "Dynamic"
            if ($isDynamic) { $dynamicAUs++ }
            
            # Get scoped role assignments for this AU
            try {
                $scopedRoleMembers = Invoke-GraphRequest -Uri "https://graph.microsoft.com/v1.0/directory/administrativeUnits/$($au.id)/scopedRoleMembers" -AllPages
                
                if ($scopedRoleMembers -and $scopedRoleMembers.Count -gt 0) {
                    $totalScopedAssignments += $scopedRoleMembers.Count
                    
                    $roleAssignments = @()
                    foreach ($assignment in $scopedRoleMembers) {
                        # Get role name
                        $roleName = "Unknown Role"
                        try {
                            $role = Invoke-GraphRequest -Uri "https://graph.microsoft.com/v1.0/directoryRoles/$($assignment.roleId)?`$select=displayName"
                            if ($role) { $roleName = $role.displayName }
                        }
                        catch { Write-Verbose "Could not resolve role name: $_" }

                        # Get member info
                        $memberName = "Unknown"
                        try {
                            $member = Invoke-GraphRequest -Uri "https://graph.microsoft.com/v1.0/directoryObjects/$($assignment.roleMemberInfo.id)?`$select=displayName"
                            if ($member) { $memberName = $member.displayName }
                        }
                        catch { Write-Verbose "Could not resolve member name: $_" }
                        
                        $roleAssignments += "$memberName ($roleName)"
                    }
                    
                    Add-Finding -Status "INFO" `
                        -Object "AU: $($au.displayName)" `
                        -Description "Administrative unit '$($au.displayName)' has $($scopedRoleMembers.Count) scoped role assignment(s): $($roleAssignments -join '; ')" `
                        -Remediation "Review scoped administrators to ensure appropriate delegation."
                }
            }
            catch {
                Write-Verbose "Could not query AU scoped role members: $_"
            }
        }
        
        # Summary finding
        Add-Finding -Status "INFO" `
            -Object "Administrative Units Summary" `
            -Description "Total AUs: $totalAUs. Restricted (hidden membership): $restrictedAUs. Dynamic membership: $dynamicAUs. Total scoped role assignments: $totalScopedAssignments." `
            -Remediation "Review administrative units and their delegated administrators periodically."
        
        # Flag if no AUs have delegated admins
        if ($totalScopedAssignments -eq 0 -and $totalAUs -gt 0) {
            Add-Finding -Status "INFO" `
                -Object "AU Delegation" `
                -Description "Administrative units exist but have no scoped role assignments. AUs may not be actively used for delegation." `
                -Remediation "If AUs are intended for delegated administration, assign scoped roles to appropriate administrators."
        }
    }
    catch {
        Add-Finding -Status "WARNING" `
            -Object "Administrative Units" `
            -Description "Unable to check administrative units: $($_.Exception.Message)" `
            -Remediation "Check Graph permissions (AdministrativeUnit.Read.All required). AUs require Azure AD P1."
    }
}

<#
.SYNOPSIS
    Test-PIMConfiguration - Audits Privileged Identity Management settings.

.DESCRIPTION
    Equivalent to: N/A (cloud-specific, similar concept to time-limited admin access)
    
    Examines PIM configuration for:
    - Whether PIM is enabled/in use
    - Role settings (approval, duration, justification)
    - Eligible vs active assignments
    - Alert configurations
    
    Graph Endpoints Used:
    - GET /roleManagement/directory/roleEligibilitySchedules
    - GET /roleManagement/directory/roleAssignmentSchedules
    - GET /policies/roleManagementPolicies
    
.OUTPUTS
    Findings with Status: INFO for inventory, WARNING for weak settings
    
.NOTES
    Required Permissions: RoleManagement.Read.Directory
    Minimum License: Azure AD P2 (PIM requires P2)
    
.LINK
    Graph Reference: https://learn.microsoft.com/en-us/graph/api/rbacapplication-list-roleeligibilityschedules
#>
function Test-PIMConfiguration {
    Write-Host "`n[+] Checking Privileged Identity Management (PIM) configuration..." -ForegroundColor Cyan
    
    # Check if PIM is available
    if (-not $script:TenantCapabilities.HasPIM) {
        Add-Finding -Status "INFO" `
            -Object "Privileged Identity Management" `
            -Description "PIM is not available. This typically means the tenant does not have Azure AD P2 licensing." `
            -Remediation "Consider upgrading to Azure AD P2 to enable PIM for just-in-time privileged access."
        return
    }
    
    try {
        # Get eligible role assignments (PIM)
        $eligibleAssignments = Invoke-GraphRequest -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilitySchedules?`$expand=principal,roleDefinition&`$top=999" -AllPages
        
        # Get active role assignments
        $activeAssignments = Invoke-GraphRequest -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentSchedules?`$expand=principal,roleDefinition&`$top=999" -AllPages
        
        $eligibleCount = if ($eligibleAssignments) { $eligibleAssignments.Count } else { 0 }
        $activeCount = if ($activeAssignments) { $activeAssignments.Count } else { 0 }
        
        # Summary finding
        Add-Finding -Status "INFO" `
            -Object "PIM Summary" `
            -Description "PIM is available. Eligible (just-in-time) assignments: $eligibleCount. Permanent/active assignments: $activeCount." `
            -Remediation "Prefer eligible (JIT) assignments over permanent assignments for privileged roles."
        
        # Check if PIM is actually being used
        if ($eligibleCount -eq 0) {
            Add-Finding -Status "WARNING" `
                -Object "PIM Usage" `
                -Description "PIM is available but no eligible (just-in-time) role assignments are configured. All privileged access appears to be permanently assigned." `
                -Remediation "Configure eligible assignments for privileged roles to enable just-in-time access. This reduces standing privilege exposure."
        }
        else {
            Add-Finding -Status "OK" `
                -Object "PIM Usage" `
                -Description "PIM eligible assignments are in use ($eligibleCount eligible vs $activeCount active)." `
                -Remediation "Continue to expand PIM usage. Aim to have most privileged access via eligible assignments."
        }
        
        # Analyze eligible assignments by role
        if ($eligibleAssignments -and $eligibleAssignments.Count -gt 0) {
            $roleStats = @{}
            
            foreach ($assignment in $eligibleAssignments) {
                $roleName = if ($assignment.roleDefinition) { $assignment.roleDefinition.displayName } else { "Unknown" }
                if (-not $roleStats.ContainsKey($roleName)) {
                    $roleStats[$roleName] = 0
                }
                $roleStats[$roleName]++
            }
            
            $topRoles = ($roleStats.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 5 | ForEach-Object { "$($_.Key): $($_.Value)" }) -join ", "
            
            Add-Finding -Status "INFO" `
                -Object "PIM Eligible Roles" `
                -Description "Top roles with eligible assignments: $topRoles" `
                -Remediation "Ensure high-risk roles like Global Administrator use PIM eligible assignments."
        }
        
        # Check Global Administrator specifically
        $gaEligible = $eligibleAssignments | Where-Object { $_.roleDefinition.displayName -eq "Global Administrator" }
        $gaActive = $activeAssignments | Where-Object { $_.roleDefinition.displayName -eq "Global Administrator" }
        
        $gaEligibleCount = if ($gaEligible) { $gaEligible.Count } else { 0 }
        $gaActiveCount = if ($gaActive) { $gaActive.Count } else { 0 }
        
        if ($gaActiveCount -gt 2) {
            Add-Finding -Status "WARNING" `
                -Object "Global Admin Assignments" `
                -Description "There are $gaActiveCount permanent/active Global Administrator assignments. Only break-glass accounts should have permanent GA access." `
                -Remediation "Convert permanent Global Admin assignments to PIM eligible assignments (except 2 break-glass accounts)."
        }
        elseif ($gaActiveCount -gt 0 -and $gaEligibleCount -gt 0) {
            Add-Finding -Status "INFO" `
                -Object "Global Admin Assignments" `
                -Description "Global Administrator: $gaActiveCount permanent, $gaEligibleCount eligible. Recommend keeping only break-glass accounts as permanent." `
                -Remediation "Review if all permanent GA assignments are break-glass accounts."
        }
        
        # Try to get role management policies (for activation settings)
        try {
            $policies = Invoke-GraphRequest -Uri "https://graph.microsoft.com/v1.0/policies/roleManagementPolicies?`$filter=scopeId eq '/' and scopeType eq 'DirectoryRole'&`$top=100" -AllPages
            
            if ($policies -and $policies.Count -gt 0) {
                # Check a sample policy for settings
                # Note: Full policy analysis requires examining rules which is complex
                Add-Finding -Status "INFO" `
                    -Object "PIM Role Policies" `
                    -Description "Found $($policies.Count) role management policies. These control activation requirements like approval, MFA, and justification." `
                    -Remediation "Review role management policies to ensure appropriate controls (approval required for GA, reasonable activation duration)."
            }
        }
        catch {
            Write-Verbose "PIM policies endpoint not accessible: $_"
        }
    }
    catch {
        Add-Finding -Status "WARNING" `
            -Object "PIM Configuration" `
            -Description "Unable to check PIM configuration: $($_.Exception.Message)" `
            -Remediation "Check Graph permissions (RoleManagement.Read.Directory required) and Azure AD P2 licensing."
    }
}

<#
.SYNOPSIS
    Test-AuditLogRetention - Checks audit log availability and retention.

.DESCRIPTION
    Equivalent to: Check-DomainControllers (AD version - health/logging check)
    
    Examines audit log availability:
    - Tests access to sign-in logs
    - Tests access to audit logs
    - Checks log age/availability
    - Identifies retention limitations
    
    Graph Endpoints Used:
    - GET /auditLogs/signIns
    - GET /auditLogs/directoryAudits
    
.OUTPUTS
    Findings with Status: INFO for details, WARNING for retention concerns
    
.NOTES
    Required Permissions: AuditLog.Read.All
    Minimum License: Azure AD P1 (sign-in logs require P1)
    
.LINK
    AD Equivalent: Check-DomainControllers (logging aspect)
    Graph Reference: https://learn.microsoft.com/en-us/graph/api/signin-list
#>
function Test-AuditLogRetention {
    Write-Host "`n[+] Checking audit log availability and retention..." -ForegroundColor Cyan
    
    $now = Get-Date
    
    try {
        # Test sign-in logs
        $signInLogsAvailable = $false
        $oldestSignIn = $null
        
        try {
            # Get oldest sign-in we can access
            $signIns = Invoke-GraphRequest -Uri "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$top=1&`$orderby=createdDateTime asc"
            
            if ($signIns.value -and $signIns.value.Count -gt 0) {
                $signInLogsAvailable = $true
                $oldestSignIn = [DateTime]$signIns.value[0].createdDateTime
            }
        }
        catch {
            Write-Verbose "Sign-in logs not available (likely no P1 license): $_"
        }
        
        # Test audit/directory logs
        $auditLogsAvailable = $false
        $oldestAudit = $null
        
        try {
            # Get oldest audit log we can access
            $audits = Invoke-GraphRequest -Uri "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?`$top=1&`$orderby=activityDateTime asc"
            
            if ($audits.value -and $audits.value.Count -gt 0) {
                $auditLogsAvailable = $true
                $oldestAudit = [DateTime]$audits.value[0].activityDateTime
            }
        }
        catch {
            Write-Verbose "Audit logs not available: $_"
        }
        
        # Report sign-in log status
        if ($signInLogsAvailable) {
            $signInRetentionDays = [math]::Round(($now - $oldestSignIn).TotalDays, 0)
            
            if ($signInRetentionDays -lt 7) {
                Add-Finding -Status "WARNING" `
                    -Object "Sign-In Logs" `
                    -Description "Sign-in logs available but only $signInRetentionDays days of history accessible. Oldest log: $($oldestSignIn.ToString('yyyy-MM-dd'))." `
                    -Remediation "Default retention is 30 days. Consider exporting to Azure Log Analytics for longer retention (up to 2 years)."
            }
            elseif ($signInRetentionDays -le 30) {
                Add-Finding -Status "INFO" `
                    -Object "Sign-In Logs" `
                    -Description "Sign-in logs available with approximately $signInRetentionDays days of history. Oldest log: $($oldestSignIn.ToString('yyyy-MM-dd'))." `
                    -Remediation "For compliance or investigation needs, export to Azure Log Analytics or SIEM for longer retention."
            }
            else {
                Add-Finding -Status "OK" `
                    -Object "Sign-In Logs" `
                    -Description "Sign-in logs available with $signInRetentionDays days of history (extended retention likely via Log Analytics)." `
                    -Remediation "No action needed. Continue to monitor log availability."
            }
        }
        else {
            Add-Finding -Status "WARNING" `
                -Object "Sign-In Logs" `
                -Description "Sign-in logs are NOT available. This typically requires Azure AD P1 licensing." `
                -Remediation "Upgrade to Azure AD P1 to enable sign-in logs. These are critical for security monitoring and incident investigation."
        }
        
        # Report audit log status
        if ($auditLogsAvailable) {
            $auditRetentionDays = [math]::Round(($now - $oldestAudit).TotalDays, 0)
            
            if ($auditRetentionDays -lt 7) {
                Add-Finding -Status "WARNING" `
                    -Object "Directory Audit Logs" `
                    -Description "Audit logs available but only $auditRetentionDays days of history accessible. Oldest log: $($oldestAudit.ToString('yyyy-MM-dd'))." `
                    -Remediation "Export to Azure Log Analytics or SIEM for longer retention and compliance."
            }
            else {
                Add-Finding -Status "INFO" `
                    -Object "Directory Audit Logs" `
                    -Description "Directory audit logs available with approximately $auditRetentionDays days of history. Oldest log: $($oldestAudit.ToString('yyyy-MM-dd'))." `
                    -Remediation "For compliance needs (7 years for some regulations), export to long-term storage."
            }
        }
        else {
            Add-Finding -Status "WARNING" `
                -Object "Directory Audit Logs" `
                -Description "Directory audit logs are NOT accessible." `
                -Remediation "Check AuditLog.Read.All permission. Audit logs should be available on all license tiers."
        }
        
        # Summary
        $summary = @()
        if ($signInLogsAvailable) { $summary += "Sign-in: Yes" } else { $summary += "Sign-in: No (P1 required)" }
        if ($auditLogsAvailable) { $summary += "Audit: Yes" } else { $summary += "Audit: No" }
        
        Add-Finding -Status "INFO" `
            -Object "Audit Log Summary" `
            -Description "Log availability: $($summary -join ', '). Standard retention is 30 days." `
            -Remediation "Configure Azure Diagnostic Settings to export logs to Log Analytics workspace or storage account for extended retention."
    }
    catch {
        Add-Finding -Status "WARNING" `
            -Object "Audit Logs" `
            -Description "Unable to check audit log availability: $($_.Exception.Message)" `
            -Remediation "Check Graph permissions (AuditLog.Read.All required)."
    }
}

<#
.SYNOPSIS
    Test-DirectoryRoleAssignmentPaths - Analyzes role assignment patterns and paths.

.DESCRIPTION
    Equivalent to: Check-AdminSDHolderDrift (AD version - privilege analysis)
    
    Examines how directory roles are assigned:
    - Direct user assignments vs group assignments
    - PIM eligible vs permanent assignments
    - Role-assignable groups used for roles
    - Identifies unusual assignment patterns
    
    Graph Endpoints Used:
    - GET /roleManagement/directory/roleAssignments
    - GET /directoryRoles/{id}/members
    
.OUTPUTS
    Findings with Status: INFO for patterns, WARNING for risky configurations
    
.NOTES
    Required Permissions: RoleManagement.Read.Directory, Directory.Read.All
    Minimum License: Azure AD Free (basic), P2 for PIM analysis
    
.LINK
    AD Equivalent: Check-AdminSDHolderDrift
    Graph Reference: https://learn.microsoft.com/en-us/graph/api/rbacapplication-list-roleassignments
#>
function Test-DirectoryRoleAssignmentPaths {
    Write-Host "`n[+] Checking directory role assignment patterns..." -ForegroundColor Cyan
    
    try {
        # Get all role assignments
        $roleAssignments = Invoke-GraphRequest -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?`$expand=principal,roleDefinition&`$top=999" -AllPages
        
        if (-not $roleAssignments -or $roleAssignments.Count -eq 0) {
            Add-Finding -Status "INFO" `
                -Object "Role Assignments" `
                -Description "No role assignments found via roleManagement API." `
                -Remediation "This may indicate a permissions issue or no custom role assignments."
            return
        }
        
        # Analyze assignment patterns
        $userAssignments = 0
        $groupAssignments = 0
        $spAssignments = 0
        $roleStats = @{}
        $usersWithMultipleRoles = @{}
        
        foreach ($assignment in $roleAssignments) {
            $principalType = $assignment.principal.'@odata.type' -replace '#microsoft.graph.', ''
            $roleName = if ($assignment.roleDefinition) { $assignment.roleDefinition.displayName } else { "Unknown" }
            $principalId = $assignment.principalId
            $principalName = if ($assignment.principal.displayName) { $assignment.principal.displayName } else { "Unknown" }
            
            # Count by principal type
            switch ($principalType) {
                "user" { 
                    $userAssignments++
                    
                    # Track users with multiple roles
                    if (-not $usersWithMultipleRoles.ContainsKey($principalId)) {
                        $usersWithMultipleRoles[$principalId] = @{
                            Name = $principalName
                            UPN = $assignment.principal.userPrincipalName
                            Roles = @()
                        }
                    }
                    $usersWithMultipleRoles[$principalId].Roles += $roleName
                }
                "group" { $groupAssignments++ }
                "servicePrincipal" { $spAssignments++ }
            }
            
            # Count by role
            if (-not $roleStats.ContainsKey($roleName)) {
                $roleStats[$roleName] = @{
                    Total = 0
                    Users = 0
                    Groups = 0
                    ServicePrincipals = 0
                }
            }
            $roleStats[$roleName].Total++
            switch ($principalType) {
                "user" { $roleStats[$roleName].Users++ }
                "group" { $roleStats[$roleName].Groups++ }
                "servicePrincipal" { $roleStats[$roleName].ServicePrincipals++ }
            }
        }
        
        # Summary finding
        $totalAssignments = $roleAssignments.Count
        Add-Finding -Status "INFO" `
            -Object "Role Assignment Summary" `
            -Description "Total assignments: $totalAssignments. Direct to users: $userAssignments. Via groups: $groupAssignments. To service principals: $spAssignments." `
            -Remediation "Consider using groups for role assignments for easier management. Review service principal assignments carefully."
        
        # Check for users with many roles
        $multiRoleUsers = $usersWithMultipleRoles.Values | Where-Object { $_.Roles.Count -ge 3 }
        
        if ($multiRoleUsers.Count -gt 0) {
            foreach ($user in $multiRoleUsers) {
                $roleList = $user.Roles -join ', '
                Add-Finding -Status "INFO" `
                    -Object $user.UPN `
                    -Description "User '$($user.Name)' has $($user.Roles.Count) directory role assignments: $roleList" `
                    -Remediation "Review if this user needs all these roles. Consider separation of duties."
            }
        }
        
        # Check high-risk roles
        $highRiskRoles = @("Global Administrator", "Privileged Role Administrator", "Privileged Authentication Administrator")
        
        foreach ($role in $highRiskRoles) {
            if ($roleStats.ContainsKey($role)) {
                $stats = $roleStats[$role]
                
                if ($stats.Total -gt 5) {
                    Add-Finding -Status "REVIEW" `
                        -Object "Role: $role" `
                        -Description "$role has $($stats.Total) assignments (Users: $($stats.Users), Groups: $($stats.Groups), SPs: $($stats.ServicePrincipals)). High-risk roles should have minimal assignments." `
                        -Remediation "Review all $role assignments. Consider using PIM for just-in-time access instead of permanent assignments."
                }
                else {
                    Add-Finding -Status "INFO" `
                        -Object "Role: $role" `
                        -Description "$role has $($stats.Total) assignments (Users: $($stats.Users), Groups: $($stats.Groups), SPs: $($stats.ServicePrincipals))." `
                        -Remediation "Ensure each assignment is justified and documented."
                }
                
                # Flag if service principals have high-risk roles
                if ($stats.ServicePrincipals -gt 0) {
                    Add-Finding -Status "REVIEW" `
                        -Object "Role: $role (Service Principals)" `
                        -Description "$($stats.ServicePrincipals) service principal(s) have the $role role. Applications with admin roles are high risk." `
                        -Remediation "Review if these applications truly require $role. Consider using more granular application permissions."
                }
            }
        }
        
        # Check if groups are used effectively
        $percentViaGroups = if ($totalAssignments -gt 0) { [math]::Round(($groupAssignments / $totalAssignments) * 100, 0) } else { 0 }
        
        if ($percentViaGroups -lt 20 -and $userAssignments -gt 10) {
            Add-Finding -Status "INFO" `
                -Object "Role Assignment Method" `
                -Description "Only $percentViaGroups% of role assignments are via groups. Direct user assignments are harder to manage at scale." `
                -Remediation "Consider using role-assignable groups for role assignments to simplify management and enable group-based access reviews."
        }
    }
    catch {
        Add-Finding -Status "WARNING" `
            -Object "Role Assignment Paths" `
            -Description "Unable to analyze role assignment patterns: $($_.Exception.Message)" `
            -Remediation "Check Graph permissions (RoleManagement.Read.Directory required)."
    }
}

<#
.SYNOPSIS
    Test-NamedLocation - Audits named locations configuration for Conditional Access.

.DESCRIPTION
    Examines named locations used in Conditional Access:
    - IP-based named locations
    - Country-based named locations
    - Trusted location configurations
    - Locations marked as trusted but with broad ranges
    
    Graph Endpoints Used:
    - GET /identity/conditionalAccess/namedLocations
    
.OUTPUTS
    Findings with Status: INFO for inventory, WARNING for risky configurations
    
.NOTES
    Required Permissions: Policy.Read.All
    Minimum License: Azure AD P1 (Conditional Access requires P1)
    
.LINK
    Graph Reference: https://learn.microsoft.com/en-us/graph/api/conditionalaccessroot-list-namedlocations
#>
function Test-NamedLocation {
    Write-Host "`n[+] Checking named locations configuration..." -ForegroundColor Cyan
    
    # Check if CA is available
    if (-not $script:TenantCapabilities.HasConditionalAccess) {
        Add-Finding -Status "INFO" `
            -Object "Named Locations" `
            -Description "Conditional Access (and named locations) requires Azure AD P1 licensing." `
            -Remediation "Consider upgrading to Azure AD P1 to use location-based Conditional Access policies."
        return
    }
    
    try {
        # Get all named locations
        $namedLocations = Invoke-GraphRequest -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/namedLocations" -AllPages
        
        if (-not $namedLocations -or $namedLocations.Count -eq 0) {
            Add-Finding -Status "INFO" `
                -Object "Named Locations" `
                -Description "No named locations configured. Named locations allow location-based Conditional Access policies." `
                -Remediation "Consider defining named locations for corporate offices, VPN ranges, and trusted networks to enable location-based policies."
            return
        }
        
        $totalLocations = $namedLocations.Count
        $ipLocations = 0
        $countryLocations = 0
        $trustedLocations = 0
        
        foreach ($location in $namedLocations) {
            $locationType = $location.'@odata.type' -replace '#microsoft.graph.', ''
            $isTrusted = $location.isTrusted -eq $true
            
            if ($isTrusted) { $trustedLocations++ }
            
            switch ($locationType) {
                "ipNamedLocation" {
                    $ipLocations++
                    
                    # Check for overly broad IP ranges
                    if ($location.ipRanges) {
                        $broadRanges = @()
                        
                        foreach ($range in $location.ipRanges) {
                            $cidr = $range.cidrAddress
                            if ($cidr) {
                                # Check for very broad ranges (e.g., /8, /16 for IPv4)
                                if ($cidr -match '/(\d+)$') {
                                    $prefix = [int]$matches[1]
                                    if ($prefix -lt 16) {
                                        $broadRanges += $cidr
                                    }
                                }
                            }
                        }
                        
                        if ($broadRanges.Count -gt 0 -and $isTrusted) {
                            Add-Finding -Status "REVIEW" `
                                -Object "Location: $($location.displayName)" `
                                -Description "Trusted IP location '$($location.displayName)' contains overly broad IP ranges: $($broadRanges -join ', '). Broad trusted ranges may include untrusted networks." `
                                -Remediation "Review and narrow the IP ranges in this trusted location. Use specific corporate IP ranges rather than broad CIDR blocks."
                        }
                    }
                    
                    # Info about the IP location
                    $rangeCount = if ($location.ipRanges) { $location.ipRanges.Count } else { 0 }
                    $trustStatus = if ($isTrusted) { "TRUSTED" } else { "Not trusted" }
                    
                    Add-Finding -Status "INFO" `
                        -Object "IP Location: $($location.displayName)" `
                        -Description "IP-based named location with $rangeCount IP range(s). Trust status: $trustStatus." `
                        -Remediation "Ensure IP ranges are current and accurately represent trusted networks."
                }
                "countryNamedLocation" {
                    $countryLocations++
                    
                    $countries = if ($location.countriesAndRegions) { $location.countriesAndRegions -join ', ' } else { "None" }
                    $includeUnknown = $location.includeUnknownCountriesAndRegions
                    
                    Add-Finding -Status "INFO" `
                        -Object "Country Location: $($location.displayName)" `
                        -Description "Country-based named location. Countries: $countries. Include unknown: $includeUnknown." `
                        -Remediation "Review country list periodically. Consider blocking high-risk countries in Conditional Access."
                    
                    if ($includeUnknown -and $isTrusted) {
                        Add-Finding -Status "REVIEW" `
                            -Object "Location: $($location.displayName)" `
                            -Description "Trusted country location '$($location.displayName)' includes unknown countries/regions. This could allow access from unexpected locations." `
                            -Remediation "Consider not trusting locations that include unknown countries/regions."
                    }
                }
            }
        }
        
        # Summary
        Add-Finding -Status "INFO" `
            -Object "Named Locations Summary" `
            -Description "Total named locations: $totalLocations. IP-based: $ipLocations. Country-based: $countryLocations. Marked as trusted: $trustedLocations." `
            -Remediation "Review named locations quarterly. Ensure trusted locations accurately reflect current network topology."
        
        # Check if any trusted locations exist
        if ($trustedLocations -eq 0) {
            Add-Finding -Status "INFO" `
                -Object "Trusted Locations" `
                -Description "No named locations are marked as trusted. Trusted locations can be used to reduce MFA prompts for users on corporate networks." `
                -Remediation "Consider marking corporate office IP ranges as trusted if you want to reduce MFA friction for on-premises users."
        }
    }
    catch {
        Add-Finding -Status "WARNING" `
            -Object "Named Locations" `
            -Description "Unable to check named locations: $($_.Exception.Message)" `
            -Remediation "Check Graph permissions (Policy.Read.All required)."
    }
}

#endregion

#region ==================== REPORTING ====================

<#
.SYNOPSIS
    Exports findings to CSV and HTML reports.

.DESCRIPTION
    Generates formatted reports from the collected findings.
    Creates both CSV (for data processing) and HTML (for readability) versions.
#>
function Export-Finding {
    param(
        [string]$CheckName = "AllChecks"
    )
    
    $ExportCsv = Join-Path $ReportDir "EntraSecurityFindings-$CheckName-$script:TimeVal.csv"
    $ExportHtml = Join-Path $ReportDir "EntraSecurityFindings-$CheckName-$script:TimeVal.html"
    $ExportJson = Join-Path $ReportDir "EntraSecurityFindings-$CheckName-$script:TimeVal.json"
    
    $findingsToExport = @($script:Findings) | Where-Object { $null -ne $_ }
    
    # Determine which formats to export
    $formats = $OutputFormat
    if ($formats -contains "All") {
        $formats = @("CSV", "HTML", "JSON")
    }
    
    # Count findings by status
    $okCount = ($findingsToExport | Where-Object { $_.Status -eq "OK" }).Count
    $infoCount = ($findingsToExport | Where-Object { $_.Status -eq "INFO" }).Count
    $warnCount = ($findingsToExport | Where-Object { $_.Status -eq "WARNING" }).Count
    $failCount = ($findingsToExport | Where-Object { $_.Status -eq "FAIL" }).Count
    
    if ($findingsToExport.Count -gt 0) {
        
        # === CSV Export ===
        if ($formats -contains "CSV") {
            $findingsToExport | Export-Csv -Path $ExportCsv -NoTypeInformation
            Write-Host "    CSV: $ExportCsv" -ForegroundColor Gray
        }
        
        # === JSON Export (with metadata for comparison) ===
        if ($formats -contains "JSON") {
            $jsonOutput = @{
                Metadata = @{
                    Timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
                    TenantId = $script:TenantCapabilities.TenantId
                    TenantName = $script:TenantCapabilities.TenantName
                    ScriptVersion = "1.5.0"
                    ChecksRun = $CheckName
                    Summary = @{
                        Total = $findingsToExport.Count
                        OK = $okCount
                        INFO = $infoCount
                        WARNING = $warnCount
                        FAIL = $failCount
                    }
                    Capabilities = $script:TenantCapabilities
                    Parameters = @{
                        UserInactivityDays = $script:UserInactivityDays
                        PasswordAgeDays = $script:PasswordAgeDays
                        RecentDays = $script:RecentDays
                    }
                }
                Findings = $findingsToExport | ForEach-Object {
                    @{
                        Time = $_.Time
                        Status = $_.Status
                        Object = $_.Object
                        Description = $_.Description
                        Remediation = $_.Remediation
                        # Add a hash for comparison purposes
                        FindingHash = [System.BitConverter]::ToString(
                            [System.Security.Cryptography.SHA256]::Create().ComputeHash(
                                [System.Text.Encoding]::UTF8.GetBytes("$($_.Status)|$($_.Object)|$($_.Description)")
                            )
                        ).Replace("-", "").Substring(0, 16)
                    }
                }
            }
            
            $jsonOutput | ConvertTo-Json -Depth 10 | Set-Content -Path $ExportJson
            Write-Host "    JSON: $ExportJson" -ForegroundColor Gray
        }
        
        # === HTML Export with styling ===
        if ($formats -contains "HTML") {
            $htmlHead = @"
<style>
    body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background-color: #f5f5f5; }
    h2 { color: #333; border-bottom: 2px solid #0078d4; padding-bottom: 10px; }
    table { border-collapse: collapse; width: 100%; background-color: white; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
    th { background-color: #0078d4; color: white; padding: 12px; text-align: left; }
    td { padding: 10px; border-bottom: 1px solid #ddd; vertical-align: top; }
    tr:hover { background-color: #f5f5f5; }
    .OK { color: #107c10; font-weight: bold; }
    .INFO { color: #0078d4; font-weight: bold; }
    .WARNING { color: #ff8c00; font-weight: bold; }
    .FAIL { color: #d13438; font-weight: bold; }
    .summary { background-color: #fff; padding: 15px; margin-bottom: 20px; border-radius: 5px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
    .comparison { background-color: #e7f3ff; padding: 15px; margin-bottom: 20px; border-radius: 5px; border-left: 4px solid #0078d4; }
    .new-finding { background-color: #fff4ce; }
    .resolved-finding { background-color: #dff6dd; }
</style>
"@
            
            # Build comparison section if previous assessment loaded
            $comparisonHtml = ""
            if ($script:PreviousFindings) {
                $prevFail = $script:PreviousFindings.Metadata.Summary.FAIL
                $prevWarn = $script:PreviousFindings.Metadata.Summary.WARNING

                $failDiff = $failCount - $prevFail
                $warnDiff = $warnCount - $prevWarn

                $failTrend = if ($failDiff -gt 0) { "+$failDiff ⬆️" } elseif ($failDiff -lt 0) { "$failDiff ⬇️" } else { "No change" }
                $warnTrend = if ($warnDiff -gt 0) { "+$warnDiff ⬆️" } elseif ($warnDiff -lt 0) { "$warnDiff ⬇️" } else { "No change" }
                
                $comparisonHtml = @"
<div class="comparison">
    <h3>📊 Comparison with Previous Assessment</h3>
    <p><strong>Previous Assessment:</strong> $($script:PreviousFindings.Metadata.Timestamp)</p>
    <p><strong>FAIL Findings:</strong> $prevFail → $failCount ($failTrend)</p>
    <p><strong>WARNING Findings:</strong> $prevWarn → $warnCount ($warnTrend)</p>
</div>
"@
            }
            
            $summaryHtml = @"
<div class="summary">
    <h3>Findings Summary</h3>
    <p><span class="OK">OK: $okCount</span> | <span class="INFO">INFO: $infoCount</span> | <span class="WARNING">WARNING: $warnCount</span> | <span class="FAIL">FAIL: $failCount</span></p>
    <p>Tenant: $($script:TenantCapabilities.TenantName) ($($script:TenantCapabilities.TenantId))</p>
    <p>Report Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
</div>
$comparisonHtml
"@
            
            $findingsToExport | Select-Object Time, Status, Object, Description, Remediation |
                ConvertTo-Html -Title "Entra ID Security Audit Report" -Head $htmlHead -PreContent "<h2>Microsoft Entra ID Security Findings</h2>$summaryHtml" |
                ForEach-Object {
                    # Add CSS classes for status coloring
                    $_ -replace '<td>OK</td>', '<td class="OK">OK</td>' `
                        -replace '<td>INFO</td>', '<td class="INFO">INFO</td>' `
                        -replace '<td>WARNING</td>', '<td class="WARNING">WARNING</td>' `
                        -replace '<td>FAIL</td>', '<td class="FAIL">FAIL</td>'
                } |
                Set-Content -Path $ExportHtml
            
            Write-Host "    HTML: $ExportHtml" -ForegroundColor Gray
        }
        
        Write-Host "`n[+] Results exported to $ReportDir" -ForegroundColor Green
    }
    else {
        # Create empty reports
        $dummy = [PSCustomObject]@{
            Time = ''
            Status = ''
            Object = ''
            Description = 'No findings for this run.'
            Remediation = ''
        }
        
        if ($formats -contains "CSV") {
            $dummy | Export-Csv -Path $ExportCsv -NoTypeInformation
        }
        if ($formats -contains "HTML") {
            $dummy | ConvertTo-Html -Title "Entra ID Security Audit Report" -PreContent "<h2>Microsoft Entra ID Security Findings</h2>" |
                Set-Content -Path $ExportHtml
        }
        if ($formats -contains "JSON") {
            @{
                Metadata = @{
                    Timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
                    TenantId = $script:TenantCapabilities.TenantId
                    Summary = @{ Total = 0; OK = 0; INFO = 0; WARNING = 0; FAIL = 0 }
                }
                Findings = @()
            } | ConvertTo-Json -Depth 5 | Set-Content -Path $ExportJson
        }
        
        Write-Host "`n[INFO] No findings to export - empty report created." -ForegroundColor Yellow
    }
    
    # Return file paths for further processing
    return @{
        CSV = $ExportCsv
        HTML = $ExportHtml
        JSON = $ExportJson
    }
}

<#
.SYNOPSIS
    Displays organizational/process recommendations based on findings.
#>
function Show-Recommendation {
    Write-Host "`n[+] Organizational/Process Recommendations:" -ForegroundColor Yellow
    
    $RecSet = @{}
    
    # Phase 1 Recommendations
    if ($script:Findings | Where-Object { $_.Status -eq "FAIL" -and $_.Description -match "Password never expires" }) {
        $RecSet["Password Never Expires"] = "Eliminate 'Password Never Expires' for all user accounts. For service scenarios, migrate to managed identities or workload identities."
    }
    
    if ($script:Findings | Where-Object { $_.Status -eq "FAIL" -and $_.Description -match "Guest user.*privileged role" }) {
        $RecSet["Guest Privileged Access"] = "Remove guest users from all privileged roles. External admin access should use dedicated accounts with strict Conditional Access."
    }
    
    if ($script:Findings | Where-Object { $_.Status -eq "WARNING" -and $_.Description -match "Service principal.*privileged" }) {
        $RecSet["Service Principal Roles"] = "Review all service principals with directory roles. Prefer granular application permissions over broad admin roles."
    }
    
    if ($script:Findings | Where-Object { $_.Status -match "FAIL|WARNING" -and $_.Description -match "NOT on the approved allowlist" }) {
        $RecSet["Privileged Access Governance"] = "Implement Privileged Identity Management (PIM) for just-in-time access. Maintain and enforce privileged role allowlists."
    }
    
    if ($script:Findings | Where-Object { $_.Status -eq "FAIL" -and $_.Description -match "was created.*days ago.*privileged" }) {
        $RecSet["New Privileged Accounts"] = "Implement approval workflows for privileged role assignments. Monitor for unexpected privileged account creation."
    }
    
    if ($script:Findings | Where-Object { $_.Status -eq "WARNING" -and $_.Description -match "Disabled user.*privileged role" }) {
        $RecSet["Disabled Account Cleanup"] = "Implement automated removal of disabled users from privileged roles. Review role membership during offboarding."
    }
    
    # Phase 2 Recommendations
    if ($script:Findings | Where-Object { $_.Status -eq "WARNING" -and $_.Description -match "inactive for.*days" }) {
        $RecSet["Inactive Accounts"] = "Implement automated account lifecycle management. Disable accounts after extended inactivity and remove after confirmation."
    }
    
    if ($script:Findings | Where-Object { $_.Status -eq "WARNING" -and $_.Description -match "password not changed in" }) {
        $RecSet["Stale Passwords"] = "Enforce regular password rotation or migrate to passwordless authentication. Review accounts with very old passwords."
    }
    
    if ($script:Findings | Where-Object { $_.Status -eq "WARNING" -and $_.Description -match "NEVER signed in" }) {
        $RecSet["Never-Used Accounts"] = "Audit accounts that have never been used. Consider removing or disabling them if they serve no purpose."
    }
    
    if ($script:Findings | Where-Object { $_.Status -eq "WARNING" -and $_.Description -match "Guest invitation pending" }) {
        $RecSet["Stale Guest Invitations"] = "Clean up pending guest invitations that were never accepted. Implement invitation expiration policies."
    }
    
    if ($script:Findings | Where-Object { $_.Status -eq "FAIL" -and $_.Description -match "possible password/secret" }) {
        $RecSet["Secrets in Metadata"] = "Train all administrators to NEVER store passwords or secrets in profile fields or descriptions. Use Azure Key Vault for secrets."
    }
    
    if ($script:Findings | Where-Object { $_.Status -match "WARNING|FAIL" -and $_.Description -match "shadow.*group|lookalike" }) {
        $RecSet["Shadow Groups"] = "Implement naming conventions for groups. Regularly audit for groups that mimic privileged role names."
    }
    
    if ($script:Findings | Where-Object { $_.Status -eq "FAIL" -and $_.Description -match "Non-privileged user.*owner of role-assignable" }) {
        $RecSet["Role-Assignable Group Ownership"] = "Restrict ownership of role-assignable groups to Global Administrators or Privileged Role Administrators only."
    }
    
    if ($script:Findings | Where-Object { $_.Description -match "role-assignable group" }) {
        $RecSet["Role-Assignable Groups Governance"] = "Implement strict controls for role-assignable groups: require approval for membership changes, audit regularly, use PIM where possible."
    }
    
    if ($script:Findings | Where-Object { $_.Description -match "Total guest users" }) {
        $RecSet["Guest Access Reviews"] = "Implement quarterly access reviews for all guest users. Use Azure AD Access Reviews if available (P2 license)."
    }
    
    # Phase 3 Recommendations
    if ($script:Findings | Where-Object { $_.Status -eq "WARNING" -and $_.Description -match "EXPIRED.*credential" }) {
        $RecSet["Expired Credentials"] = "Remove all expired credentials from applications immediately. Implement credential expiration monitoring."
    }
    
    if ($script:Findings | Where-Object { $_.Status -eq "WARNING" -and $_.Description -match "expiring in.*days" }) {
        $RecSet["Credential Rotation"] = "Implement proactive credential rotation. Set up alerts for credentials expiring within 30 days."
    }
    
    if ($script:Findings | Where-Object { $_.Status -eq "WARNING" -and $_.Description -match "long-lived.*credential" }) {
        $RecSet["Credential Lifetime"] = "Reduce credential lifetimes to 1 year maximum. Consider migrating to certificate-based authentication or managed identities."
    }
    
    if ($script:Findings | Where-Object { $_.Description -match "More applications use password credentials.*than certificates" }) {
        $RecSet["Certificate Authentication"] = "Migrate applications from password credentials to certificate-based authentication for improved security."
    }
    
    if ($script:Findings | Where-Object { $_.Status -match "FAIL|WARNING" -and $_.Description -match "high-risk permissions|CRITICAL Graph permissions" }) {
        $RecSet["Overprivileged Applications"] = "Review all applications with high-risk permissions. Apply principle of least privilege. Remove unnecessary permissions."
    }
    
    if ($script:Findings | Where-Object { $_.Status -eq "WARNING" -and $_.Description -match "Third-party.*admin consent" }) {
        $RecSet["Third-Party App Governance"] = "Implement strict review process for third-party applications. Require security review before granting admin consent."
    }
    
    if ($script:Findings | Where-Object { $_.Description -match "High volume of user consent grants" }) {
        $RecSet["Consent Workflow"] = "Restrict user consent to apps. Implement admin consent workflow requiring approval for new applications."
    }
    
    if ($script:Findings | Where-Object { $_.Status -eq "FAIL" -and $_.Description -match "Duplicate.*URI|Duplicate.*SPN" }) {
        $RecSet["Duplicate Identifiers"] = "Resolve all duplicate application identifiers immediately. Each identifier must be unique to prevent authentication issues."
    }
    
    if ($script:Findings | Where-Object { $_.Description -match "Third-party apps:" }) {
        $RecSet["App Inventory"] = "Maintain an inventory of all third-party applications. Regularly review and remove unused applications."
    }
    
    # Phase 4 Recommendations
    if ($script:Findings | Where-Object { $_.Status -eq "FAIL" -and $_.Description -match "No Conditional Access policy.*MFA for admin" }) {
        $RecSet["Admin MFA Policy"] = "CRITICAL: Create a Conditional Access policy requiring MFA for all administrative roles immediately."
    }
    
    if ($script:Findings | Where-Object { $_.Status -eq "WARNING" -and $_.Description -match "No Conditional Access policy.*blocks legacy authentication" }) {
        $RecSet["Block Legacy Auth"] = "Create a Conditional Access policy to block legacy authentication protocols. Legacy auth bypasses MFA."
    }
    
    if ($script:Findings | Where-Object { $_.Status -eq "WARNING" -and $_.Description -match "No phishing-resistant authentication methods" }) {
        $RecSet["Phishing-Resistant MFA"] = "Enable FIDO2 security keys or Windows Hello for Business. These methods are resistant to phishing attacks."
    }
    
    if ($script:Findings | Where-Object { $_.Status -eq "WARNING" -and $_.Description -match "Weaker authentication methods are enabled" }) {
        $RecSet["Weak MFA Methods"] = "Consider restricting SMS and voice-based MFA for privileged users. Use Authentication Strengths in Conditional Access."
    }
    
    if ($script:Findings | Where-Object { $_.Status -eq "WARNING" -and $_.Description -match "Number matching is not enabled" }) {
        $RecSet["Authenticator Settings"] = "Enable number matching for Microsoft Authenticator to help prevent MFA fatigue attacks."
    }
    
    if ($script:Findings | Where-Object { $_.Status -eq "FAIL" -and $_.Description -match "NO MFA methods registered.*Privileged user" }) {
        $RecSet["Privileged User MFA"] = "CRITICAL: Ensure all privileged users have MFA methods registered. Consider blocking sign-in until MFA is configured."
    }
    
    if ($script:Findings | Where-Object { $_.Status -eq "WARNING" -and $_.Description -match "only has weak MFA methods" }) {
        $RecSet["Admin MFA Strength"] = "Encourage privileged users to register stronger MFA methods (Authenticator app, FIDO2 keys) instead of SMS/voice."
    }
    
    if ($script:Findings | Where-Object { $_.Status -eq "WARNING" -and $_.Description -match "Users can consent to third-party applications.*legacy" }) {
        $RecSet["User Consent"] = "Restrict user consent for applications. Implement an admin consent workflow to review app permission requests."
    }
    
    if ($script:Findings | Where-Object { $_.Status -eq "WARNING" -and $_.Description -match "Anyone.*can invite external users" }) {
        $RecSet["Guest Invitation"] = "Restrict guest invitations to administrators or the Guest Inviter role to maintain control over external access."
    }
    
    if ($script:Findings | Where-Object { $_.Status -eq "WARNING" -and $_.Description -match "Users can create new Azure AD tenants" }) {
        $RecSet["Tenant Creation"] = "Disable tenant creation by regular users to prevent shadow IT environments."
    }
    
    if ($script:Findings | Where-Object { $_.Status -eq "FAIL" -and $_.Description -match "No Conditional Access policies found" }) {
        $RecSet["Implement Conditional Access"] = "CRITICAL: Implement Conditional Access policies immediately. Start with MFA for admins and blocking legacy auth."
    }
    
    # Phase 5 Recommendations
    if ($script:Findings | Where-Object { $_.Description -match "Administrative units exist but have no scoped role assignments" }) {
        $RecSet["Admin Unit Usage"] = "If administrative units are configured, assign scoped roles to enable delegated administration."
    }
    
    if ($script:Findings | Where-Object { $_.Status -eq "WARNING" -and $_.Description -match "PIM is available but no eligible.*just-in-time.*role assignments" }) {
        $RecSet["Enable PIM"] = "Configure PIM eligible assignments for privileged roles. Just-in-time access significantly reduces standing privilege exposure."
    }
    
    if ($script:Findings | Where-Object { $_.Status -eq "WARNING" -and $_.Description -match "permanent.*Global Administrator assignments" }) {
        $RecSet["Reduce Permanent GA"] = "Convert permanent Global Administrator assignments to PIM eligible. Keep only 2 break-glass accounts as permanent."
    }
    
    if ($script:Findings | Where-Object { $_.Status -eq "WARNING" -and $_.Description -match "Sign-in logs are NOT available" }) {
        $RecSet["Enable Sign-In Logs"] = "Upgrade to Azure AD P1 to enable sign-in logs. These are critical for security monitoring and incident investigation."
    }
    
    if ($script:Findings | Where-Object { $_.Description -match "30 days.*retention|Export.*Log Analytics" }) {
        $RecSet["Log Retention"] = "Configure Azure Diagnostic Settings to export logs to Log Analytics for extended retention (compliance may require 1-7 years)."
    }
    
    if ($script:Findings | Where-Object { $_.Status -eq "WARNING" -and $_.Description -match "service principal.*have the.*Administrator role" }) {
        $RecSet["SP Admin Roles"] = "Review service principals with administrative directory roles. Applications should use granular app permissions, not admin roles."
    }
    
    if ($script:Findings | Where-Object { $_.Description -match "Direct to users.*Via groups" }) {
        $RecSet["Group-Based Roles"] = "Consider using role-assignable groups for role assignments. This simplifies management and enables group-based access reviews."
    }
    
    if ($script:Findings | Where-Object { $_.Status -eq "WARNING" -and $_.Description -match "Trusted.*contains overly broad IP ranges" }) {
        $RecSet["Named Location Ranges"] = "Narrow overly broad IP ranges in trusted named locations. Broad ranges may inadvertently trust untrusted networks."
    }
    
    if ($script:Findings | Where-Object { $_.Description -match "No named locations configured" }) {
        $RecSet["Define Named Locations"] = "Define named locations for corporate offices and VPN ranges to enable location-based Conditional Access policies."
    }
    
    # Always add routine audit recommendation
    $RecSet["Routine Audit"] = "Repeat this Entra ID security audit quarterly and after any major changes. Document all exceptions."
    
    foreach ($rec in $RecSet.GetEnumerator()) { 
        Write-Host "  * $($rec.Value)" -ForegroundColor White
    }
}

<#
.SYNOPSIS
    Generates a remediation script based on findings.

.DESCRIPTION
    Creates a PowerShell script with commented remediation commands
    for each finding. The script is not executable by default - it
    requires manual review and uncommenting of desired actions.
#>
function New-RemediationScript {
    $remediationPath = Join-Path $ReportDir "EntraChecks-Remediation-$script:TimeVal.ps1"
    
    $scriptContent = @"
<#
.SYNOPSIS
    Entra ID Security Remediation Script
    Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    Tenant: $($script:TenantCapabilities.TenantName)

.DESCRIPTION
    This script contains remediation commands for findings from the Entra ID security assessment.
    
    IMPORTANT:
    - Review each section carefully before executing
    - Commands are COMMENTED OUT by default for safety
    - Uncomment only the commands you want to execute
    - Test in a non-production environment first
    - Ensure you have appropriate permissions
    
.NOTES
    Required Modules: Microsoft.Graph
    Required Permissions: Varies by remediation action (see comments)
#>

# Connect to Microsoft Graph (uncomment and run first)
# Connect-MgGraph -Scopes "User.ReadWrite.All", "Group.ReadWrite.All", "Application.ReadWrite.All", "RoleManagement.ReadWrite.Directory"

"@
    
    $findingsToRemediate = $script:Findings | Where-Object { $_.Status -in @("FAIL", "WARNING") }
    
    if ($findingsToRemediate.Count -eq 0) {
        $scriptContent += @"

# ============================================
# No FAIL or WARNING findings to remediate!
# ============================================
Write-Host "No remediation actions required." -ForegroundColor Green
"@
    }
    else {
        # Group findings by type for organized remediation
        $passwordNeverExpires = $findingsToRemediate | Where-Object { $_.Description -match "Password never expires" }
        $expiredCredentials = $findingsToRemediate | Where-Object { $_.Description -match "EXPIRED.*credential" }
        $guestsInRoles = $findingsToRemediate | Where-Object { $_.Description -match "Guest user.*privileged role" }
        $disabledInRoles = $findingsToRemediate | Where-Object { $_.Description -match "Disabled user.*privileged role" }
        $noMfaAdmins = $findingsToRemediate | Where-Object { $_.Description -match "NO MFA methods registered.*Privileged" }
        $secretsInMetadata = $findingsToRemediate | Where-Object { $_.Description -match "possible password/secret" }
        
        $scriptContent += @"

# ============================================
# REMEDIATION SECTIONS
# ============================================

"@
        
        # Password Never Expires
        if ($passwordNeverExpires.Count -gt 0) {
            $scriptContent += @"

# --------------------------------------------
# Section: Password Never Expires Users
# Findings: $($passwordNeverExpires.Count)
# Risk: Users with non-expiring passwords are more vulnerable to credential theft
# Permission Required: User.ReadWrite.All
# --------------------------------------------

"@
            foreach ($finding in $passwordNeverExpires) {
                $upn = if ($finding.Object -match '(.+@.+)') { $matches[1] } else { $finding.Object }
                $scriptContent += @"
# Finding: $($finding.Object)
# Description: $($finding.Description)
# Uncomment to remediate:
# Update-MgUser -UserId "$upn" -PasswordPolicies "None"
# Write-Host "Removed 'Password Never Expires' from $upn"

"@
            }
        }
        
        # Expired Credentials
        if ($expiredCredentials.Count -gt 0) {
            $scriptContent += @"

# --------------------------------------------
# Section: Expired Application Credentials
# Findings: $($expiredCredentials.Count)
# Risk: Expired credentials indicate poor credential hygiene
# Permission Required: Application.ReadWrite.All
# --------------------------------------------

"@
            foreach ($finding in $expiredCredentials) {
                $scriptContent += @"
# Finding: $($finding.Object)
# Description: $($finding.Description)
# Action: Remove expired credential from application
# Note: Requires identifying the specific keyId - review in Azure Portal
# Get-MgApplication -Filter "displayName eq 'APP_NAME'" | Select-Object -ExpandProperty PasswordCredentials

"@
            }
        }
        
        # Guests in Privileged Roles
        if ($guestsInRoles.Count -gt 0) {
            $scriptContent += @"

# --------------------------------------------
# Section: Guest Users in Privileged Roles
# Findings: $($guestsInRoles.Count)
# Risk: External users should not have administrative access
# Permission Required: RoleManagement.ReadWrite.Directory
# --------------------------------------------

"@
            foreach ($finding in $guestsInRoles) {
                $scriptContent += @"
# Finding: $($finding.Object)
# Description: $($finding.Description)
# Action: Remove guest from directory role
# Uncomment after identifying the role assignment:
# Remove-MgDirectoryRoleMember -DirectoryRoleId "ROLE_ID" -DirectoryObjectId "USER_OBJECT_ID"

"@
            }
        }
        
        # Disabled Users in Roles
        if ($disabledInRoles.Count -gt 0) {
            $scriptContent += @"

# --------------------------------------------
# Section: Disabled Users in Privileged Roles
# Findings: $($disabledInRoles.Count)
# Risk: Disabled accounts should not retain privileged access
# Permission Required: RoleManagement.ReadWrite.Directory
# --------------------------------------------

"@
            foreach ($finding in $disabledInRoles) {
                $scriptContent += @"
# Finding: $($finding.Object)
# Description: $($finding.Description)
# Action: Remove disabled user from directory role
# Remove-MgDirectoryRoleMember -DirectoryRoleId "ROLE_ID" -DirectoryObjectId "USER_OBJECT_ID"

"@
            }
        }
        
        # Admins without MFA
        if ($noMfaAdmins.Count -gt 0) {
            $scriptContent += @"

# --------------------------------------------
# Section: Privileged Users Without MFA
# Findings: $($noMfaAdmins.Count)
# Risk: Administrators without MFA are highly vulnerable to account compromise
# Action: These users must register MFA - this cannot be done programmatically
# --------------------------------------------

"@
            foreach ($finding in $noMfaAdmins) {
                $scriptContent += @"
# Finding: $($finding.Object)
# Description: $($finding.Description)
# MANUAL ACTION REQUIRED:
# 1. Contact user and require MFA registration
# 2. Consider using Conditional Access to block sign-in until MFA is registered
# 3. Use Authentication Methods Registration Campaign if available (P2)

"@
            }
        }
        
        # Secrets in Metadata
        if ($secretsInMetadata.Count -gt 0) {
            $scriptContent += @"

# --------------------------------------------
# Section: Secrets Found in Metadata Fields
# Findings: $($secretsInMetadata.Count)
# Risk: Credentials stored in description fields are easily discoverable
# Permission Required: User.ReadWrite.All, Group.ReadWrite.All, Application.ReadWrite.All
# --------------------------------------------

"@
            foreach ($finding in $secretsInMetadata) {
                $scriptContent += @"
# Finding: $($finding.Object)
# Description: $($finding.Description)
# MANUAL ACTION REQUIRED:
# 1. Identify the actual credential/secret
# 2. Rotate the credential immediately
# 3. Store new credential in Azure Key Vault
# 4. Clear the metadata field

"@
            }
        }
        
        # General remediation for other findings
        $otherFindings = $findingsToRemediate | Where-Object { 
            $_.Description -notmatch "Password never expires|EXPIRED.*credential|Guest user.*privileged|Disabled user.*privileged|NO MFA methods|possible password/secret"
        }
        
        if ($otherFindings.Count -gt 0) {
            $scriptContent += @"

# --------------------------------------------
# Section: Other Findings Requiring Review
# Findings: $($otherFindings.Count)
# These findings require manual review and remediation
# --------------------------------------------

"@
            foreach ($finding in $otherFindings) {
                $scriptContent += @"
# [$($finding.Status)] $($finding.Object)
# Description: $($finding.Description)
# Remediation: $($finding.Remediation)

"@
            }
        }
    }
    
    $scriptContent += @"

# ============================================
# END OF REMEDIATION SCRIPT
# ============================================

Write-Host "`nRemediation script execution complete." -ForegroundColor Green
Write-Host "Remember to re-run the security assessment to verify remediation." -ForegroundColor Yellow
"@
    
    $scriptContent | Set-Content -Path $remediationPath
    Write-Host "[+] Remediation script generated: $remediationPath" -ForegroundColor Green
    
    return $remediationPath
}

<#
.SYNOPSIS
    Shows comparison between current and previous assessment.
#>
function Show-Comparison {
    if (-not $script:PreviousFindings) {
        return
    }
    
    Write-Host "`n[+] Assessment Comparison:" -ForegroundColor Cyan
    Write-Host "    Previous: $($script:PreviousFindings.Metadata.Timestamp)" -ForegroundColor Gray
    Write-Host "    Current:  $(Get-Date -Format 'yyyy-MM-ddTHH:mm:ssZ')" -ForegroundColor Gray
    
    $prevSummary = $script:PreviousFindings.Metadata.Summary
    $currentFail = ($script:Findings | Where-Object { $_.Status -eq "FAIL" }).Count
    $currentWarn = ($script:Findings | Where-Object { $_.Status -eq "WARNING" }).Count
    
    $failDiff = $currentFail - $prevSummary.FAIL
    $warnDiff = $currentWarn - $prevSummary.WARNING
    
    Write-Host ""
    if ($failDiff -lt 0) {
        Write-Host "    FAIL findings: $($prevSummary.FAIL) → $currentFail ($failDiff) ✅ Improved!" -ForegroundColor Green
    }
    elseif ($failDiff -gt 0) {
        Write-Host "    FAIL findings: $($prevSummary.FAIL) → $currentFail (+$failDiff) ⚠️ Regression" -ForegroundColor Red
    }
    else {
        Write-Host "    FAIL findings: $($prevSummary.FAIL) → $currentFail (No change)" -ForegroundColor Gray
    }
    
    if ($warnDiff -lt 0) {
        Write-Host "    WARNING findings: $($prevSummary.WARNING) → $currentWarn ($warnDiff) ✅ Improved!" -ForegroundColor Green
    }
    elseif ($warnDiff -gt 0) {
        Write-Host "    WARNING findings: $($prevSummary.WARNING) → $currentWarn (+$warnDiff) ⚠️ Regression" -ForegroundColor Yellow
    }
    else {
        Write-Host "    WARNING findings: $($prevSummary.WARNING) → $currentWarn (No change)" -ForegroundColor Gray
    }
    
    # Identify new and resolved findings by comparing hashes
    if ($script:PreviousFindings.Findings) {
        $prevHashes = $script:PreviousFindings.Findings | ForEach-Object { $_.FindingHash }
        $currentHashes = @()
        
        foreach ($finding in $script:Findings) {
            $hash = [System.BitConverter]::ToString(
                [System.Security.Cryptography.SHA256]::Create().ComputeHash(
                    [System.Text.Encoding]::UTF8.GetBytes("$($finding.Status)|$($finding.Object)|$($finding.Description)")
                )
            ).Replace("-", "").Substring(0, 16)
            $currentHashes += $hash
        }
        
        $newFindings = $currentHashes | Where-Object { $prevHashes -notcontains $_ }
        $resolvedFindings = $prevHashes | Where-Object { $currentHashes -notcontains $_ }
        
        if ($newFindings.Count -gt 0) {
            Write-Host "`n    New findings this assessment: $($newFindings.Count)" -ForegroundColor Yellow
        }
        if ($resolvedFindings.Count -gt 0) {
            Write-Host "    Resolved since last assessment: $($resolvedFindings.Count)" -ForegroundColor Green
        }
    }
}

#endregion

#region ==================== MENU SYSTEM ====================

# Define available checks
$script:MenuChecks = @(
    @{ Name = "Run ALL Checks"; Func = "ALL" }
    # --- Phase 1: Foundation ---
    @{ Name = "Check Tenant and Domain Info"; Func = "Test-TenantAndDomainInfo" }
    @{ Name = "Check Password Never Expires"; Func = "Test-PasswordNeverExpires" }
    @{ Name = "Check Directory Roles and Members"; Func = "Test-DirectoryRolesAndMembers" }
    @{ Name = "Check Privileged Role Creep"; Func = "Test-PrivilegedRoleCreep" }
    @{ Name = "Check Recent Privileged Accounts"; Func = "Test-RecentPrivilegedAccounts" }
    # --- Phase 2: User & Identity ---
    @{ Name = "Check User Accounts and Inactivity"; Func = "Test-UserAccountsAndInactivity" }
    @{ Name = "Check Guest Users"; Func = "Test-GuestUsers" }
    @{ Name = "Check Passwords in Profile Fields"; Func = "Test-PasswordsInProfileFields" }
    @{ Name = "Check Shadow Groups"; Func = "Test-ShadowGroups" }
    @{ Name = "Check Role-Assignable Group Ownership"; Func = "Test-RoleAssignableGroupOwnership" }
    # --- Phase 3: Applications & Service Principals ---
    @{ Name = "Check Application Credentials"; Func = "Test-ApplicationCredentials" }
    @{ Name = "Check Service Principal Permissions"; Func = "Test-ServicePrincipalPermissions" }
    @{ Name = "Check OAuth Consent Grants"; Func = "Test-OAuthConsentGrants" }
    @{ Name = "Check App Role Assignments"; Func = "Test-AppRoleAssignments" }
    @{ Name = "Check Duplicate App Identifiers"; Func = "Test-DuplicateAppIdentifiers" }
    # --- Phase 4: Authentication & Policy ---
    @{ Name = "Check Conditional Access Policies"; Func = "Test-ConditionalAccessPolicies" }
    @{ Name = "Check Authentication Methods Policy"; Func = "Test-AuthenticationMethodsPolicy" }
    @{ Name = "Check Privileged User MFA Coverage"; Func = "Test-PrivilegedUserMFACoverage" }
    @{ Name = "Check Cross-Tenant Access Policy"; Func = "Test-CrossTenantAccessPolicy" }
    @{ Name = "Check Authorization Policy"; Func = "Test-AuthorizationPolicy" }
    # --- Phase 5: Governance & Audit ---
    @{ Name = "Check Admin Unit Delegation"; Func = "Test-AdminUnitDelegation" }
    @{ Name = "Check PIM Configuration"; Func = "Test-PIMConfiguration" }
    @{ Name = "Check Audit Log Retention"; Func = "Test-AuditLogRetention" }
    @{ Name = "Check Directory Role Assignment Paths"; Func = "Test-DirectoryRoleAssignmentPaths" }
    @{ Name = "Check Named Locations"; Func = "Test-NamedLocation" }
)

function Show-Menu {
    Write-Host ""
    Write-Host "=================================" -ForegroundColor Cyan
    Write-Host " Entra ID Security Check Menu" -ForegroundColor Cyan
    Write-Host "=================================" -ForegroundColor Cyan
    Write-Host ""
    
    for ($i = 0; $i -lt $script:MenuChecks.Count; $i++) {
        Write-Host ("[{0}] {1}" -f ($i + 1), $script:MenuChecks[$i].Name)
    }
    
    Write-Host ""
}

function Invoke-MenuLoop {
    do {
        Show-Menu
        $sel = Read-Host "Enter a number to run a check (or 'q' to quit)"
        
        if ($sel -eq "q") { 
            Write-Host "`nExiting..." -ForegroundColor Cyan
            break 
        }
        
        if ($sel -as [int] -and $sel -ge 1 -and $sel -le $script:MenuChecks.Count) {
            $script:Findings = @()  # Clear findings for this run
            $selectedFunc = $script:MenuChecks[$sel - 1].Func
            $checkName = $script:MenuChecks[$sel - 1].Name -replace '\s+', ''
            
            if ($selectedFunc -eq "ALL") {
                Write-Host "`n[*] Running ALL checks..." -ForegroundColor Cyan
                $checkName = "AllChecks"
                foreach ($chk in $script:MenuChecks[1..($script:MenuChecks.Count - 1)]) {
                    try {
                        & $chk.Func
                    }
                    catch {
                        Write-CheckError -CheckName $chk.Func -Message $_.Exception.Message -ErrorRecord $_
                    }
                }
            }
            else {
                Write-Host "`n[*] Running: $($script:MenuChecks[$sel-1].Name)..." -ForegroundColor Cyan
                try {
                    & $selectedFunc
                }
                catch {
                    Write-CheckError -CheckName $selectedFunc -Message $_.Exception.Message -ErrorRecord $_
                }
            }
            
            # Export findings
            Export-Finding -CheckName $checkName

            # Show recommendations
            Show-Recommendation

            # Show error summary with log file path
            Show-ErrorSummary

            Write-Host "`nPress Enter to return to menu..." -ForegroundColor Gray
            Read-Host
        }
        else {
            Write-Host "Invalid selection. Try again or enter 'q' to quit." -ForegroundColor Red
        }
    } while ($true)
}

#endregion

#region ==================== MAIN EXECUTION ====================

Write-Host @"

===============================================
  Microsoft Entra ID Security Checks v1.5
  Complete: All 25 Security Checks
  Enhanced: Automation & Reporting Features
===============================================

"@ -ForegroundColor Cyan

# Show mode indicator
if ($NonInteractive) {
    Write-Host "[Mode: Non-Interactive / Automated]" -ForegroundColor Yellow
}
else {
    Write-Host "[Mode: Interactive]" -ForegroundColor Cyan
}

# Connect to Graph
$connected = Connect-EntraChecks
if (-not $connected) {
    Write-Error "Failed to connect to Microsoft Graph. Exiting."
    Stop-Transcript -ErrorAction SilentlyContinue
    exit 1
}

# Detect capabilities (suppress output to prevent polluting the output stream when called via & from Start-EntraChecks)
Get-TenantCapabilities | Out-Null

# Determine which checks to run
$checksToExecute = @()
$allCheckFunctions = $script:MenuChecks | Where-Object { $_.Func -ne "ALL" } | ForEach-Object { $_.Func }

if ($ChecksToRun -and $ChecksToRun.Count -gt 0) {
    # Use specified checks
    $checksToExecute = $ChecksToRun
    Write-Host "[*] Running specified checks: $($ChecksToRun -join ', ')" -ForegroundColor Gray
}
else {
    # Run all checks
    $checksToExecute = $allCheckFunctions
}

# Apply exclusions
if ($ExcludeChecks -and $ExcludeChecks.Count -gt 0) {
    $checksToExecute = $checksToExecute | Where-Object { $ExcludeChecks -notcontains $_ }
    Write-Host "[*] Excluding checks: $($ExcludeChecks -join ', ')" -ForegroundColor Gray
}

if ($NonInteractive) {
    # ========== NON-INTERACTIVE MODE ==========
    Write-Host "`n[+] Running $($checksToExecute.Count) security checks..." -ForegroundColor Cyan
    
    $totalChecks = $checksToExecute.Count
    $currentCheck = 0
    
    foreach ($checkFunc in $checksToExecute) {
        $currentCheck++
        
        # Progress indicator
        $percentComplete = [math]::Round(($currentCheck / $totalChecks) * 100, 0)
        Write-Progress -Activity "Running Security Checks" -Status "$checkFunc ($currentCheck of $totalChecks)" -PercentComplete $percentComplete
        
        # Execute the check (pipe to Out-Null to prevent output stream pollution when captured by Start-EntraChecks)
        try {
            & $checkFunc | Out-Null
        }
        catch {
            Write-CheckError -CheckName $checkFunc -Message $_.Exception.Message -ErrorRecord $_
        }
    }
    
    Write-Progress -Activity "Running Security Checks" -Completed
    
    # Show summary
    $failCount = ($script:Findings | Where-Object { $_.Status -eq "FAIL" }).Count
    $warnCount = ($script:Findings | Where-Object { $_.Status -eq "WARNING" }).Count
    $okCount = ($script:Findings | Where-Object { $_.Status -eq "OK" }).Count
    $infoCount = ($script:Findings | Where-Object { $_.Status -eq "INFO" }).Count
    
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Assessment Complete" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "FAIL:    $failCount" -ForegroundColor $(if ($failCount -gt 0) { "Red" } else { "Green" })
    Write-Host "WARNING: $warnCount" -ForegroundColor $(if ($warnCount -gt 0) { "Yellow" } else { "Green" })
    Write-Host "OK:      $okCount" -ForegroundColor Green
    Write-Host "INFO:    $infoCount" -ForegroundColor Cyan
    Write-Host "Total:   $($script:Findings.Count)" -ForegroundColor White
    
    # Show comparison if previous assessment was loaded
    if ($script:PreviousFindings) {
        Show-Comparison
    }

    # Export findings
    Export-Finding -CheckName "AllChecks" | Out-Null

    # Generate remediation script if requested
    if ($GenerateRemediationScript) {
        New-RemediationScript | Out-Null
    }
    
    # Show recommendations
    Show-Recommendation

    # Show error summary with log file path
    Show-ErrorSummary
}
else {
    # ========== INTERACTIVE MODE ==========
    # Run menu loop
    Invoke-MenuLoop
}

# Cleanup - only disconnect in standalone/interactive mode
# When called from Start-EntraChecks (-NonInteractive), the caller manages the Graph session
if (-not $NonInteractive) {
    Disconnect-EntraChecks
}

# Log session summary
if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
    $failCount = ($script:Findings | Where-Object { $_.Status -eq "FAIL" }).Count
    $warnCount = ($script:Findings | Where-Object { $_.Status -eq "WARNING" }).Count
    $okCount = ($script:Findings | Where-Object { $_.Status -eq "OK" }).Count
    $infoCount = ($script:Findings | Where-Object { $_.Status -eq "INFO" }).Count

    Write-Log -Level INFO -Message "Assessment completed" -Category "System" -Properties @{
        TotalFindings = $script:Findings.Count
        FailFindings = $failCount
        WarningFindings = $warnCount
        OKFindings = $okCount
        InfoFindings = $infoCount
    }

    Write-AuditLog -EventType "SessionEnded" -Description "EntraChecks assessment completed" -Details @{
        TotalFindings = $script:Findings.Count
        FailCount = $failCount
        WarningCount = $warnCount
    } -Result $(if ($failCount -gt 0) { "Warning" } else { "Success" })

    # Flush and stop logging
    Stop-Logging | Out-Null
}

Stop-Transcript -ErrorAction SilentlyContinue | Out-Null

Write-Host "`n[+] Script complete. Check $ReportDir for reports." -ForegroundColor Green

# Return findings for integration with Start-EntraChecks
if ($NonInteractive) {
    # Output findings as objects so they can be captured
    Write-Output $script:Findings

    # Return exit code based on findings (useful for CI/CD)
    $failCount = ($script:Findings | Where-Object { $_.Status -eq "FAIL" }).Count
    if ($failCount -gt 0) {
        $global:LASTEXITCODE = 1
    }
    else {
        $global:LASTEXITCODE = 0
    }
}

#endregion
