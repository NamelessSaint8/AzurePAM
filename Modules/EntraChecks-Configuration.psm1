<#
.SYNOPSIS
    EntraChecks Configuration Management Module

.DESCRIPTION
    Provides centralized configuration management with schema validation,
    environment-specific configurations, and secure credential handling.

.NOTES
    Version: 1.0.0
    Author: David Stells
    Requires: PowerShell 5.1 or higher
#>

#region ==================== MODULE INITIALIZATION ====================

# Import logging module if available
$loggingModulePath = Join-Path $PSScriptRoot "EntraChecks-Logging.psm1"
if (Test-Path $loggingModulePath) {
    Import-Module $loggingModulePath -Force -ErrorAction SilentlyContinue
}

# Configuration state
$script:Config = $null
$script:ConfigSchema = $null
$script:ConfigLoaded = $false
$script:ConfigFilePath = $null

#endregion

#region ==================== CONFIGURATION SCHEMA ====================

<#
.SYNOPSIS
    Gets the default configuration schema for EntraChecks.

.DESCRIPTION
    Returns the JSON schema that defines the structure and validation rules
    for EntraChecks configuration files.

.EXAMPLE
    $schema = Get-ConfigurationSchema
#>
function Get-ConfigurationSchema {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    return @{
        '$schema' = "http://json-schema.org/draft-07/schema#"
        'title' = "EntraChecks Configuration Schema"
        'version' = "1.0.0"
        'type' = "object"
        'required' = @('Version', 'Assessment', 'Logging', 'ErrorHandling')
        'properties' = @{
            Version = @{
                type = "string"
                pattern = '^\d+\.\d+\.\d+$'
                description = "Configuration schema version (semver format)"
            }
            Assessment = @{
                type = "object"
                required = @('Scope', 'Output')
                properties = @{
                    Scope = @{
                        type = "array"
                        items = @{
                            type = "string"
                            enum = @(
                                "Core",
                                "Compliance",
                                "DefenderCompliance",
                                "PurviewCompliance",
                                "IdentityProtection",
                                "SecureScore",
                                "Devices",
                                "Hybrid",
                                "AzurePolicy",
                                "DeltaReporting"
                            )
                        }
                        minItems = 1
                        uniqueItems = $true
                        description = "Assessment modules to execute"
                    }
                    Mode = @{
                        type = "string"
                        enum = @("Interactive", "Scheduled", "CI/CD")
                        default = "Interactive"
                        description = "Execution mode"
                    }
                    Tenant = @{
                        type = "object"
                        properties = @{
                            TenantId = @{
                                type = "string"
                                pattern = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
                                description = "Azure AD Tenant ID (GUID)"
                            }
                            TenantName = @{
                                type = "string"
                                description = "Tenant display name"
                            }
                        }
                    }
                    Output = @{
                        type = "object"
                        required = @('Directory', 'Formats')
                        properties = @{
                            Directory = @{
                                type = "string"
                                description = "Output directory path"
                            }
                            Formats = @{
                                type = "array"
                                items = @{
                                    type = "string"
                                    enum = @("HTML", "CSV", "JSON", "XML")
                                }
                                minItems = 1
                                uniqueItems = $true
                                description = "Report output formats"
                            }
                            IncludeTimestamp = @{
                                type = "boolean"
                                default = $true
                                description = "Include timestamp in output filenames"
                            }
                        }
                    }
                    Exclusions = @{
                        type = "object"
                        properties = @{
                            Users = @{
                                type = "array"
                                items = @{ type = "string" }
                                description = "User UPNs to exclude from checks"
                            }
                            Groups = @{
                                type = "array"
                                items = @{ type = "string" }
                                description = "Group names to exclude from checks"
                            }
                            Checks = @{
                                type = "array"
                                items = @{ type = "string" }
                                description = "Specific checks to skip"
                            }
                        }
                    }
                }
            }
            Authentication = @{
                type = "object"
                properties = @{
                    Method = @{
                        type = "string"
                        enum = @("Interactive", "DeviceCode", "ServicePrincipal", "ManagedIdentity", "Certificate")
                        default = "Interactive"
                        description = "Authentication method"
                    }
                    ServicePrincipal = @{
                        type = "object"
                        properties = @{
                            ClientId = @{
                                type = "string"
                                pattern = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
                                description = "Service Principal Client ID"
                            }
                            CertificateThumbprint = @{
                                type = "string"
                                pattern = '^[0-9a-fA-F]{40}$'
                                description = "Certificate thumbprint (SHA1)"
                            }
                            KeyVaultName = @{
                                type = "string"
                                description = "Azure Key Vault name for secret storage"
                            }
                            SecretName = @{
                                type = "string"
                                description = "Secret name in Key Vault"
                            }
                        }
                    }
                    Scopes = @{
                        type = "array"
                        items = @{ type = "string" }
                        default = @(
                            "Directory.Read.All",
                            "Policy.Read.All",
                            "IdentityRiskyUser.Read.All",
                            "SecurityEvents.Read.All"
                        )
                        description = "Microsoft Graph API scopes"
                    }
                }
            }
            Logging = @{
                type = "object"
                required = @('Directory', 'MinimumLevel')
                properties = @{
                    Directory = @{
                        type = "string"
                        description = "Log files directory"
                    }
                    MinimumLevel = @{
                        type = "string"
                        enum = @("DEBUG", "INFO", "WARN", "ERROR", "CRITICAL")
                        default = "INFO"
                        description = "Minimum log level"
                    }
                    Targets = @{
                        type = "array"
                        items = @{
                            type = "string"
                            enum = @("File", "Console", "EventLog")
                        }
                        default = @("File", "Console")
                        uniqueItems = $true
                        description = "Log output targets"
                    }
                    StructuredLogging = @{
                        type = "boolean"
                        default = $true
                        description = "Enable JSON structured logging"
                    }
                    RetentionDays = @{
                        type = "integer"
                        minimum = 1
                        maximum = 3650
                        default = 90
                        description = "Log retention period in days"
                    }
                    MaxFileSizeMB = @{
                        type = "integer"
                        minimum = 1
                        maximum = 1000
                        default = 100
                        description = "Maximum log file size in MB"
                    }
                    BufferSize = @{
                        type = "integer"
                        minimum = 1
                        maximum = 1000
                        default = 100
                        description = "Log buffer size (entries)"
                    }
                }
            }
            ErrorHandling = @{
                type = "object"
                properties = @{
                    MaxRetries = @{
                        type = "integer"
                        minimum = 0
                        maximum = 10
                        default = 3
                        description = "Maximum retry attempts"
                    }
                    BaseDelaySeconds = @{
                        type = "integer"
                        minimum = 1
                        maximum = 60
                        default = 5
                        description = "Base delay between retries (seconds)"
                    }
                    ExponentialBackoff = @{
                        type = "boolean"
                        default = $true
                        description = "Enable exponential backoff"
                    }
                    CircuitBreaker = @{
                        type = "object"
                        properties = @{
                            Enabled = @{
                                type = "boolean"
                                default = $true
                                description = "Enable circuit breaker"
                            }
                            FailureThreshold = @{
                                type = "integer"
                                minimum = 1
                                maximum = 20
                                default = 5
                                description = "Failures before opening circuit"
                            }
                            TimeoutSeconds = @{
                                type = "integer"
                                minimum = 10
                                maximum = 600
                                default = 60
                                description = "Circuit breaker timeout (seconds)"
                            }
                            HalfOpenRequests = @{
                                type = "integer"
                                minimum = 1
                                maximum = 10
                                default = 1
                                description = "Test requests in half-open state"
                            }
                        }
                    }
                }
            }
            KeyVault = @{
                type = "object"
                properties = @{
                    Enabled = @{
                        type = "boolean"
                        default = $false
                        description = "Enable Azure Key Vault integration (optional)"
                    }
                    VaultName = @{
                        type = "string"
                        description = "Azure Key Vault name"
                    }
                    AuthenticationMethod = @{
                        type = "string"
                        enum = @("ManagedIdentity", "ServicePrincipal", "Interactive")
                        default = "ManagedIdentity"
                        description = "Key Vault authentication method"
                    }
                    TenantId = @{
                        type = "string"
                        pattern = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
                        description = "Tenant ID (required for ServicePrincipal/Interactive)"
                    }
                    ClientId = @{
                        type = "string"
                        pattern = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
                        description = "Service Principal Client ID (for ServicePrincipal auth)"
                    }
                    CertificateThumbprint = @{
                        type = "string"
                        pattern = '^[0-9a-fA-F]{40}$'
                        description = "Certificate thumbprint (for ServicePrincipal with cert)"
                    }
                    Secrets = @{
                        type = "object"
                        description = "Mapping of secret purposes to Key Vault secret names"
                        properties = @{
                            GraphAPISecret = @{
                                type = "string"
                                description = "Secret name for Graph API credentials"
                            }
                            ServicePrincipalSecret = @{
                                type = "string"
                                description = "Secret name for Service Principal secret"
                            }
                        }
                    }
                }
            }
            Performance = @{
                type = "object"
                properties = @{
                    MaxConcurrentRequests = @{
                        type = "integer"
                        minimum = 1
                        maximum = 50
                        default = 10
                        description = "Maximum concurrent API requests"
                    }
                    RateLimitBuffer = @{
                        type = "integer"
                        minimum = 0
                        maximum = 50
                        default = 10
                        description = "Percentage buffer for rate limits"
                    }
                    CacheDurationMinutes = @{
                        type = "integer"
                        minimum = 0
                        maximum = 1440
                        default = 15
                        description = "Cache duration for API responses (minutes)"
                    }
                    EnableCaching = @{
                        type = "boolean"
                        default = $false
                        description = "Enable response caching"
                    }
                }
            }
            Notifications = @{
                type = "object"
                properties = @{
                    Email = @{
                        type = "object"
                        properties = @{
                            Enabled = @{
                                type = "boolean"
                                default = $false
                            }
                            SMTPServer = @{ type = "string" }
                            Port = @{
                                type = "integer"
                                minimum = 1
                                maximum = 65535
                                default = 587
                            }
                            From = @{ type = "string"; format = "email" }
                            To = @{
                                type = "array"
                                items = @{ type = "string"; format = "email" }
                            }
                            UseSSL = @{
                                type = "boolean"
                                default = $true
                            }
                        }
                    }
                    Teams = @{
                        type = "object"
                        properties = @{
                            Enabled = @{
                                type = "boolean"
                                default = $false
                            }
                            WebhookURL = @{ type = "string"; format = "uri" }
                        }
                    }
                    Slack = @{
                        type = "object"
                        properties = @{
                            Enabled = @{
                                type = "boolean"
                                default = $false
                            }
                            WebhookURL = @{ type = "string"; format = "uri" }
                        }
                    }
                }
            }
            Compliance = @{
                type = "object"
                properties = @{
                    Frameworks = @{
                        type = "array"
                        items = @{
                            type = "string"
                            enum = @("NIST", "CIS", "ISO27001", "SOC2", "PCI-DSS", "HIPAA", "GDPR")
                        }
                        uniqueItems = $true
                        description = "Compliance frameworks to assess against"
                    }
                    CustomBenchmarks = @{
                        type = "array"
                        items = @{
                            type = "object"
                            properties = @{
                                Name = @{ type = "string" }
                                FilePath = @{ type = "string" }
                            }
                        }
                        description = "Custom benchmark definitions"
                    }
                }
            }
            SOC2 = @{
                type = "object"
                description = "SOC 2 internal readiness assessment configuration"
                properties = @{
                    Enabled = @{
                        type = "boolean"
                        default = $false
                        description = "Enable SOC 2 assessment workflow"
                    }
                    Type = @{
                        type = "string"
                        enum = @("Type1", "Type2")
                        default = "Type1"
                        description = "SOC 2 report type"
                    }
                    Categories = @{
                        type = "array"
                        items = @{
                            type = "string"
                            enum = @("CC", "A", "C", "PI", "P")
                        }
                        default = @("CC", "A", "C", "PI", "P")
                        uniqueItems = $true
                        description = "Trust Services Categories in scope"
                    }
                    IncludeManualAttestation = @{
                        type = "boolean"
                        default = $true
                        description = "Emit MANUAL findings for non-automatable TSCs"
                    }
                    TypeTwoPeriod = @{
                        type = "object"
                        properties = @{
                            StartDate = @{ type = "string"; description = "ISO 8601 start date (Type 2 only)" }
                            EndDate = @{ type = "string"; description = "ISO 8601 end date (Type 2 only)" }
                            MinSnapshotsRequired = @{ type = "integer"; minimum = 1; maximum = 365; default = 12 }
                            SnapshotCadence = @{ type = "string"; enum = @("Daily", "Weekly", "Monthly"); default = "Weekly" }
                        }
                    }
                    Evidence = @{
                        type = "object"
                        properties = @{
                            IncludeRawPayloads = @{ type = "boolean"; default = $true }
                            HashAlgorithm = @{ type = "string"; enum = @("SHA256", "SHA384", "SHA512"); default = "SHA256" }
                            SignReports = @{ type = "boolean"; default = $false }
                            SigningCertificateThumbprint = @{ type = "string" }
                            KeyVaultName = @{ type = "string" }
                            KeyVaultCertificateName = @{ type = "string" }
                            Assessor = @{ type = "string" }
                            ServiceOrganization = @{ type = "string" }
                            RetentionYears = @{ type = "integer"; minimum = 1; maximum = 50; default = 7 }
                        }
                    }
                    Redaction = @{
                        type = "object"
                        properties = @{
                            RedactUserPII = @{ type = "boolean"; default = $true }
                            RedactDeviceNames = @{ type = "boolean"; default = $true }
                            EmitIdentityResolutionMap = @{ type = "boolean"; default = $true }
                            IdentityResolutionMapPath = @{ type = "string"; default = ".\\Output\\SOC2\\identity-resolution\\" }
                            EmbedResolutionMapInWorkbook = @{ type = "boolean"; default = $false }
                        }
                    }
                    Branding = @{
                        type = "object"
                        properties = @{
                            WhiteLabel = @{ type = "boolean"; default = $false }
                            OrganizationName = @{ type = "string" }
                            OrganizationLogoPath = @{ type = "string" }
                            ReportFooter = @{ type = "string" }
                            PrimaryColor = @{ type = "string"; pattern = '^#[0-9A-Fa-f]{6}$' }
                            SuppressEntraChecksBranding = @{ type = "boolean"; default = $false }
                        }
                    }
                    Phase2 = @{
                        type = "object"
                        description = "SOC 2 Phase 2 Azure-readiness check configuration"
                        properties = @{
                            SubscriptionFilter = @{
                                type = "array"
                                items = @{ type = "string" }
                                default = @()
                                description = "Optional list of subscription IDs or names to scope Azure-side Phase 2 checks"
                            }
                            Backup = @{
                                type = "object"
                                properties = @{
                                    VaultFilter = @{
                                        type = "array"
                                        items = @{ type = "string" }
                                        default = @()
                                    }
                                    MinRedundancyTier = @{
                                        type = "string"
                                        enum = @("LRS", "ZRS", "GRS", "RA-GRS")
                                        default = "GRS"
                                    }
                                }
                            }
                            ServiceHealth = @{
                                type = "object"
                                properties = @{
                                    AvailabilityThresholdPercent = @{
                                        type = "integer"
                                        minimum = 0
                                        maximum = 100
                                        default = 98
                                    }
                                }
                            }
                            DiagnosticSettings = @{
                                type = "object"
                                properties = @{
                                    RequiredWorkspaceId = @{
                                        type = "string"
                                        description = "Optional Log Analytics workspace resource ID; when set, Entra diag export must target this workspace"
                                    }
                                    RequiredCategories = @{
                                        type = "array"
                                        items = @{ type = "string" }
                                        default = @("AuditLogs", "SignInLogs")
                                    }
                                }
                            }
                            BreakGlass = @{
                                type = "object"
                                properties = @{
                                    MinimumAccounts = @{
                                        type = "integer"
                                        minimum = 1
                                        maximum = 10
                                        default = 2
                                    }
                                    AccountUpnPatterns = @{
                                        type = "array"
                                        items = @{ type = "string" }
                                        default = @()
                                    }
                                }
                            }
                            Licensing = @{
                                type = "object"
                                description = "Override licensing-gap finding severity (default INFO). Feature keys: IdentityProtection, Intune, PurviewE5, DefenderForCloud, DefenderForEndpoint, Priva"
                                properties = @{
                                    Overrides = @{
                                        type = "object"
                                        additionalProperties = @{
                                            type = "string"
                                            enum = @("INFO", "WARNING", "FAIL")
                                        }
                                    }
                                }
                            }
                        }
                    }
                    AzureReadiness = @{
                        type = "object"
                        description = "SOC 2 Azure-readiness check configuration. Replaces SOC2.Phase2 (deprecated; removed in v1.8.0). Schema is identical."
                        properties = @{
                            SubscriptionFilter = @{
                                type = "array"
                                items = @{ type = "string" }
                                default = @()
                                description = "Optional list of subscription IDs or names to scope Azure-side checks"
                            }
                            Backup = @{
                                type = "object"
                                properties = @{
                                    VaultFilter = @{
                                        type = "array"
                                        items = @{ type = "string" }
                                        default = @()
                                    }
                                    MinRedundancyTier = @{
                                        type = "string"
                                        enum = @("LRS", "ZRS", "GRS", "RA-GRS")
                                        default = "GRS"
                                    }
                                }
                            }
                            ServiceHealth = @{
                                type = "object"
                                properties = @{
                                    AvailabilityThresholdPercent = @{
                                        type = "integer"
                                        minimum = 0
                                        maximum = 100
                                        default = 98
                                    }
                                }
                            }
                            DiagnosticSettings = @{
                                type = "object"
                                properties = @{
                                    RequiredWorkspaceId = @{
                                        type = "string"
                                        description = "Optional Log Analytics workspace resource ID; when set, Entra diag export must target this workspace"
                                    }
                                    RequiredCategories = @{
                                        type = "array"
                                        items = @{ type = "string" }
                                        default = @("AuditLogs", "SignInLogs")
                                    }
                                }
                            }
                            BreakGlass = @{
                                type = "object"
                                properties = @{
                                    MinimumAccounts = @{
                                        type = "integer"
                                        minimum = 1
                                        maximum = 10
                                        default = 2
                                    }
                                    AccountUpnPatterns = @{
                                        type = "array"
                                        items = @{ type = "string" }
                                        default = @()
                                    }
                                }
                            }
                            Licensing = @{
                                type = "object"
                                description = "Override licensing-gap finding severity (default INFO). Feature keys: IdentityProtection, Intune, PurviewE5, DefenderForCloud, DefenderForEndpoint, Priva"
                                properties = @{
                                    Overrides = @{
                                        type = "object"
                                        additionalProperties = @{
                                            type = "string"
                                            enum = @("INFO", "WARNING", "FAIL")
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

#endregion

#region ==================== CONFIGURATION VALIDATION ====================

<#
.SYNOPSIS
    Validates a configuration object against the schema.

.DESCRIPTION
    Performs comprehensive validation of a configuration object to ensure
    it meets all schema requirements and business rules.

.PARAMETER ConfigObject
    The configuration hashtable to validate.

.PARAMETER Schema
    Optional custom schema. If not provided, uses default schema.

.OUTPUTS
    PSCustomObject with IsValid, Errors, and Warnings properties.

.EXAMPLE
    $result = Test-Configuration -ConfigObject $config
    if (-not $result.IsValid) {
        $result.Errors | ForEach-Object { Write-Error $_ }
    }
#>
function Test-Configuration {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$ConfigObject,

        [hashtable]$Schema
    )

    if (-not $Schema) {
        $Schema = Get-ConfigurationSchema
    }

    $errors = @()
    $warnings = @()

    # Write log if available
    if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
        Write-Log -Level DEBUG -Message "Validating configuration" -Category "Configuration"
    }

    # Validate version
    if (-not $ConfigObject.ContainsKey('Version')) {
        $errors += "Missing required field: Version"
    } elseif ($ConfigObject.Version -notmatch '^\d+\.\d+\.\d+$') {
        $errors += "Invalid Version format. Expected semver (e.g., 1.0.0)"
    }

    # Validate required sections
    $requiredSections = $Schema.required
    foreach ($section in $requiredSections) {
        if (-not $ConfigObject.ContainsKey($section)) {
            $errors += "Missing required section: $section"
        }
    }

    # Validate Assessment section
    if ($ConfigObject.Assessment) {
        $assessment = $ConfigObject.Assessment

        # Validate Scope
        if (-not $assessment.Scope -or $assessment.Scope.Count -eq 0) {
            $errors += "Assessment.Scope must contain at least one module"
        } else {
            $validScopes = $Schema.properties.Assessment.properties.Scope.items.enum
            foreach ($scope in $assessment.Scope) {
                if ($scope -notin $validScopes) {
                    $errors += "Invalid scope '$scope'. Valid values: $($validScopes -join ', ')"
                }
            }
        }

        # Validate Mode
        if ($assessment.Mode) {
            $validModes = $Schema.properties.Assessment.properties.Mode.enum
            if ($assessment.Mode -notin $validModes) {
                $errors += "Invalid Mode '$($assessment.Mode)'. Valid values: $($validModes -join ', ')"
            }
        }

        # Validate Tenant ID format
        if ($assessment.Tenant -and $assessment.Tenant.TenantId) {
            if ($assessment.Tenant.TenantId -notmatch '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') {
                $errors += "Invalid TenantId format. Expected GUID format"
            }
        }

        # Validate Output
        if (-not $assessment.Output) {
            $errors += "Missing required section: Assessment.Output"
        } else {
            if (-not $assessment.Output.Directory) {
                $errors += "Missing required field: Assessment.Output.Directory"
            }
            if (-not $assessment.Output.Formats -or $assessment.Output.Formats.Count -eq 0) {
                $errors += "Assessment.Output.Formats must contain at least one format"
            } else {
                $validFormats = $Schema.properties.Assessment.properties.Output.properties.Formats.items.enum
                foreach ($format in $assessment.Output.Formats) {
                    if ($format -notin $validFormats) {
                        $errors += "Invalid output format '$format'. Valid values: $($validFormats -join ', ')"
                    }
                }
            }
        }
    }

    # Validate Authentication section
    if ($ConfigObject.Authentication) {
        $auth = $ConfigObject.Authentication

        if ($auth.Method) {
            $validMethods = $Schema.properties.Authentication.properties.Method.enum
            if ($auth.Method -notin $validMethods) {
                $errors += "Invalid authentication method '$($auth.Method)'. Valid values: $($validMethods -join ', ')"
            }

            # Validate ServicePrincipal configuration
            if ($auth.Method -eq "ServicePrincipal" -and $auth.ServicePrincipal) {
                if (-not $auth.ServicePrincipal.ClientId) {
                    $errors += "ServicePrincipal.ClientId is required when using ServicePrincipal authentication"
                } elseif ($auth.ServicePrincipal.ClientId -notmatch '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') {
                    $errors += "Invalid ServicePrincipal.ClientId format. Expected GUID"
                }

                if ($auth.ServicePrincipal.CertificateThumbprint -and
                    $auth.ServicePrincipal.CertificateThumbprint -notmatch '^[0-9a-fA-F]{40}$') {
                    $errors += "Invalid CertificateThumbprint format. Expected 40-character hexadecimal"
                }

                if (-not $auth.ServicePrincipal.CertificateThumbprint -and
                    -not $auth.ServicePrincipal.KeyVaultName) {
                    $warnings += "ServicePrincipal authentication requires either CertificateThumbprint or KeyVaultName"
                }
            }
        }
    }

    # Validate Logging section
    if ($ConfigObject.Logging) {
        $logging = $ConfigObject.Logging

        if (-not $logging.Directory) {
            $errors += "Missing required field: Logging.Directory"
        }

        if (-not $logging.MinimumLevel) {
            $errors += "Missing required field: Logging.MinimumLevel"
        } else {
            $validLevels = $Schema.properties.Logging.properties.MinimumLevel.enum
            if ($logging.MinimumLevel -notin $validLevels) {
                $errors += "Invalid log level '$($logging.MinimumLevel)'. Valid values: $($validLevels -join ', ')"
            }
        }

        if ($logging.Targets) {
            $validTargets = $Schema.properties.Logging.properties.Targets.items.enum
            foreach ($target in $logging.Targets) {
                if ($target -notin $validTargets) {
                    $errors += "Invalid log target '$target'. Valid values: $($validTargets -join ', ')"
                }
            }

            if ('EventLog' -in $logging.Targets) {
                $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
                if (-not $isAdmin) {
                    $warnings += "EventLog target requires administrator privileges. It may fall back to File/Console"
                }
            }
        }

        # Validate numeric ranges
        if ($logging.RetentionDays) {
            if ($logging.RetentionDays -lt 1 -or $logging.RetentionDays -gt 3650) {
                $errors += "RetentionDays must be between 1 and 3650"
            }
        }

        if ($logging.MaxFileSizeMB) {
            if ($logging.MaxFileSizeMB -lt 1 -or $logging.MaxFileSizeMB -gt 1000) {
                $errors += "MaxFileSizeMB must be between 1 and 1000"
            }
        }
    }

    # Validate ErrorHandling section
    if ($ConfigObject.ErrorHandling) {
        $errorHandling = $ConfigObject.ErrorHandling

        if ($errorHandling.MaxRetries -and ($errorHandling.MaxRetries -lt 0 -or $errorHandling.MaxRetries -gt 10)) {
            $errors += "MaxRetries must be between 0 and 10"
        }

        if ($errorHandling.BaseDelaySeconds -and ($errorHandling.BaseDelaySeconds -lt 1 -or $errorHandling.BaseDelaySeconds -gt 60)) {
            $errors += "BaseDelaySeconds must be between 1 and 60"
        }

        if ($errorHandling.CircuitBreaker) {
            $cb = $errorHandling.CircuitBreaker

            if ($cb.FailureThreshold -and ($cb.FailureThreshold -lt 1 -or $cb.FailureThreshold -gt 20)) {
                $errors += "CircuitBreaker.FailureThreshold must be between 1 and 20"
            }

            if ($cb.TimeoutSeconds -and ($cb.TimeoutSeconds -lt 10 -or $cb.TimeoutSeconds -gt 600)) {
                $errors += "CircuitBreaker.TimeoutSeconds must be between 10 and 600"
            }
        }
    }

    # Validate Performance section
    if ($ConfigObject.Performance) {
        $perf = $ConfigObject.Performance

        if ($perf.MaxConcurrentRequests -and ($perf.MaxConcurrentRequests -lt 1 -or $perf.MaxConcurrentRequests -gt 50)) {
            $errors += "MaxConcurrentRequests must be between 1 and 50"
        }

        if ($perf.RateLimitBuffer -and ($perf.RateLimitBuffer -lt 0 -or $perf.RateLimitBuffer -gt 50)) {
            $errors += "RateLimitBuffer must be between 0 and 50"
        }
    }

    # Validate Notifications section
    if ($ConfigObject.Notifications) {
        $notifications = $ConfigObject.Notifications

        # Email validation
        if ($notifications.Email -and $notifications.Email.Enabled) {
            if (-not $notifications.Email.SMTPServer) {
                $errors += "Email.SMTPServer is required when email notifications are enabled"
            }
            if (-not $notifications.Email.From) {
                $errors += "Email.From is required when email notifications are enabled"
            }
            if (-not $notifications.Email.To -or $notifications.Email.To.Count -eq 0) {
                $errors += "Email.To must contain at least one recipient when email notifications are enabled"
            }
        }

        # Teams validation
        if ($notifications.Teams -and $notifications.Teams.Enabled -and -not $notifications.Teams.WebhookURL) {
            $errors += "Teams.WebhookURL is required when Teams notifications are enabled"
        }

        # Slack validation
        if ($notifications.Slack -and $notifications.Slack.Enabled -and -not $notifications.Slack.WebhookURL) {
            $errors += "Slack.WebhookURL is required when Slack notifications are enabled"
        }
    }

    # Validate SOC2 section (optional; only validate when present)
    if ($ConfigObject.SOC2) {
        $soc2 = $ConfigObject.SOC2

        if ($soc2.Type -and $soc2.Type -notin @('Type1', 'Type2')) {
            $errors += "SOC2.Type must be 'Type1' or 'Type2'"
        }

        if ($soc2.Categories) {
            $validCategories = @('CC', 'A', 'C', 'PI', 'P')
            foreach ($cat in $soc2.Categories) {
                if ($cat -notin $validCategories) {
                    $errors += "Invalid SOC2.Categories value '$cat'. Valid: $($validCategories -join ', ')"
                }
            }
        }

        if ($soc2.Type -eq 'Type2' -and $soc2.TypeTwoPeriod) {
            if (-not $soc2.TypeTwoPeriod.StartDate -or -not $soc2.TypeTwoPeriod.EndDate) {
                $warnings += "SOC2.Type=Type2 requires TypeTwoPeriod.StartDate and TypeTwoPeriod.EndDate"
            }
        }

        if ($soc2.Evidence) {
            if ($soc2.Evidence.HashAlgorithm -and $soc2.Evidence.HashAlgorithm -notin @('SHA256', 'SHA384', 'SHA512')) {
                $errors += "SOC2.Evidence.HashAlgorithm must be SHA256, SHA384, or SHA512"
            }
            if ($soc2.Evidence.SignReports -and -not $soc2.Evidence.KeyVaultName) {
                $warnings += "SOC2.Evidence.SignReports is true but no KeyVaultName is configured"
            }
            if ($soc2.Evidence.RetentionYears -and ($soc2.Evidence.RetentionYears -lt 1 -or $soc2.Evidence.RetentionYears -gt 50)) {
                $errors += "SOC2.Evidence.RetentionYears must be between 1 and 50"
            }
        }

        if ($soc2.Branding -and $soc2.Branding.WhiteLabel) {
            if (-not $soc2.Branding.OrganizationName) {
                $errors += "SOC2.Branding.OrganizationName is required when WhiteLabel = true"
            }
            if ($soc2.Branding.PrimaryColor -and $soc2.Branding.PrimaryColor -notmatch '^#[0-9A-Fa-f]{6}$') {
                $errors += "SOC2.Branding.PrimaryColor must be a 6-digit hex color (e.g., '#005A9E')"
            }
            if ($soc2.Branding.OrganizationLogoPath -and -not (Test-Path -LiteralPath $soc2.Branding.OrganizationLogoPath)) {
                $warnings += "SOC2.Branding.OrganizationLogoPath does not exist: $($soc2.Branding.OrganizationLogoPath)"
            }
        }

        # Phase 2 / AzureReadiness validation (identical schema; share logic)
        $azReadinessBlocks = @()
        if ($soc2.Phase2) {
            $azReadinessBlocks += @{ Block = $soc2.Phase2; Path = 'SOC2.Phase2' }
        }
        if ($soc2.AzureReadiness) {
            $azReadinessBlocks += @{ Block = $soc2.AzureReadiness; Path = 'SOC2.AzureReadiness' }
        }

        foreach ($entry in $azReadinessBlocks) {
            $block = $entry.Block
            $path = $entry.Path

            if ($block.BreakGlass -and $null -ne $block.BreakGlass.MinimumAccounts) {
                $min = $block.BreakGlass.MinimumAccounts
                if ($min -lt 1 -or $min -gt 10) {
                    $errors += "$path.BreakGlass.MinimumAccounts must be between 1 and 10"
                }
            }

            if ($block.ServiceHealth -and $null -ne $block.ServiceHealth.AvailabilityThresholdPercent) {
                $threshold = $block.ServiceHealth.AvailabilityThresholdPercent
                if ($threshold -lt 0 -or $threshold -gt 100) {
                    $errors += "$path.ServiceHealth.AvailabilityThresholdPercent must be between 0 and 100"
                }
            }

            if ($block.Backup -and $block.Backup.MinRedundancyTier) {
                $validTiers = @("LRS", "ZRS", "GRS", "RA-GRS")
                if ($block.Backup.MinRedundancyTier -notin $validTiers) {
                    $errors += "$path.Backup.MinRedundancyTier must be one of: $($validTiers -join ', ')"
                }
            }

            if ($block.Licensing -and $block.Licensing.Overrides) {
                $validSeverities = @("INFO", "WARNING", "FAIL")
                foreach ($feature in $block.Licensing.Overrides.Keys) {
                    $severity = $block.Licensing.Overrides[$feature]
                    if ($severity -notin $validSeverities) {
                        $errors += "$path.Licensing.Overrides.$feature = '$severity' invalid; must be one of: $($validSeverities -join ', ')"
                    }
                }
            }

            if ($block.DiagnosticSettings -and $block.DiagnosticSettings.RequiredWorkspaceId) {
                $wsId = $block.DiagnosticSettings.RequiredWorkspaceId
                if ($wsId -notmatch '^/subscriptions/[0-9a-fA-F-]+/resourceGroups/.+/providers/Microsoft\.OperationalInsights/workspaces/.+$') {
                    $warnings += "$path.DiagnosticSettings.RequiredWorkspaceId does not look like a full Log Analytics workspace resource ID"
                }
            }
        }
    }

    # Validate path accessibility
    $pathsToCheck = @()
    if ($ConfigObject.Assessment -and $ConfigObject.Assessment.Output -and $ConfigObject.Assessment.Output.Directory) {
        $pathsToCheck += @{ Path = $ConfigObject.Assessment.Output.Directory; Name = "Assessment.Output.Directory" }
    }
    if ($ConfigObject.Logging -and $ConfigObject.Logging.Directory) {
        $pathsToCheck += @{ Path = $ConfigObject.Logging.Directory; Name = "Logging.Directory" }
    }

    foreach ($pathCheck in $pathsToCheck) {
        $path = $pathCheck.Path
        $name = $pathCheck.Name

        # Check if path is rooted (absolute)
        if (-not [System.IO.Path]::IsPathRooted($path) -and -not $path.StartsWith('.')) {
            $warnings += "$name uses a relative path: $path. Consider using absolute paths for clarity"
        }

        # Check if parent directory exists (create if possible)
        try {
            $parentDir = Split-Path -Parent $path
            if ($parentDir -and -not (Test-Path $parentDir)) {
                $warnings += "$name parent directory does not exist: $parentDir. It will be created on initialization"
            }
        }
        catch {
            $warnings += "Unable to validate path for ${name}: $path"
        }
    }

    $isValid = ($errors.Count -eq 0)

    if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
        if ($isValid) {
            Write-Log -Level INFO -Message "Configuration validation passed" -Category "Configuration" -Properties @{
                Warnings = $warnings.Count
            }
        } else {
            Write-Log -Level ERROR -Message "Configuration validation failed" -Category "Configuration" -Properties @{
                Errors = $errors.Count
                Warnings = $warnings.Count
            }
        }
    }

    return [PSCustomObject]@{
        IsValid = $isValid
        Errors = $errors
        Warnings = $warnings
        ValidatedAt = Get-Date
    }
}

#endregion

#region ==================== CONFIGURATION LOADING ====================

<#
.SYNOPSIS
    Recursively converts a PSCustomObject (typically from ConvertFrom-Json) into
    a nested hashtable structure. Internal helper.

.DESCRIPTION
    Replaces the functionality of PowerShell 6+ `ConvertFrom-Json -AsHashtable`
    for Windows PowerShell 5.1 compatibility. Walks the object graph:
    PSCustomObject becomes hashtable, enumerables become arrays (single-element
    arrays preserved), primitives pass through. Strings are treated as scalars,
    not enumerables.

.PARAMETER InputObject
    The object to convert. May be null.

.OUTPUTS
    Hashtable for objects, array for enumerables, scalar otherwise.

.NOTES
    Private to this module; not exported. The leading comma on the array
    return preserves single-element arrays so callers iterating via foreach
    don't see a scalar when JSON declared an array with one element.
#>
function ConvertTo-HashtableDeep {
    [CmdletBinding()]
    [OutputType([hashtable], [object[]], [object])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [AllowNull()]
        $InputObject
    )

    process {
        if ($null -eq $InputObject) { return $null }

        # Strings are IEnumerable<char> but must not be exploded.
        if ($InputObject -is [string]) { return $InputObject }

        if ($InputObject -is [System.Collections.IEnumerable]) {
            $list = New-Object System.Collections.ArrayList
            foreach ($item in $InputObject) {
                $null = $list.Add((ConvertTo-HashtableDeep -InputObject $item))
            }
            # Leading comma prevents single-element arrays from being unwrapped.
            return , $list.ToArray()
        }

        if ($InputObject -is [System.Management.Automation.PSCustomObject]) {
            $ht = @{}
            foreach ($prop in $InputObject.PSObject.Properties) {
                $ht[$prop.Name] = ConvertTo-HashtableDeep -InputObject $prop.Value
            }
            return $ht
        }

        return $InputObject
    }
}

# Module-scoped guard so the deprecation warning fires once per session.
$script:Soc2DeprecationWarningIssued = $false

<#
.SYNOPSIS
    Resolves SOC2.Phase2 vs SOC2.AzureReadiness namespace migration in place.

.DESCRIPTION
    SOC 2 Phase 3 renamed `SOC2.Phase2.*` to `SOC2.AzureReadiness.*`. Both keys
    are accepted through v1.7.x with a deprecation warning. v1.8.0 will remove
    Phase2 support entirely.

    This shim merges the two namespaces in place so all downstream consumers
    see the same canonical shape under both keys:

    - When only `SOC2.Phase2` is present, copies it to `SOC2.AzureReadiness`
      and emits a single deprecation warning.
    - When only `SOC2.AzureReadiness` is present, mirrors it to `SOC2.Phase2`
      so any caller that has not yet migrated keeps working. No warning.
    - When both are present, `SOC2.AzureReadiness` wins per key (recursive merge),
      and a "both present" warning is emitted.
    - When neither is present, no action.

    The deprecation warning is emitted via Write-Warning AND Write-Log (when
    available), suppressed after first issuance for the lifetime of the module.

.PARAMETER ConfigObject
    The full configuration hashtable. Modified in place; also returned for
    pipeline use.

.OUTPUTS
    The same hashtable, with SOC2.AzureReadiness and SOC2.Phase2 in sync.

.EXAMPLE
    $config = Import-Configuration -FilePath '.\config\entrachecks.config.json'
    # ^ Resolve-SOC2NamespaceConfig runs internally during Import-Configuration

.EXAMPLE
    $rawCfg = Get-Content '.\config\entrachecks.config.json' -Raw | ConvertFrom-Json | ConvertTo-HashtableDeep
    $rawCfg = Resolve-SOC2NamespaceConfig -ConfigObject $rawCfg
    # ^ For callers that bypass Import-Configuration (e.g., menu handlers reading raw JSON)
#>
function Resolve-SOC2NamespaceConfig {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [hashtable]$ConfigObject
    )

    if ($null -eq $ConfigObject) { return $ConfigObject }
    if (-not $ConfigObject.ContainsKey('SOC2')) { return $ConfigObject }

    $soc2 = $ConfigObject.SOC2
    if ($null -eq $soc2 -or -not ($soc2 -is [hashtable])) { return $ConfigObject }

    $hasPhase2 = $soc2.ContainsKey('Phase2') -and $null -ne $soc2.Phase2
    $hasAzureReadiness = $soc2.ContainsKey('AzureReadiness') -and $null -ne $soc2.AzureReadiness

    if (-not $hasPhase2 -and -not $hasAzureReadiness) { return $ConfigObject }

    # Reusable deprecation notification. Single fire per session.
    $emitWarning = {
        param([string]$Reason)
        if ($script:Soc2DeprecationWarningIssued) { return }
        $script:Soc2DeprecationWarningIssued = $true
        $msg = "SOC2.Phase2.* configuration keys are deprecated. Please rename your block to SOC2.AzureReadiness.* (same schema, semantic name). Old keys remain functional through version 1.7.x and will be removed in version 1.8.0. See docs/SOC2-Guide.md SS13 for migration details. ($Reason)"
        Write-Warning $msg
        if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
            Write-Log -Level WARN -Message $msg -Category 'Configuration'
        }
    }

    if ($hasPhase2 -and -not $hasAzureReadiness) {
        # Old-only: alias Phase2 into AzureReadiness so downstream code sees the canonical name.
        $soc2['AzureReadiness'] = $soc2.Phase2
        & $emitWarning 'detected SOC2.Phase2 only'
        return $ConfigObject
    }

    if ($hasAzureReadiness -and -not $hasPhase2) {
        # New-only: mirror AzureReadiness back to Phase2 so any pre-Phase-3 caller still works. No warning.
        $soc2['Phase2'] = $soc2.AzureReadiness
        return $ConfigObject
    }

    # Both present: AzureReadiness wins per key via recursive merge.
    $soc2['AzureReadiness'] = Merge-NamespaceBlocks -Base $soc2.Phase2 -Override $soc2.AzureReadiness
    $soc2['Phase2'] = $soc2.AzureReadiness
    & $emitWarning 'both SOC2.AzureReadiness and SOC2.Phase2 detected; AzureReadiness wins per key'
    return $ConfigObject
}

<#
.SYNOPSIS
    Internal helper: recursive hashtable merge where Override wins per key.
    Private to this module; supports Resolve-SOC2NamespaceConfig.
#>
function Merge-NamespaceBlocks {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][AllowNull()][hashtable]$Base,
        [Parameter(Mandatory)][AllowNull()][hashtable]$Override
    )

    if ($null -eq $Base) { return $Override }
    if ($null -eq $Override) { return $Base }

    $merged = @{}
    foreach ($key in $Base.Keys) { $merged[$key] = $Base[$key] }

    foreach ($key in $Override.Keys) {
        if ($merged.ContainsKey($key) -and ($merged[$key] -is [hashtable]) -and ($Override[$key] -is [hashtable])) {
            $merged[$key] = Merge-NamespaceBlocks -Base $merged[$key] -Override $Override[$key]
        } else {
            $merged[$key] = $Override[$key]
        }
    }

    return $merged
}

<#
.SYNOPSIS
    Loads configuration from a JSON file.

.DESCRIPTION
    Reads and validates configuration from a JSON file. Supports environment
    variable substitution and default value merging.

.PARAMETER FilePath
    Path to the configuration JSON file.

.PARAMETER ValidateOnly
    If specified, only validates the configuration without loading it.

.PARAMETER Environment
    Optional environment name (e.g., "dev", "staging", "prod") for
    environment-specific configuration overrides.

.OUTPUTS
    Hashtable containing the loaded configuration.

.EXAMPLE
    $config = Import-Configuration -FilePath ".\config\entrachecks.config.json"

.EXAMPLE
    $config = Import-Configuration -FilePath ".\config.json" -Environment "prod"
#>
function Import-Configuration {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [string]$FilePath,

        [switch]$ValidateOnly,

        [string]$Environment
    )

    if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
        Write-Log -Level INFO -Message "Loading configuration" -Category "Configuration" -Properties @{
            FilePath = $FilePath
            Environment = $Environment
        }
    }

    # Check if file exists
    if (-not (Test-Path $FilePath)) {
        $errorMsg = "Configuration file not found: $FilePath"
        if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
            Write-Log -Level ERROR -Message $errorMsg -Category "Configuration"
        }
        throw $errorMsg
    }

    # Read and parse JSON
    try {
        $jsonContent = Get-Content -Path $FilePath -Raw
        $config = $jsonContent | ConvertFrom-Json | ConvertTo-HashtableDeep
    }
    catch {
        $errorMsg = "Failed to parse configuration file: $_"
        if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
            Write-Log -Level ERROR -Message $errorMsg -Category "Configuration" -ErrorRecord $_
        }
        throw $errorMsg
    }

    # Perform environment variable substitution
    $config = Expand-ConfigurationVariables -ConfigObject $config

    # Load environment-specific overrides if specified
    if ($Environment) {
        $envConfigPath = $FilePath -replace '\.json$', ".$Environment.json"
        if (Test-Path $envConfigPath) {
            if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
                Write-Log -Level INFO -Message "Loading environment-specific configuration" -Category "Configuration" -Properties @{
                    Environment = $Environment
                    FilePath = $envConfigPath
                }
            }

            try {
                $envJsonContent = Get-Content -Path $envConfigPath -Raw
                $envConfig = $envJsonContent | ConvertFrom-Json | ConvertTo-HashtableDeep
                $config = Merge-Configuration -BaseConfig $config -OverrideConfig $envConfig
            }
            catch {
                if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
                    Write-Log -Level WARN -Message "Failed to load environment configuration" -Category "Configuration" -ErrorRecord $_
                }
            }
        }
    }

    # SOC 2 Phase 3: namespace migration shim — runs after env-override merge,
    # before defaults merge, so all downstream consumers (Test-Configuration,
    # Get-ConfigValue, etc.) see SOC2.AzureReadiness as the canonical name.
    $config = Resolve-SOC2NamespaceConfig -ConfigObject $config

    # Merge with defaults
    $config = Merge-ConfigurationDefaults -ConfigObject $config

    # Validate configuration
    $validation = Test-Configuration -ConfigObject $config

    if (-not $validation.IsValid) {
        $errorMsg = "Configuration validation failed:`n" + ($validation.Errors -join "`n")
        if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
            Write-Log -Level ERROR -Message $errorMsg -Category "Configuration"
        }
        throw $errorMsg
    }

    # Log warnings
    if ($validation.Warnings.Count -gt 0 -and (Get-Command Write-Log -ErrorAction SilentlyContinue)) {
        foreach ($warning in $validation.Warnings) {
            Write-Log -Level WARN -Message $warning -Category "Configuration"
        }
    }

    if (-not $ValidateOnly) {
        $script:Config = $config
        $script:ConfigLoaded = $true
        $script:ConfigFilePath = $FilePath

        if (Get-Command Write-AuditLog -ErrorAction SilentlyContinue) {
            Write-AuditLog -EventType "ConfigurationChanged" -Description "Configuration loaded successfully" -Details @{
                FilePath = $FilePath
                Environment = $Environment
            } -Result "Success"
        }
    }

    return $config
}

<#
.SYNOPSIS
    Expands environment variables in configuration values.

.DESCRIPTION
    Replaces placeholders like ${ENV:VAR_NAME} with environment variable values.

.PARAMETER ConfigObject
    Configuration hashtable to process.

.OUTPUTS
    Hashtable with expanded variables.

.EXAMPLE
    $config = Expand-ConfigurationVariables -ConfigObject $config
#>
function Expand-ConfigurationVariables {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$ConfigObject
    )

    $expanded = @{}

    foreach ($key in $ConfigObject.Keys) {
        $value = $ConfigObject[$key]

        if ($value -is [hashtable]) {
            # Recursively process nested hashtables
            $expanded[$key] = Expand-ConfigurationVariables -ConfigObject $value
        }
        elseif ($value -is [array]) {
            # Process arrays
            $expanded[$key] = $value | ForEach-Object {
                if ($_ -is [hashtable]) {
                    Expand-ConfigurationVariables -ConfigObject $_
                }
                elseif ($_ -is [string]) {
                    Expand-StringVariable -Value $_
                }
                else {
                    $_
                }
            }
        }
        elseif ($value -is [string]) {
            # Expand environment variables in strings
            $expanded[$key] = Expand-StringVariable -Value $value
        }
        else {
            $expanded[$key] = $value
        }
    }

    return $expanded
}

<#
.SYNOPSIS
    Expands environment variables in a string value.

.PARAMETER Value
    String value to expand.

.OUTPUTS
    String with expanded variables.
#>
function Expand-StringVariable {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Value
    )

    # Empty input has nothing to expand.
    if ([string]::IsNullOrEmpty($Value)) { return $Value }

    # Pattern: ${ENV:VAR_NAME} or ${ENV:VAR_NAME:default_value}
    $pattern = '\$\{ENV:([^:}]+)(?::([^}]+))?\}'

    $expandedValue = [regex]::Replace($Value, $pattern, {
            param($match)
            $envVarName = $match.Groups[1].Value
            $defaultValue = $match.Groups[2].Value

            $envValue = [Environment]::GetEnvironmentVariable($envVarName)

            if ($null -ne $envValue) {
                return $envValue
            }
            elseif ($defaultValue) {
                return $defaultValue
            }
            else {
                # Keep placeholder if no value or default
                return $match.Value
            }
        })

    return $expandedValue
}

<#
.SYNOPSIS
    Merges two configuration hashtables.

.DESCRIPTION
    Recursively merges override configuration into base configuration.
    Override values take precedence.

.PARAMETER BaseConfig
    Base configuration hashtable.

.PARAMETER OverrideConfig
    Override configuration hashtable.

.OUTPUTS
    Merged configuration hashtable.
#>
function Merge-Configuration {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$BaseConfig,

        [Parameter(Mandatory)]
        [hashtable]$OverrideConfig
    )

    $merged = $BaseConfig.Clone()

    foreach ($key in $OverrideConfig.Keys) {
        $overrideValue = $OverrideConfig[$key]

        if ($merged.ContainsKey($key) -and $merged[$key] -is [hashtable] -and $overrideValue -is [hashtable]) {
            # Recursively merge nested hashtables
            $merged[$key] = Merge-Configuration -BaseConfig $merged[$key] -OverrideConfig $overrideValue
        }
        else {
            # Override value
            $merged[$key] = $overrideValue
        }
    }

    return $merged
}

<#
.SYNOPSIS
    Merges default values into configuration.

.DESCRIPTION
    Adds default values for any missing configuration properties.

.PARAMETER ConfigObject
    Configuration hashtable to merge defaults into.

.OUTPUTS
    Configuration with defaults applied.
#>
function Merge-ConfigurationDefaults {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$ConfigObject
    )

    $schema = Get-ConfigurationSchema

    # Apply defaults from schema
    $withDefaults = Set-SchemaDefaults -ConfigObject $ConfigObject -SchemaProperties $schema.properties

    return $withDefaults
}

<#
.SYNOPSIS
    Applies default values from schema to configuration.

.PARAMETER ConfigObject
    Configuration object to apply defaults to.

.PARAMETER SchemaProperties
    Schema properties containing default values.

.OUTPUTS
    Configuration with defaults applied.
#>
function Set-SchemaDefaults {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$ConfigObject,

        [Parameter(Mandatory)]
        [hashtable]$SchemaProperties
    )

    $result = $ConfigObject.Clone()

    foreach ($key in $SchemaProperties.Keys) {
        $schemaProp = $SchemaProperties[$key]

        if ($schemaProp.ContainsKey('default') -and -not $result.ContainsKey($key)) {
            # Apply default value
            $result[$key] = $schemaProp.default
        }
        elseif ($result.ContainsKey($key) -and $result[$key] -is [hashtable] -and $schemaProp.type -eq 'object' -and $schemaProp.ContainsKey('properties')) {
            # Recursively apply defaults to nested objects
            $result[$key] = Set-SchemaDefaults -ConfigObject $result[$key] -SchemaProperties $schemaProp.properties
        }
    }

    return $result
}

#endregion

#region ==================== CONFIGURATION ACCESS ====================

<#
.SYNOPSIS
    Gets the currently loaded configuration.

.DESCRIPTION
    Returns the configuration that was loaded via Import-Configuration.

.OUTPUTS
    Hashtable containing the current configuration, or $null if not loaded.

.EXAMPLE
    $config = Get-Configuration
    if ($config) {
        Write-Host "Log level: $($config.Logging.MinimumLevel)"
    }
#>
function Get-Configuration {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    if (-not $script:ConfigLoaded) {
        if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
            Write-Log -Level WARN -Message "Configuration not loaded" -Category "Configuration"
        }
        return $null
    }

    return $script:Config
}

<#
.SYNOPSIS
    Gets a specific configuration value by path.

.DESCRIPTION
    Retrieves a configuration value using dot notation path.

.PARAMETER Path
    Dot-separated path to the configuration value (e.g., "Logging.MinimumLevel").

.PARAMETER DefaultValue
    Optional default value to return if path not found.

.OUTPUTS
    The configuration value at the specified path, or default value if not found.

.EXAMPLE
    $logLevel = Get-ConfigValue -Path "Logging.MinimumLevel" -DefaultValue "INFO"

.EXAMPLE
    $scopes = Get-ConfigValue -Path "Assessment.Scope"
#>
function Get-ConfigValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [object]$DefaultValue = $null
    )

    if (-not $script:ConfigLoaded) {
        if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
            Write-Log -Level WARN -Message "Configuration not loaded, returning default value" -Category "Configuration" -Properties @{
                Path = $Path
            }
        }
        return $DefaultValue
    }

    $pathParts = $Path -split '\.'
    $current = $script:Config

    foreach ($part in $pathParts) {
        if ($current -is [hashtable] -and $current.ContainsKey($part)) {
            $current = $current[$part]
        }
        else {
            if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
                Write-Log -Level DEBUG -Message "Configuration path not found, returning default" -Category "Configuration" -Properties @{
                    Path = $Path
                }
            }
            return $DefaultValue
        }
    }

    return $current
}

<#
.SYNOPSIS
    Exports the current configuration to a JSON file.

.DESCRIPTION
    Saves the current configuration to a file with optional pretty printing.

.PARAMETER FilePath
    Path where configuration should be saved.

.PARAMETER NoPrettyPrint
    If specified, outputs compact JSON without formatting.

.EXAMPLE
    Export-Configuration -FilePath ".\config\backup.json"
#>
function Export-Configuration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$FilePath,

        [switch]$NoPrettyPrint
    )

    if (-not $script:ConfigLoaded) {
        throw "No configuration loaded to export"
    }

    try {
        $jsonDepth = 10
        if ($NoPrettyPrint) {
            $json = $script:Config | ConvertTo-Json -Depth $jsonDepth -Compress
        }
        else {
            $json = $script:Config | ConvertTo-Json -Depth $jsonDepth
        }

        $json | Out-File -FilePath $FilePath -Encoding UTF8

        if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
            Write-Log -Level INFO -Message "Configuration exported" -Category "Configuration" -Properties @{
                FilePath = $FilePath
            }
        }

        if (Get-Command Write-AuditLog -ErrorAction SilentlyContinue) {
            Write-AuditLog -EventType "DataExported" -Description "Configuration exported to file" -Details @{
                FilePath = $FilePath
            } -Result "Success"
        }
    }
    catch {
        if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
            Write-Log -Level ERROR -Message "Failed to export configuration" -Category "Configuration" -ErrorRecord $_
        }
        throw
    }
}

#endregion

#region ==================== TEMPLATE GENERATION ====================

<#
.SYNOPSIS
    Creates a default configuration template file.

.DESCRIPTION
    Generates a starter configuration file with all schema properties
    and default values.

.PARAMETER FilePath
    Path where template should be created.

.PARAMETER IncludeComments
    If specified, includes comments explaining each section.

.PARAMETER Minimal
    If specified, creates a minimal configuration with only required fields.

.EXAMPLE
    New-ConfigurationTemplate -FilePath ".\config\template.json" -IncludeComments

.EXAMPLE
    New-ConfigurationTemplate -FilePath ".\config\minimal.json" -Minimal
#>
function New-ConfigurationTemplate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$FilePath,

        [switch]$IncludeComments,

        [switch]$Minimal
    )

    if (Test-Path $FilePath) {
        $response = Read-Host "File '$FilePath' already exists. Overwrite? (y/n)"
        if ($response -ne 'y') {
            Write-Host "Operation cancelled"
            return
        }
    }

    $template = @{
        Version = "1.0.0"
        Assessment = @{
            Scope = @("Core")
            Mode = "Interactive"
            Tenant = @{
                TenantId = ""
                TenantName = ""
            }
            Output = @{
                Directory = ".\Output"
                Formats = @("HTML", "CSV")
                IncludeTimestamp = $true
            }
        }
        Authentication = @{
            Method = "Interactive"
            Scopes = @(
                "Directory.Read.All",
                "Policy.Read.All"
            )
        }
        Logging = @{
            Directory = ".\Logs"
            MinimumLevel = "INFO"
            Targets = @("File", "Console")
            StructuredLogging = $true
            RetentionDays = 90
            MaxFileSizeMB = 100
            BufferSize = 100
        }
        ErrorHandling = @{
            MaxRetries = 3
            BaseDelaySeconds = 5
            ExponentialBackoff = $true
            CircuitBreaker = @{
                Enabled = $true
                FailureThreshold = 5
                TimeoutSeconds = 60
                HalfOpenRequests = 1
            }
        }
    }

    if (-not $Minimal) {
        $template.Assessment.Exclusions = @{
            Users = @()
            Groups = @()
            Checks = @()
        }

        $template.Performance = @{
            MaxConcurrentRequests = 10
            RateLimitBuffer = 10
            CacheDurationMinutes = 15
            EnableCaching = $false
        }

        $template.Notifications = @{
            Email = @{
                Enabled = $false
                SMTPServer = ""
                Port = 587
                From = ""
                To = @()
                UseSSL = $true
            }
            Teams = @{
                Enabled = $false
                WebhookURL = ""
            }
        }

        $template.Compliance = @{
            Frameworks = @("CIS")
            CustomBenchmarks = @()
        }
    }

    try {
        $json = $template | ConvertTo-Json -Depth 10

        if ($IncludeComments) {
            # Add comments to JSON (as a header)
            $comments = @"
/*
 * EntraChecks Configuration File
 * Version: 1.0.0
 *
 * This configuration file controls all aspects of EntraChecks assessment execution.
 *
 * Environment Variables:
 *   You can use environment variable substitution with the syntax: `${ENV:VAR_NAME}` or `${ENV:VAR_NAME:default_value}`
 *
 * Environment-Specific Overrides:
 *   Create files like entrachecks.config.dev.json or entrachecks.config.prod.json
 *   These will be merged with the base configuration when using -Environment parameter
 *
 * For full schema documentation, run: Get-ConfigurationSchema | ConvertTo-Json -Depth 10
 */

"@
            $json = $comments + $json
        }

        $json | Out-File -FilePath $FilePath -Encoding UTF8

        Write-Host "Configuration template created: $FilePath" -ForegroundColor Green

        if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
            Write-Log -Level INFO -Message "Configuration template created" -Category "Configuration" -Properties @{
                FilePath = $FilePath
                Minimal = $Minimal.IsPresent
            }
        }
    }
    catch {
        Write-Error "Failed to create configuration template: $_"
        if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
            Write-Log -Level ERROR -Message "Failed to create configuration template" -Category "Configuration" -ErrorRecord $_
        }
    }
}

#endregion

#region ==================== MODULE EXPORTS ====================

Export-ModuleMember -Function @(
    'Get-ConfigurationSchema',
    'Test-Configuration',
    'Import-Configuration',
    'Get-Configuration',
    'Get-ConfigValue',
    'Export-Configuration',
    'New-ConfigurationTemplate',
    'Resolve-SOC2NamespaceConfig'
)

#endregion
