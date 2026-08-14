<#
.SYNOPSIS
EntraChecks-Connection.psm1 - Authentication and connection management for EntraChecks

.DESCRIPTION
Provides robust authentication handling for EntraChecks including interactive authentication,
app registration authentication (service principal), connection validation, permission verification,
retry logic for transient failures, and throttling/rate limit handling.

.NOTES
Version: 1.0.0
Author: NamelessSaint
#>

#Requires -Version 5.1

$script:ModuleVersion = "1.0.0"
$script:ModuleName = "EntraChecks-Connection"

# Import logging module
$loggingModulePath = Join-Path $PSScriptRoot "EntraChecks-Logging.psm1"
if (Test-Path $loggingModulePath) {
    Import-Module $loggingModulePath -Force -ErrorAction SilentlyContinue
}

# Import error handling module
$errorHandlingModulePath = Join-Path $PSScriptRoot "EntraChecks-ErrorHandling.psm1"
if (Test-Path $errorHandlingModulePath) {
    Import-Module $errorHandlingModulePath -Force -ErrorAction SilentlyContinue
}

# Import Key Vault module (optional)
$keyVaultModulePath = Join-Path $PSScriptRoot "EntraChecks-KeyVault.psm1"
if (Test-Path $keyVaultModulePath) {
    Import-Module $keyVaultModulePath -Force -ErrorAction SilentlyContinue
}

# Retry configuration (legacy - now handled by ErrorHandling module)
$script:MaxRetries = 3
$script:RetryDelaySeconds = 2
$script:ThrottleWaitSeconds = 30

#region ==================== PERMISSION DEFINITIONS ====================

# Define all permissions used by EntraChecks modules
$script:PermissionSets = @{
    Core = @{
        Scopes = @(
            "Directory.Read.All",
            "Policy.Read.All",
            "AuditLog.Read.All"
        )
        Description = "Core Entra ID security checks"
        AdminConsentRequired = $true
    }
    IdentityProtection = @{
        Scopes = @(
            "IdentityRiskEvent.Read.All",
            "IdentityRiskyUser.Read.All"
        )
        Description = "Identity Protection risk checks"
        AdminConsentRequired = $true
        LicenseRequired = "Azure AD Premium P2"
    }
    Devices = @{
        Scopes = @(
            "Device.Read.All",
            "DeviceManagementManagedDevices.Read.All",
            "DeviceManagementConfiguration.Read.All"
        )
        Description = "Device and Intune compliance checks"
        AdminConsentRequired = $true
        LicenseRequired = "Microsoft Intune"
    }
    SecureScore = @{
        Scopes = @(
            "SecurityEvents.Read.All"
        )
        Description = "Microsoft Secure Score integration"
        AdminConsentRequired = $true
    }
    Purview = @{
        Scopes = @(
            "ComplianceManager.Read.All",
            "InformationProtectionPolicy.Read"
        )
        Description = "Purview Compliance Manager"
        AdminConsentRequired = $true
        LicenseRequired = "Microsoft 365 E5 Compliance"
    }
    All = @{
        Scopes = @(
            "Directory.Read.All",
            "Policy.Read.All",
            "AuditLog.Read.All",
            "SecurityEvents.Read.All",
            "IdentityRiskEvent.Read.All",
            "IdentityRiskyUser.Read.All",
            "Device.Read.All",
            "DeviceManagementManagedDevices.Read.All",
            "DeviceManagementConfiguration.Read.All",
            "ComplianceManager.Read.All",
            "InformationProtectionPolicy.Read"
        )
        Description = "All EntraChecks modules"
        AdminConsentRequired = $true
    }
}

#endregion

#region ==================== CONNECTION FUNCTIONS ====================

<#
.SYNOPSIS
    Connects to Microsoft Graph with proper error handling.

.DESCRIPTION
    Establishes a connection to Microsoft Graph using either:
    - Interactive authentication (user sign-in)
    - App Registration (client credentials)
    
    Validates the connection and checks for required permissions.

.PARAMETER Modules
    Which module permission sets to request. Default: Core
    Options: Core, IdentityProtection, Devices, SecureScore, Purview, All

.PARAMETER Interactive
    Use interactive (browser) authentication. This is the default.

.PARAMETER TenantId
    Azure AD tenant ID. Required for app authentication, optional for interactive.

.PARAMETER ClientId
    App Registration client ID. Required for app authentication.

.PARAMETER ClientSecret
    App Registration client secret. Use with -ClientId for app authentication.

.PARAMETER CertificateThumbprint
    Certificate thumbprint for app authentication. Use with -ClientId.

.PARAMETER ValidatePermissions
    Check if all requested permissions are actually granted. Default: $true

.EXAMPLE
    # Interactive - Global Admin (easiest)
    Connect-EntraChecks -Modules All
    
.EXAMPLE
    # Interactive - specific modules
    Connect-EntraChecks -Modules Core, SecureScore
    
.EXAMPLE
    # App Registration with secret
    Connect-EntraChecks -TenantId "contoso.onmicrosoft.com" -ClientId "app-id" -ClientSecret $secret -Modules All
    
.EXAMPLE
    # App Registration with certificate
    Connect-EntraChecks -TenantId "contoso.onmicrosoft.com" -ClientId "app-id" -CertificateThumbprint "ABC123" -Modules All
#>
function Connect-EntraChecks {
    [CmdletBinding(DefaultParameterSetName = "Interactive")]
    param(
        [Parameter()]
        [ValidateSet("Core", "IdentityProtection", "Devices", "SecureScore", "Purview", "All")]
        [string[]]$Modules = @("Core"),

        [Parameter(ParameterSetName = "Interactive")]
        [switch]$Interactive,

        [Parameter(ParameterSetName = "Interactive")]
        [switch]$UseDeviceCode,

        [Parameter(Mandatory, ParameterSetName = "ClientSecret")]
        [Parameter(Mandatory, ParameterSetName = "Certificate")]
        [Parameter(Mandatory, ParameterSetName = "KeyVault")]
        [string]$TenantId,

        [Parameter(Mandatory, ParameterSetName = "ClientSecret")]
        [Parameter(Mandatory, ParameterSetName = "Certificate")]
        [Parameter(Mandatory, ParameterSetName = "KeyVault")]
        [string]$ClientId,

        [Parameter(Mandatory, ParameterSetName = "ClientSecret")]
        [SecureString]$ClientSecret,

        [Parameter(Mandatory, ParameterSetName = "Certificate")]
        [string]$CertificateThumbprint,

        [Parameter(Mandatory, ParameterSetName = "KeyVault")]
        [string]$KeyVaultName,

        [Parameter(ParameterSetName = "KeyVault")]
        [string]$KeyVaultSecretName = "entrachecks-client-secret",

        [Parameter()]
        [switch]$SkipPermissionValidation
    )
    
    Write-Host "`n" -NoNewline
    Write-Host "╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║              EntraChecks Authentication                       ║" -ForegroundColor Cyan
    Write-Host "╚═══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan

    # Log authentication attempt
    if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
        Write-Log -Level INFO -Message "Starting Entra authentication" -Category "Authentication" -Properties @{
            Modules = ($Modules -join ', ')
            AuthMethod = $PSCmdlet.ParameterSetName
        }
    }

    # Collect required scopes
    $requiredScopes = @()
    foreach ($module in $Modules) {
        $requiredScopes += $script:PermissionSets[$module].Scopes
    }
    $requiredScopes = $requiredScopes | Select-Object -Unique

    Write-Host "`n  Requested modules: $($Modules -join ', ')" -ForegroundColor Cyan
    Write-Host "  Required scopes: $($requiredScopes.Count)" -ForegroundColor Cyan

    if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
        Write-Log -Level DEBUG -Message "Required scopes collected" -Category "Authentication" -Properties @{
            RequiredScopes = ($requiredScopes -join ', ')
            ScopeCount = $requiredScopes.Count
        }
    }
    
    # Check if Microsoft.Graph module is available
    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
        Write-Host "`n[!] Microsoft.Graph module not found!" -ForegroundColor Red
        Write-Host "    Install with: Install-Module Microsoft.Graph -Scope CurrentUser" -ForegroundColor Yellow
        return $false
    }
    
    try {
        # Disconnect any existing session
        $existingContext = Get-MgContext -ErrorAction SilentlyContinue
        if ($existingContext) {
            Write-Host "[i] Disconnecting existing session..." -ForegroundColor Gray
            Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        }
        
        # Connect based on authentication type
        switch ($PSCmdlet.ParameterSetName) {
            "Interactive" {
                Write-Host "`n[+] Starting interactive authentication..." -ForegroundColor Cyan

                if ($UseDeviceCode) {
                    Write-Host "    Using device code authentication." -ForegroundColor Gray
                    Write-Host "    You will receive a code to enter at https://microsoft.com/devicelogin" -ForegroundColor Gray
                    Connect-MgGraph -Scopes $requiredScopes -UseDeviceAuthentication -NoWelcome -ErrorAction Stop
                }
                else {
                    Write-Host "    A browser window will open for sign-in." -ForegroundColor Gray
                    Write-Host "    Sign in with a Global Admin or appropriately privileged account." -ForegroundColor Gray
                    Write-Host "    NOTE: If browser fails, try: Connect-EntraChecks -UseDeviceCode" -ForegroundColor Yellow
                    Connect-MgGraph -Scopes $requiredScopes -NoWelcome -ErrorAction Stop
                }
            }

            "ClientSecret" {
                Write-Host "`n[+] Authenticating with App Registration (client secret)..." -ForegroundColor Cyan

                $credential = New-Object System.Management.Automation.PSCredential($ClientId, $ClientSecret)
                Connect-MgGraph -TenantId $TenantId -ClientSecretCredential $credential -NoWelcome -ErrorAction Stop
            }

            "Certificate" {
                Write-Host "`n[+] Authenticating with App Registration (certificate)..." -ForegroundColor Cyan

                Connect-MgGraph -TenantId $TenantId -ClientId $ClientId -CertificateThumbprint $CertificateThumbprint -NoWelcome -ErrorAction Stop
            }

            "KeyVault" {
                Write-Host "`n[+] Authenticating with Azure Key Vault..." -ForegroundColor Cyan

                # Check if Key Vault module is available
                if (-not (Get-Command Connect-EntraChecksKeyVault -ErrorAction SilentlyContinue)) {
                    throw "Key Vault module not loaded. Ensure EntraChecks-KeyVault.psm1 is available."
                }

                # Connect to Key Vault (using Managed Identity by default)
                Write-Host "    Connecting to Key Vault: $KeyVaultName" -ForegroundColor Gray
                $kvConnected = Connect-EntraChecksKeyVault -KeyVaultName $KeyVaultName -AuthenticationMethod ManagedIdentity -ErrorAction Stop

                if (-not $kvConnected) {
                    throw "Failed to connect to Key Vault: $KeyVaultName"
                }

                # Retrieve client secret from Key Vault
                Write-Host "    Retrieving secret: $KeyVaultSecretName" -ForegroundColor Gray
                $secretValue = Get-KeyVaultSecret -SecretName $KeyVaultSecretName -ErrorAction Stop

                if (-not $secretValue) {
                    throw "Failed to retrieve secret '$KeyVaultSecretName' from Key Vault"
                }

                # Authenticate to Graph API using the retrieved secret
                Write-Host "    Authenticating to Microsoft Graph..." -ForegroundColor Gray
                $credential = New-Object System.Management.Automation.PSCredential($ClientId, $secretValue)
                Connect-MgGraph -TenantId $TenantId -ClientSecretCredential $credential -NoWelcome -ErrorAction Stop

                Write-Host "    [OK] Successfully authenticated using Key Vault" -ForegroundColor Green
            }
        }
        
        # Verify connection
        $context = Get-MgContext
        if (-not $context) {
            Write-Host "[!] Connection failed - no context returned" -ForegroundColor Red
            return $false
        }
        
        Write-Host "`n[OK] Connected successfully!" -ForegroundColor Green
        Write-Host "    Account: $($context.Account)" -ForegroundColor White
        Write-Host "    Tenant:  $($context.TenantId)" -ForegroundColor White
        Write-Host "    Auth:    $($context.AuthType)" -ForegroundColor White
        
        # Validate permissions
        if (-not $SkipPermissionValidation) {
            Write-Host "`n[+] Validating permissions..." -ForegroundColor Cyan
            $permissionResult = Test-EntraChecksPermissions -RequiredScopes $requiredScopes -GrantedScopes $context.Scopes
            
            if (-not $permissionResult.AllGranted) {
                Write-Host "`n[!] Some permissions are missing!" -ForegroundColor Yellow
                Write-Host "    Missing: $($permissionResult.Missing -join ', ')" -ForegroundColor Yellow
                Write-Host "`n    Options:" -ForegroundColor White
                Write-Host "    1. Run as Global Admin (can consent on the fly)" -ForegroundColor Gray
                Write-Host "    2. Have an admin grant consent in Azure Portal" -ForegroundColor Gray
                Write-Host "    3. Use App Registration with pre-consented permissions" -ForegroundColor Gray
                Write-Host "`n    Continuing with available permissions..." -ForegroundColor Yellow
            }
            else {
                Write-Host "    [OK] All requested permissions available" -ForegroundColor Green
            }
        }

        # Store connection info
        $script:ConnectionInfo = @{
            Connected = $true
            Account = $context.Account
            TenantId = $context.TenantId
            AuthType = $context.AuthType
            Scopes = $context.Scopes
            ConnectedAt = Get-Date
        }

        # Log successful authentication
        if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
            Write-Log -Level INFO -Message "Entra authentication successful" -Category "Authentication" -Properties @{
                Account = $context.Account
                TenantId = $context.TenantId
                AuthType = $context.AuthType
                GrantedScopes = ($context.Scopes -join ', ')
            }
            Write-AuditLog -EventType "AuthenticationSuccess" -Description "Successfully authenticated to Microsoft Entra" -TargetObject $context.Account -Result "Success"
        }

        return $true
    }
    catch {
        Write-Host "`n[!] Authentication failed!" -ForegroundColor Red
        Write-Host "    Error: $($_.Exception.Message)" -ForegroundColor Red

        # Log authentication failure
        if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
            Write-Log -Level ERROR -Message "Entra authentication failed" -Category "Authentication" -ErrorRecord $_ -Properties @{
                AuthMethod = $PSCmdlet.ParameterSetName
                TenantId = $TenantId
            }
            Write-AuditLog -EventType "AuthenticationFailure" -Description "Failed to authenticate to Microsoft Entra" -Result "Failure"
        }
        
        if ($_.Exception.Message -match "AADSTS65001") {
            Write-Host "`n    This error means admin consent is required." -ForegroundColor Yellow
            Write-Host "    Ask a Global Admin to consent, or use an App Registration." -ForegroundColor Yellow
        }
        elseif ($_.Exception.Message -match "AADSTS50076") {
            Write-Host "`n    This error means MFA is required." -ForegroundColor Yellow
            Write-Host "    Complete the MFA challenge in the browser." -ForegroundColor Yellow
        }
        
        return $false
    }
}

<#
.SYNOPSIS
    Tests if required permissions are granted.
#>
function Test-EntraChecksPermissions {
    [CmdletBinding()]
    param(
        [string[]]$RequiredScopes,
        [string[]]$GrantedScopes
    )
    
    $missing = @()
    $granted = @()
    
    foreach ($required in $RequiredScopes) {
        # Check for exact match or .Default (application permissions)
        $hasPermission = $GrantedScopes | Where-Object { 
            $_ -eq $required -or 
            $_ -eq "$required.Default" -or
            $_ -match "^$([regex]::Escape($required))$"
        }
        
        if ($hasPermission) {
            $granted += $required
        }
        else {
            $missing += $required
        }
    }
    
    return @{
        AllGranted = ($missing.Count -eq 0)
        Granted = $granted
        Missing = $missing
    }
}

<#
.SYNOPSIS
    Connects to Azure for Defender/Policy modules.
#>
function Connect-EntraChecksAzure {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$TenantId,
        
        [Parameter()]
        [string]$SubscriptionId,
        
        [Parameter()]
        [switch]$UseManagedIdentity
    )
    
    Write-Host "`n[+] Connecting to Azure..." -ForegroundColor Cyan
    
    # Check if Az module is available
    if (-not (Get-Module -ListAvailable -Name Az.Accounts)) {
        Write-Host "[!] Az module not found!" -ForegroundColor Red
        Write-Host "    Install with: Install-Module Az -Scope CurrentUser" -ForegroundColor Yellow
        return $false
    }
    
    try {
        $existingContext = Get-AzContext -ErrorAction SilentlyContinue
        
        if ($existingContext -and -not $TenantId) {
            Write-Host "[i] Using existing Azure session: $($existingContext.Account.Id)" -ForegroundColor Gray
            return $true
        }
        
        if ($UseManagedIdentity) {
            Connect-AzAccount -Identity -ErrorAction Stop | Out-Null
        }
        elseif ($TenantId) {
            Connect-AzAccount -TenantId $TenantId -ErrorAction Stop | Out-Null
        }
        else {
            Connect-AzAccount -ErrorAction Stop | Out-Null
        }
        
        $context = Get-AzContext
        Write-Host "  Connected to Azure" -ForegroundColor Green
        Write-Host "    Account:      $($context.Account.Id)" -ForegroundColor White
        Write-Host "    Subscription: $($context.Subscription.Name)" -ForegroundColor White
        
        return $true
    }
    catch {
        Write-Host "  Azure connection failed: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

<#
.SYNOPSIS
    Validates connection before running checks.
#>
function Test-EntraChecksConnection {
    [CmdletBinding()]
    param()
    
    $result = @{
        Graph = $false
        Azure = $false
        GraphAccount = $null
        AzureAccount = $null
    }
    
    # Test Graph
    $graphContext = Get-MgContext -ErrorAction SilentlyContinue
    if ($graphContext) {
        $result.Graph = $true
        $result.GraphAccount = $graphContext.Account
    }
    
    # Test Azure
    $azContext = Get-AzContext -ErrorAction SilentlyContinue
    if ($azContext) {
        $result.Azure = $true
        $result.AzureAccount = $azContext.Account.Id
    }
    
    return $result
}

#endregion

#region ==================== RETRY AND ERROR HANDLING ====================

<#
.SYNOPSIS
    Invokes a Graph API request with retry logic and throttling handling.

.DESCRIPTION
    Wraps Invoke-MgGraphRequest with:
    - Automatic retry on transient failures
    - Throttling (429) handling with exponential backoff
    - Consistent error formatting
    - Pagination support

.PARAMETER Uri
    The Graph API endpoint URI.

.PARAMETER Method
    HTTP method. Default: GET

.PARAMETER Body
    Request body for POST/PATCH requests.

.PARAMETER AllPages
    Automatically follow @odata.nextLink for paged results.

.PARAMETER MaxRetries
    Maximum retry attempts. Default: 3
#>
function Invoke-EntraChecksGraphRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Uri,

        [Parameter()]
        [ValidateSet("GET", "POST", "PATCH", "DELETE")]
        [string]$Method = "GET",

        [Parameter()]
        $Body,

        [Parameter()]
        [switch]$AllPages,

        [Parameter()]
        [int]$MaxRetries = $script:MaxRetries
    )

    # Use new error handling module if available, otherwise fall back to legacy logic
    if (Get-Command Invoke-GraphRequestWithRetry -ErrorAction SilentlyContinue) {
        # Use new retry logic with circuit breaker
        if ($AllPages) {
            # Use pagination helper
            return Get-AllGraphPages -Uri $Uri -MaxPages 0
        }
        else {
            # Single request with retry
            $result = Invoke-GraphRequestWithRetry -Uri $Uri -Method $Method -Body $Body -MaxRetries $MaxRetries
            return $result
        }
    }
    else {
        # Legacy fallback (original implementation)
        $attempt = 0
        $allResults = @()
        $currentUri = $Uri

        while ($currentUri) {
            $attempt = 0
            $success = $false

            while (-not $success -and $attempt -lt $MaxRetries) {
                $attempt++

                try {
                    $params = @{
                        Uri = $currentUri
                        Method = $Method
                        ErrorAction = "Stop"
                    }

                    if ($Body) {
                        $params.Body = $Body
                        $params.ContentType = "application/json"
                    }

                    $response = Invoke-MgGraphRequest @params
                    $success = $true

                    # Handle results
                    if ($response.value) {
                        $allResults += $response.value
                    }
                    elseif ($response -and -not $response.'@odata.nextLink') {
                        $allResults += $response
                    }

                    # Handle pagination
                    if ($AllPages -and $response.'@odata.nextLink') {
                        $currentUri = $response.'@odata.nextLink'
                    }
                    else {
                        $currentUri = $null
                    }
                }
                catch {
                    $errorMessage = $_.Exception.Message

                    # Check for throttling (429)
                    if ($errorMessage -match "429" -or $errorMessage -match "Too Many Requests" -or $errorMessage -match "throttl") {
                        $waitTime = $script:ThrottleWaitSeconds * $attempt
                        Write-Host "    [i] Rate limited. Waiting $waitTime seconds..." -ForegroundColor Yellow
                        Start-Sleep -Seconds $waitTime
                    }
                    # Check for transient errors
                    elseif (($errorMessage -match "503" -or $errorMessage -match "504" -or $errorMessage -match "500" -or $errorMessage -match "timeout") -and $attempt -lt $MaxRetries) {
                        $waitTime = $script:RetryDelaySeconds * $attempt
                        Write-Host "    [i] Transient error. Retrying in $waitTime seconds... (attempt $attempt/$MaxRetries)" -ForegroundColor Yellow
                        Start-Sleep -Seconds $waitTime
                    }
                    # Permission errors - don't retry
                    elseif ($errorMessage -match "403|Forbidden|Authorization|Access Denied") {
                        Write-Verbose "Permission denied for: $Uri"
                        throw $_
                    }
                    # Not found - don't retry
                    elseif ($errorMessage -match "404|Not Found") {
                        Write-Verbose "Resource not found: $Uri"
                        throw $_
                    }
                    # Unknown error on last attempt
                    elseif ($attempt -ge $MaxRetries) {
                        throw $_
                    }
                    else {
                        $waitTime = $script:RetryDelaySeconds * $attempt
                        Write-Verbose "Error: $errorMessage. Retrying in $waitTime seconds..."
                        Start-Sleep -Seconds $waitTime
                    }
                }
            }

            if (-not $success) {
                throw "Failed after $MaxRetries attempts"
            }
        }

        return $allResults
    }
}

<#
.SYNOPSIS
    Invokes an Azure REST API request with retry logic.
#>
function Invoke-EntraChecksAzureRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Uri,
        
        [Parameter()]
        [ValidateSet("GET", "POST", "PATCH", "DELETE")]
        [string]$Method = "GET",
        
        [Parameter()]
        $Body,
        
        [Parameter()]
        [int]$MaxRetries = $script:MaxRetries
    )
    
    $attempt = 0
    
    while ($attempt -lt $MaxRetries) {
        $attempt++
        
        try {
            $params = @{
                Uri = $Uri
                Method = $Method
                ErrorAction = "Stop"
            }
            
            if ($Body) {
                $params.Body = ($Body | ConvertTo-Json -Depth 10)
                $params.ContentType = "application/json"
            }
            
            $response = Invoke-AzRestMethod @params
            
            if ($response.StatusCode -ge 200 -and $response.StatusCode -lt 300) {
                if ($response.Content) {
                    return ($response.Content | ConvertFrom-Json)
                }
                return $null
            }
            elseif ($response.StatusCode -eq 429) {
                $waitTime = $script:ThrottleWaitSeconds * $attempt
                Write-Host "    [i] Rate limited. Waiting $waitTime seconds..." -ForegroundColor Yellow
                Start-Sleep -Seconds $waitTime
            }
            elseif ($response.StatusCode -in @(500, 503, 504) -and $attempt -lt $MaxRetries) {
                $waitTime = $script:RetryDelaySeconds * $attempt
                Write-Host "    [i] Transient error ($($response.StatusCode)). Retrying..." -ForegroundColor Yellow
                Start-Sleep -Seconds $waitTime
            }
            else {
                throw "HTTP $($response.StatusCode): $($response.Content)"
            }
        }
        catch {
            if ($attempt -ge $MaxRetries) {
                throw $_
            }
            Start-Sleep -Seconds ($script:RetryDelaySeconds * $attempt)
        }
    }
}

#endregion

#region ==================== SETUP HELPERS ====================

<#
.SYNOPSIS
    Displays setup instructions for EntraChecks.
#>
function Show-EntraChecksSetup {
    [CmdletBinding()]
    param()
    
    $setupGuide = @"

╔═══════════════════════════════════════════════════════════════════════════════╗
║                        EntraChecks Setup Guide                                ║
╚═══════════════════════════════════════════════════════════════════════════════╝

OPTION 1: Interactive (Easiest - requires Global Admin)
═══════════════════════════════════════════════════════
  
  Just run:
    Connect-EntraChecks -Modules All
  
  Sign in as a Global Admin when the browser opens.
  The admin can consent to all permissions on the fly.


OPTION 2: Pre-Consented (For non-admin users)
═════════════════════════════════════════════
  
  1. Have a Global Admin run this ONCE:
     
     Connect-MgGraph -Scopes "Directory.Read.All","Policy.Read.All","AuditLog.Read.All","SecurityEvents.Read.All","IdentityRiskEvent.Read.All","IdentityRiskyUser.Read.All","Device.Read.All","DeviceManagementManagedDevices.Read.All","DeviceManagementConfiguration.Read.All","ComplianceManager.Read.All","InformationProtectionPolicy.Read"
     
     # Then consent for the organization when prompted
  
  2. Now any user with appropriate roles can run:
     
     Connect-EntraChecks -Modules All


OPTION 3: App Registration (For automation/scheduled tasks)
═══════════════════════════════════════════════════════════
  
  1. Create App Registration in Azure Portal:
     - Azure Portal > App Registrations > New Registration
     - Name: "EntraChecks"
     - Supported account types: Single tenant
  
  2. Add API Permissions:
     - Microsoft Graph > Application permissions:
       • Directory.Read.All
       • Policy.Read.All
       • AuditLog.Read.All
       • SecurityEvents.Read.All
       • IdentityRiskEvent.Read.All
       • IdentityRiskyUser.Read.All
       • Device.Read.All
       • DeviceManagementManagedDevices.Read.All
       • DeviceManagementConfiguration.Read.All
       • (Purview permissions if needed)
     - Click "Grant admin consent"
  
  3. Create a secret or certificate:
     - Certificates & secrets > New client secret
     - Copy the secret value (shown only once!)
  
  4. For Azure modules (Defender/Policy), also assign RBAC:
     - Azure Portal > Subscriptions > [subscription] > Access control
     - Add role assignment: "Security Reader" to the app
  
  5. Connect with:
     
     `$secret = ConvertTo-SecureString "your-secret" -AsPlainText -Force
     Connect-EntraChecks -TenantId "contoso.onmicrosoft.com" -ClientId "app-id" -ClientSecret `$secret -Modules All


REQUIRED PERMISSIONS BY MODULE:
═══════════════════════════════
  Core:               Directory.Read.All, Policy.Read.All, AuditLog.Read.All
  Identity Protection: IdentityRiskEvent.Read.All, IdentityRiskyUser.Read.All
  Devices:            Device.Read.All, DeviceManagementManagedDevices.Read.All, 
                      DeviceManagementConfiguration.Read.All
  Secure Score:       SecurityEvents.Read.All
  Purview:            ComplianceManager.Read.All, InformationProtectionPolicy.Read
  
  Defender/Policy (Azure): Security Reader RBAC role on subscription(s)


MINIMUM ROLES FOR INTERACTIVE USE:
══════════════════════════════════
  - Global Administrator: Can do everything, consent on the fly
  - Global Reader + Security Reader: Read-only, needs pre-consent
  - Security Administrator: Most checks, needs pre-consent for some

"@

    Write-Host $setupGuide -ForegroundColor Cyan
}

<#
.SYNOPSIS
    Generates an App Registration setup script.
#>
function New-EntraChecksAppRegistration {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$AppName = "EntraChecks-Assessment",
        
        [Parameter()]
        [string]$OutputPath = ".\Setup-EntraChecksApp.ps1"
    )
    
    $script = @'
<#
.SYNOPSIS
    Creates an App Registration for EntraChecks with all required permissions.
    
.DESCRIPTION
    Run this script as a Global Administrator to create and configure
    an App Registration for EntraChecks automated assessments.
    
.NOTES
    Requires: Microsoft.Graph PowerShell module
#>

#Requires -Modules Microsoft.Graph.Applications

param(
    [string]$AppName = "EntraChecks-Assessment",
    [switch]$CreateSecret
)

# Connect as Global Admin
Write-Host "Connecting to Microsoft Graph..." -ForegroundColor Cyan
Connect-MgGraph -Scopes "Application.ReadWrite.All", "AppRoleAssignment.ReadWrite.All"

# Define required permissions
$graphAppId = "00000003-0000-0000-c000-000000000000"  # Microsoft Graph

$requiredPermissions = @(
    "7ab1d382-f21e-4acd-a863-ba3e13f7da61",  # Directory.Read.All
    "246dd0d5-5bd0-4def-940b-0421030a5b68",  # Policy.Read.All
    "b0afded3-3588-46d8-8b3d-9842eff778da",  # AuditLog.Read.All
    "bf394140-e372-4bf9-a898-299cfc7564e5",  # SecurityEvents.Read.All
    "6e472fd1-ad78-48da-a0f0-97ab2c6b769e",  # IdentityRiskEvent.Read.All
    "dc5007c0-2d7d-4c42-879c-2dab87571379",  # IdentityRiskyUser.Read.All
    "7438b122-aefc-4978-80ed-43db9fcc7571",  # Device.Read.All
    "2f51be20-0bb4-4fed-bf7b-db946066c75e",  # DeviceManagementManagedDevices.Read.All
    "dc377aa6-52d8-4e23-b271-2a7ae04cedf3"   # DeviceManagementConfiguration.Read.All
)

# Create the app registration
Write-Host "Creating App Registration: $AppName" -ForegroundColor Cyan

$app = New-MgApplication -DisplayName $AppName -SignInAudience "AzureADMyOrg"

# Add required permissions
$resourceAccess = $requiredPermissions | ForEach-Object {
    @{
        Id = $_
        Type = "Role"  # Application permission
    }
}

$requiredResourceAccess = @{
    ResourceAppId = $graphAppId
    ResourceAccess = $resourceAccess
}

Update-MgApplication -ApplicationId $app.Id -RequiredResourceAccess @($requiredResourceAccess)

# Create service principal
$sp = New-MgServicePrincipal -AppId $app.AppId

Write-Host "`nApp Registration created!" -ForegroundColor Green
Write-Host "  Application ID: $($app.AppId)" -ForegroundColor White
Write-Host "  Object ID:      $($app.Id)" -ForegroundColor White

# Grant admin consent
Write-Host "`nGranting admin consent..." -ForegroundColor Cyan

$graphSp = Get-MgServicePrincipal -Filter "appId eq '$graphAppId'"

foreach ($permId in $requiredPermissions) {
    try {
        New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id -PrincipalId $sp.Id -ResourceId $graphSp.Id -AppRoleId $permId -ErrorAction Stop | Out-Null
    }
    catch {
        Write-Verbose "Permission may already be granted: $permId"
    }
}

Write-Host "Admin consent granted!" -ForegroundColor Green

# Create secret if requested
if ($CreateSecret) {
    Write-Host "`nCreating client secret..." -ForegroundColor Cyan
    
    $secret = Add-MgApplicationPassword -ApplicationId $app.Id -PasswordCredential @{
        DisplayName = "EntraChecks-Secret"
        EndDateTime = (Get-Date).AddYears(1)
    }
    
    Write-Host "`n╔════════════════════════════════════════════════════════════════╗" -ForegroundColor Yellow
    Write-Host "║  IMPORTANT: Copy this secret now! It won't be shown again.    ║" -ForegroundColor Yellow
    Write-Host "╚════════════════════════════════════════════════════════════════╝" -ForegroundColor Yellow
    Write-Host "`n  Client Secret: $($secret.SecretText)" -ForegroundColor Cyan
    Write-Host "  Expires:       $($secret.EndDateTime)" -ForegroundColor White
}

Write-Host "`n═══════════════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host "  Setup complete! Use these values to connect:" -ForegroundColor Green
Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host @"

  `$secret = ConvertTo-SecureString "YOUR-SECRET" -AsPlainText -Force
  Connect-EntraChecks -TenantId "$($(Get-MgContext).TenantId)" -ClientId "$($app.AppId)" -ClientSecret `$secret

"@ -ForegroundColor White

Write-Host "`nFor Azure modules (Defender/Policy), also run:" -ForegroundColor Yellow
Write-Host @"

  # Assign Security Reader role to the app
  New-AzRoleAssignment -ObjectId "$($sp.Id)" -RoleDefinitionName "Security Reader" -Scope "/subscriptions/<subscription-id>"

"@ -ForegroundColor Gray
'@

    $script | Out-File -FilePath $OutputPath -Encoding UTF8
    Write-Host "[OK] App registration setup script saved to: $OutputPath" -ForegroundColor Green
    Write-Host "    Run it as a Global Administrator to create the app." -ForegroundColor Gray
}

#endregion

#region ==================== MODULE EXPORTS ====================

Export-ModuleMember -Function @(
    'Connect-EntraChecks',
    'Connect-EntraChecksAzure',
    'Test-EntraChecksConnection',
    'Test-EntraChecksPermissions',
    'Invoke-EntraChecksGraphRequest',
    'Invoke-EntraChecksAzureRequest',
    'Show-EntraChecksSetup',
    'New-EntraChecksAppRegistration'
)

#endregion

# Show setup hint on import
Write-Host "`n[+] EntraChecks-Connection module loaded" -ForegroundColor Magenta
Write-Host "    Run 'Show-EntraChecksSetup' for authentication options" -ForegroundColor Gray
Write-Host "    Run 'Connect-EntraChecks -Modules All' to connect" -ForegroundColor Gray
