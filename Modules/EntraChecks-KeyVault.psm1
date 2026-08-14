<#
.SYNOPSIS
    EntraChecks Azure Key Vault Integration Module

.DESCRIPTION
    Optional module providing secure secret management via Azure Key Vault.
    This module is completely optional - all EntraChecks functionality works
    without it. Use it when you want to store credentials securely in Azure
    Key Vault instead of environment variables or interactive prompts.

.NOTES
    Version: 1.0.0
    Author: NamelessSaint
    Requires: Az.KeyVault module (optional)
#>

#region ==================== MODULE INITIALIZATION ====================

# Import logging module if available
$loggingModulePath = Join-Path $PSScriptRoot "EntraChecks-Logging.psm1"
if (Test-Path $loggingModulePath) {
    Import-Module $loggingModulePath -Force -ErrorAction SilentlyContinue
}

# Module state
$script:KeyVaultConnected = $false
$script:KeyVaultName = $null
$script:KeyVaultConnection = $null

#endregion

#region ==================== KEY VAULT CONNECTIVITY ====================

<#
.SYNOPSIS
    Tests if Azure Key Vault module is available.

.DESCRIPTION
    Checks if the Az.KeyVault PowerShell module is installed and available.

.OUTPUTS
    Boolean indicating if Az.KeyVault is available.

.EXAMPLE
    if (Test-KeyVaultAvailable) {
        Write-Host "Key Vault integration available"
    }
#>
function Test-KeyVaultAvailable {
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    try {
        $module = Get-Module -Name Az.KeyVault -ListAvailable -ErrorAction SilentlyContinue
        return ($null -ne $module)
    }
    catch {
        return $false
    }
}

<#
.SYNOPSIS
    Connects to Azure Key Vault.

.DESCRIPTION
    Establishes a connection to Azure Key Vault using one of several authentication methods:
    - Managed Identity (recommended for Azure-hosted scenarios)
    - Service Principal with Certificate
    - Service Principal with Secret
    - Interactive (for development)

.PARAMETER KeyVaultName
    Name of the Azure Key Vault to connect to.

.PARAMETER AuthenticationMethod
    Method to use for authentication. Options: ManagedIdentity, ServicePrincipal, Interactive
    Default: ManagedIdentity

.PARAMETER TenantId
    Azure AD Tenant ID (required for ServicePrincipal and Interactive).

.PARAMETER ClientId
    Service Principal Client ID (required for ServicePrincipal authentication).

.PARAMETER ClientSecret
    Service Principal Client Secret (required for ServicePrincipal with secret).

.PARAMETER CertificateThumbprint
    Certificate thumbprint (required for ServicePrincipal with certificate).

.OUTPUTS
    Boolean indicating connection success.

.EXAMPLE
    # Managed Identity (recommended for Azure VMs, Functions, etc.)
    Connect-EntraChecksKeyVault -KeyVaultName "mykeyvault"

.EXAMPLE
    # Service Principal with Secret
    Connect-EntraChecksKeyVault -KeyVaultName "mykeyvault" `
        -AuthenticationMethod ServicePrincipal `
        -TenantId "tenant-guid" `
        -ClientId "client-guid" `
        -ClientSecret (ConvertTo-SecureString "secret" -AsPlainText -Force)

.EXAMPLE
    # Interactive (for development)
    Connect-EntraChecksKeyVault -KeyVaultName "mykeyvault" `
        -AuthenticationMethod Interactive `
        -TenantId "tenant-guid"
#>
function Connect-EntraChecksKeyVault {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [string]$KeyVaultName,

        [Parameter()]
        [ValidateSet('ManagedIdentity', 'ServicePrincipal', 'Interactive')]
        [string]$AuthenticationMethod = 'ManagedIdentity',

        [Parameter()]
        [string]$TenantId,

        [Parameter()]
        [string]$ClientId,

        [Parameter()]
        [SecureString]$ClientSecret,

        [Parameter()]
        [string]$CertificateThumbprint
    )

    if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
        Write-Log -Level INFO -Message "Connecting to Azure Key Vault" -Category "KeyVault" -Properties @{
            KeyVaultName = $KeyVaultName
            AuthenticationMethod = $AuthenticationMethod
        }
    }

    # Check if Az.KeyVault module is available
    if (-not (Test-KeyVaultAvailable)) {
        $message = "Az.KeyVault module not found. Install with: Install-Module Az.KeyVault -Scope CurrentUser"
        if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
            Write-Log -Level WARN -Message $message -Category "KeyVault"
        }
        Write-Warning $message
        return $false
    }

    try {
        # Import Az.KeyVault module
        Import-Module Az.KeyVault -ErrorAction Stop

        # Authenticate based on method
        $connectParams = @{
            ErrorAction = 'Stop'
        }

        switch ($AuthenticationMethod) {
            'ManagedIdentity' {
                if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
                    Write-Log -Level INFO -Message "Using Managed Identity authentication" -Category "KeyVault"
                }
                Connect-AzAccount -Identity @connectParams | Out-Null
            }

            'ServicePrincipal' {
                if (-not $TenantId -or -not $ClientId) {
                    throw "TenantId and ClientId are required for ServicePrincipal authentication"
                }

                if ($CertificateThumbprint) {
                    # Certificate-based authentication
                    if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
                        Write-Log -Level INFO -Message "Using Service Principal with Certificate" -Category "KeyVault"
                    }
                    Connect-AzAccount -ServicePrincipal -TenantId $TenantId -ApplicationId $ClientId `
                        -CertificateThumbprint $CertificateThumbprint @connectParams | Out-Null
                }
                elseif ($ClientSecret) {
                    # Secret-based authentication
                    if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
                        Write-Log -Level INFO -Message "Using Service Principal with Secret" -Category "KeyVault"
                    }
                    $credential = New-Object System.Management.Automation.PSCredential($ClientId, $ClientSecret)
                    Connect-AzAccount -ServicePrincipal -TenantId $TenantId -Credential $credential @connectParams | Out-Null
                }
                else {
                    throw "Either CertificateThumbprint or ClientSecret is required for ServicePrincipal authentication"
                }
            }

            'Interactive' {
                if (-not $TenantId) {
                    throw "TenantId is required for Interactive authentication"
                }

                if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
                    Write-Log -Level INFO -Message "Using Interactive authentication" -Category "KeyVault"
                }
                Connect-AzAccount -TenantId $TenantId @connectParams | Out-Null
            }
        }

        # Verify access to Key Vault
        try {
            $vault = Get-AzKeyVault -VaultName $KeyVaultName -ErrorAction Stop
            if (-not $vault) {
                throw "Key Vault '$KeyVaultName' not found or not accessible"
            }
        }
        catch {
            throw "Unable to access Key Vault '$KeyVaultName': $_"
        }

        # Update module state
        $script:KeyVaultConnected = $true
        $script:KeyVaultName = $KeyVaultName

        if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
            Write-Log -Level INFO -Message "Successfully connected to Key Vault" -Category "KeyVault" -Properties @{
                KeyVaultName = $KeyVaultName
            }
        }

        if (Get-Command Write-AuditLog -ErrorAction SilentlyContinue) {
            Write-AuditLog -EventType "AuthenticationSuccess" `
                -Description "Connected to Azure Key Vault" `
                -TargetObject $KeyVaultName `
                -Result "Success"
        }

        return $true
    }
    catch {
        $script:KeyVaultConnected = $false
        $script:KeyVaultName = $null

        if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
            Write-Log -Level ERROR -Message "Failed to connect to Key Vault" -Category "KeyVault" -ErrorRecord $_
        }

        if (Get-Command Write-AuditLog -ErrorAction SilentlyContinue) {
            Write-AuditLog -EventType "AuthenticationFailure" `
                -Description "Failed to connect to Azure Key Vault" `
                -TargetObject $KeyVaultName `
                -Result "Failure"
        }

        throw
    }
}

<#
.SYNOPSIS
    Tests if connected to Azure Key Vault.

.DESCRIPTION
    Checks if a connection to Azure Key Vault is currently established.

.OUTPUTS
    Boolean indicating connection status.

.EXAMPLE
    if (Test-KeyVaultConnected) {
        $secret = Get-KeyVaultSecret -SecretName "mysecret"
    }
#>
function Test-KeyVaultConnected {
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    return $script:KeyVaultConnected
}

<#
.SYNOPSIS
    Disconnects from Azure Key Vault.

.DESCRIPTION
    Closes the connection to Azure Key Vault and clears cached credentials.

.EXAMPLE
    Disconnect-EntraChecksKeyVault
#>
function Disconnect-EntraChecksKeyVault {
    [CmdletBinding()]
    param()

    if ($script:KeyVaultConnected) {
        try {
            Disconnect-AzAccount -ErrorAction SilentlyContinue | Out-Null

            if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
                Write-Log -Level INFO -Message "Disconnected from Key Vault" -Category "KeyVault"
            }
        }
        catch {
            Write-Verbose "Error during Key Vault disconnect: $_"
        }
        finally {
            $script:KeyVaultConnected = $false
            $script:KeyVaultName = $null
        }
    }
}

#endregion

#region ==================== SECRET RETRIEVAL ====================

<#
.SYNOPSIS
    Retrieves a secret from Azure Key Vault.

.DESCRIPTION
    Securely retrieves a secret value from Azure Key Vault. Automatically handles
    connection if not already connected. Falls back gracefully if Key Vault is
    not configured or available.

.PARAMETER SecretName
    Name of the secret to retrieve from Key Vault.

.PARAMETER KeyVaultName
    Name of the Key Vault (optional if already connected).

.PARAMETER AsPlainText
    Return secret as plain text string instead of SecureString.
    Use with caution - only for scenarios that require plain text.

.PARAMETER DefaultValue
    Default value to return if secret is not found or Key Vault is not available.

.OUTPUTS
    SecureString or String (if AsPlainText) containing the secret value.

.EXAMPLE
    # Get secret as SecureString
    $securePassword = Get-KeyVaultSecret -SecretName "AdminPassword"

.EXAMPLE
    # Get secret as plain text (use cautiously)
    $apiKey = Get-KeyVaultSecret -SecretName "ApiKey" -AsPlainText

.EXAMPLE
    # With default value for graceful fallback
    $secret = Get-KeyVaultSecret -SecretName "MySecret" -DefaultValue "default-value"
#>
function Get-KeyVaultSecret {
    [OutputType([string])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$SecretName,

        [Parameter()]
        [string]$KeyVaultName,

        [switch]$AsPlainText,

        [Parameter()]
        [string]$DefaultValue
    )

    # Use connected vault if not specified
    if (-not $KeyVaultName) {
        if (-not $script:KeyVaultConnected) {
            $message = "Not connected to Key Vault. Use Connect-EntraChecksKeyVault first or specify -KeyVaultName."
            if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
                Write-Log -Level WARN -Message $message -Category "KeyVault"
            }

            if ($DefaultValue) {
                if ($AsPlainText) {
                    return $DefaultValue
                }
                else {
                    return (New-Object System.Net.NetworkCredential('', $DefaultValue)).SecurePassword
                }
            }

            throw $message
        }
        $KeyVaultName = $script:KeyVaultName
    }

    try {
        if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
            Write-Log -Level DEBUG -Message "Retrieving secret from Key Vault" -Category "KeyVault" -Properties @{
                SecretName = $SecretName
                KeyVaultName = $KeyVaultName
            }
        }

        # Retrieve secret
        $secret = Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $SecretName -ErrorAction Stop

        if (-not $secret) {
            throw "Secret '$SecretName' not found in Key Vault '$KeyVaultName'"
        }

        if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
            Write-Log -Level INFO -Message "Successfully retrieved secret from Key Vault" -Category "KeyVault" -Properties @{
                SecretName = $SecretName
            }
        }

        if (Get-Command Write-AuditLog -ErrorAction SilentlyContinue) {
            Write-AuditLog -EventType "DataExported" `
                -Description "Retrieved secret from Key Vault" `
                -TargetObject $SecretName `
                -Result "Success"
        }

        # Return in requested format
        if ($AsPlainText) {
            return $secret.SecretValue | ConvertFrom-SecureString -AsPlainText
        }
        else {
            return $secret.SecretValue
        }
    }
    catch {
        if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
            Write-Log -Level ERROR -Message "Failed to retrieve secret from Key Vault" -Category "KeyVault" -ErrorRecord $_ -Properties @{
                SecretName = $SecretName
                KeyVaultName = $KeyVaultName
            }
        }

        # Return default value if provided
        if ($DefaultValue) {
            if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
                Write-Log -Level WARN -Message "Using default value for secret" -Category "KeyVault" -Properties @{
                    SecretName = $SecretName
                }
            }

            if ($AsPlainText) {
                return $DefaultValue
            }
            else {
                return (New-Object System.Net.NetworkCredential('', $DefaultValue)).SecurePassword
            }
        }

        throw
    }
}

<#
.SYNOPSIS
    Sets a secret in Azure Key Vault.

.DESCRIPTION
    Securely stores a secret value in Azure Key Vault. Requires appropriate
    permissions (Key Vault Secrets Officer or Key Vault Contributor).

.PARAMETER SecretName
    Name of the secret to store.

.PARAMETER SecretValue
    Value to store (SecureString or plain string).

.PARAMETER KeyVaultName
    Name of the Key Vault (optional if already connected).

.PARAMETER ExpiresOn
    Optional expiration date for the secret.

.PARAMETER ContentType
    Optional content type description (e.g., "password", "api-key").

.EXAMPLE
    # Store a secure string
    $securePassword = Read-Host "Enter password" -AsSecureString
    Set-KeyVaultSecret -SecretName "AdminPassword" -SecretValue $securePassword

.EXAMPLE
    # Store a plain text secret
    Set-KeyVaultSecret -SecretName "ApiKey" -SecretValue "my-api-key"

.EXAMPLE
    # Store with expiration
    $expires = (Get-Date).AddYears(1)
    Set-KeyVaultSecret -SecretName "TempSecret" -SecretValue "value" -ExpiresOn $expires
#>
function Set-KeyVaultSecret {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$SecretName,

        [Parameter(Mandatory)]
        $SecretValue,

        [Parameter()]
        [string]$KeyVaultName,

        [Parameter()]
        [datetime]$ExpiresOn,

        [Parameter()]
        [string]$ContentType
    )

    # Use connected vault if not specified
    if (-not $KeyVaultName) {
        if (-not $script:KeyVaultConnected) {
            throw "Not connected to Key Vault. Use Connect-EntraChecksKeyVault first or specify -KeyVaultName."
        }
        $KeyVaultName = $script:KeyVaultName
    }

    # Convert to SecureString if plain text
    if ($SecretValue -is [string]) {
        $SecretValue = (New-Object System.Net.NetworkCredential('', $SecretValue)).SecurePassword
    }

    if ($PSCmdlet.ShouldProcess("Key Vault: $KeyVaultName", "Set secret: $SecretName")) {
        try {
            $params = @{
                VaultName = $KeyVaultName
                Name = $SecretName
                SecretValue = $SecretValue
                ErrorAction = 'Stop'
            }

            if ($ExpiresOn) {
                $params['Expires'] = $ExpiresOn
            }

            if ($ContentType) {
                $params['ContentType'] = $ContentType
            }

            $result = Set-AzKeyVaultSecret @params

            if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
                Write-Log -Level INFO -Message "Successfully stored secret in Key Vault" -Category "KeyVault" -Properties @{
                    SecretName = $SecretName
                    KeyVaultName = $KeyVaultName
                }
            }

            if (Get-Command Write-AuditLog -ErrorAction SilentlyContinue) {
                Write-AuditLog -EventType "ConfigurationChanged" `
                    -Description "Stored secret in Key Vault" `
                    -TargetObject $SecretName `
                    -Result "Success"
            }

            return $result
        }
        catch {
            if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
                Write-Log -Level ERROR -Message "Failed to store secret in Key Vault" -Category "KeyVault" -ErrorRecord $_
            }
            throw
        }
    }
}

<#
.SYNOPSIS
    Tests if a secret exists in Azure Key Vault.

.DESCRIPTION
    Checks if a secret with the specified name exists in Key Vault.

.PARAMETER SecretName
    Name of the secret to check.

.PARAMETER KeyVaultName
    Name of the Key Vault (optional if already connected).

.OUTPUTS
    Boolean indicating if secret exists.

.EXAMPLE
    if (Test-KeyVaultSecret -SecretName "MySecret") {
        Write-Host "Secret exists"
    }
#>
function Test-KeyVaultSecret {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [string]$SecretName,

        [Parameter()]
        [string]$KeyVaultName
    )

    # Use connected vault if not specified
    if (-not $KeyVaultName) {
        if (-not $script:KeyVaultConnected) {
            return $false
        }
        $KeyVaultName = $script:KeyVaultName
    }

    try {
        $secret = Get-AzKeyVaultSecret -VaultName $KeyVaultName -Name $SecretName -ErrorAction SilentlyContinue
        return ($null -ne $secret)
    }
    catch {
        return $false
    }
}

#endregion

#region ==================== HELPER FUNCTIONS ====================

<#
.SYNOPSIS
    Gets credential from Key Vault or falls back to alternative methods.

.DESCRIPTION
    Unified function to retrieve credentials with graceful fallback:
    1. Try Key Vault (if configured)
    2. Try environment variables
    3. Prompt user interactively (if allowed)

.PARAMETER Identity
    Name/purpose of the credential (e.g., "GraphAPI", "ServicePrincipal").

.PARAMETER KeyVaultSecretName
    Name of the secret in Key Vault.

.PARAMETER EnvironmentVariable
    Name of environment variable to check as fallback.

.PARAMETER AllowInteractive
    Allow interactive prompt if other methods fail.

.OUTPUTS
    PSCredential object or $null if not found.

.EXAMPLE
    $cred = Get-EntraChecksCredential -Identity "GraphAPI" `
        -KeyVaultSecretName "graph-api-secret" `
        -EnvironmentVariable "GRAPH_API_SECRET" `
        -AllowInteractive
#>
function Get-EntraChecksCredential {
    [CmdletBinding()]
    [OutputType([PSCredential])]
    param(
        [Parameter(Mandatory)]
        [string]$Identity,

        [Parameter()]
        [string]$KeyVaultSecretName,

        [Parameter()]
        [string]$EnvironmentVariable,

        [switch]$AllowInteractive
    )

    # Try Key Vault first (if connected and secret name provided)
    if ($KeyVaultSecretName -and (Test-KeyVaultConnected)) {
        try {
            if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
                Write-Log -Level INFO -Message "Attempting to retrieve credential from Key Vault" -Category "KeyVault" -Properties @{
                    Identity = $Identity
                }
            }

            $password = Get-KeyVaultSecret -SecretName $KeyVaultSecretName -ErrorAction Stop
            $credential = New-Object System.Management.Automation.PSCredential($Identity, $password)

            if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
                Write-Log -Level INFO -Message "Retrieved credential from Key Vault" -Category "KeyVault"
            }

            return $credential
        }
        catch {
            if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
                Write-Log -Level WARN -Message "Failed to retrieve from Key Vault, trying fallback" -Category "KeyVault" -ErrorRecord $_
            }
        }
    }

    # Try environment variable
    if ($EnvironmentVariable) {
        $envValue = [Environment]::GetEnvironmentVariable($EnvironmentVariable)
        if ($envValue) {
            if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
                Write-Log -Level INFO -Message "Retrieved credential from environment variable" -Category "KeyVault" -Properties @{
                    Variable = $EnvironmentVariable
                }
            }

            $password = (New-Object System.Net.NetworkCredential('', $envValue)).SecurePassword
            return New-Object System.Management.Automation.PSCredential($Identity, $password)
        }
    }

    # Interactive prompt (if allowed)
    if ($AllowInteractive) {
        if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
            Write-Log -Level INFO -Message "Prompting for credential interactively" -Category "KeyVault"
        }

        return Get-Credential -Message "Enter credentials for: $Identity"
    }

    # No credential found
    if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
        Write-Log -Level WARN -Message "No credential found" -Category "KeyVault" -Properties @{
            Identity = $Identity
        }
    }

    return $null
}

#endregion

#region ==================== MODULE EXPORTS ====================

Export-ModuleMember -Function @(
    'Test-KeyVaultAvailable',
    'Connect-EntraChecksKeyVault',
    'Disconnect-EntraChecksKeyVault',
    'Test-KeyVaultConnected',
    'Get-KeyVaultSecret',
    'Set-KeyVaultSecret',
    'Test-KeyVaultSecret',
    'Get-EntraChecksCredential'
)

#endregion
