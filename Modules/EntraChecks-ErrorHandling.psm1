<#
.SYNOPSIS
    EntraChecks-ErrorHandling.psm1
    Error handling, retry logic, and resilience patterns for EntraChecks

.DESCRIPTION
    Provides enterprise-grade error handling including:
    - Retry logic with exponential backoff
    - Circuit breaker pattern for API calls
    - Error categorization and handling strategies
    - Rate limit detection and handling
    - Transient error detection

.NOTES
    Version: 1.0.0
    Author: NamelessSaint
#>

#Requires -Version 5.1

$script:ModuleVersion = "1.0.0"
$script:ModuleName = "EntraChecks-ErrorHandling"

# Import logging module
$loggingModulePath = Join-Path $PSScriptRoot "EntraChecks-Logging.psm1"
if (Test-Path $loggingModulePath) {
    Import-Module $loggingModulePath -Force -ErrorAction SilentlyContinue
}

#region ==================== ERROR CATEGORIZATION ====================

# Define error categories for different handling strategies
$script:ErrorCategories = @{
    Retryable = @(
        'throttl',                    # Rate limiting
        '429',                        # HTTP 429 Too Many Requests
        '503',                        # HTTP 503 Service Unavailable
        '504',                        # HTTP 504 Gateway Timeout
        'timeout',                    # Timeout errors
        'network',                    # Network errors
        'unable to connect',          # Connection errors
        'connection.*closed',         # Connection closed
        'connection.*reset',          # Connection reset
        'temporarily unavailable',    # Temporary service issues
        'service.*unavailable',       # Service unavailable
        'GatewayTimeout'             # Gateway timeout
    )

    Authentication = @(
        'AADSTS',                     # Azure AD error codes
        'unauthorized',               # 401 Unauthorized
        '401',                        # HTTP 401
        'authentication.*failed',     # Auth failures
        'invalid.*credentials',       # Credential issues
        'token.*expired',             # Expired tokens
        'consent.*required'           # Consent issues
    )

    Permission = @(
        'insufficient.*privileges',   # Permission errors
        'access.*denied',             # Access denied
        '403',                        # HTTP 403 Forbidden
        'forbidden',                  # Forbidden
        'requires.*admin.*consent'    # Admin consent needed
    )

    NotFound = @(
        '404',                        # HTTP 404 Not Found
        'not.*found',                 # Not found
        'does not exist'              # Resource doesn't exist
    )

    BadRequest = @(
        '400',                        # HTTP 400 Bad Request
        'bad.*request',               # Bad request
        'invalid.*request',           # Invalid request
        'malformed.*request'          # Malformed request
    )
}

#endregion

#region ==================== CIRCUIT BREAKER ====================

# Circuit breaker state management
$script:CircuitBreakers = @{}

function New-CircuitBreaker {
    <#
    .SYNOPSIS
        Create a new circuit breaker for an endpoint

    .PARAMETER Name
        Name of the circuit breaker (typically endpoint or service name)

    .PARAMETER FailureThreshold
        Number of consecutive failures before opening circuit

    .PARAMETER TimeoutSeconds
        Seconds to wait before attempting half-open state

    .PARAMETER SuccessThreshold
        Number of successes in half-open state to close circuit
    #>
    [OutputType([hashtable])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [int]$FailureThreshold = 5,
        [int]$TimeoutSeconds = 60,
        [int]$SuccessThreshold = 2
    )

    $circuitBreaker = @{
        Name = $Name
        State = "Closed"  # Closed, Open, HalfOpen
        FailureCount = 0
        SuccessCount = 0
        FailureThreshold = $FailureThreshold
        TimeoutSeconds = $TimeoutSeconds
        SuccessThreshold = $SuccessThreshold
        LastFailureTime = $null
        OpenedAt = $null
    }

    $script:CircuitBreakers[$Name] = $circuitBreaker

    if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
        Write-Log -Level DEBUG -Message "Circuit breaker created: $Name" -Category "CircuitBreaker" -Properties @{
            FailureThreshold = $FailureThreshold
            TimeoutSeconds = $TimeoutSeconds
        }
    }

    return $circuitBreaker
}

function Test-CircuitBreakerState {
    <#
    .SYNOPSIS
        Test if circuit breaker allows operation
    #>
    [OutputType([bool])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name
    )

    if (-not $script:CircuitBreakers.ContainsKey($Name)) {
        # No circuit breaker exists, allow operation
        return $true
    }

    $cb = $script:CircuitBreakers[$Name]

    switch ($cb.State) {
        "Closed" {
            # Circuit is closed, allow operation
            return $true
        }

        "Open" {
            # Check if timeout has elapsed
            $elapsed = (Get-Date) - $cb.OpenedAt
            if ($elapsed.TotalSeconds -ge $cb.TimeoutSeconds) {
                # Move to half-open state
                $cb.State = "HalfOpen"
                $cb.SuccessCount = 0

                if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
                    Write-Log -Level INFO -Message "Circuit breaker entering half-open state: $Name" -Category "CircuitBreaker"
                }

                return $true
            }
            else {
                # Circuit is still open
                if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
                    Write-Log -Level WARN -Message "Circuit breaker is open: $Name" -Category "CircuitBreaker" -Properties @{
                        RemainingSeconds = [math]::Ceiling($cb.TimeoutSeconds - $elapsed.TotalSeconds)
                    }
                }
                return $false
            }
        }

        "HalfOpen" {
            # Allow limited operations in half-open state
            return $true
        }
    }

    return $false
}

function Update-CircuitBreakerSuccess {
    <#
    .SYNOPSIS
        Record a successful operation
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name
    )

    if (-not $script:CircuitBreakers.ContainsKey($Name)) {
        return
    }

    $cb = $script:CircuitBreakers[$Name]

    switch ($cb.State) {
        "Closed" {
            # Reset failure count on success
            $cb.FailureCount = 0
        }

        "HalfOpen" {
            $cb.SuccessCount++
            if ($cb.SuccessCount -ge $cb.SuccessThreshold) {
                # Close the circuit
                $cb.State = "Closed"
                $cb.FailureCount = 0
                $cb.SuccessCount = 0

                if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
                    Write-Log -Level INFO -Message "Circuit breaker closed: $Name" -Category "CircuitBreaker"
                }
            }
        }
    }
}

function Update-CircuitBreakerFailure {
    <#
    .SYNOPSIS
        Record a failed operation
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name
    )

    if (-not $script:CircuitBreakers.ContainsKey($Name)) {
        return
    }

    $cb = $script:CircuitBreakers[$Name]
    $cb.LastFailureTime = Get-Date

    switch ($cb.State) {
        "Closed" {
            $cb.FailureCount++
            if ($cb.FailureCount -ge $cb.FailureThreshold) {
                # Open the circuit
                $cb.State = "Open"
                $cb.OpenedAt = Get-Date

                if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
                    Write-Log -Level ERROR -Message "Circuit breaker opened: $Name" -Category "CircuitBreaker" -Properties @{
                        ConsecutiveFailures = $cb.FailureCount
                        TimeoutSeconds = $cb.TimeoutSeconds
                    }
                }
            }
        }

        "HalfOpen" {
            # Failed in half-open state, reopen circuit
            $cb.State = "Open"
            $cb.OpenedAt = Get-Date
            $cb.FailureCount = $cb.FailureThreshold
            $cb.SuccessCount = 0

            if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
                Write-Log -Level ERROR -Message "Circuit breaker reopened: $Name" -Category "CircuitBreaker"
            }
        }
    }
}

function Get-CircuitBreakerState {
    <#
    .SYNOPSIS
        Get current state of circuit breaker
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name
    )

    if ($script:CircuitBreakers.ContainsKey($Name)) {
        return $script:CircuitBreakers[$Name]
    }

    return $null
}

#endregion

#region ==================== ERROR DETECTION ====================

function Test-RetryableError {
    <#
    .SYNOPSIS
        Determine if an error is retryable

    .PARAMETER ErrorRecord
        The error record to analyze

    .PARAMETER Exception
        The exception to analyze
    #>
    [OutputType([bool])]
    [CmdletBinding()]
    param(
        [System.Management.Automation.ErrorRecord]$ErrorRecord,
        [System.Exception]$Exception
    )

    $errorMessage = if ($ErrorRecord) {
        $ErrorRecord.Exception.Message
    } elseif ($Exception) {
        $Exception.Message
    } else {
        return $false
    }

    # Check against retryable patterns
    foreach ($pattern in $script:ErrorCategories.Retryable) {
        if ($errorMessage -match $pattern) {
            if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
                Write-Log -Level DEBUG -Message "Retryable error detected: $pattern" -Category "ErrorHandling"
            }
            return $true
        }
    }

    return $false
}

function Get-ErrorCategory {
    <#
    .SYNOPSIS
        Categorize an error for appropriate handling

    .PARAMETER ErrorRecord
        The error record to categorize
    #>
    [OutputType([string])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )

    $errorMessage = $ErrorRecord.Exception.Message

    foreach ($category in $script:ErrorCategories.Keys) {
        foreach ($pattern in $script:ErrorCategories[$category]) {
            if ($errorMessage -match $pattern) {
                return $category
            }
        }
    }

    return "Unknown"
}

function Get-RetryDelay {
    <#
    .SYNOPSIS
        Calculate retry delay based on error type and attempt number

    .PARAMETER Attempt
        Current attempt number

    .PARAMETER ErrorRecord
        The error record

    .PARAMETER BaseDelaySeconds
        Base delay in seconds

    .PARAMETER UseExponentialBackoff
        Use exponential backoff
    #>
    [OutputType([int])]
    [CmdletBinding()]
    param(
        [int]$Attempt,
        [System.Management.Automation.ErrorRecord]$ErrorRecord,
        [int]$BaseDelaySeconds = 5,
        [switch]$UseExponentialBackoff
    )

    $errorMessage = $ErrorRecord.Exception.Message

    # Check for Retry-After header in HTTP 429 responses
    if ($errorMessage -match 'Retry-After:\s*(\d+)') {
        $retryAfter = [int]$matches[1]
        if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
            Write-Log -Level INFO -Message "Using Retry-After header value: $retryAfter seconds" -Category "RateLimiting"
        }
        return $retryAfter
    }

    # Calculate delay
    if ($UseExponentialBackoff) {
        $delay = [math]::Min([math]::Pow(2, $Attempt) * $BaseDelaySeconds, 300)  # Cap at 5 minutes
    }
    else {
        $delay = $BaseDelaySeconds
    }

    # Add jitter to prevent thundering herd
    $jitter = Get-Random -Minimum 0 -Maximum ($delay * 0.1)
    $delay += $jitter

    return [math]::Ceiling($delay)
}

#endregion

#region ==================== RETRY LOGIC ====================

function Invoke-WithRetry {
    <#
    .SYNOPSIS
        Execute a script block with automatic retry logic

    .DESCRIPTION
        Wraps any operation with intelligent retry logic including:
        - Exponential backoff
        - Circuit breaker integration
        - Transient error detection
        - Rate limit handling
        - Comprehensive logging

    .PARAMETER ScriptBlock
        The script block to execute

    .PARAMETER MaxRetries
        Maximum number of retry attempts (default: 3)

    .PARAMETER BaseDelaySeconds
        Base delay between retries (default: 5)

    .PARAMETER ExponentialBackoff
        Use exponential backoff strategy

    .PARAMETER CircuitBreakerName
        Name of circuit breaker to use

    .PARAMETER Operation
        Descriptive name of the operation

    .PARAMETER RetryableErrorPatterns
        Additional error patterns to consider retryable

    .EXAMPLE
        $users = Invoke-WithRetry -ScriptBlock {
            Get-MgUser -All
        } -Operation "Get All Users" -ExponentialBackoff

    .EXAMPLE
        $result = Invoke-WithRetry -ScriptBlock {
            Invoke-MgGraphRequest -Uri "/users" -Method GET
        } -MaxRetries 5 -CircuitBreakerName "GraphAPI" -ExponentialBackoff
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ScriptBlock]$ScriptBlock,

        [int]$MaxRetries = 3,

        [int]$BaseDelaySeconds = 5,

        [switch]$ExponentialBackoff,

        [string]$CircuitBreakerName,

        [string]$Operation = "Operation",

        [string[]]$RetryableErrorPatterns = @()
    )

    $attempt = 0
    $success = $false
    $lastError = $null
    $startTime = Get-Date

    # Check circuit breaker
    if ($CircuitBreakerName) {
        if (-not $script:CircuitBreakers.ContainsKey($CircuitBreakerName)) {
            New-CircuitBreaker -Name $CircuitBreakerName | Out-Null
        }

        if (-not (Test-CircuitBreakerState -Name $CircuitBreakerName)) {
            $error = "Circuit breaker is open for: $CircuitBreakerName"

            if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
                Write-Log -Level ERROR -Message $error -Category "CircuitBreaker"
            }

            throw $error
        }
    }

    while (-not $success -and $attempt -lt $MaxRetries) {
        $attempt++

        if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
            Write-Log -Level INFO -Message "[$Operation] Attempt $attempt of $MaxRetries" -Category "Retry" -Properties @{
                Operation = $Operation
                Attempt = $attempt
                MaxRetries = $MaxRetries
            }
        }

        try {
            $result = & $ScriptBlock
            $success = $true

            $duration = (Get-Date) - $startTime

            if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
                Write-Log -Level INFO -Message "[$Operation] Succeeded on attempt $attempt" -Category "Retry" -Properties @{
                    Operation = $Operation
                    Attempt = $attempt
                    Duration = $duration.TotalSeconds
                }
            }

            # Update circuit breaker on success
            if ($CircuitBreakerName) {
                Update-CircuitBreakerSuccess -Name $CircuitBreakerName
            }

            return $result
        }
        catch {
            $lastError = $_
            $errorCategory = Get-ErrorCategory -ErrorRecord $_

            if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
                Write-Log -Level WARN -Message "[$Operation] Attempt $attempt failed" -Category "Retry" -ErrorRecord $_ -Properties @{
                    Operation = $Operation
                    Attempt = $attempt
                    ErrorCategory = $errorCategory
                }
            }

            # Check if error is retryable
            $isRetryable = Test-RetryableError -ErrorRecord $_

            # Check custom patterns
            if (-not $isRetryable -and $RetryableErrorPatterns) {
                foreach ($pattern in $RetryableErrorPatterns) {
                    if ($_.Exception.Message -match $pattern) {
                        $isRetryable = $true
                        break
                    }
                }
            }

            # If not retryable or last attempt, throw
            if (-not $isRetryable) {
                if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
                    Write-Log -Level ERROR -Message "[$Operation] Non-retryable error encountered" -Category "Retry" -Properties @{
                        Operation = $Operation
                        ErrorCategory = $errorCategory
                    }
                }

                # Update circuit breaker on non-retryable error
                if ($CircuitBreakerName) {
                    Update-CircuitBreakerFailure -Name $CircuitBreakerName
                }

                throw
            }

            if ($attempt -ge $MaxRetries) {
                if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
                    Write-Log -Level ERROR -Message "[$Operation] Max retries ($MaxRetries) exceeded" -Category "Retry" -Properties @{
                        Operation = $Operation
                        TotalAttempts = $attempt
                    }
                }

                # Update circuit breaker on exhausted retries
                if ($CircuitBreakerName) {
                    Update-CircuitBreakerFailure -Name $CircuitBreakerName
                }

                throw
            }

            # Calculate delay
            $delay = Get-RetryDelay -Attempt $attempt -ErrorRecord $_ -BaseDelaySeconds $BaseDelaySeconds -UseExponentialBackoff:$ExponentialBackoff

            if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
                Write-Log -Level INFO -Message "[$Operation] Waiting $delay seconds before retry" -Category "Retry" -Properties @{
                    Operation = $Operation
                    DelaySeconds = $delay
                    NextAttempt = $attempt + 1
                }
            }

            Start-Sleep -Seconds $delay
        }
    }

    if (-not $success) {
        if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
            Write-Log -Level ERROR -Message "[$Operation] Failed after $attempt attempts" -Category "Retry" -ErrorRecord $lastError
        }

        throw $lastError
    }
}

#endregion

#region ==================== GRAPH API HELPERS ====================

function Invoke-GraphRequestWithRetry {
    <#
    .SYNOPSIS
        Make a Graph API request with automatic retry and circuit breaker

    .PARAMETER Uri
        Graph API endpoint URI

    .PARAMETER Method
        HTTP method (default: GET)

    .PARAMETER Body
        Request body for POST/PATCH/PUT

    .PARAMETER MaxRetries
        Maximum retry attempts (default: 3)

    .EXAMPLE
        $users = Invoke-GraphRequestWithRetry -Uri "https://graph.microsoft.com/v1.0/users"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Uri,

        [ValidateSet('GET', 'POST', 'PATCH', 'PUT', 'DELETE')]
        [string]$Method = 'GET',

        [object]$Body,

        [int]$MaxRetries = 3
    )

    $operation = "$Method $Uri"

    $result = Invoke-WithRetry -ScriptBlock {
        $params = @{
            Uri = $Uri
            Method = $Method
        }

        if ($Body) {
            $params.Body = $Body
        }

        Invoke-MgGraphRequest @params
    } -MaxRetries $MaxRetries `
        -ExponentialBackoff `
        -CircuitBreakerName "GraphAPI" `
        -Operation $operation

    return $result
}

function Get-AllGraphPages {
    <#
    .SYNOPSIS
        Get all pages from a paginated Graph API response with retry logic

    .PARAMETER Uri
        Initial Graph API endpoint URI

    .PARAMETER MaxPages
        Maximum pages to retrieve (0 = unlimited)

    .EXAMPLE
        $allUsers = Get-AllGraphPages -Uri "https://graph.microsoft.com/v1.0/users"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Uri,

        [int]$MaxPages = 0
    )

    $allData = [System.Collections.Generic.List[object]]::new()
    $currentPage = 0
    $nextLink = $Uri

    while ($nextLink -and ($MaxPages -eq 0 -or $currentPage -lt $MaxPages)) {
        $currentPage++

        $response = Invoke-GraphRequestWithRetry -Uri $nextLink -MaxRetries 5

        if ($response.value) {
            $allData.AddRange($response.value)
        }

        $nextLink = $response.'@odata.nextLink'

        if (Get-Command Write-Log -ErrorAction SilentlyContinue) {
            Write-Log -Level DEBUG -Message "Fetched page $currentPage, total items: $($allData.Count)" -Category "Pagination"
        }
    }

    return $allData.ToArray()
}

#endregion

#region ==================== EXPORTS ====================

Export-ModuleMember -Function @(
    'New-CircuitBreaker',
    'Test-CircuitBreakerState',
    'Update-CircuitBreakerSuccess',
    'Update-CircuitBreakerFailure',
    'Get-CircuitBreakerState',
    'Test-RetryableError',
    'Get-ErrorCategory',
    'Get-RetryDelay',
    'Invoke-WithRetry',
    'Invoke-GraphRequestWithRetry',
    'Get-AllGraphPages'
)

#endregion
