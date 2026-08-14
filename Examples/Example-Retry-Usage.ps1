<#
.SYNOPSIS
    Example-Retry-Usage.ps1
    Demonstrates retry logic and error handling in EntraChecks

.DESCRIPTION
    This example script shows how to use the retry logic, circuit breaker,
    and error handling features.

.NOTES
    Version: 1.0.0
    Author: NamelessSaint
#>

#region ==================== SETUP ====================

# Import required modules
$scriptRoot = Split-Path -Parent $PSScriptRoot
$modulesPath = Join-Path $scriptRoot "Modules"

Import-Module (Join-Path $modulesPath "EntraChecks-Logging.psm1") -Force
Import-Module (Join-Path $modulesPath "EntraChecks-ErrorHandling.psm1") -Force

# Initialize logging
Initialize-LoggingSubsystem -LogDirectory ".\Logs" -MinimumLevel DEBUG

#endregion

#region ==================== EXAMPLE 1: Basic Retry ====================

Write-Host "`n=== Example 1: Basic Retry Logic ===" -ForegroundColor Cyan

# Simulate an operation that might fail
function Test-UnreliableOperation {
    param([int]$FailureRate = 60)

    $random = Get-Random -Minimum 0 -Maximum 100

    if ($random -lt $FailureRate) {
        throw "Simulated transient error (network timeout)"
    }

    return "Operation succeeded!"
}

# Use Invoke-WithRetry for automatic retry
try {
    $result = Invoke-WithRetry -ScriptBlock {
        Test-UnreliableOperation -FailureRate 40
    } -Operation "Unreliable Operation" -MaxRetries 5

    Write-Host "Result: $result" -ForegroundColor Green
}
catch {
    Write-Host "Failed after retries: $($_.Exception.Message)" -ForegroundColor Red
}

#endregion

#region ==================== EXAMPLE 2: Exponential Backoff ====================

Write-Host "`n=== Example 2: Exponential Backoff ===" -ForegroundColor Cyan

# Simulate rate-limited API
$script:callCount = 0

function Test-RateLimitedAPI {
    $script:callCount++

    if ($script:callCount -lt 3) {
        throw "HTTP 429 Too Many Requests - Rate limit exceeded"
    }

    return @{ Status = "Success"; CallNumber = $script:callCount }
}

# Use exponential backoff for rate-limited APIs
try {
    $result = Invoke-WithRetry -ScriptBlock {
        Test-RateLimitedAPI
    } -Operation "Rate Limited API" `
        -MaxRetries 5 `
        -ExponentialBackoff `
        -BaseDelaySeconds 2

    Write-Host "API call succeeded on attempt $($result.CallNumber)" -ForegroundColor Green
}
catch {
    Write-Host "API call failed: $($_.Exception.Message)" -ForegroundColor Red
}

#endregion

#region ==================== EXAMPLE 3: Circuit Breaker ====================

Write-Host "`n=== Example 3: Circuit Breaker Pattern ===" -ForegroundColor Cyan

# Create circuit breaker
New-CircuitBreaker -Name "TestAPI" -FailureThreshold 3 -TimeoutSeconds 10 | Out-Null

# Function that always fails initially
$script:apiCallNumber = 0

function Test-FailingAPI {
    $script:apiCallNumber++

    # Fail first 5 calls
    if ($script:apiCallNumber -le 5) {
        throw "Service temporarily unavailable (503)"
    }

    return "API call $script:apiCallNumber succeeded"
}

# Make multiple calls - circuit breaker will open after failures
for ($i = 1; $i -le 8; $i++) {
    Write-Host "`n--- API Call $i ---" -ForegroundColor Yellow

    try {
        $result = Invoke-WithRetry -ScriptBlock {
            Test-FailingAPI
        } -Operation "Failing API Call $i" `
            -MaxRetries 2 `
            -CircuitBreakerName "TestAPI"

        Write-Host "Success: $result" -ForegroundColor Green
    }
    catch {
        Write-Host "Failed: $($_.Exception.Message)" -ForegroundColor Red

        # Show circuit breaker state
        $cbState = Get-CircuitBreakerState -Name "TestAPI"
        Write-Host "Circuit Breaker State: $($cbState.State)" -ForegroundColor $(
            switch ($cbState.State) {
                "Closed" { "Green" }
                "Open" { "Red" }
                "HalfOpen" { "Yellow" }
            }
        )
    }

    Start-Sleep -Seconds 1
}

#endregion

#region ==================== EXAMPLE 4: Graph API with Retry ====================

Write-Host "`n=== Example 4: Graph API Calls with Retry ===" -ForegroundColor Cyan

# NOTE: This requires active Graph authentication
# Uncomment to test with real Graph API

<#
try {
    # Simple Graph request with retry
    $user = Invoke-GraphRequestWithRetry `
        -Uri "https://graph.microsoft.com/v1.0/me" `
        -MaxRetries 3

    Write-Host "Retrieved user: $($user.displayName)" -ForegroundColor Green
}
catch {
    Write-Host "Graph API call failed: $($_.Exception.Message)" -ForegroundColor Red
}

# Paginated request with retry
try {
    $allUsers = Get-AllGraphPages `
        -Uri "https://graph.microsoft.com/v1.0/users?`$top=100" `
        -MaxPages 5

    Write-Host "Retrieved $($allUsers.Count) users" -ForegroundColor Green
}
catch {
    Write-Host "Paginated request failed: $($_.Exception.Message)" -ForegroundColor Red
}
#>

Write-Host "(Graph API examples commented out - requires authentication)" -ForegroundColor Gray

#endregion

#region ==================== EXAMPLE 5: Custom Retryable Errors ====================

Write-Host "`n=== Example 5: Custom Retryable Error Patterns ===" -ForegroundColor Cyan

function Test-CustomError {
    param([int]$Attempt = 1)

    if ($Attempt -lt 3) {
        throw "Custom error: Database connection pool exhausted"
    }

    return "Operation succeeded after $Attempt attempts"
}

$attemptCount = 0

try {
    $result = Invoke-WithRetry -ScriptBlock {
        $attemptCount++
        Test-CustomError -Attempt $attemptCount
    } -Operation "Custom Error Handler" `
        -MaxRetries 5 `
        -RetryableErrorPatterns @('Database.*pool.*exhausted', 'Connection pool')

    Write-Host $result -ForegroundColor Green
}
catch {
    Write-Host "Failed: $($_.Exception.Message)" -ForegroundColor Red
}

#endregion

#region ==================== EXAMPLE 6: Non-Retryable Errors ====================

Write-Host "`n=== Example 6: Non-Retryable Errors ===" -ForegroundColor Cyan

function Test-NonRetryableError {
    throw "HTTP 400 Bad Request - Invalid parameter format"
}

try {
    $result = Invoke-WithRetry -ScriptBlock {
        Test-NonRetryableError
    } -Operation "Non-Retryable Error" -MaxRetries 3

    Write-Host $result -ForegroundColor Green
}
catch {
    Write-Host "Operation failed immediately (non-retryable): $($_.Exception.Message)" -ForegroundColor Red
}

#endregion

#region ==================== EXAMPLE 7: Error Categorization ====================

Write-Host "`n=== Example 7: Error Categorization ===" -ForegroundColor Cyan

$testErrors = @(
    "HTTP 429 Too Many Requests",
    "HTTP 401 Unauthorized - Invalid credentials",
    "HTTP 403 Forbidden - Insufficient privileges",
    "HTTP 404 Not Found",
    "HTTP 503 Service Unavailable",
    "AADSTS50076 - MFA required"
)

foreach ($errorMsg in $testErrors) {
    try {
        throw $errorMsg
    }
    catch {
        $category = Get-ErrorCategory -ErrorRecord $_
        $isRetryable = Test-RetryableError -ErrorRecord $_

        Write-Host "`nError: $errorMsg" -ForegroundColor Yellow
        Write-Host "  Category: $category" -ForegroundColor White
        Write-Host "  Retryable: $isRetryable" -ForegroundColor $(if ($isRetryable) { "Green" } else { "Red" })
    }
}

#endregion

#region ==================== EXAMPLE 8: Real-World Pattern ====================

Write-Host "`n=== Example 8: Real-World Usage Pattern ===" -ForegroundColor Cyan

function Get-UserDataWithRetry {
    <#
    .SYNOPSIS
        Example function showing real-world retry usage
    #>
    param(
        [Parameter(Mandatory)]
        [string]$UserId
    )

    Write-Log -Level INFO -Message "Fetching user data" -Category "UserManagement" -Properties @{
        UserId = $UserId
    }

    try {
        $userData = Invoke-WithRetry -ScriptBlock {
            # Simulate API call
            if ((Get-Random -Minimum 0 -Maximum 100) -lt 20) {
                throw "Network timeout - unable to connect"
            }

            return @{
                Id = $UserId
                Name = "John Doe"
                Email = "john.doe@contoso.com"
                Department = "IT"
            }
        } -Operation "Get User Data" `
            -MaxRetries 3 `
            -ExponentialBackoff `
            -CircuitBreakerName "UserAPI"

        Write-Log -Level INFO -Message "User data retrieved successfully" -Category "UserManagement" -Properties @{
            UserId = $UserId
            UserName = $userData.Name
        }

        return $userData
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to retrieve user data" -Category "UserManagement" -ErrorRecord $_ -Properties @{
            UserId = $UserId
        }

        throw
    }
}

# Use the function
try {
    $user = Get-UserDataWithRetry -UserId "user123"
    Write-Host "Retrieved user: $($user.Name) ($($user.Email))" -ForegroundColor Green
}
catch {
    Write-Host "Failed to get user data: $($_.Exception.Message)" -ForegroundColor Red
}

#endregion

#region ==================== CLEANUP ====================

Write-Host "`n=== Cleanup ===" -ForegroundColor Cyan

# Show circuit breaker states
Write-Host "`nCircuit Breaker States:" -ForegroundColor Yellow
foreach ($cbName in $script:CircuitBreakers.Keys) {
    $cb = $script:CircuitBreakers[$cbName]
    Write-Host "  $cbName`: $($cb.State) (Failures: $($cb.FailureCount))" -ForegroundColor White
}

# Stop logging
Stop-Logging

Write-Host "`nRetry logic examples complete!" -ForegroundColor Green
Write-Host "Check the .\Logs directory for detailed logs." -ForegroundColor Gray

#endregion
