<#
.SYNOPSIS
    Example-Logging-Usage.ps1
    Demonstrates how to use the EntraChecks logging subsystem

.DESCRIPTION
    This example script shows various ways to use the logging functionality
    in EntraChecks, including standard logging, audit logging, and log configuration.

.NOTES
    Version: 1.0.0
    Author: NamelessSaint
#>

#region ==================== SETUP ====================

# Import logging module
$scriptRoot = Split-Path -Parent $PSScriptRoot
$modulesPath = Join-Path $scriptRoot "Modules"
$loggingModule = Join-Path $modulesPath "EntraChecks-Logging.psm1"

Import-Module $loggingModule -Force

#endregion

#region ==================== EXAMPLE 1: Basic Logging ====================

Write-Host "`n=== Example 1: Basic Logging ===" -ForegroundColor Cyan

# Initialize logging with default settings
Initialize-LoggingSubsystem -LogDirectory ".\Logs" -MinimumLevel INFO

# Write different log levels
Write-Log -Level INFO -Message "This is an informational message" -Category "Example"
Write-Log -Level WARN -Message "This is a warning message" -Category "Example"
Write-Log -Level ERROR -Message "This is an error message" -Category "Example"

# Log with custom properties
Write-Log -Level INFO -Message "User login detected" -Category "Security" -Properties @{
    Username = "john.doe@contoso.com"
    IPAddress = "192.168.1.100"
    Location = "New York"
}

#endregion

#region ==================== EXAMPLE 2: Audit Logging ====================

Write-Host "`n=== Example 2: Audit Logging ===" -ForegroundColor Cyan

# Log audit events for compliance
Write-AuditLog -EventType "AuthenticationSuccess" `
    -Description "User authenticated successfully" `
    -TargetObject "admin@contoso.com" `
    -Result "Success"

Write-AuditLog -EventType "ConfigurationChanged" `
    -Description "Log level changed to DEBUG" `
    -Details @{
    OldValue = "INFO"
    NewValue = "DEBUG"
    ChangedBy = $env:USERNAME
} `
    -Result "Success"

Write-AuditLog -EventType "FindingDetected" `
    -Description "Insecure configuration detected" `
    -TargetObject "Conditional Access Policy" `
    -Details @{
    PolicyName = "Block Legacy Auth"
    Issue = "Policy is disabled"
    Severity = "High"
} `
    -Result "Warning"

#endregion

#region ==================== EXAMPLE 3: Error Logging ====================

Write-Host "`n=== Example 3: Error Logging with ErrorRecord ===" -ForegroundColor Cyan

try {
    # Simulate an error
    throw "Simulated error for demonstration"
}
catch {
    # Log the error with full ErrorRecord
    Write-Log -Level ERROR `
        -Message "An error occurred during processing" `
        -Category "ErrorHandling" `
        -ErrorRecord $_
}

#endregion

#region ==================== EXAMPLE 4: Dynamic Log Level ====================

Write-Host "`n=== Example 4: Changing Log Level ===" -ForegroundColor Cyan

# Initial log level is INFO (set during initialization)
Write-Log -Level DEBUG -Message "This DEBUG message will NOT appear (below INFO)" -Category "Example"
Write-Log -Level INFO -Message "This INFO message WILL appear" -Category "Example"

# Change log level to DEBUG
Set-LogLevel -Level DEBUG
Write-Host "Log level changed to DEBUG" -ForegroundColor Yellow

# Now DEBUG messages will appear
Write-Log -Level DEBUG -Message "This DEBUG message WILL now appear" -Category "Example"
Write-Log -Level INFO -Message "This INFO message still appears" -Category "Example"

#endregion

#region ==================== EXAMPLE 5: Structured Logging ====================

Write-Host "`n=== Example 5: Structured Logging (JSON) ===" -ForegroundColor Cyan

# Re-initialize with structured logging enabled
Stop-Logging
Initialize-LoggingSubsystem -LogDirectory ".\Logs" -MinimumLevel INFO -StructuredLogging

Write-Log -Level INFO -Message "Structured log entry" -Category "Example" -Properties @{
    Operation = "Assessment"
    TenantId = "12345678-1234-1234-1234-123456789012"
    TenantName = "Contoso"
    Duration = 45.2
    FindingsCount = 127
}

#endregion

#region ==================== EXAMPLE 6: Getting Log Information ====================

Write-Host "`n=== Example 6: Getting Log Information ===" -ForegroundColor Cyan

# Get current log file path
$logFile = Get-LogFilePath
Write-Host "Current log file: $logFile" -ForegroundColor Green

# Get audit log file path
$auditFile = Get-AuditLogFilePath
Write-Host "Current audit log file: $auditFile" -ForegroundColor Green

# Get logging configuration
$config = Get-LoggingConfiguration
Write-Host "`nLogging Configuration:" -ForegroundColor Yellow
Write-Host "  Log Directory: $($config.Directory)" -ForegroundColor Gray
Write-Host "  Minimum Level: $($config.MinLevel)" -ForegroundColor Gray
Write-Host "  Targets: $($config.Targets -join ', ')" -ForegroundColor Gray
Write-Host "  Structured: $($config.Structured)" -ForegroundColor Gray
Write-Host "  Session ID: $($config.SessionId)" -ForegroundColor Gray

#endregion

#region ==================== EXAMPLE 7: Custom Category Logging ====================

Write-Host "`n=== Example 7: Category-Based Logging ===" -ForegroundColor Cyan

# Log different operational categories
Write-Log -Level INFO -Message "Connecting to Microsoft Graph API" -Category "API"
Write-Log -Level INFO -Message "Analyzing Conditional Access policies" -Category "Analysis"
Write-Log -Level INFO -Message "Generating HTML report" -Category "Reporting"
Write-Log -Level INFO -Message "Exporting data to CSV" -Category "Export"
Write-Log -Level INFO -Message "Cleaning up temporary files" -Category "Cleanup"

#endregion

#region ==================== EXAMPLE 8: Logging in Try/Catch Blocks ====================

Write-Host "`n=== Example 8: Logging in Error Handling ===" -ForegroundColor Cyan

function Test-ApiCall {
    param([string]$Endpoint)

    Write-Log -Level INFO -Message "Making API call" -Category "API" -Properties @{
        Endpoint = $Endpoint
    }

    try {
        # Simulate API call
        if ($Endpoint -eq "/error") {
            throw "API returned 500 Internal Server Error"
        }

        Write-Log -Level INFO -Message "API call successful" -Category "API" -Properties @{
            Endpoint = $Endpoint
            StatusCode = 200
        }

        return $true
    }
    catch {
        Write-Log -Level ERROR -Message "API call failed" -Category "API" -ErrorRecord $_ -Properties @{
            Endpoint = $Endpoint
        }

        return $false
    }
}

# Test successful call
Test-ApiCall -Endpoint "/users"

# Test failed call
Test-ApiCall -Endpoint "/error"

#endregion

#region ==================== CLEANUP ====================

Write-Host "`n=== Cleaning Up ===" -ForegroundColor Cyan

# Flush any buffered logs and close log files
Stop-Logging

Write-Host "`nLogging examples complete!" -ForegroundColor Green
Write-Host "Check the .\Logs directory for generated log files." -ForegroundColor Gray

#endregion
