<#
.SYNOPSIS
    Example-Configuration-Usage.ps1
    Demonstrates how to use the EntraChecks configuration management system

.DESCRIPTION
    This example script shows various ways to use the configuration functionality
    in EntraChecks, including loading, validating, and accessing configuration values.

.NOTES
    Version: 1.0.0
    Author: NamelessSaint
#>

#region ==================== SETUP ====================

# Import required modules
$scriptRoot = Split-Path -Parent $PSScriptRoot
$modulesPath = Join-Path $scriptRoot "Modules"

# Import logging module (optional but recommended)
$loggingModule = Join-Path $modulesPath "EntraChecks-Logging.psm1"
if (Test-Path $loggingModule) {
    Import-Module $loggingModule -Force
    Initialize-LoggingSubsystem -LogDirectory ".\Logs" -MinimumLevel INFO
}

# Import configuration module
$configModule = Join-Path $modulesPath "EntraChecks-Configuration.psm1"
Import-Module $configModule -Force

#endregion

#region ==================== EXAMPLE 1: Generate Configuration Template ====================

Write-Host "`n=== Example 1: Generate Configuration Template ===" -ForegroundColor Cyan

# Create a new configuration template
$templatePath = Join-Path $scriptRoot "config\example-generated-template.json"
New-ConfigurationTemplate -FilePath $templatePath -IncludeComments

Write-Host "Generated template at: $templatePath" -ForegroundColor Green

#endregion

#region ==================== EXAMPLE 2: Load and Validate Configuration ====================

Write-Host "`n=== Example 2: Load and Validate Configuration ===" -ForegroundColor Cyan

# Load configuration from file
$configPath = Join-Path $scriptRoot "config\entrachecks.config.json"
try {
    $config = Import-Configuration -FilePath $configPath
    Write-Host "Configuration loaded successfully!" -ForegroundColor Green
    Write-Host "  Scope: $($config.Assessment.Scope -join ', ')" -ForegroundColor Gray
    Write-Host "  Log Level: $($config.Logging.MinimumLevel)" -ForegroundColor Gray
}
catch {
    Write-Host "Failed to load configuration: $_" -ForegroundColor Red
}

#endregion

#region ==================== EXAMPLE 3: Validate Configuration Only ====================

Write-Host "`n=== Example 3: Validate Configuration Without Loading ===" -ForegroundColor Cyan

# Validate without loading
try {
    $config = Import-Configuration -FilePath $configPath -ValidateOnly
    Write-Host "Configuration is valid!" -ForegroundColor Green
}
catch {
    Write-Host "Configuration validation failed: $_" -ForegroundColor Red
}

#endregion

#region ==================== EXAMPLE 4: Environment-Specific Configuration ====================

Write-Host "`n=== Example 4: Load Environment-Specific Configuration ===" -ForegroundColor Cyan

# Load base configuration
Import-Configuration -FilePath $configPath | Out-Null

# Load with environment override (dev)
$devConfig = Import-Configuration -FilePath $configPath -Environment "dev"
Write-Host "Development Configuration:" -ForegroundColor Yellow
Write-Host "  Log Level: $($devConfig.Logging.MinimumLevel)" -ForegroundColor Gray
Write-Host "  Max Retries: $($devConfig.ErrorHandling.MaxRetries)" -ForegroundColor Gray
Write-Host "  Output Dir: $($devConfig.Assessment.Output.Directory)" -ForegroundColor Gray

# Load with environment override (prod)
$prodConfig = Import-Configuration -FilePath $configPath -Environment "prod"
Write-Host "`nProduction Configuration:" -ForegroundColor Yellow
Write-Host "  Log Level: $($prodConfig.Logging.MinimumLevel)" -ForegroundColor Gray
Write-Host "  Max Retries: $($prodConfig.ErrorHandling.MaxRetries)" -ForegroundColor Gray
Write-Host "  Output Dir: $($prodConfig.Assessment.Output.Directory)" -ForegroundColor Gray
Write-Host "  Auth Method: $($prodConfig.Authentication.Method)" -ForegroundColor Gray

#endregion

#region ==================== EXAMPLE 5: Access Configuration Values ====================

Write-Host "`n=== Example 5: Access Configuration Values ===" -ForegroundColor Cyan

# Load configuration
Import-Configuration -FilePath $configPath | Out-Null

# Get entire configuration
$fullConfig = Get-Configuration
Write-Host "Full configuration loaded: $($fullConfig -ne $null)" -ForegroundColor Green

# Get specific values using dot notation
$logLevel = Get-ConfigValue -Path "Logging.MinimumLevel" -DefaultValue "INFO"
$maxRetries = Get-ConfigValue -Path "ErrorHandling.MaxRetries" -DefaultValue 3
$scopes = Get-ConfigValue -Path "Assessment.Scope"

Write-Host "Retrieved values:" -ForegroundColor Yellow
Write-Host "  Log Level: $logLevel" -ForegroundColor Gray
Write-Host "  Max Retries: $maxRetries" -ForegroundColor Gray
Write-Host "  Scopes: $($scopes -join ', ')" -ForegroundColor Gray

# Access nested values
$cbEnabled = Get-ConfigValue -Path "ErrorHandling.CircuitBreaker.Enabled" -DefaultValue $false
$cbThreshold = Get-ConfigValue -Path "ErrorHandling.CircuitBreaker.FailureThreshold" -DefaultValue 5

Write-Host "`nCircuit Breaker Configuration:" -ForegroundColor Yellow
Write-Host "  Enabled: $cbEnabled" -ForegroundColor Gray
Write-Host "  Failure Threshold: $cbThreshold" -ForegroundColor Gray

# Try to access non-existent path (returns default)
$nonExistent = Get-ConfigValue -Path "NonExistent.Path" -DefaultValue "DEFAULT_VALUE"
Write-Host "`nNon-existent path (returns default): $nonExistent" -ForegroundColor Gray

#endregion

#region ==================== EXAMPLE 6: Manual Configuration Validation ====================

Write-Host "`n=== Example 6: Manual Configuration Validation ===" -ForegroundColor Cyan

# Create a test configuration object
$testConfig = @{
    Version = "1.0.0"
    Assessment = @{
        Scope = @("Core", "Compliance")
        Output = @{
            Directory = ".\Output"
            Formats = @("HTML", "CSV")
        }
    }
    Logging = @{
        Directory = ".\Logs"
        MinimumLevel = "INFO"
    }
    ErrorHandling = @{
        MaxRetries = 3
    }
}

# Validate the configuration
$validation = Test-Configuration -ConfigObject $testConfig

Write-Host "Validation Result:" -ForegroundColor Yellow
Write-Host "  Is Valid: $($validation.IsValid)" -ForegroundColor $(if ($validation.IsValid) { "Green" } else { "Red" })

if ($validation.Errors.Count -gt 0) {
    Write-Host "`n  Errors:" -ForegroundColor Red
    $validation.Errors | ForEach-Object {
        Write-Host "    - $_" -ForegroundColor Red
    }
}

if ($validation.Warnings.Count -gt 0) {
    Write-Host "`n  Warnings:" -ForegroundColor Yellow
    $validation.Warnings | ForEach-Object {
        Write-Host "    - $_" -ForegroundColor Yellow
    }
}

#endregion

#region ==================== EXAMPLE 7: Invalid Configuration Handling ====================

Write-Host "`n=== Example 7: Handle Invalid Configuration ===" -ForegroundColor Cyan

# Create an invalid configuration
$invalidConfig = @{
    Version = "1.0.0"
    Assessment = @{
        Scope = @("InvalidScope")  # Invalid scope
        Output = @{
            Directory = ".\Output"
            Formats = @("INVALID_FORMAT")  # Invalid format
        }
    }
    Logging = @{
        Directory = ".\Logs"
        MinimumLevel = "INVALID_LEVEL"  # Invalid log level
    }
    ErrorHandling = @{
        MaxRetries = 999  # Out of range
    }
}

# Validate
$validation = Test-Configuration -ConfigObject $invalidConfig

Write-Host "Validation Result: $($validation.IsValid)" -ForegroundColor Red
Write-Host "`nErrors found:" -ForegroundColor Red
$validation.Errors | ForEach-Object {
    Write-Host "  - $_" -ForegroundColor Red
}

#endregion

#region ==================== EXAMPLE 8: Export Configuration ====================

Write-Host "`n=== Example 8: Export Configuration ===" -ForegroundColor Cyan

# Load configuration
Import-Configuration -FilePath $configPath | Out-Null

# Export to a new file
$exportPath = Join-Path $scriptRoot "config\exported-config.json"
Export-Configuration -FilePath $exportPath

Write-Host "Configuration exported to: $exportPath" -ForegroundColor Green

#endregion

#region ==================== EXAMPLE 9: Environment Variable Substitution ====================

Write-Host "`n=== Example 9: Environment Variable Substitution ===" -ForegroundColor Cyan

# Create a config with environment variables
$envConfig = @{
    Version = "1.0.0"
    Assessment = @{
        Scope = @("Core")
        Output = @{
            Directory = '${ENV:TEMP}\EntraChecks\Output'  # Uses TEMP environment variable
            Formats = @("HTML")
        }
    }
    Logging = @{
        Directory = '${ENV:TEMP}\EntraChecks\Logs'
        MinimumLevel = '${ENV:LOG_LEVEL:INFO}'  # Uses LOG_LEVEL or defaults to INFO
    }
    ErrorHandling = @{
        MaxRetries = 3
    }
}

# Save to temp file
$tempConfigPath = Join-Path $env:TEMP "test-env-config.json"
$envConfig | ConvertTo-Json -Depth 10 | Out-File -FilePath $tempConfigPath -Encoding UTF8

# Load and see expanded values
$expandedConfig = Import-Configuration -FilePath $tempConfigPath

Write-Host "Environment variable expansion:" -ForegroundColor Yellow
Write-Host "  Output Directory: $($expandedConfig.Assessment.Output.Directory)" -ForegroundColor Gray
Write-Host "  Logging Directory: $($expandedConfig.Logging.Directory)" -ForegroundColor Gray
Write-Host "  Log Level: $($expandedConfig.Logging.MinimumLevel)" -ForegroundColor Gray

# Cleanup
Remove-Item $tempConfigPath -Force -ErrorAction SilentlyContinue

#endregion

#region ==================== EXAMPLE 10: Get Configuration Schema ====================

Write-Host "`n=== Example 10: View Configuration Schema ===" -ForegroundColor Cyan

$schema = Get-ConfigurationSchema

Write-Host "Configuration Schema Information:" -ForegroundColor Yellow
Write-Host "  Title: $($schema.title)" -ForegroundColor Gray
Write-Host "  Version: $($schema.version)" -ForegroundColor Gray
Write-Host "  Required Sections: $($schema.required -join ', ')" -ForegroundColor Gray

Write-Host "`nValid Assessment Scopes:" -ForegroundColor Yellow
$validScopes = $schema.properties.Assessment.properties.Scope.items.enum
$validScopes | ForEach-Object {
    Write-Host "  - $_" -ForegroundColor Gray
}

Write-Host "`nValid Log Levels:" -ForegroundColor Yellow
$validLevels = $schema.properties.Logging.properties.MinimumLevel.enum
$validLevels | ForEach-Object {
    Write-Host "  - $_" -ForegroundColor Gray
}

#endregion

#region ==================== EXAMPLE 11: Using Configuration in Functions ====================

Write-Host "`n=== Example 11: Using Configuration in Functions ===" -ForegroundColor Cyan

function Start-EntraAssessment {
    param()

    # Load configuration
    Import-Configuration -FilePath $configPath | Out-Null

    # Get configuration values
    $scope = Get-ConfigValue -Path "Assessment.Scope"
    $outputDir = Get-ConfigValue -Path "Assessment.Output.Directory"
    $maxRetries = Get-ConfigValue -Path "ErrorHandling.MaxRetries" -DefaultValue 3

    Write-Host "Starting assessment with configuration:" -ForegroundColor Yellow
    Write-Host "  Scope: $($scope -join ', ')" -ForegroundColor Gray
    Write-Host "  Output: $outputDir" -ForegroundColor Gray
    Write-Host "  Max Retries: $maxRetries" -ForegroundColor Gray

    # Simulate assessment
    Write-Host "  [Simulated] Running Core module..." -ForegroundColor Gray
    Write-Host "  [Simulated] Running Compliance module..." -ForegroundColor Gray
    Write-Host "Assessment complete!" -ForegroundColor Green
}

# Run the function
Start-EntraAssessment

#endregion

#region ==================== CLEANUP ====================

Write-Host "`n=== Cleanup ===" -ForegroundColor Cyan

# Stop logging if it was initialized
if (Get-Command Stop-Logging -ErrorAction SilentlyContinue) {
    Stop-Logging
}

Write-Host "`nConfiguration examples complete!" -ForegroundColor Green
Write-Host "Check the config\ directory for generated files." -ForegroundColor Gray

#endregion
