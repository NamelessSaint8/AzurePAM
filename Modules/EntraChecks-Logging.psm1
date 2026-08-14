<#
.SYNOPSIS
    EntraChecks-Logging.psm1
    Centralized logging subsystem for EntraChecks

.DESCRIPTION
    Provides structured logging capabilities with multiple output targets,
    log levels, rotation, and audit trail functionality.

.NOTES
    Version: 1.0.0
    Author: NamelessSaint
#>

#region ==================== MODULE VARIABLES ====================

$script:LogConfig = @{
    Initialized = $false
    Targets = @('File', 'Console')
    MinLevel = 'INFO'
    Directory = $null
    RetentionDays = 90
    Structured = $true
    SessionId = [guid]::NewGuid().ToString()
    StartTime = Get-Date
    CurrentLogFile = $null
    AuditLogFile = $null
    MaxFileSizeMB = 100
    BufferSize = 100
    Buffer = [System.Collections.Generic.List[object]]::new()
}

$script:LogLevels = @{
    DEBUG = 0
    INFO = 1
    WARN = 2
    ERROR = 3
    CRITICAL = 4
}

#endregion

#region ==================== INITIALIZATION ====================

function Initialize-LoggingSubsystem {
    <#
    .SYNOPSIS
        Initialize the logging subsystem with configuration

    .PARAMETER LogDirectory
        Directory where log files will be written

    .PARAMETER MinimumLevel
        Minimum log level to capture (DEBUG, INFO, WARN, ERROR, CRITICAL)

    .PARAMETER Targets
        Output targets for logs (File, Console, EventLog)

    .PARAMETER RetentionDays
        Number of days to retain log files

    .PARAMETER StructuredLogging
        Enable structured JSON logging

    .PARAMETER MaxFileSizeMB
        Maximum size of a single log file before rotation
    #>
    [OutputType([bool])]
    [CmdletBinding()]
    param(
        [string]$LogDirectory = ".\Logs",

        [ValidateSet('DEBUG', 'INFO', 'WARN', 'ERROR', 'CRITICAL')]
        [string]$MinimumLevel = 'INFO',

        [ValidateSet('File', 'Console', 'EventLog')]
        [string[]]$Targets = @('File', 'Console'),

        [int]$RetentionDays = 90,

        [switch]$StructuredLogging,

        [int]$MaxFileSizeMB = 100
    )

    try {
        # Update configuration
        $script:LogConfig.Directory = $LogDirectory
        $script:LogConfig.MinLevel = $MinimumLevel
        $script:LogConfig.Targets = $Targets
        $script:LogConfig.RetentionDays = $RetentionDays
        $script:LogConfig.Structured = $StructuredLogging.IsPresent
        $script:LogConfig.MaxFileSizeMB = $MaxFileSizeMB
        $script:LogConfig.SessionId = [guid]::NewGuid().ToString()
        $script:LogConfig.StartTime = Get-Date

        # Create log directory
        if ($Targets -contains 'File') {
            if (-not (Test-Path $LogDirectory)) {
                New-Item -Path $LogDirectory -ItemType Directory -Force | Out-Null
            }

            # Set log file paths
            $timestamp = Get-Date -Format "yyyyMMdd"
            $script:LogConfig.CurrentLogFile = Join-Path $LogDirectory "entrachecks-$timestamp.log"
            $script:LogConfig.AuditLogFile = Join-Path $LogDirectory "audit-$timestamp.json"

            # Initialize log rotation
            Start-LogRotation -Directory $LogDirectory -RetentionDays $RetentionDays
        }

        # Create EventLog source if needed
        if ($Targets -contains 'EventLog') {
            Initialize-EventLogSource
        }

        $script:LogConfig.Initialized = $true

        Write-Log -Level INFO -Message "Logging subsystem initialized" -Category "System" -Properties @{
            LogDirectory = $LogDirectory
            MinLevel = $MinimumLevel
            Targets = ($Targets -join ', ')
            SessionId = $script:LogConfig.SessionId
        }

        return $true
    }
    catch {
        Write-Warning "Failed to initialize logging subsystem: $($_.Exception.Message)"
        # Fallback to console-only logging
        $script:LogConfig.Targets = @('Console')
        $script:LogConfig.Initialized = $true
        return $false
    }
}

function Start-LogRotation {
    [CmdletBinding()]
    param(
        [string]$Directory,
        [int]$RetentionDays
    )

    try {
        $cutoffDate = (Get-Date).AddDays(-$RetentionDays)

        Get-ChildItem -Path $Directory -Filter "*.log" -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -lt $cutoffDate } |
            ForEach-Object {
                Write-Verbose "Removing old log file: $($_.Name)"
                Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
            }

        Get-ChildItem -Path $Directory -Filter "audit-*.json" -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -lt $cutoffDate } |
            ForEach-Object {
                Write-Verbose "Removing old audit file: $($_.Name)"
                Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
            }
    }
    catch {
        Write-Warning "Log rotation failed: $($_.Exception.Message)"
    }
}

function Initialize-EventLogSource {
    [CmdletBinding()]
    param()

    try {
        $sourceName = "EntraChecks"
        $logName = "Application"

        if (-not [System.Diagnostics.EventLog]::SourceExists($sourceName)) {
            # Requires admin privileges
            New-EventLog -LogName $logName -Source $sourceName -ErrorAction Stop
            Write-Verbose "EventLog source '$sourceName' created"
        }
    }
    catch {
        Write-Warning "Failed to create EventLog source (requires admin): $($_.Exception.Message)"
        # Remove EventLog from targets if initialization fails
        $script:LogConfig.Targets = $script:LogConfig.Targets | Where-Object { $_ -ne 'EventLog' }
    }
}

#endregion

#region ==================== CORE LOGGING ====================

function Write-Log {
    <#
    .SYNOPSIS
        Write a log entry to configured targets

    .PARAMETER Level
        Log level (DEBUG, INFO, WARN, ERROR, CRITICAL)

    .PARAMETER Message
        Log message

    .PARAMETER Category
        Log category for filtering

    .PARAMETER Properties
        Additional properties to include

    .PARAMETER ErrorRecord
        ErrorRecord object for error logging

    .PARAMETER NoConsole
        Suppress console output
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('DEBUG', 'INFO', 'WARN', 'ERROR', 'CRITICAL')]
        [string]$Level,

        [Parameter(Mandatory)]
        [string]$Message,

        [string]$Category = "General",

        [hashtable]$Properties = @{},

        [System.Management.Automation.ErrorRecord]$ErrorRecord,

        [switch]$NoConsole
    )

    # Initialize if not already done
    if (-not $script:LogConfig.Initialized) {
        Initialize-LoggingSubsystem -LogDirectory ".\Logs" | Out-Null
    }

    # Check minimum level
    if ($script:LogLevels[$Level] -lt $script:LogLevels[$script:LogConfig.MinLevel]) {
        return
    }

    # Create log entry
    $logEntry = @{
        Timestamp = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        Level = $Level
        Category = $Category
        Message = $Message
        SessionId = $script:LogConfig.SessionId
        ProcessId = $PID
        ThreadId = [System.Threading.Thread]::CurrentThread.ManagedThreadId
        User = $env:USERNAME
        Computer = $env:COMPUTERNAME
    }

    # Add custom properties
    foreach ($key in $Properties.Keys) {
        $logEntry[$key] = $Properties[$key]
    }

    # Add error details if provided
    if ($ErrorRecord) {
        $logEntry.ErrorType = $ErrorRecord.Exception.GetType().FullName
        $logEntry.ErrorMessage = $ErrorRecord.Exception.Message
        $logEntry.ErrorStackTrace = $ErrorRecord.ScriptStackTrace
        $logEntry.ErrorLine = $ErrorRecord.InvocationInfo.ScriptLineNumber
        $logEntry.ErrorFile = $ErrorRecord.InvocationInfo.ScriptName
    }

    # Write to targets
    foreach ($target in $script:LogConfig.Targets) {
        switch ($target) {
            'File' { Write-LogToFile -Entry $logEntry }
            'Console' { if (-not $NoConsole) { Write-LogToConsole -Entry $logEntry } }
            'EventLog' { Write-LogToEventLog -Entry $logEntry }
        }
    }
}

function Write-LogToFile {
    [CmdletBinding()]
    param([hashtable]$Entry)

    try {
        # Check file size and rotate if needed
        if ((Test-Path $script:LogConfig.CurrentLogFile)) {
            $fileSize = (Get-Item $script:LogConfig.CurrentLogFile).Length / 1MB
            if ($fileSize -gt $script:LogConfig.MaxFileSizeMB) {
                $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
                $archivePath = $script:LogConfig.CurrentLogFile -replace '\.log$', "-$timestamp.log"
                Move-Item -Path $script:LogConfig.CurrentLogFile -Destination $archivePath -Force
            }
        }

        if ($script:LogConfig.Structured) {
            # JSON structured logging
            $logLine = $Entry | ConvertTo-Json -Compress
        }
        else {
            # Traditional text logging
            $logLine = "[$($Entry.Timestamp)] [$($Entry.Level)] [$($Entry.Category)] $($Entry.Message)"

            if ($Entry.ErrorMessage) {
                $logLine += " | Error: $($Entry.ErrorMessage)"
            }

            if ($Entry.Count -gt 8) {
                $extraProps = $Entry.Keys | Where-Object { $_ -notin @('Timestamp', 'Level', 'Category', 'Message', 'SessionId', 'ProcessId', 'User', 'Computer') }
                if ($extraProps) {
                    $propStr = ($extraProps | ForEach-Object { "$_=$($Entry[$_])" }) -join ', '
                    $logLine += " | $propStr"
                }
            }
        }

        # Buffer writes for performance
        $script:LogConfig.Buffer.Add($logLine)

        if ($script:LogConfig.Buffer.Count -ge $script:LogConfig.BufferSize) {
            Clear-LogBuffer
        }
    }
    catch {
        Write-Warning "Failed to write to log file: $($_.Exception.Message)"
    }
}

function Clear-LogBuffer {
    <#
    .SYNOPSIS
        Flushes the in-memory log buffer to the configured log targets.
    #>
    [CmdletBinding()]
    param()

    if ($script:LogConfig.Buffer.Count -eq 0) {
        return
    }

    try {
        $script:LogConfig.Buffer | Add-Content -Path $script:LogConfig.CurrentLogFile -ErrorAction Stop
        $script:LogConfig.Buffer.Clear()
    }
    catch {
        Write-Warning "Failed to flush log buffer: $($_.Exception.Message)"
    }
}

function Write-LogToConsole {
    [CmdletBinding()]
    param([hashtable]$Entry)

    $color = switch ($Entry.Level) {
        'DEBUG' { 'Gray' }
        'INFO' { 'White' }
        'WARN' { 'Yellow' }
        'ERROR' { 'Red' }
        'CRITICAL' { 'Magenta' }
    }

    $timestamp = ([DateTime]$Entry.Timestamp).ToString("HH:mm:ss")
    $consoleMessage = "[$timestamp] [$($Entry.Level)] $($Entry.Message)"

    Write-Host $consoleMessage -ForegroundColor $color
}

function Write-LogToEventLog {
    [CmdletBinding()]
    param([hashtable]$Entry)

    try {
        $eventType = switch ($Entry.Level) {
            'DEBUG' { 'Information' }
            'INFO' { 'Information' }
            'WARN' { 'Warning' }
            'ERROR' { 'Error' }
            'CRITICAL' { 'Error' }
        }

        $eventId = switch ($Entry.Level) {
            'DEBUG' { 1000 }
            'INFO' { 1001 }
            'WARN' { 2000 }
            'ERROR' { 3000 }
            'CRITICAL' { 3001 }
        }

        $message = "Category: $($Entry.Category)`n$($Entry.Message)"

        Write-EventLog -LogName Application -Source "EntraChecks" -EntryType $eventType `
            -EventId $eventId -Message $message -ErrorAction SilentlyContinue
    }
    catch {
        Write-Warning "Failed to write to EventLog: $($_.Exception.Message)"
    }
}

#endregion

#region ==================== AUDIT LOGGING ====================

function Write-AuditLog {
    <#
    .SYNOPSIS
        Write an audit log entry for compliance tracking

    .PARAMETER EventType
        Type of audit event

    .PARAMETER Description
        Description of the audited action

    .PARAMETER Details
        Additional details as hashtable

    .PARAMETER TargetObject
        Object that was targeted by the action

    .PARAMETER Result
        Result of the action (Success, Failure)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('AuthenticationSuccess', 'AuthenticationFailure', 'CheckExecuted',
            'FindingDetected', 'ReportGenerated', 'ConfigurationChanged',
            'DataExported', 'SnapshotCreated', 'ComparisonPerformed',
            'ModuleLoaded', 'SessionStarted', 'SessionEnded')]
        [string]$EventType,

        [Parameter(Mandatory)]
        [string]$Description,

        [hashtable]$Details = @{},

        [string]$TargetObject,

        [ValidateSet('Success', 'Failure', 'Warning')]
        [string]$Result = "Success"
    )

    if (-not $script:LogConfig.Initialized) {
        Initialize-LoggingSubsystem | Out-Null
    }

    $auditEntry = [ordered]@{
        Timestamp = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        EventType = $EventType
        Description = $Description
        Result = $Result
        SessionId = $script:LogConfig.SessionId
        User = $env:USERNAME
        Computer = $env:COMPUTERNAME
        ProcessId = $PID
        TargetObject = $TargetObject
        Details = $Details
    }

    try {
        # Write to audit log file (always JSON format)
        if ($script:LogConfig.Targets -contains 'File' -and $script:LogConfig.AuditLogFile) {
            $auditEntry | ConvertTo-Json -Depth 10 -Compress | Add-Content -Path $script:LogConfig.AuditLogFile
        }

        # Also write to regular log
        Write-Log -Level INFO -Message "Audit: $Description" -Category "Audit" -Properties $Details -NoConsole
    }
    catch {
        Write-Warning "Failed to write audit log: $($_.Exception.Message)"
    }
}

#endregion

#region ==================== HELPER FUNCTIONS ====================

function Get-LogFilePath {
    <#
    .SYNOPSIS
        Get the current log file path
    #>
    [CmdletBinding()]
    param()

    return $script:LogConfig.CurrentLogFile
}

function Get-AuditLogFilePath {
    <#
    .SYNOPSIS
        Get the current audit log file path
    #>
    [CmdletBinding()]
    param()

    return $script:LogConfig.AuditLogFile
}

function Get-LoggingConfiguration {
    <#
    .SYNOPSIS
        Get current logging configuration
    #>
    [CmdletBinding()]
    param()

    return $script:LogConfig.Clone()
}

function Set-LogLevel {
    <#
    .SYNOPSIS
        Change the minimum log level
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('DEBUG', 'INFO', 'WARN', 'ERROR', 'CRITICAL')]
        [string]$Level
    )

    $script:LogConfig.MinLevel = $Level
    Write-Log -Level INFO -Message "Log level changed to $Level" -Category "Configuration"
}

function Stop-Logging {
    <#
    .SYNOPSIS
        Stop logging and flush buffers
    #>
    [CmdletBinding()]
    param()

    Write-Log -Level INFO -Message "Logging subsystem shutting down" -Category "System"

    # Flush any buffered logs
    Clear-LogBuffer

    # Write session summary
    $duration = (Get-Date) - $script:LogConfig.StartTime
    Write-AuditLog -EventType "SessionEnded" -Description "Session ended" -Details @{
        Duration = $duration.ToString()
        SessionId = $script:LogConfig.SessionId
    }

    $script:LogConfig.Initialized = $false
}

#endregion

#region ==================== EXPORTS ====================

Export-ModuleMember -Function @(
    'Initialize-LoggingSubsystem',
    'Write-Log',
    'Write-AuditLog',
    'Get-LogFilePath',
    'Get-AuditLogFilePath',
    'Get-LoggingConfiguration',
    'Set-LogLevel',
    'Stop-Logging',
    'Clear-LogBuffer'
)

#endregion
