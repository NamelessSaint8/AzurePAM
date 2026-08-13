<#
.SYNOPSIS
    Browser sign-in -> device-code fallback, and honest auth error
    reporting/classification.

.DESCRIPTION
    Microsoft.Graph.Authentication 2.37 ships Azure.Identity 1.18.x, which
    throws "A window handle must be configured" when the WAM broker is
    present and the host has no parent window handle (the desktop app
    spawns PowerShell with CREATE_NO_WINDOW). Browser sign-in then died in
    ~4 seconds with no browser and no code, and the Auth phase reported the
    generic "no Graph context" message classified as
    auth.insufficientPrivileges — a misdirecting "sign in as Global Reader"
    remediation for what is a host limitation.

    These tests pin:
      * a broker/window-handle failure retries device code exactly once;
      * an unrelated auth failure does NOT, and still returns $false;
      * neither do broker-RELAYED failures (consent / MFA) whose text names
        WAM but which are not host limitations;
      * the fallback's success path yields a context and the run proceeds;
      * the underlying error text reaches the auth.failed event and a
        broker failure is not classified as auth.insufficientPrivileges,
        while a genuine privileges failure still is;
      * a failed fallback classifies on the DEVICE-CODE cause and never
        advises re-running with device code;
      * the automatic fallback's wait is capped, while the direct
        device-code path keeps the full window.

    Mocked at the boundary (Connect-MgGraph / Connect-EcfMgGraphDeviceCode)
    — no network and no tenant required.

    Run: Invoke-Pester -Path Tests/Auth-BrokerFallback.Tests.ps1
#>

#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeAll {
    if (-not $env:TEMP) {
        $env:TEMP = if ($env:TMPDIR) { $env:TMPDIR.TrimEnd('/') } else { '/tmp' }
    }
    $repoRoot = Split-Path -Parent $PSScriptRoot
    . (Join-Path $PSScriptRoot 'Helpers/Stub-CloudCmdlets.ps1')
    Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-Runner.psm1') -Force

    # Dot-source the orchestration include so Connect-EntraCheck /
    # Invoke-EcfAssessmentSequence are defined here — mockable, callable —
    # without running Start-EntraChecks.ps1's setup or dispatch.
    $script:OrchPath = Join-Path $repoRoot 'EntraChecks.Orchestration.ps1'
    . $script:OrchPath

    # Substrate the auth path reads from script scope. The logging module
    # is not imported (it writes files); Connect-EntraCheck's logging calls
    # are satisfied by no-op stubs.
    $script:AllGraphScopes = @('Directory.Read.All', 'Policy.Read.All')

    function script:Write-Log {
        param(
            [string]$Level,
            [string]$Message,
            [string]$Category,
            [hashtable]$Properties,
            $ErrorRecord,
            [switch]$NoConsole
        )
    }
    function script:Write-AuditLog {
        param(
            [string]$EventType,
            [string]$Description,
            [string]$TargetObject,
            [string]$Result
        )
    }

    # Real exception texts, verbatim from the reproduced failure.
    $script:BrokerError = 'InteractiveBrowserCredential authentication failed: A window handle must be configured. See https://aka.ms/msal-net-wam#parent-window-handles'
    $script:BadCredsError = 'AADSTS50126: Error validating credentials due to invalid username or password.'

    # Errors the WAM broker RELAYS. They name WAM / the broker but are not
    # host limitations, and the affected host emits them wrapped in the same
    # InteractiveBrowserCredential prefix as the window-handle failure.
    # Matching the bare words 'wam' / 'broker' fired a pointless device-code
    # retry here and re-labelled the consent failure as auth.failed.
    $script:WamConsentError = 'InteractiveBrowserCredential authentication failed: WAM Error: AADSTS65001: The user or administrator has not consented to use the application. Send an interactive authorization request for this user and resource.'
    $script:WamMfaError = 'InteractiveBrowserCredential authentication failed: WAM broker error 0xcaa2000c: AADSTS50076: Due to a configuration change made by your administrator, you must use multi-factor authentication to access this resource.'

    # Substrate Invoke-EcfAssessmentSequence reads via dynamic scope.
    # Referenced explicitly so static analysis sees the cross-dot-source use.
    $GenerateComprehensiveReport = $false
    $GenerateExecutiveSummary = $false
    $GenerateExcelReport = $false
    $GenerateRemediationScripts = $false
    $HtmlReportSet = 'Cockpit'
    $HtmlDeepDiveDomains = @()
    $null = $GenerateComprehensiveReport, $GenerateExecutiveSummary,
    $GenerateExcelReport, $GenerateRemediationScripts, $HtmlReportSet, $HtmlDeepDiveDomains
}

Describe 'Connect-EntraCheck — device-code fallback when the WAM broker has no window handle' {

    BeforeEach {
        $script:Signed = $false
        Mock Get-EcfMgContextSafe { if ($script:Signed) { [pscustomobject]@{ Account = 'auditor@contoso.com'; TenantId = 't-1'; Scopes = $script:AllGraphScopes } } else { $null } }
        Mock Connect-EcfMgGraphDeviceCode {
            $script:Signed = $true
            [pscustomobject]@{ Account = 'auditor@contoso.com'; TenantId = 't-1'; Scopes = $script:AllGraphScopes }
        }
    }

    It 'retries device code exactly once when the browser attempt hits the broker window-handle error' {
        Mock Connect-MgGraph { throw $script:BrokerError }

        Connect-EntraCheck -GraphOnly | Should -BeTrue
        Should -Invoke Connect-MgGraph -Times 1 -Exactly
        Should -Invoke Connect-EcfMgGraphDeviceCode -Times 1 -Exactly
    }

    It 'passes the device-code callback through to the fallback so the GUI gets the code' {
        Mock Connect-MgGraph { throw $script:BrokerError }
        $cb = { param($CodeInfo) $null = $CodeInfo }

        $null = Connect-EntraCheck -GraphOnly -DeviceCodeCallback $cb
        Should -Invoke Connect-EcfMgGraphDeviceCode -Times 1 -Exactly -ParameterFilter { $null -ne $DeviceCodeCallback }
    }

    It 'does NOT fall back on an unrelated auth failure, and still returns false' {
        Mock Connect-MgGraph { throw $script:BadCredsError }

        Connect-EntraCheck -GraphOnly | Should -BeFalse
        Should -Invoke Connect-EcfMgGraphDeviceCode -Times 0 -Exactly
    }

    It 'does NOT fall back on broker-relayed failures that are not host limitations' {
        foreach ($relayed in @($script:WamConsentError, $script:WamMfaError)) {
            Mock Connect-MgGraph { throw $relayed }.GetNewClosure()
            Connect-EntraCheck -GraphOnly | Should -BeFalse -Because "'$relayed' is a broker-relayed failure, not a missing window handle"
        }
        Should -Invoke Connect-EcfMgGraphDeviceCode -Times 0 -Exactly
    }

    It 'caps the fallback wait so an unattended browser failure cannot pin the run' {
        Mock Connect-MgGraph { throw $script:BrokerError }

        $null = Connect-EntraCheck -GraphOnly
        Should -Invoke Connect-EcfMgGraphDeviceCode -Times 1 -Exactly -ParameterFilter { $TimeoutSeconds -gt 0 -and $TimeoutSeconds -le 600 }
    }

    It 'leaves the direct device-code path uncapped - that user chose to wait' {
        $null = Connect-EntraCheck -GraphOnly -UseDeviceCode
        Should -Invoke Connect-EcfMgGraphDeviceCode -Times 1 -Exactly -ParameterFilter { -not $TimeoutSeconds }
    }

    It 'does not fall back when the browser attempt succeeds' {
        Mock Connect-MgGraph { $script:Signed = $true }
        Mock Get-MgContext { [pscustomobject]@{ Account = 'auditor@contoso.com'; TenantId = 't-1'; Scopes = $script:AllGraphScopes } }

        Connect-EntraCheck -GraphOnly | Should -BeTrue
        Should -Invoke Connect-EcfMgGraphDeviceCode -Times 0 -Exactly
    }

    It 'does not recurse or retry when the fallback itself fails' {
        Mock Connect-MgGraph { throw $script:BrokerError }
        Mock Connect-EcfMgGraphDeviceCode { throw 'Device-code sign-in was declined.' }

        Connect-EntraCheck -GraphOnly | Should -BeFalse
        Should -Invoke Connect-MgGraph -Times 1 -Exactly
        Should -Invoke Connect-EcfMgGraphDeviceCode -Times 1 -Exactly
    }

    It 'records the underlying error instead of only writing it to the console' {
        Mock Connect-MgGraph { throw $script:BadCredsError }

        $null = Connect-EntraCheck -GraphOnly
        Get-EcfLastAuthError | Should -BeExactly $script:BadCredsError
    }
}

Describe 'Get-EcfAuthFailureCode / Test-EcfBrokerAuthFailure — classification' {

    It 'treats the broker window-handle error as a host failure, not a privileges failure' {
        Test-EcfBrokerAuthFailure -Message $script:BrokerError | Should -BeTrue
        Get-EcfAuthFailureCode -Message $script:BrokerError | Should -BeExactly 'auth.failed'
    }

    It 'still classifies a genuine privileges failure as auth.insufficientPrivileges' {
        # The wrapped form is what the affected host actually produces - and
        # it names WAM, so an over-broad matcher would steal it.
        Get-EcfAuthFailureCode -Message $script:WamConsentError |
            Should -BeExactly 'auth.insufficientPrivileges'
        Get-EcfAuthFailureCode -Message 'AADSTS65001: The user or administrator has not consented to use the application.' |
            Should -BeExactly 'auth.insufficientPrivileges'
        Get-EcfAuthFailureCode -Message 'Insufficient privileges to complete the operation.' |
            Should -BeExactly 'auth.insufficientPrivileges'
    }

    It 'does not treat broker-RELAYED errors as the host limitation' {
        Test-EcfBrokerAuthFailure -Message $script:WamConsentError | Should -BeFalse
        Test-EcfBrokerAuthFailure -Message $script:WamMfaError | Should -BeFalse
        # ...and each keeps the code it had before the fallback existed.
        Get-EcfAuthFailureCode -Message $script:WamMfaError | Should -BeExactly 'auth.failed'
    }

    It 'matches the host limitation by its real signature, not by the words wam or broker' {
        Test-EcfBrokerAuthFailure -Message 'A window handle must be configured.' | Should -BeTrue
        Test-EcfBrokerAuthFailure -Message 'See https://aka.ms/msal-net-wam#parent-window-handles' | Should -BeTrue
        Test-EcfBrokerAuthFailure -Message 'WAM broker returned an error.' | Should -BeFalse
    }

    It 'still classifies a cancelled / expired sign-in as auth.cancelled' {
        Get-EcfAuthFailureCode -Message 'Device-code sign-in expired before it was completed.' |
            Should -BeExactly 'auth.cancelled'
    }

    It 'does not treat unrelated failures as broker failures' {
        foreach ($m in @($script:BadCredsError, $script:WamConsentError, $script:WamMfaError,
                'The remote name could not be resolved: login.microsoftonline.com', 'User canceled authentication.', '')) {
            Test-EcfBrokerAuthFailure -Message $m | Should -BeFalse -Because "'$m' is not a window-handle host limitation"
        }
    }
}

Describe 'Invoke-EcfGraphDeviceCodeToken - the automatic fallback wait is bounded' {

    BeforeEach {
        Mock Invoke-RestMethod {
            [pscustomobject]@{
                device_code = 'dev-code'
                user_code = 'ABC-123'
                verification_uri = 'https://microsoft.com/devicelogin'
                expires_in = 900
                interval = 5
                message = 'enter the code ABC-123'
            }
        }
        # Every Get-Date jumps 30 minutes: the deadline is computed from the
        # first call and the loop condition from the second, so the window is
        # already spent - no token poll, no Start-Sleep, no 15-minute test.
        $script:FakeNow = [datetime]'2026-01-01T00:00:00'
        Mock Get-Date { $script:FakeNow = $script:FakeNow.AddMinutes(30); $script:FakeNow }
    }

    It 'fails clearly when the capped fallback wait lapses' {
        { Invoke-EcfGraphDeviceCodeToken -Scopes @('Directory.Read.All') -TimeoutSeconds 300 } |
            Should -Throw -ExpectedMessage '*300 second limit*'
    }

    It 'keeps the full device-code window when no cap is supplied' {
        { Invoke-EcfGraphDeviceCodeToken -Scopes @('Directory.Read.All') } |
            Should -Throw -ExpectedMessage '*expired before it was completed*'
    }
}

Describe 'Auth phase — the underlying error reaches the event stream' {

    BeforeEach {
        $script:Tmp = Join-Path $env:TEMP "auth-fallback-$([guid]::NewGuid().ToString('N'))"
        $null = New-Item -Path $script:Tmp -ItemType Directory -Force
        $OutputDirectory = $script:Tmp
        $null = $OutputDirectory   # read by the dot-sourced sequence (dynamic scope)
        $script:Findings = @()
        $script:AuthEvents = [System.Collections.ArrayList]::new()
        $script:Signed = $false

        Mock Get-EcfMgContextSafe { if ($script:Signed) { [pscustomobject]@{ Account = 'auditor@contoso.com'; TenantId = 't-1'; Scopes = $script:AllGraphScopes } } else { $null } }
        Mock Invoke-ModuleAssessment { [pscustomobject]@{ Duration = [timespan]::FromMinutes(1); Errors = @(); Modules = @{ Core = 'ok' } } }
        Mock Export-AssessmentResult { $script:Tmp }
        Mock Invoke-SOC2ReadinessIfEnabled { }
    }

    AfterEach {
        if (Test-Path $script:Tmp) { Remove-Item -LiteralPath $script:Tmp -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'proceeds with the run when the device-code fallback succeeds' {
        Mock Connect-MgGraph { throw $script:BrokerError }
        Mock Connect-EcfMgGraphDeviceCode {
            $script:Signed = $true
            [pscustomobject]@{ Account = 'auditor@contoso.com'; TenantId = 't-1'; Scopes = $script:AllGraphScopes }
        }

        $seq = Invoke-EcfAssessmentSequence -TenantNameValue 'Contoso' -ModuleSet @('Core') `
            -InvocationParams @{ TenantName = 'Contoso'; OutputDirectory = $script:Tmp } `
            -AuthAction { $null = Connect-EntraCheck -GraphOnly } -AuthMethod 'Interactive' `
            -EventSink { param($EcfEvent) $null = $script:AuthEvents.Add($EcfEvent) }

        $ok = @($script:AuthEvents | Where-Object { $_.type -eq 'auth.succeeded' })
        $ok.Count | Should -Be 1
        $ok[0].account | Should -BeExactly 'auditor@contoso.com'
        @($script:AuthEvents | Where-Object { $_.type -eq 'auth.failed' }).Count | Should -Be 0
        Should -Invoke Invoke-ModuleAssessment -Times 1 -Exactly
        $seq.Manifest.status | Should -BeExactly 'Succeeded'
    }

    It 'classifies a failed fallback on the device-code cause and does not re-advise device code' {
        Mock Connect-MgGraph { throw $script:BrokerError }
        Mock Connect-EcfMgGraphDeviceCode { throw 'Device-code sign-in was declined.' }

        $null = Invoke-EcfAssessmentSequence -TenantNameValue 'Contoso' -ModuleSet @('Core') `
            -InvocationParams @{ TenantName = 'Contoso'; OutputDirectory = $script:Tmp } `
            -AuthAction { $null = Connect-EntraCheck -GraphOnly } -AuthMethod 'Interactive' `
            -EventSink { param($EcfEvent) $null = $script:AuthEvents.Add($EcfEvent) }

        $failed = @($script:AuthEvents | Where-Object { $_.type -eq 'auth.failed' })
        $failed.Count | Should -Be 1
        $failed[0].code | Should -Not -BeExactly 'auth.insufficientPrivileges'
        # The device-code cause survives instead of being overwritten by the
        # broker's: the fallback was declined, so this is auth.cancelled.
        $failed[0].code | Should -BeExactly 'auth.cancelled'
        $failed[0].message | Should -Match 'declined'
        # The broker signature must not round-trip back into classification,
        # and the user must not be told to re-run with device code right
        # after device code failed.
        $failed[0].message | Should -Not -Match 'window handle'
        $failed[0].message | Should -Not -Match 're-run with Device code'
        Should -Invoke Invoke-ModuleAssessment -Times 0 -Exactly
    }

    It 'still reports a genuine privileges failure as auth.insufficientPrivileges' {
        Mock Connect-MgGraph { throw 'AADSTS65001: The user or administrator has not consented to use the application.' }
        Mock Connect-EcfMgGraphDeviceCode { throw 'should not be reached' }

        $null = Invoke-EcfAssessmentSequence -TenantNameValue 'Contoso' -ModuleSet @('Core') `
            -InvocationParams @{ TenantName = 'Contoso'; OutputDirectory = $script:Tmp } `
            -AuthAction { $null = Connect-EntraCheck -GraphOnly } -AuthMethod 'Interactive' `
            -EventSink { param($EcfEvent) $null = $script:AuthEvents.Add($EcfEvent) }

        $failed = @($script:AuthEvents | Where-Object { $_.type -eq 'auth.failed' })
        $failed.Count | Should -Be 1
        $failed[0].code | Should -BeExactly 'auth.insufficientPrivileges'
        $failed[0].message | Should -Match 'AADSTS65001'
        Should -Invoke Connect-EcfMgGraphDeviceCode -Times 0 -Exactly
    }
}

Describe 'New-EcfAuthRunOptions — Interactive carries a device-code callback' {

    It 'hands Connect-EntraCheck a callback so a fallback code reaches the GUI panel' {
        $AuthMethod = 'Interactive'
        $SkipAuthentication = $false
        $null = $AuthMethod, $SkipAuthentication   # read by New-EcfAuthRunOptions (dynamic scope)
        Mock Connect-EntraCheck { $true }

        $opts = New-EcfAuthRunOptions
        $opts.Method | Should -BeExactly 'Interactive'
        & $opts.Action ([pscustomobject]@{ RunId = 'r-1' })

        Should -Invoke Connect-EntraCheck -Times 1 -Exactly -ParameterFilter { $null -ne $DeviceCodeCallback }
    }
}
