<#
.SYNOPSIS
    Pester 5 test suite for the data-source provenance catalog.

.DESCRIPTION
    Covers:
    1. Static catalog shape — all 5 keys, required fields populated.
    2. Get-DataSourceCatalog returns clones (mutating one slot does not affect
       the master or subsequent calls).
    3. Get-DataSourceDescriptor throws on unknown keys.
    4. Update-DataSourceContext stamps runtime fields.
    5. Resolve-FindingSource:
       - returns the explicit override when valid;
       - falls back to auto-derive when override is unknown;
       - maps known module file names correctly;
       - returns 'Internal' as default.
    6. ConvertTo-DataSourceRows flattens the catalog into one-row-per-source
       with multi-value cells joined.

    Run: Invoke-Pester -Path Tests/DataSources.Tests.ps1
#>

#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeAll {
    $repoRoot = Split-Path -Parent $PSScriptRoot
    # ExcelReporting imports DataSources internally; importing it first scopes
    # those functions to the nested module. Re-importing DataSources at the
    # global scope after makes its public functions visible to the tests.
    Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-ExcelReporting.psm1') -Force
    Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-DataSources.psm1') -Force -DisableNameChecking
}

Describe 'DataSource catalog shape' {

    It 'exposes exactly the five expected keys' {
        $keys = Get-DataSourceKeys
        $keys | Should -HaveCount 5
        ($keys | Sort-Object) -join ',' | Should -BeExactly 'AzurePolicy,DefenderCompliance,Internal,PurviewCompliance,SecureScore'
    }

    It 'populates Description, Provider, and ReferenceUrl for every external source' {
        $catalog = Get-DataSourceCatalog
        foreach ($key in @('SecureScore', 'DefenderCompliance', 'AzurePolicy', 'PurviewCompliance')) {
            $catalog[$key].Description | Should -Not -BeNullOrEmpty
            $catalog[$key].Provider    | Should -Not -BeNullOrEmpty
            $catalog[$key].ReferenceUrl | Should -Match '^https?://'
        }
    }

    It 'populates Endpoints, Cmdlets, and Scopes (non-empty arrays) for external sources' {
        $catalog = Get-DataSourceCatalog
        foreach ($key in @('SecureScore', 'DefenderCompliance', 'AzurePolicy', 'PurviewCompliance')) {
            @($catalog[$key].Endpoints).Count | Should -BeGreaterThan 0
            @($catalog[$key].Cmdlets).Count   | Should -BeGreaterThan 0
            @($catalog[$key].Scopes).Count    | Should -BeGreaterThan 0
        }
    }

    It 'leaves runtime fields null on a fresh catalog' {
        $catalog = Get-DataSourceCatalog
        $catalog.SecureScore.AuthMethod | Should -BeNullOrEmpty
        $catalog.SecureScore.Upn        | Should -BeNullOrEmpty
        $catalog.SecureScore.Tenant     | Should -BeNullOrEmpty
        $catalog.SecureScore.QueriedAt  | Should -BeNullOrEmpty
    }
}

Describe 'Get-DataSourceCatalog cloning' {

    It 'returns independent clones across calls' {
        $first = Get-DataSourceCatalog
        $first.SecureScore['Upn'] = 'mutated@example.com'
        $second = Get-DataSourceCatalog
        $second.SecureScore.Upn | Should -BeNullOrEmpty
    }

    It 'protects array-valued fields from cross-call mutation' {
        $first = Get-DataSourceCatalog
        $first.SecureScore.Endpoints += 'GET /injected'
        $second = Get-DataSourceCatalog
        @($second.SecureScore.Endpoints) -contains 'GET /injected' | Should -BeFalse
    }
}

Describe 'Get-DataSourceDescriptor' {

    It 'returns a clone of the named descriptor' {
        $d = Get-DataSourceDescriptor -Key 'SecureScore'
        $d.Description | Should -BeExactly 'Microsoft Secure Score'
    }

    It 'throws on unknown keys' {
        { Get-DataSourceDescriptor -Key 'BogusSource' } | Should -Throw -ExpectedMessage '*Unknown data source key*'
    }
}

Describe 'Update-DataSourceContext' {

    It 'stamps explicit runtime fields' {
        $d = Get-DataSourceDescriptor -Key 'SecureScore'
        $stamp = (Get-Date '2026-01-01T12:34:56Z').ToUniversalTime()
        Update-DataSourceContext -Descriptor $d `
            -AuthMethod 'Delegated · interactive' `
            -Upn 'auditor@contoso.onmicrosoft.com' `
            -Tenant 'contoso.onmicrosoft.com' `
            -Subscriptions @('sub-a', 'sub-b') `
            -QueriedAt $stamp

        $d.AuthMethod | Should -BeExactly 'Delegated · interactive'
        $d.Upn        | Should -BeExactly 'auditor@contoso.onmicrosoft.com'
        $d.Tenant     | Should -BeExactly 'contoso.onmicrosoft.com'
        @($d.Subscriptions) -join ',' | Should -BeExactly 'sub-a,sub-b'
        $d.QueriedAt  | Should -Be $stamp
    }

    It 'defaults QueriedAt to current UTC time when not supplied' {
        $d = Get-DataSourceDescriptor -Key 'SecureScore'
        Update-DataSourceContext -Descriptor $d -AuthMethod 'X' -Upn 'a@b' -Tenant 't'
        $d.QueriedAt | Should -BeOfType [datetime]
        ($d.QueriedAt - (Get-Date).ToUniversalTime()).TotalMinutes | Should -BeLessThan 1
    }
}

Describe 'Resolve-FindingSource' {

    It 'honors a valid explicit override' {
        Resolve-FindingSource -ExplicitSource 'SecureScore' | Should -BeExactly 'SecureScore'
    }

    It 'falls back to auto-derive when override is unknown' {
        # Resolve-FindingSource warns and walks the call stack — from a Pester
        # test runner there's no module match, so we expect 'Internal'.
        Resolve-FindingSource -ExplicitSource 'NotARealSource' -WarningAction SilentlyContinue | Should -BeExactly 'Internal'
    }

    It 'returns Internal when called from an unrecognised script context' {
        Resolve-FindingSource | Should -BeExactly 'Internal'
    }

    It 'maps a known module via stack frame lookup' {
        # Synthesise a frame by writing a tiny module file under TestDrive that
        # invokes Resolve-FindingSource; its file name maps to SecureScore.
        $fakeModulePath = Join-Path $TestDrive 'EntraChecks-SecureScore.psm1'
        Set-Content -Path $fakeModulePath -Value @'
function Test-Caller {
    Resolve-FindingSource
}
Export-ModuleMember -Function Test-Caller
'@
        Import-Module $fakeModulePath -Force
        try {
            Test-Caller | Should -BeExactly 'SecureScore'
        }
        finally {
            Remove-Module 'EntraChecks-SecureScore' -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe 'ConvertTo-DataSourceRows' {

    It 'returns one row per source in the canonical order' {
        $rows = ConvertTo-DataSourceRows -Catalog (Get-DataSourceCatalog)
        $rows | Should -HaveCount 5
        ($rows | ForEach-Object Source) -join '|' | Should -BeExactly 'EntraChecks Internal|Microsoft Secure Score|Defender for Cloud Compliance|Azure Policy|Purview Compliance Manager'
    }

    It 'joins multi-value cells with semicolons' {
        $rows = ConvertTo-DataSourceRows -Catalog (Get-DataSourceCatalog)
        $secureRow = $rows | Where-Object { $_.Source -eq 'Microsoft Secure Score' }
        $secureRow.Endpoints | Should -Match '; '
        $secureRow.Cmdlets   | Should -Match '; '
    }

    It 'reports Status = Active for available sources and Not Available otherwise' {
        $catalog = Get-DataSourceCatalog
        $catalog.SecureScore['Available'] = $true
        $rows = ConvertTo-DataSourceRows -Catalog $catalog
        ($rows | Where-Object { $_.Source -eq 'Microsoft Secure Score' }).Status | Should -BeExactly 'Active'
        ($rows | Where-Object { $_.Source -eq 'Azure Policy' }).Status            | Should -BeExactly 'Not Available'
    }
}
