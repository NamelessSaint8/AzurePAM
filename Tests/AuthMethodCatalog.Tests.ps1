<#
.SYNOPSIS
    Pester 5 test suite for the auth method strength catalog (PR 1 of the
    MFA Detection work).

.DESCRIPTION
    Verifies:
    1. Catalog shape — every entry has the required fields populated.
    2. Strength values are valid; tier counts match expectations.
    3. Get-AuthMethodCatalog returns clones (callers can't mutate the master).
    4. Get-AuthMethodDescriptor throws on unknown keys.
    5. Get-AuthMethodKeys filters by tier correctly.
    6. Resolve-AuthMethodKey handles:
       - @odata.type values with and without the '#microsoft.graph.' prefix
       - registrationDetails canonical values
       - phoneAuthenticationMethod with PhoneType disambiguation
       - case-insensitive matching
       - returns $null on unknown identifiers
    7. Get-StrongestMethod ordering: PhishingResistant > Strong > Weak > None.
    8. Edge cases: empty list -> 'None', all-unknown list -> 'Unknown'.

    Run: Invoke-Pester -Path Tests/AuthMethodCatalog.Tests.ps1
#>

#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeAll {
    $repoRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-AuthMethodCatalog.psm1') -Force -DisableNameChecking
}

Describe 'Auth method catalog shape' {

    It 'has at least 15 entries (smoke for accidental truncation)' {
        @(Get-AuthMethodKeys).Count | Should -BeGreaterOrEqual 15
    }

    It 'has every required field populated on every entry' {
        $catalog = Get-AuthMethodCatalog
        foreach ($key in $catalog.Keys) {
            $entry = $catalog[$key]
            $entry.Key            | Should -BeExactly $key -Because "Entry stored under '$key' should self-identify as '$key'"
            $entry.DisplayName    | Should -Not -BeNullOrEmpty
            $entry.Strength       | Should -Not -BeNullOrEmpty
            $entry.WhyClassified  | Should -Not -BeNullOrEmpty
            $entry.ReferenceUrl   | Should -Match '^https?://'
            @($entry.Aliases).Count | Should -BeGreaterOrEqual 1
        }
    }

    It 'uses only the four canonical Strength values' {
        $catalog = Get-AuthMethodCatalog
        foreach ($key in $catalog.Keys) {
            $catalog[$key].Strength | Should -BeIn @('PhishingResistant', 'Strong', 'Weak', 'None')
        }
    }

    It 'has at least one entry in each tier' {
        @(Get-AuthMethodKeys -Strength 'PhishingResistant').Count | Should -BeGreaterOrEqual 3
        @(Get-AuthMethodKeys -Strength 'Strong').Count            | Should -BeGreaterOrEqual 3
        @(Get-AuthMethodKeys -Strength 'Weak').Count              | Should -BeGreaterOrEqual 3
        @(Get-AuthMethodKeys -Strength 'None').Count              | Should -BeGreaterOrEqual 1
    }

    It 'classifies the canonical strong-tier methods correctly' {
        # These are the methods auditors most often misjudge — explicit guard.
        Get-AuthMethodStrength -Key 'softwareOath'                 | Should -BeExactly 'Strong'
        Get-AuthMethodStrength -Key 'microsoftAuthenticatorPush'   | Should -BeExactly 'Strong'
        Get-AuthMethodStrength -Key 'temporaryAccessPass'          | Should -BeExactly 'Strong'
    }

    It 'classifies the canonical phishing-resistant methods correctly' {
        Get-AuthMethodStrength -Key 'fido2'                       | Should -BeExactly 'PhishingResistant'
        Get-AuthMethodStrength -Key 'windowsHelloForBusiness'     | Should -BeExactly 'PhishingResistant'
        Get-AuthMethodStrength -Key 'passKeyDeviceBound'          | Should -BeExactly 'PhishingResistant'
        Get-AuthMethodStrength -Key 'certificateBasedAuth'        | Should -BeExactly 'PhishingResistant'
    }

    It 'classifies SMS, voice, and email as Weak' {
        Get-AuthMethodStrength -Key 'mobilePhone'           | Should -BeExactly 'Weak'
        Get-AuthMethodStrength -Key 'alternateMobilePhone'  | Should -BeExactly 'Weak'
        Get-AuthMethodStrength -Key 'voiceCall'             | Should -BeExactly 'Weak'
        Get-AuthMethodStrength -Key 'email'                 | Should -BeExactly 'Weak'
    }

    It 'classifies password and security questions as None (not MFA)' {
        Get-AuthMethodStrength -Key 'password'           | Should -BeExactly 'None'
        Get-AuthMethodStrength -Key 'securityQuestions'  | Should -BeExactly 'None'
    }
}

Describe 'Get-AuthMethodCatalog cloning' {

    It 'returns independent clones across calls' {
        $first = Get-AuthMethodCatalog
        $first['fido2'].DisplayName = 'mutated'
        $second = Get-AuthMethodCatalog
        $second['fido2'].DisplayName | Should -BeExactly 'FIDO2 security key'
    }

    It 'protects array-valued Aliases from cross-call mutation' {
        $first = Get-AuthMethodCatalog
        $first['fido2'].Aliases += 'injected-alias'
        $second = Get-AuthMethodCatalog
        @($second['fido2'].Aliases) -contains 'injected-alias' | Should -BeFalse
    }
}

Describe 'Get-AuthMethodDescriptor' {

    It 'returns a clone for a known key' {
        $d = Get-AuthMethodDescriptor -Key 'fido2'
        $d.Strength    | Should -BeExactly 'PhishingResistant'
        $d.DisplayName | Should -BeExactly 'FIDO2 security key'
    }

    It 'throws on an unknown key' {
        { Get-AuthMethodDescriptor -Key 'BogusMethod' } | Should -Throw -ExpectedMessage '*Unknown auth method key*'
    }
}

Describe 'Resolve-AuthMethodKey — naming conventions' {

    It 'resolves bare @odata.type names' {
        Resolve-AuthMethodKey -Identifier 'fido2AuthenticationMethod'                  | Should -BeExactly 'fido2'
        Resolve-AuthMethodKey -Identifier 'windowsHelloForBusinessAuthenticationMethod' | Should -BeExactly 'windowsHelloForBusiness'
        Resolve-AuthMethodKey -Identifier 'softwareOathAuthenticationMethod'           | Should -BeExactly 'softwareOath'
        Resolve-AuthMethodKey -Identifier 'emailAuthenticationMethod'                  | Should -BeExactly 'email'
    }

    It 'resolves @odata.type names with the #microsoft.graph. prefix' {
        Resolve-AuthMethodKey -Identifier '#microsoft.graph.fido2AuthenticationMethod'                | Should -BeExactly 'fido2'
        Resolve-AuthMethodKey -Identifier '#microsoft.graph.temporaryAccessPassAuthenticationMethod'  | Should -BeExactly 'temporaryAccessPass'
    }

    It 'resolves registrationDetails canonical values' {
        Resolve-AuthMethodKey -Identifier 'fido2'                  | Should -BeExactly 'fido2'
        Resolve-AuthMethodKey -Identifier 'softwareOneTimePasscode' | Should -BeExactly 'softwareOath'
        Resolve-AuthMethodKey -Identifier 'mobilePhone'             | Should -BeExactly 'mobilePhone'
        Resolve-AuthMethodKey -Identifier 'alternateMobilePhone'    | Should -BeExactly 'alternateMobilePhone'
        Resolve-AuthMethodKey -Identifier 'temporaryAccessPass'     | Should -BeExactly 'temporaryAccessPass'
        Resolve-AuthMethodKey -Identifier 'hardwareOneTimePasscode' | Should -BeExactly 'hardwareOath'
    }

    It 'is case-insensitive' {
        Resolve-AuthMethodKey -Identifier 'FIDO2AUTHENTICATIONMETHOD' | Should -BeExactly 'fido2'
        Resolve-AuthMethodKey -Identifier 'softwareoath'              | Should -BeExactly 'softwareOath'
    }

    It 'disambiguates phoneAuthenticationMethod via -PhoneType' {
        Resolve-AuthMethodKey -Identifier 'phoneAuthenticationMethod' -PhoneType 'mobile'          | Should -BeExactly 'mobilePhone'
        Resolve-AuthMethodKey -Identifier 'phoneAuthenticationMethod' -PhoneType 'alternateMobile' | Should -BeExactly 'alternateMobilePhone'
        Resolve-AuthMethodKey -Identifier 'phoneAuthenticationMethod' -PhoneType 'office'          | Should -BeExactly 'voiceCall'
    }

    It 'returns $null for phoneAuthenticationMethod when -PhoneType is missing' {
        Resolve-AuthMethodKey -Identifier 'phoneAuthenticationMethod' | Should -BeNullOrEmpty
    }

    It 'returns $null for unknown identifiers' {
        Resolve-AuthMethodKey -Identifier 'bogusUnknownMethod' | Should -BeNullOrEmpty
    }
}

Describe 'Get-StrongestMethod — ordering' {

    It 'returns PhishingResistant when any phishing-resistant method is present' {
        Get-StrongestMethod -Methods 'fido2', 'mobilePhone'        | Should -BeExactly 'PhishingResistant'
        Get-StrongestMethod -Methods 'mobilePhone', 'fido2'        | Should -BeExactly 'PhishingResistant'  # order independence
        Get-StrongestMethod -Methods 'windowsHelloForBusiness'     | Should -BeExactly 'PhishingResistant'
    }

    It 'returns Strong when no phishing-resistant method but a strong method is present' {
        Get-StrongestMethod -Methods 'softwareOath', 'email'              | Should -BeExactly 'Strong'
        Get-StrongestMethod -Methods 'microsoftAuthenticatorPush', 'mobilePhone' | Should -BeExactly 'Strong'
    }

    It 'returns Weak when only weak methods are present' {
        Get-StrongestMethod -Methods 'mobilePhone'                | Should -BeExactly 'Weak'
        Get-StrongestMethod -Methods 'mobilePhone', 'email'       | Should -BeExactly 'Weak'
    }

    It 'returns None for password-only or empty input' {
        Get-StrongestMethod -Methods 'password'           | Should -BeExactly 'None'
        Get-StrongestMethod -Methods 'securityQuestions'  | Should -BeExactly 'None'
        Get-StrongestMethod -Methods @()                  | Should -BeExactly 'None'
        Get-StrongestMethod -Methods $null                | Should -BeExactly 'None'
    }

    It 'returns Unknown when only uncatalogued methods are present' {
        Get-StrongestMethod -Methods 'somethingNew', 'anotherNew' | Should -BeExactly 'Unknown'
    }

    It 'ignores Unknown when a recognised method is also present' {
        Get-StrongestMethod -Methods 'fido2', 'somethingNew'      | Should -BeExactly 'PhishingResistant'
        Get-StrongestMethod -Methods 'mobilePhone', 'somethingNew' | Should -BeExactly 'Weak'
    }
}
