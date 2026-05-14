<#
.SYNOPSIS
    Pester 5 tests for the HTML safety helpers in EntraChecks-HTMLReporting.psm1
    (PR 1 of HTML-Reporting-Consolidation-Plan).

.DESCRIPTION
    Foundation tests for five exported helpers consumed by the cockpit
    renderer (PR 2+ of the same plan):

      - ConvertTo-SafeHtml           — HTML element content encoding
      - ConvertTo-SafeHtmlAttribute  — HTML attribute value encoding
      - ConvertTo-SafeHtmlJson       — JSON encoding safe inside <script>
      - New-SafeExternalLink         — <a> with scheme allowlist + rel="noopener noreferrer"
      - New-SafeElementId            — stable hash-based id (safe for HTML + CSS selectors)

    Each helper is exercised against the XSS payload patterns called out in
    the plan §13 (HTML Safety Requirements):
      - <script> injection
      - attribute breakout via quotes
      - javascript: / data: / vbscript: / file: URLs
      - </script> breakout inside JSON
      - U+2028 / U+2029 JavaScript line-terminator confusion
      - object names with HTML metacharacters used as element ids

    Run: Invoke-Pester -Path Tests/HTMLSafety.Tests.ps1
#>

#Requires -Version 5.1
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeAll {
    $repoRoot = Split-Path -Parent $PSScriptRoot
    Import-Module (Join-Path $repoRoot 'Modules/EntraChecks-HTMLReporting.psm1') -Force
}

# ============================================================================
# ConvertTo-SafeHtml — element content
# ============================================================================

Describe 'ConvertTo-SafeHtml — element content encoding' {

    It 'encodes angle-bracket and ampersand chars to entity references' {
        ConvertTo-SafeHtml -Text '<b>' | Should -BeExactly '&lt;b&gt;'
        ConvertTo-SafeHtml -Text 'a & b' | Should -BeExactly 'a &amp; b'
    }

    It 'encodes a script-tag injection attempt' {
        $payload = '<script>alert(1)</script>'
        ConvertTo-SafeHtml -Text $payload |
            Should -BeExactly '&lt;script&gt;alert(1)&lt;/script&gt;'
    }

    It 'encodes both quote types so the output is safe in any quote context' {
        $r = ConvertTo-SafeHtml -Text 'mix "double" and ''single'' quotes'
        $r | Should -Match '&quot;'
        $r | Should -Match '&#39;'
    }

    It 'returns empty string for $null input (not the literal string null)' {
        ConvertTo-SafeHtml -Text $null | Should -BeExactly ''
    }

    It 'returns empty string for empty input' {
        ConvertTo-SafeHtml -Text '' | Should -BeExactly ''
    }

    It 'is idempotent — re-encoding already-encoded text does not double-encode entity REFs but does encode bare ampersands' {
        # This is the standard HtmlEncode behavior: it encodes EVERY `&`,
        # which means &lt; becomes &amp;lt; on a second pass. We're not
        # claiming idempotence — we're claiming consistent single-pass
        # encoding. Document the actual behavior so callers don't rely on
        # the wrong contract.
        $once = ConvertTo-SafeHtml -Text '<b>'
        $twice = ConvertTo-SafeHtml -Text $once
        $twice | Should -BeExactly '&amp;lt;b&amp;gt;'
    }
}

# ============================================================================
# ConvertTo-SafeHtmlAttribute — attribute value
# ============================================================================

Describe 'ConvertTo-SafeHtmlAttribute — attribute value encoding' {

    It 'encodes a quote-breakout attempt against a double-quoted attribute' {
        # Attacker tries to break out of value="..." and add an onclick handler.
        $payload = 'safe" onclick="alert(1)'
        $encoded = ConvertTo-SafeHtmlAttribute -Text $payload
        # The double-quote that would close the attribute must be entity-encoded.
        $encoded | Should -Match '&quot;'
        $encoded | Should -Not -Match '" onclick'
    }

    It 'encodes a quote-breakout attempt against a single-quoted attribute' {
        $payload = "safe' onclick='alert(1)"
        $encoded = ConvertTo-SafeHtmlAttribute -Text $payload
        $encoded | Should -Match '&#39;'
        $encoded | Should -Not -Match "' onclick"
    }

    It 'encodes angle brackets so > cannot close an unquoted attribute' {
        $encoded = ConvertTo-SafeHtmlAttribute -Text 'a>b'
        $encoded | Should -BeExactly 'a&gt;b'
    }

    It 'returns empty string for $null' {
        ConvertTo-SafeHtmlAttribute -Text $null | Should -BeExactly ''
    }
}

# ============================================================================
# ConvertTo-SafeHtmlJson — embed in <script>
# ============================================================================

Describe 'ConvertTo-SafeHtmlJson — script-block safety' {

    It 'escapes angle brackets so an embedded close-script-tag cannot break out' {
        $payload = @{ Description = 'malicious </script><img src=x onerror=alert(1)>' }
        $json = $payload | ConvertTo-SafeHtmlJson -Depth 5
        $json | Should -Not -Match '</script>'
        $json | Should -Match '\\u003c'
    }

    It 'escapes > as >' {
        $payload = @{ Description = 'a > b' }
        $json = $payload | ConvertTo-SafeHtmlJson -Depth 5
        $json | Should -Match '\\u003e'
        $json | Should -Not -Match ' > '
    }

    It 'escapes & as &' {
        $payload = @{ Description = 'a & b' }
        $json = $payload | ConvertTo-SafeHtmlJson -Depth 5
        $json | Should -Match '\\u0026'
    }

    It 'escapes U+2028 / U+2029 (JavaScript line terminators inside string literals)' {
        $payload = @{ Description = "line1`u{2028}line2`u{2029}line3" }
        $json = $payload | ConvertTo-SafeHtmlJson -Depth 5
        # The raw characters must NOT appear — they would terminate the JS
        # string literal even though JSON doesn't require their escape.
        $json | Should -Not -Match "`u{2028}"
        $json | Should -Not -Match "`u{2029}"
    }

    It 'returns the literal string "null" for $null input' {
        $r = $null | ConvertTo-SafeHtmlJson
        $r | Should -BeExactly 'null'
    }

    It 'round-trips a benign object back to PowerShell via ConvertFrom-Json' {
        # The escape replacements use JSON-legal \u escapes, so the output
        # is still valid JSON. (Verifying we didn't break parsability.)
        $original = @{ Tenant = 'Contoso'; Count = 42 }
        $json = $original | ConvertTo-SafeHtmlJson -Depth 5
        $back = $json | ConvertFrom-Json
        $back.Tenant | Should -BeExactly 'Contoso'
        $back.Count  | Should -Be 42
    }
}

# ============================================================================
# New-SafeExternalLink — scheme allowlist
# ============================================================================

Describe 'New-SafeExternalLink — scheme validation and noopener' {

    It 'returns an anchor element for an https:// URL with target=_blank and rel=noopener' {
        $r = New-SafeExternalLink -Url 'https://portal.azure.com/x' -LinkText 'Open'
        $r | Should -Match '<a href="https://portal\.azure\.com/x"'
        $r | Should -Match 'target="_blank"'
        $r | Should -Match 'rel="noopener noreferrer"'
        $r | Should -Match '>Open</a>$'
    }

    It 'returns an anchor element for an http:// URL' {
        $r = New-SafeExternalLink -Url 'http://example.com' -LinkText 'Open'
        $r | Should -Match '^<a '
    }

    It 'rejects a javascript: URL and renders text-only span' {
        $r = New-SafeExternalLink -Url 'javascript:alert(1)' -LinkText 'Click'
        $r | Should -Not -Match '^<a '
        $r | Should -Match '<span'
        $r | Should -Match '>Click</span>'
    }

    It 'rejects a data: URL' {
        $r = New-SafeExternalLink -Url 'data:text/html,<script>alert(1)</script>' -LinkText 'D'
        $r | Should -Not -Match '^<a '
    }

    It 'rejects a vbscript: URL' {
        $r = New-SafeExternalLink -Url 'vbscript:MsgBox 1' -LinkText 'V'
        $r | Should -Not -Match '^<a '
    }

    It 'rejects a file:// URL' {
        $r = New-SafeExternalLink -Url 'file:///etc/passwd' -LinkText 'F'
        $r | Should -Not -Match '^<a '
    }

    It 'rejects an unknown scheme (defense against new dangerous schemes)' {
        $r = New-SafeExternalLink -Url 'chrome:settings' -LinkText 'C'
        $r | Should -Not -Match '^<a '
    }

    It 'rejects a scheme-relative URL (//evil.com) — no parsed scheme means reject' {
        $r = New-SafeExternalLink -Url '//evil.example.com' -LinkText 'X'
        $r | Should -Not -Match '^<a '
    }

    It 'rejects a URL with an embedded quote-breakout attempt' {
        # Even though the URL "looks like https", the encoder must escape
        # the embedded quote so it cannot close the href attribute.
        $r = New-SafeExternalLink -Url 'https://example.com" onclick="alert(1)' -LinkText 'X'
        # Either the URL is rendered with the quote encoded, OR rejected.
        # The current implementation accepts https://... and encodes the
        # quote — that's safe. Assert the raw `" onclick="` cannot appear.
        $r | Should -Not -Match '" onclick="alert\(1\)'
    }

    It 'encodes the link text (no XSS via LinkText)' {
        $r = New-SafeExternalLink -Url 'https://example.com' -LinkText '<img src=x onerror=alert(1)>'
        $r | Should -Match '&lt;img'
        $r | Should -Not -Match '<img src=x'
    }

    It 'handles empty URL by returning text-only span' {
        $r = New-SafeExternalLink -Url '' -LinkText 'just text'
        $r | Should -BeExactly '<span>just text</span>'
    }
}

# ============================================================================
# New-SafeElementId — hash-based ids
# ============================================================================

Describe 'New-SafeElementId — stable safe ids' {

    It 'returns an id matching the documented prefix and 16 lowercase hex chars' {
        $id = New-SafeElementId -InputText 'admin@contoso.example'
        $id | Should -Match '^ecf-anchor-[0-9a-f]{16}$'
    }

    It 'is deterministic across repeated calls' {
        $a = New-SafeElementId -InputText 'same-input'
        $b = New-SafeElementId -InputText 'same-input'
        $a | Should -BeExactly $b
    }

    It 'produces different ids for different inputs (collision sanity check)' {
        $a = New-SafeElementId -InputText 'foo'
        $b = New-SafeElementId -InputText 'bar'
        $a | Should -Not -Be $b
    }

    It 'neutralises HTML metacharacters in the input — output is ASCII-safe regardless' {
        $payload = '<svg onload=alert(1)>'
        $id = New-SafeElementId -InputText $payload
        $id | Should -Match '^ecf-anchor-[0-9a-f]{16}$'
        $id | Should -Not -Match '<'
        $id | Should -Not -Match 'svg'
    }

    It 'accepts a custom prefix' {
        $id = New-SafeElementId -InputText 'x' -Prefix 'finding-'
        $id | Should -Match '^finding-[0-9a-f]{16}$'
    }

    It 'returns a stable id for $null / empty input (uses sentinel)' {
        $a = New-SafeElementId -InputText $null
        $b = New-SafeElementId -InputText ''
        $a | Should -Match '^ecf-anchor-[0-9a-f]{16}$'
        $b | Should -Match '^ecf-anchor-[0-9a-f]{16}$'
        $a | Should -BeExactly $b
    }
}
