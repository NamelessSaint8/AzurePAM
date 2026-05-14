# EntraChecks Enhanced Reporting Guide

## Overview

EntraChecks now includes enterprise-ready reporting capabilities designed for IT directors, security directors, CIOs, and CISOs. The enhanced reporting system addresses three key analyst pain points:

1. ✅ **Takes too long to analyze findings** → Interactive HTML with filtering and search
2. ✅ **Hard to prioritize what to fix** → Risk scoring and priority recommendations
3. ✅ **Difficult to map to compliance frameworks** → Automatic mapping to CIS M365, NIST CSF, SOC2, PCI-DSS

## Analyst Cockpit (default HTML)

A normal assessment produces **one primary HTML file** — the analyst cockpit (`EntraChecks-Analyst-Cockpit-<ts>.html`). It replaces the pre-PR-4 multi-report layout (comprehensive + unified + per-domain HTML).

The cockpit has 8 sections in analyst-workflow order: Executive Digest → Action Queue → Review Queue → Source Posture → Evidence and Provenance → Full Findings → Deep Dive Hub → Integrity Footer. Action Queue / Review Queue / Full Findings are interactive (text search, multi-column filters, pagination, expandable rows showing the full v2 detail).

Switch modes via `-HtmlReportSet`:

| Mode | Output |
|---|---|
| `Cockpit` (default) | Cockpit only |
| `CockpitAndDeepDives` | Cockpit + only the deep dives listed in `-HtmlDeepDiveDomains`, under `DeepDives/` |
| `DeepDivesOnly` | Only the listed deep dives (no cockpit) |
| `LegacyAll` | Pre-PR-4 multi-report layout (compatibility mode) |

Examples:

```powershell
# Default — cockpit only
.\Start-EntraChecks.ps1

# Cockpit + Azure Policy + Defender deep dives
.\Start-EntraChecks.ps1 -HtmlReportSet CockpitAndDeepDives `
    -HtmlDeepDiveDomains AzurePolicy,DefenderCompliance

# Old multi-report behavior
.\Start-EntraChecks.ps1 -HtmlReportSet LegacyAll
```

Full reference: [Cockpit-Report-Guide.md](Cockpit-Report-Guide.md).

---

## v2 Finding Schema — what's new in the reports

Every report consumes the central v2 finding schema (`SchemaVersion='2.0'`). Each finding now carries a stable `FindingId`, derived `Disposition`, analyst-overlaid `Owner` / `Exception` / `ReviewStatus`, framework-flattened `ControlMappings`, and an `Evidence` chain of references. Legacy code paths still work; v2 fields are additive.

**Excel workbook** ([Modules/EntraChecks-ExcelReporting.psm1](../Modules/EntraChecks-ExcelReporting.psm1)) — `All Findings` gains FindingId / Disposition / Owner / Exception / Review State / Tags columns. Six new sheets are emitted automatically when v2 fields are populated:

| Sheet | Contents | Filter rule |
|---|---|---|
| **Analyst Queue** | Actionable items only | Disposition ∈ {Open, ActionRequired, Review, ExpiredException}; excludes accepted exceptions |
| **Review Queue** | Human-judgment items | Status=REVIEW OR ReviewStatus.State ∈ {NeedsReview, InReview, ActionRequired} |
| **Control Register** | One row per (finding × framework × control) | Sorted by Framework, ControlId |
| **Evidence Register** | Provenance audit trail | One row per Evidence reference with Hash + RedactionStatus |
| **Exceptions** | Risk-acceptance lifecycle | Every finding with non-None Exception.Status |
| **Remediation Plan** | Roadmap | Actionable items sorted by PriorityScore desc, with flattened RemediationDetail |

**Unified HTML report** ([Modules/EntraChecks-Compliance.psm1](../Modules/EntraChecks-Compliance.psm1)) — adds:
- New **Action Queue** and **Exceptions** tiles in the Findings Summary Overview (with anchor links).
- New **Action Queue** section above All Assessment Findings — filtered actionable items, sorted by `-PriorityScore`.
- New **Exceptions Lifecycle** table — sorted Expired → Revoked → Approved (by expiry asc) → Requested → Rejected.
- Finding row body surfaces Owner / Disposition / Exception / Evidence count / FindingId (HTML-encoded).

**CSV** — flat-row shape via `ConvertTo-FindingFlatRow` (no more `@{...}` cells). Owner/Exception/ReviewStatus flatten to prefixed scalar columns; ControlMappings/Evidence/Tags/Links flatten to semicolon-joined strings (`CIS_M365:1.1.1;NIST_CSF:PR.AC-1`).

**JSON** — full v2 finding objects emitted at `-Depth 15`. `Metadata.SchemaVersion='2.0'` on the envelope. The legacy `FindingHash` is superseded by `FindingId`.

For the complete schema reference + analyst-state workflow, see [Finding-Schema-Guide.md](Finding-Schema-Guide.md).

## What's New

### New Modules

Four new PowerShell modules power the enhanced reporting system:

1. **EntraChecks-ComplianceMapping.psm1** - Maps findings to compliance frameworks
2. **EntraChecks-RiskScoring.psm1** - Calculates risk scores and prioritizes findings
3. **EntraChecks-RemediationGuidance.psm1** - Provides step-by-step remediation instructions
4. **EntraChecks-HTMLReporting.psm1** - Generates interactive HTML reports
5. **EntraChecks-ExcelReporting.psm1** - Creates multi-worksheet Excel workbooks

### Supported Compliance Frameworks

- **CIS Microsoft 365 Foundations Benchmark** - Industry best practices for M365
- **NIST Cybersecurity Framework (CSF)** - Risk management framework
- **SOC 2 Trust Services Criteria** - Common Criteria (CC6, CC7)
- **PCI-DSS v4.0.1** - Payment card data security requirements

## Quick Start

### Basic Usage (Enhanced HTML)

```powershell
# Import the new modules
Import-Module .\Modules\EntraChecks-ComplianceMapping.psm1
Import-Module .\Modules\EntraChecks-RiskScoring.psm1
Import-Module .\Modules\EntraChecks-RemediationGuidance.psm1
Import-Module .\Modules\EntraChecks-HTMLReporting.psm1

# Generate enhanced HTML report
$findings = @(Get-YourFindings)  # Your existing findings array
$tenantInfo = @{
    TenantName = "Contoso Corporation"
    TenantId = "12345678-1234-1234-1234-123456789012"
}

New-EnhancedHTMLReport -Findings $findings -OutputPath "EntraChecks-Report.html" -TenantInfo $tenantInfo
```

### Excel Reporting

```powershell
# Requires ImportExcel module (install if needed)
Install-Module ImportExcel -Scope CurrentUser

# Import Excel reporting module
Import-Module .\Modules\EntraChecks-ExcelReporting.psm1

# Generate Excel workbook
New-EnhancedExcelReport -Findings $findings -OutputPath "EntraChecks-Report.xlsx" -TenantInfo $tenantInfo
```

## Report Features

### 1. Executive Dashboard (HTML)

The executive dashboard provides a high-level overview designed for leadership:

**Risk Summary:**
- Critical, High, Medium, Low risk counts and percentages
- Average and maximum risk scores
- Quick wins counter (high-impact, low-effort)

**Compliance Impact:**
- Number of affected controls/criteria per framework
- Visual breakdown by framework
- Gap analysis across all standards

**Example:**
```
📊 Executive Summary
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Critical Risk: 5 findings (8.3%)
High Risk: 12 findings (20.0%)
Medium Risk: 25 findings (41.7%)
Quick Wins Available: 8 findings

Compliance Impact:
- CIS M365: 15 controls affected
- NIST CSF: 12 functions affected
- SOC 2: 8 criteria affected
- PCI-DSS: 10 requirements affected
```

### 2. Quick Wins Section

Identifies high-impact, low-effort findings that provide immediate security improvements:

**Criteria:**
- Risk Score ≥ 50
- Remediation Effort ≤ 3 (Quick Win or Easy)

**Example Quick Win:**
```
⚡ Enable MFA for Admin Users

Risk Score: 95 (Critical)
Effort: Quick Win (< 1 hour)
Priority Score: 47.5

Remediation: Create Conditional Access policy requiring MFA for all admin roles.
              Implementation time: 30 minutes.
```

### 3. Priority Findings

Findings ranked by **Priority Score** (Risk Score / Remediation Effort), providing the best ROI:

| Rank | Finding | Risk | Score | Effort | Priority |
|------|---------|------|-------|--------|----------|
| 1 | MFA disabled for admins | Critical | 95 | Quick Win | 47.5 |
| 2 | Legacy auth enabled | Critical | 85 | Easy | 28.3 |
| 3 | Global admins excessive | High | 70 | Easy | 23.3 |

### 4. Compliance Mapping

Each finding is automatically mapped to relevant controls:

**Example Mapping:**
```
Finding: MFA Disabled for Administrators

Compliance Frameworks:
- CIS M365: 1.1.1, 1.1.3 - Ensure multifactor authentication is enabled for all admin users
- NIST CSF: PR.AC-1, PR.AC-7 - Identities and credentials are managed; Authentication
- SOC 2: CC6.1, CC6.2, CC6.3 - Access controls; Credential management; Privileged access
- PCI-DSS: 8.4.2, 8.4.3 - MFA for all access; MFA for administrative access
```

### 5. Detailed Findings with Remediation

Each finding includes comprehensive remediation guidance:

**Included Information:**
- Risk level and score
- Priority score
- Remediation effort estimate
- Compliance framework references
- **Azure Portal steps** (numbered, easy to follow)
- **PowerShell scripts** (copy-paste ready)
- Impact analysis (positive outcomes + considerations)
- Common issues and troubleshooting

**Example:**
```html
🔴 Critical: MFA Disabled for Administrators

Risk Score: 95 / 100
Remediation Effort: Quick Win (< 1 hour)
Priority Score: 47.5

📝 Remediation Steps (Azure Portal):
1. Sign in to Azure AD portal (https://entra.microsoft.com)
2. Navigate to Protection > Conditional Access
3. Create new policy: "Require MFA for administrators"
4. Assignments > Users > Select "Directory roles"
5. Select admin roles: Global Admin, Security Admin, etc.
...

💻 PowerShell Remediation:
[Copy-paste ready script with comments]

Impact:
✅ Protects privileged accounts from compromise
⚠️ Admins must enroll in MFA initially
```

### 6. Interactive Features (HTML)

**Search:** Real-time filtering by keyword
```
[Search findings...]  → Type "MFA", "admin", "guest", etc.
```

**Risk Filter:** Filter by risk level
```
[All Risk Levels ▼]  → Select Critical, High, Medium, or Low
```

**Expand/Collapse:** Toggle detailed information
```
[Expand All] [Collapse All]  → Show/hide remediation guidance
```

**Navigation:** Jump to sections
```
[Executive] [Quick Wins] [Priority] [Compliance] [Detailed]
```

## Excel Workbook Structure

### Worksheet Overview

| Sheet Name | Purpose | Best For |
|------------|---------|----------|
| Executive Summary | High-level metrics | Leadership presentations |
| All Findings | Complete dataset | Detailed analysis, pivot tables |
| Priority Findings | Top 25 ranked | Remediation planning |
| Quick Wins | High ROI items | Immediate action items |
| Compliance - CIS M365 | CIS controls | CIS compliance reporting |
| Compliance - NIST CSF | NIST functions | NIST compliance reporting |
| Compliance - SOC2 | SOC2 criteria | SOC2 audit preparation |
| Compliance - PCI-DSS | PCI requirements | PCI compliance reporting |
| Risk Analysis | Statistical breakdown | Risk assessments |

### Excel Features

**Auto-Filters:** Every data sheet has filters enabled
**Frozen Headers:** Top row frozen for easy scrolling
**Auto-Sized Columns:** Optimal width for readability
**Pivot-Ready:** Data structure designed for pivot tables

### Creating Pivot Tables

```excel
1. Go to "All Findings" sheet
2. Select any cell in the data
3. Insert > PivotTable
4. Drag fields:
   - Rows: Risk Level
   - Values: Count of Description
   - Report Filter: Compliance Frameworks
```

## Integration with Existing Workflow

### Option 1: Standalone Usage

Generate reports from existing findings JSON:

```powershell
# Load previous assessment results
$previousAssessment = Get-Content ".\Reports\EntraSecurityFindings-AllChecks-20260210-143000.json" | ConvertFrom-Json

# Extract findings
$findings = $previousAssessment.Findings | ForEach-Object {
    [PSCustomObject]@{
        Time = $_.Time
        Status = $_.Status
        Object = $_.Object
        Description = $_.Description
        Remediation = $_.Remediation
    }
}

# Generate enhanced reports
$tenantInfo = $previousAssessment.Metadata
New-EnhancedHTMLReport -Findings $findings -OutputPath "Enhanced-Report.html" -TenantInfo $tenantInfo
```

### Option 2: Integration with Invoke-EntraChecks

Modify the `Export-Findings` function in `Invoke-EntraChecks.ps1`:

```powershell
# Add to Export-Findings function (around line 4140)

# Generate enhanced reports if modules available
$enhancedModulesPath = Join-Path $PSScriptRoot "Modules"
$htmlReportingModule = Join-Path $enhancedModulesPath "EntraChecks-HTMLReporting.psm1"

if (Test-Path $htmlReportingModule) {
    Write-Host "    Generating enhanced HTML report..." -ForegroundColor Cyan

    Import-Module $htmlReportingModule -Force

    $enhancedHtmlPath = $ExportHtml -replace '\.html$', '-Enhanced.html'
    $tenantInfo = @{
        TenantName = $script:TenantCapabilities.TenantName
        TenantId = $script:TenantCapabilities.TenantId
    }

    New-EnhancedHTMLReport -Findings $findingsToExport -OutputPath $enhancedHtmlPath -TenantInfo $tenantInfo
    Write-Host "    Enhanced HTML: $enhancedHtmlPath" -ForegroundColor Gray
}
```

## Risk Scoring Methodology

### Base Risk Scores

Findings are assigned base risk scores (0-100) based on security impact:

| Risk Level | Score Range | Examples |
|------------|-------------|----------|
| Critical | 80-100 | MFA disabled for admins, Legacy auth enabled |
| High | 60-79 | MFA disabled for users, Conditional Access missing |
| Medium | 40-59 | Guest access unrestricted, App permissions excessive |
| Low | 20-39 | Password policy weak, Session timeout not configured |

### Impact Multipliers

Base scores are adjusted based on:

1. **Scope** (1.0 - 1.3x multiplier)
   - Organization-wide: 1.3x
   - All users: 1.2x
   - Admin users: 1.25x
   - Multiple users: 1.1x
   - Single user: 0.9x

2. **Data Sensitivity** (0.8 - 1.3x multiplier)
   - Highly sensitive: 1.3x
   - Sensitive: 1.2x
   - Internal: 1.0x
   - Public: 0.8x

3. **Exploitability** (0.9 - 1.3x multiplier)
   - Easy to exploit: 1.3x
   - Moderate difficulty: 1.1x
   - Difficult to exploit: 0.9x

4. **Compliance Requirement** (+5 points)
   - If 3+ frameworks affected: +5 points

### Remediation Effort

Effort scores (1-10 scale):

| Effort Score | Description | Time Estimate |
|--------------|-------------|---------------|
| 1-2 | Quick Win | < 1 hour |
| 3-4 | Easy | 1-4 hours |
| 5-6 | Moderate | 1-2 days |
| 7-8 | Complex | 3-5 days |
| 9-10 | Very Complex | > 1 week |

### Priority Score Calculation

```
Priority Score = Risk Score / Remediation Effort
```

**Example:**
```
Finding: Enable MFA for Admins
Risk Score: 95
Remediation Effort: 2 (Quick Win)
Priority Score: 95 / 2 = 47.5  ← Highest priority
```

## Use Cases

### 1. Executive Briefing

**Scenario:** Present security posture to CISO

**Steps:**
1. Generate enhanced HTML report
2. Open in browser, navigate to Executive Summary
3. Show risk distribution and compliance impact
4. Review Quick Wins for immediate actions
5. Print or export to PDF for distribution

**Key Metrics to Highlight:**
- Number of Critical/High findings
- Quick wins available
- Compliance gaps per framework

### 2. Compliance Audit Preparation

**Scenario:** Prepare for SOC 2 audit

**Steps:**
1. Generate Excel workbook
2. Open "Compliance - SOC2" worksheet
3. Filter by controls being audited
4. Export to PDF or share with auditors
5. Use remediation guidance to fix gaps

**Deliverables:**
- List of affected SOC 2 criteria
- Evidence of remediation efforts
- Timeline for outstanding items

### 3. Remediation Planning

**Scenario:** Plan security improvement sprint

**Steps:**
1. Open HTML report, go to Priority Findings
2. Identify top 10 items
3. Use Quick Wins for sprint 1
4. Use effort estimates for sprint planning
5. Assign findings to team members

**Sprint Planning:**
```
Sprint 1 (Quick Wins):
- Enable MFA for admins (2 hours)
- Enable audit logging (2 hours)
- Enable Security Defaults (1 hour)

Sprint 2 (High Priority):
- Block legacy auth (4 hours + testing)
- Configure Conditional Access (8 hours)
```

### 4. Risk Assessment

**Scenario:** Quantify security risk for leadership

**Steps:**
1. Open Excel workbook, go to Risk Analysis
2. Review risk distribution
3. Calculate risk reduction potential
4. Present to leadership with budget request

**Risk Metrics:**
```
Current State:
- Average Risk Score: 62.3 / 100
- Critical Findings: 5
- High Findings: 12

After Quick Wins:
- Estimated Average: 45.7 / 100 (27% reduction)
- Critical Findings: 1 (80% reduction)
- High Findings: 5 (58% reduction)

ROI: 8 findings fixed in ~10 hours = 72% risk reduction
```

### 5. Compliance Mapping

**Scenario:** Map findings to multiple frameworks

**Steps:**
1. Open HTML report, expand any finding
2. View compliance references section
3. See all applicable controls/criteria
4. Use for gap analysis across frameworks

**Example Output:**
```
Finding: Legacy Authentication Enabled

Maps to:
✓ CIS M365: Control 1.1.4
✓ NIST CSF: PR.AC-7, DE.CM-7
✓ SOC 2: CC6.1, CC6.6, CC7.2
✓ PCI-DSS: 8.4.2, 8.3.8

Single remediation fixes 4 compliance gaps!
```

## Advanced Features

### Custom Risk Scores

Modify base risk scores in `EntraChecks-RiskScoring.psm1`:

```powershell
# Add custom finding types
$Script:BaseRiskScores['CustomFinding_Type'] = 75

# Adjust existing scores
$Script:BaseRiskScores['MFA_Disabled'] = 80  # Reduce from 75
```

### Custom Compliance Mappings

Add custom compliance frameworks in `EntraChecks-ComplianceMapping.psm1`:

```powershell
# Add ISO 27001 mappings
$Script:ISO27001Mapping = @{
    'MFA_Disabled' = @{
        Controls = @('A.9.2.1', 'A.9.4.2')
        Description = 'Access control and user authentication'
    }
}
```

### Custom Remediation Guidance

Add remediation steps in `EntraChecks-RemediationGuidance.psm1`:

```powershell
$Script:RemediationGuidance['CustomFinding'] = @{
    Title = 'Fix Custom Finding'
    Summary = 'Description of the fix'
    StepsPortal = @(
        '1. Step one',
        '2. Step two'
    )
    StepsPowerShell = 'PowerShell script here'
    # ... additional fields
}
```

## Troubleshooting

### ImportExcel Module Not Found

**Issue:** Excel export fails with "ImportExcel module not found"

**Solution:**
```powershell
Install-Module ImportExcel -Scope CurrentUser -Force
Import-Module ImportExcel
```

**Alternative:** CSV files are automatically generated as fallback

### Module Import Errors

**Issue:** "Cannot find module EntraChecks-ComplianceMapping.psm1"

**Solution:**
```powershell
# Ensure modules are in correct location
cd EntraChecks
ls Modules\EntraChecks-*.psm1

# Import explicitly
Import-Module .\Modules\EntraChecks-ComplianceMapping.psm1 -Force
```

### Findings Not Enhanced

**Issue:** Risk scores or compliance mappings missing

**Cause:** Findings missing required properties (Type, CheckType, or Category)

**Solution:**
```powershell
# Ensure findings have a type field
$finding | Add-Member -NotePropertyName 'Type' -NotePropertyValue 'MFA_Disabled' -Force
```

### HTML Report Not Displaying

**Issue:** HTML file opens but appears blank

**Cause:** JavaScript errors or browser security restrictions

**Solution:**
- Open browser developer console (F12)
- Check for JavaScript errors
- Try different browser (Edge, Chrome, Firefox)
- Disable strict content security policies

### Performance Issues

**Issue:** Report generation is slow with many findings

**Solution:**
```powershell
# Limit findings for testing
$findings | Select-Object -First 50 | New-EnhancedHTMLReport ...

# For production, use Excel instead of HTML for large datasets
New-EnhancedExcelReport ...  # Better performance for 500+ findings
```

## Best Practices

### 1. Report Distribution

**For Executives:**
- Use HTML executive dashboard section
- Print or export to PDF
- Focus on risk metrics and quick wins

**For Analysts:**
- Provide full HTML report with detailed findings
- Include Excel workbook for deep analysis
- Use Priority Findings for task planning

**For Auditors:**
- Export compliance-specific worksheets
- Provide remediation evidence
- Include timestamps and tenant info

### 2. Regular Assessments

```powershell
# Schedule monthly assessments
# Compare reports over time to track progress

# January
New-EnhancedHTMLReport ... -OutputPath "Reports\2026-01-EntraChecks.html"

# February
New-EnhancedHTMLReport ... -OutputPath "Reports\2026-02-EntraChecks.html"

# Compare risk scores month-over-month
```

### 3. Documentation

- Save reports in version control
- Document custom risk scores
- Track remediation progress
- Maintain audit trail

### 4. Collaboration

```powershell
# Export Quick Wins for immediate action
$quickWins = Get-QuickWins -Findings $findings
$quickWins | Export-Csv "QuickWins-ActionItems.csv" -NoTypeInformation

# Assign to team via task management tool
# Track completion in sprint board
```

## Performance Considerations

### Report Generation Time

| Findings Count | HTML Time | Excel Time |
|----------------|-----------|------------|
| 50 | < 5 seconds | < 10 seconds |
| 100 | ~10 seconds | ~15 seconds |
| 500 | ~30 seconds | ~45 seconds |
| 1000+ | ~60 seconds | ~90 seconds |

### Optimization Tips

1. **Use Excel for large datasets** (500+ findings)
2. **Filter findings before reporting** (e.g., FAIL and WARNING only)
3. **Run reports async** if integrating into automated pipelines
4. **Cache compliance mappings** (already cached in modules)

## Future Enhancements

Potential additions for future versions:

- [ ] **PDF Export** - Direct PDF generation with formatting
- [ ] **Charts and Graphs** - Visual risk trends in HTML
- [ ] **Email Reports** - Automated email delivery
- [ ] **Custom Templates** - Branded report templates
- [ ] **API Integration** - Export to SIEM or GRC tools
- [ ] **Historical Trending** - Multi-report comparison
- [ ] **MITRE ATT&CK Mapping** - Threat-based categorization
- [ ] **Cost Estimation** - Remediation cost/time estimation

## Resources

### Documentation

- **Compliance Mapping Module:** See `EntraChecks-ComplianceMapping.psm1`
- **Risk Scoring Module:** See `EntraChecks-RiskScoring.psm1`
- **Remediation Guidance Module:** See `EntraChecks-RemediationGuidance.psm1`
- **HTML Reporting Module:** See `EntraChecks-HTMLReporting.psm1`
- **Excel Reporting Module:** See `EntraChecks-ExcelReporting.psm1`

### PowerShell Help

```powershell
Get-Help New-EnhancedHTMLReport -Full
Get-Help New-EnhancedExcelReport -Full
Get-Help Get-ComplianceMapping -Examples
Get-Help Calculate-RiskScore -Detailed
Get-Help Get-RemediationGuidance -Full
```

### Framework References

- **CIS M365:** https://www.cisecurity.org/benchmark/microsoft_365
- **NIST CSF:** https://www.nist.gov/cyberframework
- **SOC 2:** https://www.aicpa.org/soc2
- **PCI-DSS:** https://www.pcisecuritystandards.org/

### Module Requirements

```powershell
# Required (already part of EntraChecks)
- PowerShell 5.1+
- Microsoft.Graph modules

# Optional (for Excel export)
- ImportExcel module: Install-Module ImportExcel -Scope CurrentUser
```

## Summary

The enhanced reporting system transforms EntraChecks from a security assessment tool into an enterprise-ready platform for:

✅ **Fast Analysis** - Interactive HTML with search and filtering
✅ **Clear Prioritization** - Risk-based ranking with ROI calculation
✅ **Compliance Mapping** - Automatic mapping to 4 major frameworks
✅ **Actionable Guidance** - Step-by-step remediation with scripts
✅ **Executive Communication** - Professional reports for leadership
✅ **Audit Preparation** - Framework-specific compliance views

**Target Audience:** IT Directors, Security Directors, CIOs, CISOs, Security Analysts, Compliance Teams

**Key Differentiators:**
- Risk/effort-based prioritization (Priority Score)
- Multi-framework compliance mapping
- Copy-paste PowerShell remediation scripts
- Interactive HTML for fast triage
- Excel workbooks for deep analysis

**Pain Points Solved:**
1. ⏱️ Takes too long to analyze → **Solved:** Interactive HTML, search, filters
2. 🤔 Hard to prioritize → **Solved:** Risk scoring, Priority Score (ROI)
3. 📋 Difficult compliance mapping → **Solved:** Auto-mapping to 4 frameworks

---

**For questions or feature requests:** Review module source code or submit issues to the EntraChecks repository.
