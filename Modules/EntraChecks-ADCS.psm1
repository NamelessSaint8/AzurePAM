<#
.SYNOPSIS
    EntraChecks-ADCS.psm1
    Active Directory Certificate Services vulnerability audit (ESC1-ESC8).

.DESCRIPTION
    Detects the 8 ESC-class misconfigurations documented in SpecterOps's
    "Certified Pre-Owned" research. All checks are read-only.

    Coverage is AD-attribute + ACL based for ESC1-5 (runs from any
    domain-joined host with read access), best-effort registry probing
    for ESC6-7 (requires PSRemoting to the CA server), and HTTP
    endpoint probing for ESC8 (requires network access to the CA).

    Imported on-demand by EntraChecks-ActiveDirectory.psm1's
    Invoke-ActiveDirectoryAssessment when an Enterprise CA is detected.
    No findings are produced (beyond a single INFO) when AD CS isn't
    deployed in the domain.

.NOTES
    Version: 1.0.0
    Author:  David Stells
    References:
    - SpecterOps "Certified Pre-Owned" whitepaper
    - MS-WCCE, MS-CRTD protocol specifications

.LINK
    Plan: plans/AD-PR3-ADCS-ESC-Plan.md
    Guide: docs/ADCS-Guide.md
#>

#Requires -Version 5.1

#region ==================== MODULE STATE ====================

$script:ModuleName = 'EntraChecks-ADCS'
$script:ModuleVersion = '1.0.0'

# PKI config container DN is derived from the domain at runtime.
$script:PkiServicesContainerTemplate = 'CN=Public Key Services,CN=Services,CN=Configuration,{0}'

# EKU OIDs of interest.
$script:EKU_ClientAuth = '1.3.6.1.5.5.7.3.2'
$script:EKU_SmartCardLogon = '1.3.6.1.4.1.311.20.2.2'
$script:EKU_AnyPurpose = '2.5.29.37.0'
$script:EKU_CertificateRequestAgent = '1.3.6.1.4.1.311.20.2.1'
$script:EKU_PkInitClientAuth = '1.3.6.1.5.2.3.4'

# msPKI-Certificate-Name-Flag bits.
$script:CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x1
$script:CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME = 0x10000

# msPKI-Enrollment-Flag bits.
$script:CT_FLAG_PEND_ALL_REQUESTS = 0x2
$script:CT_FLAG_NO_SECURITY_EXTENSION = 0x80000

# flags attribute on CA object for EDITF_ATTRIBUTESUBJECTALTNAME2 (ESC6) lives in registry,
# not in AD. Handled separately.

# Groups / principals always considered authorized to hold enrollment / modify rights.
$script:AuthorizedPrincipals = @(
    'Domain Admins', 'Enterprise Admins', 'Administrators', 'SYSTEM',
    'Cert Publishers', 'Enterprise Read-only Domain Controllers',
    'NT AUTHORITY\SYSTEM', 'BUILTIN\Administrators'
)

$script:CheckMetadata = @{}
$script:CheckMetadata['Test-ADCSInventory'] = @{ Category = 'Infrastructure'; Frameworks = @('CIS-AD-CS', 'NIST-SC-17') }
$script:CheckMetadata['Test-ADCSEscalation1'] = @{ Category = 'Privileged Access'; Frameworks = @('CIS-AD-CS', 'NIST-SC-17', 'MCSB-IM', 'SOC2-CC6.1') }
$script:CheckMetadata['Test-ADCSEscalation2'] = @{ Category = 'Privileged Access'; Frameworks = @('CIS-AD-CS', 'NIST-SC-17', 'MCSB-IM') }
$script:CheckMetadata['Test-ADCSEscalation3'] = @{ Category = 'Privileged Access'; Frameworks = @('CIS-AD-CS', 'NIST-SC-17') }
$script:CheckMetadata['Test-ADCSEscalation4'] = @{ Category = 'Privileged Access'; Frameworks = @('CIS-AD-CS', 'NIST-AC-6', 'SOC2-CC6.1') }
$script:CheckMetadata['Test-ADCSEscalation5'] = @{ Category = 'Privileged Access'; Frameworks = @('CIS-AD-CS', 'NIST-AC-6', 'SOC2-CC6.1') }
$script:CheckMetadata['Test-ADCSEscalation6'] = @{ Category = 'Authentication'; Frameworks = @('CIS-AD-CS', 'NIST-SC-17', 'SOC2-CC6.1') }
$script:CheckMetadata['Test-ADCSEscalation7'] = @{ Category = 'Privileged Access'; Frameworks = @('CIS-AD-CS', 'NIST-AC-6') }
$script:CheckMetadata['Test-ADCSEscalation8'] = @{ Category = 'Authentication'; Frameworks = @('CIS-AD-CS', 'NIST-SC-17', 'SOC2-CC6.8') }

# Critical-severity escalation list (FAIL -> Critical, not High).
$script:CriticalChecks = @(
    'Test-ADCSEscalation1',  # SAN abuse = instant domain admin
    'Test-ADCSEscalation4',  # Template ACL abuse = create your own ESC1
    'Test-ADCSEscalation6',  # CA-wide EDITF_ATTRIBUTESUBJECTALTNAME2
    'Test-ADCSEscalation8'   # NTLM relay to HTTP enrollment
)

# Findings accumulator - produced via the parent AD module's Add-ADFinding when available.
$script:Findings = @()

#endregion

#region ==================== PRIVATE HELPERS ====================

<#
.SYNOPSIS
    Adds a finding to the accumulator. Mirrors Add-ADFinding from the AD module.
.DESCRIPTION
    Populates the standard EntraChecks schema. Severity is derived from
    Status + the critical-check list; RiskScore from Severity. When the
    parent AD module is loaded (expected case), its Add-ADFinding function
    is reused so findings appear under Source='ActiveDirectory' in the
    unified report, keeping AD CS findings grouped with other AD findings.
#>
function Add-ADCSFinding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$CheckName,
        [Parameter(Mandatory)] [ValidateSet('PASS', 'FAIL', 'WARNING', 'INFO', 'OK')] [string]$Status,
        [Parameter(Mandatory)] [string]$Object,
        [Parameter(Mandatory)] [string]$Description,
        [string]$Remediation = ''
    )

    if ($Status -eq 'OK') { $Status = 'PASS' }

    $meta = $script:CheckMetadata[$CheckName]
    $category = if ($meta) { $meta.Category } else { 'ActiveDirectory' }
    $frameworks = if ($meta) { $meta.Frameworks } else { @() }

    $severity = switch ($Status) {
        'FAIL' { if ($script:CriticalChecks -contains $CheckName) { 'Critical' } else { 'High' } }
        'WARNING' { 'Medium' }
        'PASS' { 'Low' }
        'INFO' { 'Low' }
        default { 'Low' }
    }

    $riskScore = switch ($severity) {
        'Critical' { 90 }
        'High' { 70 }
        'Medium' { 50 }
        'Low' { 10 }
        default { 0 }
    }

    $finding = [pscustomobject]@{
        Time = Get-Date
        CheckName = $CheckName
        Status = $Status
        Severity = $severity
        Category = $category
        Object = $Object
        Description = $Description
        Remediation = $Remediation
        ComplianceFrameworks = $frameworks
        ComplianceReference = ($frameworks -join ', ')
        RiskScore = $riskScore
        Type = "AD_$CheckName"
        Source = 'ActiveDirectory'
    }
    $script:Findings += $finding
}

<#
.SYNOPSIS
    Probes the AD forest for Enterprise CAs.
.DESCRIPTION
    Returns an object describing whether AD CS is deployed and the CAs found.
    Used as the gate for the full ESC check suite.
#>
function Test-ADCSEnvironment {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    $result = [ordered]@{
        HasADCS = $false
        CAs = @()
        Templates = @()
        FailureReason = $null
    }

    try {
        $configNC = (Get-ADRootDSE).configurationNamingContext
        $enrollmentDN = "CN=Enrollment Services,CN=Public Key Services,CN=Services,$configNC"
        $templateDN = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"

        $cas = @(Get-ADObject -SearchBase $enrollmentDN -LDAPFilter '(objectClass=pKIEnrollmentService)' `
                -Properties cn, dNSHostName, certificateTemplates, flags -ErrorAction Stop)

        if ($cas.Count -eq 0) {
            return [pscustomobject]$result
        }

        $templates = @(Get-ADObject -SearchBase $templateDN -LDAPFilter '(objectClass=pKICertificateTemplate)' `
                -Properties cn, displayName, 'msPKI-Certificate-Name-Flag', 'msPKI-Enrollment-Flag', `
                'msPKI-RA-Signature', 'msPKI-Template-Schema-Version', 'pKIExtendedKeyUsage', `
                'msPKI-Private-Key-Flag', flags -ErrorAction SilentlyContinue)

        $result['HasADCS'] = $true
        $result['CAs'] = $cas
        $result['Templates'] = $templates
    }
    catch {
        $result['FailureReason'] = $_.Exception.Message
    }

    return [pscustomobject]$result
}

<#
.SYNOPSIS
    Returns the list of principals with a given right on an AD object's ACL,
    filtered to non-authorized principals.
#>
function Get-UnauthorizedACEs {
    [CmdletBinding()]
    [OutputType([array])]
    param(
        [Parameter(Mandatory)] [string]$DistinguishedName,
        [Parameter(Mandatory)] [string[]]$RightsPattern
    )

    $out = @()
    try {
        $acl = Get-Acl -Path ("AD:\$DistinguishedName") -ErrorAction Stop
    }
    catch {
        return $out
    }

    $joined = ($RightsPattern -join '|')
    foreach ($ace in $acl.Access) {
        if ($ace.ActiveDirectoryRights -match $joined) {
            $identity = [string]$ace.IdentityReference
            $isAuthorized = $false
            foreach ($auth in $script:AuthorizedPrincipals) {
                if ($identity -like "*\$auth" -or $identity -eq $auth) {
                    $isAuthorized = $true
                    break
                }
            }
            if (-not $isAuthorized) {
                $out += $ace
            }
        }
    }
    return $out
}

<#
.SYNOPSIS
    Returns $true if the template's EKU list allows client-authentication
    (or smart-card logon, or any-purpose, or PKINIT).
#>
function Test-TemplateAllowsClientAuth {
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)] [object]$Template)

    $ekus = @($Template.pKIExtendedKeyUsage)
    if (-not $ekus -or $ekus.Count -eq 0) { return $false }

    $targets = @(
        $script:EKU_ClientAuth,
        $script:EKU_SmartCardLogon,
        $script:EKU_AnyPurpose,
        $script:EKU_PkInitClientAuth
    )
    foreach ($e in $ekus) {
        if ($targets -contains $e) { return $true }
    }
    return $false
}

#endregion

#region ==================== INVENTORY ====================

function Test-ADCSInventory {
    <#
    .SYNOPSIS
        INFO-only: enumerates Enterprise CAs and published templates.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [object]$Environment)

    foreach ($ca in $Environment.CAs) {
        Add-ADCSFinding -CheckName 'Test-ADCSInventory' -Status 'INFO' -Object $ca.cn `
            -Description "Enterprise CA: $($ca.cn); host: $($ca.dNSHostName); published templates: $(@($ca.certificateTemplates).Count)" `
            -Remediation 'Reference only. Review the published template list during routine audits.'
    }

    Add-ADCSFinding -CheckName 'Test-ADCSInventory' -Status 'INFO' -Object 'Certificate Templates' `
        -Description "Total published certificate templates in the forest: $($Environment.Templates.Count)" `
        -Remediation 'Reference only.'
}

#endregion

#region ==================== ESC1 - SAN ABUSE ====================

function Test-ADCSEscalation1 {
    <#
    .SYNOPSIS
        ESC1: template allows enrollee to specify SAN, issues client-auth
        certs, requires no manager approval, and is enrollable by non-admins.
    .DESCRIPTION
        Flag combination: (EKU allows client auth) AND (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT
        set on msPKI-Certificate-Name-Flag) AND (CT_FLAG_PEND_ALL_REQUESTS NOT set on
        msPKI-Enrollment-Flag) AND (msPKI-RA-Signature = 0) AND
        (template ACL grants Enroll to a non-admin principal).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [object]$Environment)

    $vulnerable = @()
    foreach ($t in $Environment.Templates) {
        if (-not (Test-TemplateAllowsClientAuth -Template $t)) { continue }

        $nameFlag = [int]([int]$t.'msPKI-Certificate-Name-Flag')
        $enrollFlag = [int]([int]$t.'msPKI-Enrollment-Flag')
        $raSig = if ($null -ne $t.'msPKI-RA-Signature') { [int]$t.'msPKI-RA-Signature' } else { 0 }

        $enrolleeSuppliesSubject = ($nameFlag -band $script:CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT) -ne 0
        $managerApprovalRequired = ($enrollFlag -band $script:CT_FLAG_PEND_ALL_REQUESTS) -ne 0

        if (-not $enrolleeSuppliesSubject) { continue }
        if ($managerApprovalRequired) { continue }
        if ($raSig -gt 0) { continue }

        $unauthEnroll = Get-UnauthorizedACEs -DistinguishedName $t.DistinguishedName `
            -RightsPattern @('ExtendedRight', 'GenericAll', 'GenericWrite', 'WriteProperty')
        if ($unauthEnroll.Count -eq 0) { continue }

        $vulnerable += [pscustomobject]@{
            Template = $t.cn
            NonAdminIdentities = ($unauthEnroll.IdentityReference -join ', ')
            NameFlag = '0x' + $nameFlag.ToString('X')
            EnrollFlag = '0x' + $enrollFlag.ToString('X')
        }

        Add-ADCSFinding -CheckName 'Test-ADCSEscalation1' -Status 'FAIL' -Object $t.cn `
            -Description "ESC1: Template '$($t.cn)' allows enrollee-supplied SAN, issues client-auth certificates, does not require manager approval, and grants enrollment rights to non-admin principal(s): $($unauthEnroll.IdentityReference -join ', '). An attacker holding any of those identities can request a certificate with an arbitrary SAN - effectively impersonating any user including Domain Admin." `
            -Remediation "Remove CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT from the template, OR require manager approval (set CT_FLAG_PEND_ALL_REQUESTS on msPKI-Enrollment-Flag), OR restrict enrollment rights to privileged groups only."
    }

    if ($vulnerable.Count -eq 0) {
        Add-ADCSFinding -CheckName 'Test-ADCSEscalation1' -Status 'PASS' -Object 'All Templates' `
            -Description 'No templates vulnerable to ESC1 detected.' -Remediation 'No action needed.'
    }
}

#endregion

#region ==================== ESC2 - ANY PURPOSE / SUBCA ====================

function Test-ADCSEscalation2 {
    <#
    .SYNOPSIS
        ESC2: "Any Purpose" or SubCA-capable templates enrollable by non-admins.
    .DESCRIPTION
        A template with EKU=AnyPurpose (2.5.29.37.0) or an empty EKU list
        (SubCA-style) can issue certificates for any purpose - including
        client auth even if not explicitly listed. Non-admin enrollment
        rights on such a template equal ESC1.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [object]$Environment)

    $vulnerable = @()
    foreach ($t in $Environment.Templates) {
        $ekus = @($t.pKIExtendedKeyUsage)
        $hasAnyPurpose = $ekus -contains $script:EKU_AnyPurpose
        $isSubCAStyle = ($ekus.Count -eq 0)
        if (-not ($hasAnyPurpose -or $isSubCAStyle)) { continue }

        $unauthEnroll = Get-UnauthorizedACEs -DistinguishedName $t.DistinguishedName `
            -RightsPattern @('ExtendedRight', 'GenericAll', 'GenericWrite', 'WriteProperty')
        if ($unauthEnroll.Count -eq 0) { continue }

        $label = if ($hasAnyPurpose) { 'Any Purpose EKU' } else { 'Empty EKU (SubCA-style)' }
        $vulnerable += $t.cn

        Add-ADCSFinding -CheckName 'Test-ADCSEscalation2' -Status 'FAIL' -Object $t.cn `
            -Description "ESC2: Template '$($t.cn)' has $label and grants enrollment / write rights to non-admin principal(s): $($unauthEnroll.IdentityReference -join ', '). This allows issuing certificates usable for any EKU - including client authentication." `
            -Remediation "Restrict enrollment to privileged groups only, or scope the EKU list to a specific purpose (remove Any Purpose / populate EKU list explicitly)."
    }

    if ($vulnerable.Count -eq 0) {
        Add-ADCSFinding -CheckName 'Test-ADCSEscalation2' -Status 'PASS' -Object 'All Templates' `
            -Description 'No Any-Purpose or SubCA templates enrollable by non-admins.' `
            -Remediation 'No action needed.'
    }
}

#endregion

#region ==================== ESC3 - ENROLLMENT AGENT ====================

function Test-ADCSEscalation3 {
    <#
    .SYNOPSIS
        ESC3: Enrollment Agent templates without proper restrictions.
    .DESCRIPTION
        Templates with EKU including 1.3.6.1.4.1.311.20.2.1 (Certificate Request
        Agent) allow holders to enroll on behalf of other users. Non-admin
        enrollment rights on such a template, without enrollment-agent
        restrictions, enable domain-wide impersonation.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [object]$Environment)

    $vulnerable = @()
    foreach ($t in $Environment.Templates) {
        $ekus = @($t.pKIExtendedKeyUsage)
        if ($ekus -notcontains $script:EKU_CertificateRequestAgent) { continue }

        $unauthEnroll = Get-UnauthorizedACEs -DistinguishedName $t.DistinguishedName `
            -RightsPattern @('ExtendedRight', 'GenericAll', 'GenericWrite', 'WriteProperty')
        if ($unauthEnroll.Count -eq 0) { continue }

        $vulnerable += $t.cn

        Add-ADCSFinding -CheckName 'Test-ADCSEscalation3' -Status 'FAIL' -Object $t.cn `
            -Description "ESC3: Enrollment Agent template '$($t.cn)' is enrollable by non-admin principal(s): $($unauthEnroll.IdentityReference -join ', '). Combined with another template that accepts enrollment-agent requests, this allows impersonation enrollment." `
            -Remediation 'Restrict enrollment-agent template enrollment to a small, highly-privileged group. Configure enrollment agent restrictions on the CA (Issuance Policies / Enrollment Agent tab).'
    }

    if ($vulnerable.Count -eq 0) {
        Add-ADCSFinding -CheckName 'Test-ADCSEscalation3' -Status 'PASS' -Object 'All Templates' `
            -Description 'No unrestricted Enrollment Agent templates detected.' `
            -Remediation 'No action needed.'
    }
}

#endregion

#region ==================== ESC4 - TEMPLATE ACL ABUSE ====================

function Test-ADCSEscalation4 {
    <#
    .SYNOPSIS
        ESC4: non-admin has write access on a template object (enables ESC1 creation).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [object]$Environment)

    $vulnerable = 0
    foreach ($t in $Environment.Templates) {
        $unauthWrite = Get-UnauthorizedACEs -DistinguishedName $t.DistinguishedName `
            -RightsPattern @('GenericAll', 'GenericWrite', 'WriteOwner', 'WriteDacl', 'WriteProperty')
        if ($unauthWrite.Count -eq 0) { continue }
        $vulnerable++

        Add-ADCSFinding -CheckName 'Test-ADCSEscalation4' -Status 'FAIL' -Object $t.cn `
            -Description "ESC4: Template '$($t.cn)' has write-class permissions granted to non-admin principal(s): $($unauthWrite.IdentityReference -join ', '). Any holder of those identities can modify the template to make it ESC1-vulnerable (e.g., enable CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)." `
            -Remediation 'Restrict write-class permissions on every certificate template to Domain Admins, Enterprise Admins, and SYSTEM only.'
    }

    if ($vulnerable -eq 0) {
        Add-ADCSFinding -CheckName 'Test-ADCSEscalation4' -Status 'PASS' -Object 'All Templates' `
            -Description 'No templates with non-admin write permissions.' `
            -Remediation 'No action needed.'
    }
}

#endregion

#region ==================== ESC5 - PKI OBJECT ACL ABUSE ====================

function Test-ADCSEscalation5 {
    <#
    .SYNOPSIS
        ESC5: non-admin has modify rights on CA server / Enrollment Services / PKI containers.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [object]$Environment)

    $configNC = (Get-ADRootDSE).configurationNamingContext
    $targets = @(
        "CN=Enrollment Services,CN=Public Key Services,CN=Services,$configNC",
        "CN=Certification Authorities,CN=Public Key Services,CN=Services,$configNC",
        "CN=AIA,CN=Public Key Services,CN=Services,$configNC",
        "CN=NTAuthCertificates,CN=Public Key Services,CN=Services,$configNC"
    )

    $vulnerable = 0
    foreach ($dn in $targets) {
        $unauth = Get-UnauthorizedACEs -DistinguishedName $dn `
            -RightsPattern @('GenericAll', 'GenericWrite', 'WriteOwner', 'WriteDacl', 'WriteProperty')
        if ($unauth.Count -eq 0) { continue }
        $vulnerable++

        Add-ADCSFinding -CheckName 'Test-ADCSEscalation5' -Status 'FAIL' -Object $dn `
            -Description "ESC5: PKI object '$dn' has write-class permissions granted to non-admin principal(s): $($unauth.IdentityReference -join ', '). This can be leveraged to compromise the CA infrastructure itself." `
            -Remediation 'Restrict write-class permissions on PKI infrastructure containers to Enterprise Admins and SYSTEM only.'
    }

    if ($vulnerable -eq 0) {
        Add-ADCSFinding -CheckName 'Test-ADCSEscalation5' -Status 'PASS' -Object 'PKI Containers' `
            -Description 'No non-admin write permissions on PKI infrastructure containers.' `
            -Remediation 'No action needed.'
    }
}

#endregion

#region ==================== ESC6 - EDITF_ATTRIBUTESUBJECTALTNAME2 ====================

function Test-ADCSEscalation6 {
    <#
    .SYNOPSIS
        ESC6: CA has EDITF_ATTRIBUTESUBJECTALTNAME2 flag set, allowing arbitrary SAN on any request.
    .DESCRIPTION
        Reads the EditFlags value from the CA's Policy\EditFlags registry
        key (HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\
        <CAName>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy).
        The EDITF_ATTRIBUTESUBJECTALTNAME2 bit is 0x40000. If set, every
        template on the CA effectively becomes ESC1-vulnerable (the attacker
        can supply a SAN in the request regardless of template flags).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [object]$Environment)

    $EDITF_ATTRIBUTESUBJECTALTNAME2 = 0x40000

    foreach ($ca in $Environment.CAs) {
        $caHost = $ca.dNSHostName
        $caName = $ca.cn
        try {
            $editFlags = Invoke-Command -ComputerName $caHost -ScriptBlock {
                param($name)
                $path = "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$name\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy"
                (Get-ItemProperty -Path $path -Name EditFlags -ErrorAction Stop).EditFlags
            } -ArgumentList $caName -ErrorAction Stop
        }
        catch {
            Add-ADCSFinding -CheckName 'Test-ADCSEscalation6' -Status 'WARNING' -Object $caName `
                -Description "Unable to read EditFlags from CA '$caName' ($caHost): $($_.Exception.Message). Check is advisory for this CA." `
                -Remediation "Run this check from the CA server directly, or enable PSRemoting to '$caHost'. Verify EditFlags manually: 'certutil -getreg policy\EditFlags'."
            continue
        }

        if (($editFlags -band $EDITF_ATTRIBUTESUBJECTALTNAME2) -ne 0) {
            Add-ADCSFinding -CheckName 'Test-ADCSEscalation6' -Status 'FAIL' -Object $caName `
                -Description "ESC6: CA '$caName' has EDITF_ATTRIBUTESUBJECTALTNAME2 set (EditFlags = 0x$($editFlags.ToString('X'))). EVERY template on this CA is effectively ESC1-vulnerable - attackers can specify arbitrary SAN in any request." `
                -Remediation "On the CA, run: certutil -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2 ; net stop certsvc ; net start certsvc. Then audit all certificates issued while the flag was set."
        }
        else {
            Add-ADCSFinding -CheckName 'Test-ADCSEscalation6' -Status 'PASS' -Object $caName `
                -Description "CA '$caName' does not have EDITF_ATTRIBUTESUBJECTALTNAME2 set (EditFlags = 0x$($editFlags.ToString('X'))). Safe." `
                -Remediation 'No action needed.'
        }
    }
}

#endregion

#region ==================== ESC7 - CA ACL ABUSE ====================

function Test-ADCSEscalation7 {
    <#
    .SYNOPSIS
        ESC7: non-admin has ManageCA or ManageCertificates rights on the CA.
    .DESCRIPTION
        Reads the CA's security descriptor via Invoke-Command on the CA
        server and looks for non-admin principals with ManageCA (which
        allows enabling ESC6 flag, approving pending requests, etc.) or
        ManageCertificates (which allows reissuing / re-enrolling).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [object]$Environment)

    foreach ($ca in $Environment.CAs) {
        $caHost = $ca.dNSHostName
        $caName = $ca.cn
        try {
            $sd = Invoke-Command -ComputerName $caHost -ScriptBlock {
                param($name)
                # Uses certutil's -getreg security output.
                certutil -getreg "CA\$name\Security" 2>&1 | Out-String
            } -ArgumentList $caName -ErrorAction Stop
        }
        catch {
            Add-ADCSFinding -CheckName 'Test-ADCSEscalation7' -Status 'WARNING' -Object $caName `
                -Description "Unable to read CA security descriptor from '$caHost': $($_.Exception.Message). Check is advisory for this CA." `
                -Remediation "Run 'certutil -getreg ca\<CAName>\Security' on the CA directly, or enable PSRemoting."
            continue
        }

        # Heuristic: look for non-admin SIDs granted ManageCA / ManageCertificates.
        # certutil output is semi-structured; we scan for entries that aren't in the authorized list.
        if ($sd -match '(Domain Users|Authenticated Users|Everyone|Users|Domain Computers)' -and
            $sd -match '(ManageCA|ManageCertificates|CA Administrator)') {
            Add-ADCSFinding -CheckName 'Test-ADCSEscalation7' -Status 'FAIL' -Object $caName `
                -Description "ESC7: CA '$caName' appears to grant CA administration rights to a broad principal (Domain Users / Authenticated Users / Everyone / similar). This allows enabling ESC6, issuing arbitrary certificates, etc." `
                -Remediation "On the CA, restrict the CA security descriptor so only Enterprise Admins / specific PKI admins have ManageCA / ManageCertificates. certsrv.msc -> CA Properties -> Security tab."
        }
        else {
            Add-ADCSFinding -CheckName 'Test-ADCSEscalation7' -Status 'PASS' -Object $caName `
                -Description "CA '$caName' security descriptor does not appear to grant broad administrative access." `
                -Remediation 'Confirm manually via certsrv.msc as part of routine audit.'
        }
    }
}

#endregion

#region ==================== ESC8 - NTLM RELAY TO HTTP ENROLLMENT ====================

function Test-ADCSEscalation8 {
    <#
    .SYNOPSIS
        ESC8: web enrollment exposed over HTTP without channel binding / EPA.
    .DESCRIPTION
        Probes each CA for the /certsrv/ HTTP endpoint. If reachable over
        plain HTTP, NTLM relay to that endpoint can issue a client-auth
        cert to the relayed identity. Full verification of EPA/channel
        binding requires IIS config inspection on the CA - out of scope
        here; we WARN on any HTTP reachability.
    .PARAMETER ProbeHTTP
        Default $true. Set to $false to skip the network probe.
    .PARAMETER TimeoutSeconds
        Per-request timeout. Default 10.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object]$Environment,
        [bool]$ProbeHTTP = $true,
        [int]$TimeoutSeconds = 10
    )

    if (-not $ProbeHTTP) {
        Add-ADCSFinding -CheckName 'Test-ADCSEscalation8' -Status 'INFO' -Object 'Web Enrollment' `
            -Description 'HTTP probe skipped (ProbeHTTP=$false).' `
            -Remediation 'Enable the ADCS.ProbeHTTP config flag to probe the /certsrv/ endpoint for HTTP reachability.'
        return
    }

    foreach ($ca in $Environment.CAs) {
        $caHost = $ca.dNSHostName
        $httpUrl = "http://$caHost/certsrv/"
        try {
            $response = Invoke-WebRequest -Uri $httpUrl -UseBasicParsing -TimeoutSec $TimeoutSeconds -ErrorAction Stop
            # Any 200/401/etc from HTTP means the endpoint is reachable over plain HTTP.
            Add-ADCSFinding -CheckName 'Test-ADCSEscalation8' -Status 'FAIL' -Object $caHost `
                -Description "ESC8: Web enrollment endpoint '$httpUrl' responded over plain HTTP (status $($response.StatusCode)). NTLM relay attacks can coerce a DC's machine account into authenticating here, obtaining a client-auth cert as the DC. Verify if HTTPS is enforced and Extended Protection for Authentication (EPA) / channel binding is enabled." `
                -Remediation "Disable HTTP for /certsrv/ (IIS: require SSL). Enable EPA / channel binding for the authentication. Better: remove the Web Enrollment role entirely if not needed."
        }
        catch [System.Net.WebException] {
            $status = $_.Exception.Response.StatusCode.value__
            if ($status) {
                # A 401 / 403 / etc over HTTP still means the endpoint is reachable over HTTP.
                Add-ADCSFinding -CheckName 'Test-ADCSEscalation8' -Status 'FAIL' -Object $caHost `
                    -Description "ESC8: Web enrollment endpoint '$httpUrl' returned HTTP $status over plain HTTP. Endpoint is reachable and susceptible to NTLM relay unless EPA / channel binding is enforced." `
                    -Remediation "Disable HTTP for /certsrv/ (IIS: require SSL). Enable EPA / channel binding. Better: remove the Web Enrollment role if not needed."
            }
            else {
                Add-ADCSFinding -CheckName 'Test-ADCSEscalation8' -Status 'PASS' -Object $caHost `
                    -Description "Web enrollment HTTP probe failed with no response - endpoint likely not exposed over HTTP. ($($_.Exception.Message))" `
                    -Remediation 'No action needed.'
            }
        }
        catch {
            Add-ADCSFinding -CheckName 'Test-ADCSEscalation8' -Status 'WARNING' -Object $caHost `
                -Description "Unable to probe web enrollment endpoint at '$httpUrl': $($_.Exception.Message). Check is advisory." `
                -Remediation 'Verify manually that /certsrv/ requires HTTPS and enforces EPA / channel binding.'
        }
    }
}

#endregion

#region ==================== MAIN ENTRY POINT ====================

<#
.SYNOPSIS
    Runs the AD CS ESC1-8 assessment.
.DESCRIPTION
    Probes for Enterprise CAs first. If none are found, emits a single INFO
    finding and returns. Otherwise runs all 9 checks (inventory + ESC1-8)
    and returns the accumulated findings.
.PARAMETER ProbeHTTP
    Enable the ESC8 HTTP probe. Default $true.
.PARAMETER HTTPProbeTimeoutSeconds
    Per-request timeout for the ESC8 probe. Default 10.
#>
function Invoke-ADCSAssessment {
    [CmdletBinding()]
    [OutputType([array])]
    param(
        [bool]$ProbeHTTP = $true,
        [int]$HTTPProbeTimeoutSeconds = 10
    )

    $script:Findings = @()

    $env = Test-ADCSEnvironment
    if (-not $env.HasADCS) {
        $reason = if ($env.FailureReason) {
            "AD CS environment probe failed: $($env.FailureReason)"
        }
        else {
            'No Enterprise Certificate Authority detected in the forest. AD CS checks skipped.'
        }
        Add-ADCSFinding -CheckName 'Test-ADCSInventory' -Status 'INFO' -Object 'AD CS' `
            -Description $reason `
            -Remediation 'No action needed if AD CS is intentionally not deployed.'
        return , $script:Findings
    }

    try { Test-ADCSInventory -Environment $env } catch { Write-Verbose "Inventory: $_" }
    try { Test-ADCSEscalation1 -Environment $env } catch { Write-Verbose "ESC1: $_" }
    try { Test-ADCSEscalation2 -Environment $env } catch { Write-Verbose "ESC2: $_" }
    try { Test-ADCSEscalation3 -Environment $env } catch { Write-Verbose "ESC3: $_" }
    try { Test-ADCSEscalation4 -Environment $env } catch { Write-Verbose "ESC4: $_" }
    try { Test-ADCSEscalation5 -Environment $env } catch { Write-Verbose "ESC5: $_" }
    try { Test-ADCSEscalation6 -Environment $env } catch { Write-Verbose "ESC6: $_" }
    try { Test-ADCSEscalation7 -Environment $env } catch { Write-Verbose "ESC7: $_" }
    try { Test-ADCSEscalation8 -Environment $env -ProbeHTTP $ProbeHTTP -TimeoutSeconds $HTTPProbeTimeoutSeconds } catch { Write-Verbose "ESC8: $_" }

    return , $script:Findings
}

#endregion

#region ==================== MODULE EXPORTS ====================

Export-ModuleMember -Function @(
    'Invoke-ADCSAssessment',
    'Test-ADCSEnvironment',
    'Test-ADCSInventory',
    'Test-ADCSEscalation1',
    'Test-ADCSEscalation2',
    'Test-ADCSEscalation3',
    'Test-ADCSEscalation4',
    'Test-ADCSEscalation5',
    'Test-ADCSEscalation6',
    'Test-ADCSEscalation7',
    'Test-ADCSEscalation8'
)

#endregion
