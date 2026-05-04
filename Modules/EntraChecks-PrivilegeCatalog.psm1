<#
.SYNOPSIS
    EntraChecks-PrivilegeCatalog.psm1
    Authoritative catalog of every privileged role, group, ACL path, and app
    permission EntraChecks recognises — with tier classification, why-it-matters
    explanations, and attack-path hints.

.DESCRIPTION
    The catalog answers two auditor questions at once:
        1. Is this assignment privileged?     -> Surface, Tier, Sensitivity
        2. Why is it privileged?              -> WhyPrivileged + AttackPaths

    Used by:
        - Privileged Identity Roster aggregators (PR 2 AD, PR 3 Entra)
        - Cross-surface correlator (PR 4)
        - Report rendering (PR 5)

    Adding a new privilege = one entry in $script:PrivilegeCatalog.

.NOTES
    Tier model (canonical):
        0 — Forest/tenant-wide compromise. DA, EA, Schema, BUILTIN\Administrators,
            Global Administrator, Privileged Role Administrator, Privileged
            Authentication Administrator, Hybrid Identity Administrator,
            DCSync rights, AdminSDHolder writers, krbtgt.
        1 — Service-tier admin. Account/Backup/Server/Print Operators,
            DnsAdmins, Cert Publishers, Group Policy Creator Owners, Exchange
            Administrator, SharePoint Administrator, Teams Administrator,
            Compliance Administrator, Security Administrator, Application
            Administrator, Cloud Application Administrator, Intune
            Administrator, Conditional Access Administrator, User
            Administrator.
        2 — Targeted-user/limited-scope admin. Helpdesk Administrator,
            Authentication Administrator, Reports Reader, etc.
    Service — non-human identities (service principals, gMSAs).

.LINK
    Microsoft tier model: https://learn.microsoft.com/en-us/security/privileged-access-workstations/privileged-access-access-model
    Entra built-in roles: https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference
#>

#Requires -Version 5.1

$script:ModuleVersion = '1.0.0'
$script:ModuleName = 'EntraChecks-PrivilegeCatalog'

#region ==================== CATALOG ====================

# Each entry follows a fixed schema:
#   Key           — canonical "<Surface>:<Identifier>" string. Stable join key.
#   Surface       — 'AD' | 'Entra' | 'MSGraph' | 'App'
#   DisplayName   — what an auditor would call it
#   Aliases       — alternate names (handles localisation, common shorthand)
#   Tier          — 0 (critical) | 1 (high) | 2 (medium) | 'Service'
#   Sensitivity   — 'Critical' | 'High' | 'Medium' (drives finding severity)
#   WhyPrivileged — 1-paragraph plain-English explanation of what holding this
#                   privilege actually lets a principal do.
#   AttackPaths   — short list of named attack techniques unlocked
#   ExpectedControls — controls that should gate this privilege (PIM, MFA, etc.)
#   ReferenceUrl  — single link an auditor can follow

$script:PrivilegeCatalog = @{

    #region ---- AD privileged groups ----

    'AD:DomainAdmins' = @{
        Key = 'AD:DomainAdmins'
        Surface = 'AD'
        DisplayName = 'Domain Admins'
        Aliases = @('Domain Admins', 'DA')
        Tier = 0
        Sensitivity = 'Critical'
        WhyPrivileged = 'Members can manage every domain-joined workstation and server via Group Policy and remote management, modify any user/group, reset most passwords, and extract password hashes via DCSync (every member is implicitly granted Replicating Directory Changes / All).'
        AttackPaths = @(
            'DCSync — extract krbtgt and arbitrary user hashes',
            'Group Policy preference deployment for lateral movement',
            'AdminSDHolder ACL injection for persistence',
            'Skeleton key / DSRM password reset on domain controllers'
        )
        ExpectedControls = @('PIM/JIT or eligible-only', 'MFA on logon', 'Smart card required', 'Protected Users membership', 'Tier-0 PAW (privileged access workstation)')
        ReferenceUrl = 'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory'
    }

    'AD:EnterpriseAdmins' = @{
        Key = 'AD:EnterpriseAdmins'
        Surface = 'AD'
        DisplayName = 'Enterprise Admins'
        Aliases = @('Enterprise Admins', 'EA')
        Tier = 0
        Sensitivity = 'Critical'
        WhyPrivileged = 'Forest-wide super-user. Members hold administrative rights in every domain of the forest, can modify the configuration partition, manage trusts, and perform schema-affecting operations indirectly. The most powerful built-in group in AD.'
        AttackPaths = @(
            'Cross-domain compromise via configuration-partition writes',
            'Forest-wide DCSync',
            'Trust manipulation for cross-forest access'
        )
        ExpectedControls = @('PIM/JIT or eligible-only', 'MFA', 'Smart card required', 'Empty during steady-state operations', 'Tier-0 PAW')
        ReferenceUrl = 'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory'
    }

    'AD:SchemaAdmins' = @{
        Key = 'AD:SchemaAdmins'
        Surface = 'AD'
        DisplayName = 'Schema Admins'
        Aliases = @('Schema Admins')
        Tier = 0
        Sensitivity = 'Critical'
        WhyPrivileged = 'Members can modify the AD schema — the global definition of every object class and attribute in the forest. Schema changes are forest-wide and largely irreversible, and a malicious schema change can introduce hidden persistence (e.g., shadow attributes that bypass auditing).'
        AttackPaths = @(
            'Schema-level persistence (custom attributes outside audit scope)',
            'Defaultsecuritydescriptor manipulation on object classes'
        )
        ExpectedControls = @('Empty during steady-state operations', 'Add only for the duration of a schema change, then remove', 'Tier-0 PAW')
        ReferenceUrl = 'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory'
    }

    'AD:Administrators' = @{
        Key = 'AD:Administrators'
        Surface = 'AD'
        DisplayName = 'BUILTIN\Administrators'
        Aliases = @('Administrators', 'BUILTIN\Administrators', 'Builtin Administrators')
        Tier = 0
        Sensitivity = 'Critical'
        WhyPrivileged = 'Domain-level Administrators group. Members have full administrative rights to every domain controller and to the domain root container. Equivalent to Domain Admins for most practical purposes; nests Domain Admins and Enterprise Admins by default.'
        AttackPaths = @(
            'Direct admin access to every DC',
            'DCSync via inherited replication rights',
            'GPO modification on domain root'
        )
        ExpectedControls = @('PIM/JIT', 'MFA', 'Tier-0 PAW', 'Protected Users')
        ReferenceUrl = 'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory'
    }

    'AD:AccountOperators' = @{
        Key = 'AD:AccountOperators'
        Surface = 'AD'
        DisplayName = 'Account Operators'
        Aliases = @('Account Operators')
        Tier = 1
        Sensitivity = 'High'
        WhyPrivileged = 'Members can create, modify, and delete user, group, and computer accounts in the domain (except built-in admin objects). Membership is widely abused as a stepping stone — Account Operators can in turn create accounts and add them to less-watched privileged groups.'
        AttackPaths = @(
            'Create a backdoor account and add it to delegated-rights groups',
            'Compromise less-protected admin accounts via password reset',
            'Computer-account creation for resource-based delegation abuse'
        )
        ExpectedControls = @('PIM/JIT', 'Replace with scoped delegation', 'MFA')
        ReferenceUrl = 'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory'
    }

    'AD:BackupOperators' = @{
        Key = 'AD:BackupOperators'
        Surface = 'AD'
        DisplayName = 'Backup Operators'
        Aliases = @('Backup Operators')
        Tier = 1
        Sensitivity = 'High'
        WhyPrivileged = 'Members hold the SeBackupPrivilege and SeRestorePrivilege on domain controllers, which lets them read any file on a DC including the NTDS.dit database. With NTDS.dit + the SYSTEM hive, an attacker extracts every domain credential offline.'
        AttackPaths = @(
            'NTDS.dit theft -> offline credential extraction (entire domain)',
            'SYSVOL / GPP password retrieval',
            'Certificate-store theft on DCs'
        )
        ExpectedControls = @('PIM/JIT', 'MFA', 'Audited backup-operations workflow', 'Replace with delegated backup service account where possible')
        ReferenceUrl = 'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory'
    }

    'AD:ServerOperators' = @{
        Key = 'AD:ServerOperators'
        Surface = 'AD'
        DisplayName = 'Server Operators'
        Aliases = @('Server Operators')
        Tier = 1
        Sensitivity = 'High'
        WhyPrivileged = 'Members can log on locally to domain controllers and start/stop services. Local logon to a DC is effectively Tier 0 — anyone who can run code on a DC with elevated rights can dump LSASS, install a service, or schedule a task that runs as SYSTEM.'
        AttackPaths = @(
            'LSASS dumping on a DC',
            'Service installation for persistence',
            'Local privilege escalation via misconfigured service binaries'
        )
        ExpectedControls = @('Empty in modern AD designs (servers managed via SCCM/Intune)', 'PIM/JIT if used', 'MFA')
        ReferenceUrl = 'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory'
    }

    'AD:PrintOperators' = @{
        Key = 'AD:PrintOperators'
        Surface = 'AD'
        DisplayName = 'Print Operators'
        Aliases = @('Print Operators')
        Tier = 1
        Sensitivity = 'High'
        WhyPrivileged = 'Members can load and unload device drivers on domain controllers. A malicious printer driver runs as SYSTEM on the DC — historic source of multiple privilege-escalation CVEs (PrintNightmare et al.).'
        AttackPaths = @(
            'Malicious printer driver -> SYSTEM on DC',
            'Driver-based rootkit deployment'
        )
        ExpectedControls = @('Empty', 'Manage printers from member servers, not DCs')
        ReferenceUrl = 'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory'
    }

    'AD:DnsAdmins' = @{
        Key = 'AD:DnsAdmins'
        Surface = 'AD'
        DisplayName = 'DnsAdmins'
        Aliases = @('DnsAdmins', 'DNSAdmins', 'DNS Admins')
        Tier = 1
        Sensitivity = 'High'
        WhyPrivileged = 'On legacy DC OS versions, DnsAdmins members can load arbitrary DLLs into the DNS service via the ServerLevelPluginDll registry value (CVE-2021-40469-class). The DNS service runs on domain controllers as SYSTEM, so this is a one-step DC compromise. Mitigated on Server 2019+ by default ACL changes.'
        AttackPaths = @(
            'ServerLevelPluginDll abuse -> SYSTEM on DC (legacy OS)',
            'DNS record manipulation for ADIDNS-based MITM'
        )
        ExpectedControls = @('Server 2019+ DCs (mitigated default)', 'Empty group on legacy hosts', 'Audit registry change on dnsserver key')
        ReferenceUrl = 'https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/dns-rce-vulnerability-on-domain-controllers'
    }

    'AD:CertPublishers' = @{
        Key = 'AD:CertPublishers'
        Surface = 'AD'
        DisplayName = 'Cert Publishers'
        Aliases = @('Cert Publishers')
        Tier = 1
        Sensitivity = 'High'
        WhyPrivileged = 'Members publish certificates to the userCertificate attribute of AD objects. In an environment with PKINIT-friendly templates, this can be parlayed into ESC-class certificate-based authentication abuses (ESC1 / ESC4 / ESC8) and credential forging.'
        AttackPaths = @(
            'Certificate-based persistence (ESC1/ESC4)',
            'NTLM relay to AD CS endpoints (ESC8)'
        )
        ExpectedControls = @('AD CS hardening (ESC mitigations)', 'Restrict CA enrollment to issuance officers')
        ReferenceUrl = 'https://posts.specterops.io/certified-pre-owned-d95910965cd2'
    }

    'AD:GroupPolicyCreatorOwners' = @{
        Key = 'AD:GroupPolicyCreatorOwners'
        Surface = 'AD'
        DisplayName = 'Group Policy Creator Owners'
        Aliases = @('Group Policy Creator Owners', 'GPO Creators')
        Tier = 1
        Sensitivity = 'High'
        WhyPrivileged = 'Members can create new Group Policy Objects. Combined with link rights on a privileged OU, this is a path to push code to every machine in scope. Even without link rights, an attacker who creates a GPO can sometimes wait for an admin to link it.'
        AttackPaths = @(
            'GPO injection for code execution at scope',
            'Group Policy Preferences password recovery from cached gpp.xml'
        )
        ExpectedControls = @('Audit GPO creation events', 'Restrict to GPO admins only', 'MFA')
        ReferenceUrl = 'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory'
    }

    'AD:PreWindows2000Compat' = @{
        Key = 'AD:PreWindows2000Compat'
        Surface = 'AD'
        DisplayName = 'Pre-Windows 2000 Compatible Access'
        Aliases = @('Pre-Windows 2000 Compatible Access', 'Pre-Windows 2000', 'Pre-Win2K')
        Tier = 1
        Sensitivity = 'High'
        WhyPrivileged = 'Legacy compatibility group. When it contains "Anonymous Logon" or "Authenticated Users", every authenticated principal (including computer accounts) can read most user attributes, group memberships, and group policy preferences — useful reconnaissance and a stepping stone for downstream credential discovery (LAPS values, GPP passwords).'
        AttackPaths = @(
            'Mass attribute enumeration without admin rights',
            'GPP password discovery if SYSVOL contains legacy preferences'
        )
        ExpectedControls = @('Remove Anonymous Logon and Authenticated Users', 'Use only when explicitly required by legacy app')
        ReferenceUrl = 'https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/security-changes-pre-windows-2000-compatible'
    }

    #endregion

    #region ---- AD privileged paths (ACL/object-level, not group-membership) ----

    'AD:DCSyncRights' = @{
        Key = 'AD:DCSyncRights'
        Surface = 'AD'
        DisplayName = 'DCSync rights (Replicating Directory Changes / All)'
        Aliases = @('DCSync', 'Replicating Directory Changes', 'Replicating Directory Changes All', 'DS-Replication-Get-Changes', 'DS-Replication-Get-Changes-All')
        Tier = 0
        Sensitivity = 'Critical'
        WhyPrivileged = 'A principal holding the Replicating Directory Changes and Replicating Directory Changes All extended rights on the domain root can request domain-wide replication data via the Microsoft Directory Replication Service Remote Protocol (MS-DRSR). That includes every secret hash in the domain — krbtgt, all users, all computers — without ever needing to be in a built-in admin group.'
        AttackPaths = @(
            'Domain-wide hash extraction via mimikatz lsadump::dcsync',
            'Golden Ticket forgery using the extracted krbtgt hash',
            'Stealth credential theft (no membership audit-trail)'
        )
        ExpectedControls = @('Restrict the right to DCs and a single audited backup account', 'Audit replication API calls', 'Tier-0 logging pipeline')
        ReferenceUrl = 'https://attack.mitre.org/techniques/T1003/006/'
    }

    'AD:AdminSDHolderWriter' = @{
        Key = 'AD:AdminSDHolderWriter'
        Surface = 'AD'
        DisplayName = 'AdminSDHolder writer (non-default ACE)'
        Aliases = @('AdminSDHolder', 'AdminSDHolder ACL')
        Tier = 0
        Sensitivity = 'Critical'
        WhyPrivileged = 'AdminSDHolder is the ACL template AD copies onto every protected (privileged) account every 60 minutes via SDProp. A principal with write access to AdminSDHolder can inject an ACE that gets stamped onto every Domain Admin within an hour — silent, repeating, persistence-grade privilege escalation.'
        AttackPaths = @(
            'ACE injection -> propagated to all Tier-0 accounts on next SDProp run',
            'Persistence that survives password resets'
        )
        ExpectedControls = @('Restore default ACL', 'Audit any modification of CN=AdminSDHolder', 'Tier-0 only')
        ReferenceUrl = 'https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory'
    }

    'AD:KrbTgt' = @{
        Key = 'AD:KrbTgt'
        Surface = 'AD'
        DisplayName = 'krbtgt account'
        Aliases = @('krbtgt')
        Tier = 0
        Sensitivity = 'Critical'
        WhyPrivileged = 'The krbtgt account holds the secret used to sign every Kerberos TGT in the domain. Compromise of its hash enables Golden Ticket attacks: an attacker can forge a TGT for any user, with arbitrary group membership, that authenticates against any service in the domain for the validity period (default 10 hours).'
        AttackPaths = @(
            'Golden Ticket forgery — forge tickets for any principal',
            'Persistent TGT issuance even after every other credential is rotated'
        )
        ExpectedControls = @('Rotate password twice (with 10+ hour gap) on any DA compromise', 'Rotate every 180 days even without incident', 'Disable account, never log on interactively')
        ReferenceUrl = 'https://attack.mitre.org/techniques/T1558/001/'
    }

    'AD:ProtectedUsersMember' = @{
        Key = 'AD:ProtectedUsersMember'
        Surface = 'AD'
        DisplayName = 'Protected Users (member)'
        Aliases = @('Protected Users')
        Tier = 'Service'
        Sensitivity = 'Medium'
        WhyPrivileged = 'Membership in Protected Users is itself a control, not a privilege — it disables NTLM, Kerberos delegation, and weak ciphers for the member. Listed here because the roster surfaces it as a positive signal next to a privileged identity (a Tier-0 admin in Protected Users is doing it right).'
        AttackPaths = @()
        ExpectedControls = @('All Tier-0 admins should be members')
        ReferenceUrl = 'https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group'
    }

    #endregion

    #region ---- Entra built-in directory roles ----

    'Entra:GlobalAdministrator' = @{
        Key = 'Entra:GlobalAdministrator'
        Surface = 'Entra'
        DisplayName = 'Global Administrator'
        Aliases = @('Global Administrator', 'Global Admin', 'Company Administrator', 'GA')
        Tier = 0
        Sensitivity = 'Critical'
        WhyPrivileged = 'Tenant-wide super-user. Can read and modify every Entra ID object, every M365 service configuration, every Conditional Access policy, every license, and every other administrator role assignment. The single most powerful role in the M365 stack.'
        AttackPaths = @(
            'Backdoor-account creation across all M365 services',
            'Conditional Access policy disablement',
            'Federation/IdP injection for persistence',
            'Application consent grants on behalf of all users'
        )
        ExpectedControls = @('PIM eligibility (no permanent assignments)', 'MFA', 'Phishing-resistant authentication', 'Break-glass policy for the count (typically 2-4 emergency accounts)')
        ReferenceUrl = 'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference#global-administrator'
    }

    'Entra:PrivilegedRoleAdministrator' = @{
        Key = 'Entra:PrivilegedRoleAdministrator'
        Surface = 'Entra'
        DisplayName = 'Privileged Role Administrator'
        Aliases = @('Privileged Role Administrator')
        Tier = 0
        Sensitivity = 'Critical'
        WhyPrivileged = 'Manages every directory role assignment, including who is Global Administrator. Functionally equivalent to GA via one extra step — a Privileged Role Admin can grant themselves GA at will.'
        AttackPaths = @(
            'Self-elevation to Global Administrator',
            'Stealth assignment of admin roles to attacker-controlled accounts'
        )
        ExpectedControls = @('PIM eligibility', 'MFA', 'Audit every role assignment')
        ReferenceUrl = 'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference#privileged-role-administrator'
    }

    'Entra:PrivilegedAuthenticationAdministrator' = @{
        Key = 'Entra:PrivilegedAuthenticationAdministrator'
        Surface = 'Entra'
        DisplayName = 'Privileged Authentication Administrator'
        Aliases = @('Privileged Authentication Administrator')
        Tier = 0
        Sensitivity = 'Critical'
        WhyPrivileged = 'Can reset MFA methods, change passwords, and revoke sessions for any user, including other administrators. Bypasses the MFA-protection-of-admin assumption — an attacker with this role can disable an admin''s MFA, set a known password, and sign in as them.'
        AttackPaths = @(
            'MFA reset on Global Admin -> credential takeover',
            'Session revocation as a denial-of-access weapon'
        )
        ExpectedControls = @('PIM eligibility', 'MFA', 'Restrict to a tiny operations team')
        ReferenceUrl = 'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference#privileged-authentication-administrator'
    }

    'Entra:HybridIdentityAdministrator' = @{
        Key = 'Entra:HybridIdentityAdministrator'
        Surface = 'Entra'
        DisplayName = 'Hybrid Identity Administrator'
        Aliases = @('Hybrid Identity Administrator')
        Tier = 0
        Sensitivity = 'Critical'
        WhyPrivileged = 'Configures Entra Connect / cloud sync. Owns the channel that synchronises on-prem AD to Entra. Compromise enables both inbound (sync hijack) and outbound (write-back to AD) attacks, and the operational state of the sync engine touches every hybrid identity.'
        AttackPaths = @(
            'Modify sync rules to elevate cloud accounts',
            'Disable filtering to expose previously-scoped objects',
            'Federation tampering for SAML-token forgery'
        )
        ExpectedControls = @('PIM eligibility', 'MFA', 'Tier-0 PAW for sync server administration')
        ReferenceUrl = 'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference#hybrid-identity-administrator'
    }

    'Entra:PartnerTier2Support' = @{
        Key = 'Entra:PartnerTier2Support'
        Surface = 'Entra'
        DisplayName = 'Partner Tier2 Support'
        Aliases = @('Partner Tier2 Support')
        Tier = 0
        Sensitivity = 'Critical'
        WhyPrivileged = 'Hidden role assigned to CSP/partner tenants under DAP/GDAP. Can reset any user password including Global Admins. Most tenants do not realise this role is even assigned; abuse via partner-tenant compromise is a documented intrusion path.'
        AttackPaths = @(
            'Partner-tenant compromise -> tenant takeover (Nobelium pattern)',
            'GA password reset without alerting'
        )
        ExpectedControls = @('Audit GDAP relationships quarterly', 'Remove DAP', 'Granular GDAP only')
        ReferenceUrl = 'https://learn.microsoft.com/en-us/partner-center/customers/transition-from-dap-to-gdap'
    }

    'Entra:UserAdministrator' = @{
        Key = 'Entra:UserAdministrator'
        Surface = 'Entra'
        DisplayName = 'User Administrator'
        Aliases = @('User Administrator')
        Tier = 1
        Sensitivity = 'High'
        WhyPrivileged = 'Creates and manages users and groups, and resets passwords for non-admin users. Cannot reset admin passwords on its own (use Privileged Authentication Administrator for that), but can create accounts and add them to groups that hold delegated rights — common privilege-escalation stepping-stone.'
        AttackPaths = @(
            'Backdoor-account creation in delegated-rights groups',
            'Bulk-password-reset spray (non-admin scope)'
        )
        ExpectedControls = @('PIM', 'MFA', 'Audit user-creation events')
        ReferenceUrl = 'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference#user-administrator'
    }

    'Entra:AuthenticationAdministrator' = @{
        Key = 'Entra:AuthenticationAdministrator'
        Surface = 'Entra'
        DisplayName = 'Authentication Administrator'
        Aliases = @('Authentication Administrator')
        Tier = 1
        Sensitivity = 'High'
        WhyPrivileged = 'Resets credentials and MFA methods for non-admin users. Limited compared to Privileged Authentication Administrator (which covers admins), but still able to silently take over any standard user account.'
        AttackPaths = @(
            'Targeted account takeover of high-value non-admin users (CFO, finance ops)',
            'Phishing recovery as a vector for malware persistence'
        )
        ExpectedControls = @('PIM', 'MFA', 'Audit MFA-reset events')
        ReferenceUrl = 'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference#authentication-administrator'
    }

    'Entra:HelpdeskAdministrator' = @{
        Key = 'Entra:HelpdeskAdministrator'
        Surface = 'Entra'
        DisplayName = 'Helpdesk Administrator'
        Aliases = @('Helpdesk Administrator', 'Password Administrator')
        Tier = 2
        Sensitivity = 'Medium'
        WhyPrivileged = 'Resets passwords for non-admin users. Common helpdesk-tier role. Lower blast radius than Authentication Administrator (no MFA reset), but at scale (large helpdesk team), the cumulative attack surface is meaningful.'
        AttackPaths = @(
            'Targeted password reset for account takeover',
            'Cumulative risk from broad assignment'
        )
        ExpectedControls = @('PIM', 'MFA', 'Scope down via Administrative Units')
        ReferenceUrl = 'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference#helpdesk-administrator'
    }

    'Entra:ApplicationAdministrator' = @{
        Key = 'Entra:ApplicationAdministrator'
        Surface = 'Entra'
        DisplayName = 'Application Administrator'
        Aliases = @('Application Administrator')
        Tier = 1
        Sensitivity = 'High'
        WhyPrivileged = 'Creates and configures app registrations and service principals, including credentials. With a malicious app registration plus user/admin consent, an attacker has a persistent OAuth-based path back into the tenant. Self-elevation paths exist via app-role assignments.'
        AttackPaths = @(
            'Malicious app registration with admin-consent permissions',
            'Client-secret addition to existing privileged SP for impersonation',
            'OAuth-based persistent access surviving credential rotation'
        )
        ExpectedControls = @('PIM', 'MFA', 'Disable user consent or restrict to verified publishers', 'Audit app-credential creation')
        ReferenceUrl = 'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference#application-administrator'
    }

    'Entra:CloudApplicationAdministrator' = @{
        Key = 'Entra:CloudApplicationAdministrator'
        Surface = 'Entra'
        DisplayName = 'Cloud Application Administrator'
        Aliases = @('Cloud Application Administrator')
        Tier = 1
        Sensitivity = 'High'
        WhyPrivileged = 'Same as Application Administrator but scoped to cloud-only apps (excludes on-prem app proxy). Same attack surface for app-credential abuse.'
        AttackPaths = @(
            'Malicious cloud app registration',
            'Privileged-app credential injection'
        )
        ExpectedControls = @('PIM', 'MFA', 'Audit app-credential creation')
        ReferenceUrl = 'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference#cloud-application-administrator'
    }

    'Entra:ConditionalAccessAdministrator' = @{
        Key = 'Entra:ConditionalAccessAdministrator'
        Surface = 'Entra'
        DisplayName = 'Conditional Access Administrator'
        Aliases = @('Conditional Access Administrator')
        Tier = 1
        Sensitivity = 'High'
        WhyPrivileged = 'Reads, creates, and modifies Conditional Access policies — the primary access-control plane in Entra. A malicious policy can disable MFA enforcement for an attacker IP range, exclude an admin from CA, or block legitimate access (DoS).'
        AttackPaths = @(
            'CA policy carve-out for attacker IP / device',
            'Bulk-disable MFA on legacy authentication paths',
            'Denial-of-access via overly-restrictive blanket policies'
        )
        ExpectedControls = @('PIM', 'MFA', 'Two-person review for CA changes', 'Audit policy modifications')
        ReferenceUrl = 'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference#conditional-access-administrator'
    }

    'Entra:SecurityAdministrator' = @{
        Key = 'Entra:SecurityAdministrator'
        Surface = 'Entra'
        DisplayName = 'Security Administrator'
        Aliases = @('Security Administrator')
        Tier = 1
        Sensitivity = 'High'
        WhyPrivileged = 'Manages security-related features: Defender for Cloud Apps, Identity Protection, Conditional Access (read), Privileged Identity Management. Can investigate and respond to alerts, modify many security policies, and (critically) disable security signal sources to cover an attack.'
        AttackPaths = @(
            'Disable Identity Protection policies during an attack',
            'Suppress alerts in Defender XDR',
            'Modify or disable Sign-in Risk policies'
        )
        ExpectedControls = @('PIM', 'MFA', 'Alert on configuration changes')
        ReferenceUrl = 'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference#security-administrator'
    }

    'Entra:ExchangeAdministrator' = @{
        Key = 'Entra:ExchangeAdministrator'
        Surface = 'Entra'
        DisplayName = 'Exchange Administrator'
        Aliases = @('Exchange Administrator', 'Exchange Online Administrator')
        Tier = 1
        Sensitivity = 'High'
        WhyPrivileged = 'Full administrative control over Exchange Online. Read every mailbox, configure transport rules (silent forwarding), modify mail-flow, set inbox rules on any mailbox. The classic BEC and exfiltration vector.'
        AttackPaths = @(
            'Mailbox forwarding rule for exfiltration',
            'Transport-rule injection for tag-based phishing bypass',
            'Mailbox export request -> bulk PST exfil'
        )
        ExpectedControls = @('PIM', 'MFA', 'Alert on transport-rule and mailbox-permission changes', 'Audit mailbox export')
        ReferenceUrl = 'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference#exchange-administrator'
    }

    'Entra:SharePointAdministrator' = @{
        Key = 'Entra:SharePointAdministrator'
        Surface = 'Entra'
        DisplayName = 'SharePoint Administrator'
        Aliases = @('SharePoint Administrator')
        Tier = 1
        Sensitivity = 'High'
        WhyPrivileged = 'Full SharePoint Online and OneDrive admin. Can grant themselves access to any site, modify sharing policies, and run the eDiscovery API. Where regulated data lives in SharePoint, this role is effectively read-everything.'
        AttackPaths = @(
            'Self-grant of site-collection admin to any site',
            'External-sharing policy disablement (data exfil)',
            'OneDrive content extraction across users'
        )
        ExpectedControls = @('PIM', 'MFA', 'External-sharing alerts')
        ReferenceUrl = 'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference#sharepoint-administrator'
    }

    'Entra:TeamsAdministrator' = @{
        Key = 'Entra:TeamsAdministrator'
        Surface = 'Entra'
        DisplayName = 'Teams Administrator'
        Aliases = @('Teams Administrator')
        Tier = 1
        Sensitivity = 'High'
        WhyPrivileged = 'Full admin over Microsoft Teams: messaging, calling, meeting, federation, and policies. Can modify external-access settings (federation with arbitrary tenants) and configure call-recording policies — both are exfiltration vectors.'
        AttackPaths = @(
            'External-access policy widening for federation-based exfil',
            'Recording-policy injection for meeting interception'
        )
        ExpectedControls = @('PIM', 'MFA')
        ReferenceUrl = 'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference#teams-administrator'
    }

    'Entra:ComplianceAdministrator' = @{
        Key = 'Entra:ComplianceAdministrator'
        Surface = 'Entra'
        DisplayName = 'Compliance Administrator'
        Aliases = @('Compliance Administrator')
        Tier = 1
        Sensitivity = 'High'
        WhyPrivileged = 'Full read access in Microsoft Purview Compliance Manager, including content searches and eDiscovery. A Compliance Admin can search every mailbox, every SharePoint site, and every OneDrive in the tenant. Read-everything role.'
        AttackPaths = @(
            'Bulk content-search-based exfiltration',
            'eDiscovery hold abuse for legal-data interception'
        )
        ExpectedControls = @('PIM', 'MFA', 'Two-person eDiscovery workflow')
        ReferenceUrl = 'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference#compliance-administrator'
    }

    'Entra:IntuneAdministrator' = @{
        Key = 'Entra:IntuneAdministrator'
        Surface = 'Entra'
        DisplayName = 'Intune Administrator'
        Aliases = @('Intune Administrator', 'Intune Service Administrator')
        Tier = 1
        Sensitivity = 'High'
        WhyPrivileged = 'Full admin of Intune device management. Can deploy scripts and apps to every managed device — equivalent to "remote code execution on the fleet." Common ransomware-style detonation path once tenant credentials are obtained.'
        AttackPaths = @(
            'Malicious app or script deployment to all managed devices',
            'Wipe-everything as denial-of-service / coverup',
            'Compliance policy manipulation to bypass CA device controls'
        )
        ExpectedControls = @('PIM', 'MFA', 'Two-person review for fleet-wide deployments')
        ReferenceUrl = 'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference#intune-administrator'
    }

    'Entra:ReportsReader' = @{
        Key = 'Entra:ReportsReader'
        Surface = 'Entra'
        DisplayName = 'Reports Reader'
        Aliases = @('Reports Reader')
        Tier = 2
        Sensitivity = 'Medium'
        WhyPrivileged = 'Reads sign-in logs, audit logs, and usage reports for the entire tenant. Not destructive, but a reconnaissance goldmine for an attacker — sign-in logs reveal who admins are, what apps they use, and where they sign in from.'
        AttackPaths = @(
            'Pre-attack reconnaissance (admin identification, location patterns)',
            'Detection-evasion (knowing what gets logged)'
        )
        ExpectedControls = @('PIM', 'MFA')
        ReferenceUrl = 'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference#reports-reader'
    }

    'Entra:GlobalReader' = @{
        Key = 'Entra:GlobalReader'
        Surface = 'Entra'
        DisplayName = 'Global Reader'
        Aliases = @('Global Reader')
        Tier = 2
        Sensitivity = 'Medium'
        WhyPrivileged = 'Read-only counterpart of Global Administrator. Can see configuration of every M365 service, every Conditional Access policy, every Defender setting. Pure reconnaissance role — no destructive capability — but the breadth of visibility makes it a Tier-2 listing rather than ignored.'
        AttackPaths = @(
            'Comprehensive tenant reconnaissance',
            'Enumeration of admin roles and CA gaps'
        )
        ExpectedControls = @('PIM', 'MFA')
        ReferenceUrl = 'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference#global-reader'
    }

    #endregion

    #region ---- High-privilege Microsoft Graph app permissions (curated) ----

    # Curated to the ~20 most dangerous app-role permissions. These are the
    # permissions that, granted to a service principal with admin consent, give
    # the SP capability equivalent to a Tier-0 or Tier-1 admin without holding
    # any directory role.

    'MSGraph:Directory.ReadWrite.All' = @{
        Key = 'MSGraph:Directory.ReadWrite.All'
        Surface = 'MSGraph'
        DisplayName = 'Directory.ReadWrite.All (app)'
        Aliases = @('Directory.ReadWrite.All')
        Tier = 0
        Sensitivity = 'Critical'
        WhyPrivileged = 'Application-level read and write across the entire directory. An SP with this permission can create users, modify groups, and read most directory data without an interactive admin. Combined with RoleManagement.ReadWrite.Directory, it is a self-elevation path to Global Admin equivalence.'
        AttackPaths = @(
            'Directory-wide write via service identity (no human admin in the loop)',
            'Backdoor-user creation outside human-admin audit trail'
        )
        ExpectedControls = @('Treat the SP as Tier 0', 'Rotate credentials', 'Audit app-role-assignment changes')
        ReferenceUrl = 'https://learn.microsoft.com/en-us/graph/permissions-reference#directoryreadwriteall'
    }

    'MSGraph:RoleManagement.ReadWrite.Directory' = @{
        Key = 'MSGraph:RoleManagement.ReadWrite.Directory'
        Surface = 'MSGraph'
        DisplayName = 'RoleManagement.ReadWrite.Directory (app)'
        Aliases = @('RoleManagement.ReadWrite.Directory')
        Tier = 0
        Sensitivity = 'Critical'
        WhyPrivileged = 'Lets the SP grant and revoke any directory role assignment, including Global Administrator. A single compromised app credential becomes Global Admin in one API call.'
        AttackPaths = @(
            'Self-elevation to Global Admin via API',
            'Silent admin-role grant to attacker-controlled accounts'
        )
        ExpectedControls = @('Tier-0 SP treatment', 'Rotate credentials', 'Conditional Access for the workload identity')
        ReferenceUrl = 'https://learn.microsoft.com/en-us/graph/permissions-reference#rolemanagementreadwritedirectory'
    }

    'MSGraph:Application.ReadWrite.All' = @{
        Key = 'MSGraph:Application.ReadWrite.All'
        Surface = 'MSGraph'
        DisplayName = 'Application.ReadWrite.All (app)'
        Aliases = @('Application.ReadWrite.All')
        Tier = 0
        Sensitivity = 'Critical'
        WhyPrivileged = 'Lets the SP create, modify, and credentialise any app registration, including itself. Self-elevation pattern: add new permissions, mint new credentials, take over arbitrary apps.'
        AttackPaths = @(
            'Self-credential addition for persistence',
            'Modification of arbitrary app to inject privileged permissions',
            'Cross-app pivot via shared credentials'
        )
        ExpectedControls = @('Tier-0 SP treatment', 'Rotate credentials')
        ReferenceUrl = 'https://learn.microsoft.com/en-us/graph/permissions-reference#applicationreadwriteall'
    }

    'MSGraph:AppRoleAssignment.ReadWrite.All' = @{
        Key = 'MSGraph:AppRoleAssignment.ReadWrite.All'
        Surface = 'MSGraph'
        DisplayName = 'AppRoleAssignment.ReadWrite.All (app)'
        Aliases = @('AppRoleAssignment.ReadWrite.All')
        Tier = 0
        Sensitivity = 'Critical'
        WhyPrivileged = 'Grants the SP authority to assign any app permission to any service principal — including itself. The classic stealth-self-elevation primitive used in app-consent attacks.'
        AttackPaths = @(
            'Self-grant of Directory.ReadWrite.All / RoleManagement.ReadWrite.Directory',
            'Cross-tenant CSP-style pivot'
        )
        ExpectedControls = @('Tier-0 SP treatment', 'Audit app-role-assignment events')
        ReferenceUrl = 'https://learn.microsoft.com/en-us/graph/permissions-reference#approleassignmentreadwriteall'
    }

    'MSGraph:User.ReadWrite.All' = @{
        Key = 'MSGraph:User.ReadWrite.All'
        Surface = 'MSGraph'
        DisplayName = 'User.ReadWrite.All (app)'
        Aliases = @('User.ReadWrite.All')
        Tier = 1
        Sensitivity = 'High'
        WhyPrivileged = 'Lets the SP read and write every user object, including password resets (with the right additional permissions) and account modification. Bulk identity manipulation without an admin in the loop.'
        AttackPaths = @(
            'Bulk-modify users for spray attacks',
            'Account creation for footholds'
        )
        ExpectedControls = @('Audit user-write events', 'Rotate credentials')
        ReferenceUrl = 'https://learn.microsoft.com/en-us/graph/permissions-reference#userreadwriteall'
    }

    'MSGraph:Group.ReadWrite.All' = @{
        Key = 'MSGraph:Group.ReadWrite.All'
        Surface = 'MSGraph'
        DisplayName = 'Group.ReadWrite.All (app)'
        Aliases = @('Group.ReadWrite.All')
        Tier = 1
        Sensitivity = 'High'
        WhyPrivileged = 'Lets the SP create, modify, and delete any group — including security groups that gate access to resources. Combined with privileged group ownership in AD or Entra, this is a delegated-rights elevation path.'
        AttackPaths = @(
            'Membership injection into delegated-rights groups',
            'Group ownership transfer for downstream pivots'
        )
        ExpectedControls = @('Audit group changes', 'Limit which groups the SP can modify')
        ReferenceUrl = 'https://learn.microsoft.com/en-us/graph/permissions-reference#groupreadwriteall'
    }

    'MSGraph:Mail.ReadWrite.All' = @{
        Key = 'MSGraph:Mail.ReadWrite.All'
        Surface = 'MSGraph'
        DisplayName = 'Mail.ReadWrite.All (app)'
        Aliases = @('Mail.ReadWrite.All', 'Mail.Read.All')
        Tier = 1
        Sensitivity = 'High'
        WhyPrivileged = 'Application-wide read and write of every mailbox in the tenant. The textbook BEC and silent-exfiltration permission. Often requested by reasonable-looking integrations and granted with admin consent before its scope is understood.'
        AttackPaths = @(
            'Silent mailbox exfiltration',
            'Inbox-rule injection for ongoing interception'
        )
        ExpectedControls = @('Strong justification', 'Restrict via application access policies', 'Audit Graph Mail API calls')
        ReferenceUrl = 'https://learn.microsoft.com/en-us/graph/permissions-reference#mailreadwriteall'
    }

    'MSGraph:Files.ReadWrite.All' = @{
        Key = 'MSGraph:Files.ReadWrite.All'
        Surface = 'MSGraph'
        DisplayName = 'Files.ReadWrite.All (app)'
        Aliases = @('Files.ReadWrite.All')
        Tier = 1
        Sensitivity = 'High'
        WhyPrivileged = 'Read and write every file in OneDrive and SharePoint across the tenant. Comprehensive content-exfiltration permission.'
        AttackPaths = @(
            'Bulk content exfiltration',
            'Ransomware-style content overwrite'
        )
        ExpectedControls = @('Restrict via SharePoint/OneDrive site-permissions', 'Audit Graph Files API')
        ReferenceUrl = 'https://learn.microsoft.com/en-us/graph/permissions-reference#filesreadwriteall'
    }

    'MSGraph:Sites.FullControl.All' = @{
        Key = 'MSGraph:Sites.FullControl.All'
        Surface = 'MSGraph'
        DisplayName = 'Sites.FullControl.All (app)'
        Aliases = @('Sites.FullControl.All')
        Tier = 1
        Sensitivity = 'High'
        WhyPrivileged = 'Full control of every SharePoint site, including permission management. Equivalent to SharePoint Administrator for the SharePoint workload.'
        AttackPaths = @(
            'Permission tampering for cross-site exfiltration',
            'Site-collection-admin self-grant'
        )
        ExpectedControls = @('Restrict via Sites.Selected for least privilege', 'Audit site-permission changes')
        ReferenceUrl = 'https://learn.microsoft.com/en-us/graph/permissions-reference#sitesfullcontrolall'
    }

    'MSGraph:Policy.ReadWrite.ConditionalAccess' = @{
        Key = 'MSGraph:Policy.ReadWrite.ConditionalAccess'
        Surface = 'MSGraph'
        DisplayName = 'Policy.ReadWrite.ConditionalAccess (app)'
        Aliases = @('Policy.ReadWrite.ConditionalAccess')
        Tier = 0
        Sensitivity = 'Critical'
        WhyPrivileged = 'Read and modify every Conditional Access policy. An SP with this permission can disable MFA enforcement, exclude attacker IPs, or block legitimate access — equivalent to Conditional Access Administrator for the workload identity.'
        AttackPaths = @(
            'CA policy disablement during an attack',
            'Carve-out for attacker IP / device'
        )
        ExpectedControls = @('Tier-0 SP treatment', 'Rotate credentials', 'Audit policy changes')
        ReferenceUrl = 'https://learn.microsoft.com/en-us/graph/permissions-reference#policyreadwriteconditionalaccess'
    }

    'MSGraph:DeviceManagementConfiguration.ReadWrite.All' = @{
        Key = 'MSGraph:DeviceManagementConfiguration.ReadWrite.All'
        Surface = 'MSGraph'
        DisplayName = 'DeviceManagementConfiguration.ReadWrite.All (app)'
        Aliases = @('DeviceManagementConfiguration.ReadWrite.All')
        Tier = 1
        Sensitivity = 'High'
        WhyPrivileged = 'Modify Intune configuration policies — push scripts and apps to managed devices. Equivalent to Intune Administrator at the workload-identity layer.'
        AttackPaths = @(
            'Malicious script deployment to fleet',
            'Compliance policy manipulation'
        )
        ExpectedControls = @('Tier-0 SP treatment', 'Audit Intune policy changes')
        ReferenceUrl = 'https://learn.microsoft.com/en-us/graph/permissions-reference#devicemanagementconfigurationreadwriteall'
    }

    'MSGraph:DeviceManagementApps.ReadWrite.All' = @{
        Key = 'MSGraph:DeviceManagementApps.ReadWrite.All'
        Surface = 'MSGraph'
        DisplayName = 'DeviceManagementApps.ReadWrite.All (app)'
        Aliases = @('DeviceManagementApps.ReadWrite.All')
        Tier = 1
        Sensitivity = 'High'
        WhyPrivileged = 'Manage Intune-deployed apps. An SP can publish a malicious app package and target it at every managed device.'
        AttackPaths = @(
            'Malicious app deployment to all managed devices'
        )
        ExpectedControls = @('Audit app-publish events', 'Restrict to dedicated automation tenant')
        ReferenceUrl = 'https://learn.microsoft.com/en-us/graph/permissions-reference#devicemanagementappsreadwriteall'
    }

    'MSGraph:DeviceManagementManagedDevices.PrivilegedOperations.All' = @{
        Key = 'MSGraph:DeviceManagementManagedDevices.PrivilegedOperations.All'
        Surface = 'MSGraph'
        DisplayName = 'DeviceManagementManagedDevices.PrivilegedOperations.All (app)'
        Aliases = @('DeviceManagementManagedDevices.PrivilegedOperations.All')
        Tier = 1
        Sensitivity = 'High'
        WhyPrivileged = 'Run privileged operations against managed devices: remote-wipe, remote-lock, custom action invocation. The "remote brick the fleet" permission.'
        AttackPaths = @(
            'Mass remote-wipe as denial-of-service or anti-forensics',
            'Targeted device wipe to remove an investigator''s endpoint'
        )
        ExpectedControls = @('Tier-0 SP treatment', 'Two-person review for bulk operations')
        ReferenceUrl = 'https://learn.microsoft.com/en-us/graph/permissions-reference#devicemanagementmanageddevicesprivilegedoperationsall'
    }

    'MSGraph:Domain.ReadWrite.All' = @{
        Key = 'MSGraph:Domain.ReadWrite.All'
        Surface = 'MSGraph'
        DisplayName = 'Domain.ReadWrite.All (app)'
        Aliases = @('Domain.ReadWrite.All')
        Tier = 0
        Sensitivity = 'Critical'
        WhyPrivileged = 'Add or modify custom domains in the tenant. A malicious domain addition combined with federation configuration is a documented tenant-takeover technique (the AADInternals "any-tenant-domain" attack class).'
        AttackPaths = @(
            'Federation injection on a fake domain -> SAML-token forgery',
            'Domain hijack via tenant-level DNS misconfiguration'
        )
        ExpectedControls = @('Tier-0 SP treatment', 'Audit domain operations')
        ReferenceUrl = 'https://learn.microsoft.com/en-us/graph/permissions-reference#domainreadwriteall'
    }

    'MSGraph:PrivilegedAccess.ReadWrite.AzureAD' = @{
        Key = 'MSGraph:PrivilegedAccess.ReadWrite.AzureAD'
        Surface = 'MSGraph'
        DisplayName = 'PrivilegedAccess.ReadWrite.AzureAD (app)'
        Aliases = @('PrivilegedAccess.ReadWrite.AzureAD')
        Tier = 0
        Sensitivity = 'Critical'
        WhyPrivileged = 'Manage Privileged Identity Management (PIM) for Entra roles. An SP with this can change role-eligibility settings, activate roles, or remove PIM from privileged roles entirely — defeating the JIT control that the rest of the privileged-access programme depends on.'
        AttackPaths = @(
            'Disable PIM on Global Admin assignments to convert eligible to permanent',
            'Self-activate eligible role assignments'
        )
        ExpectedControls = @('Tier-0 SP treatment', 'Audit PIM policy changes')
        ReferenceUrl = 'https://learn.microsoft.com/en-us/graph/permissions-reference#privilegedaccessreadwriteazuread'
    }

    'MSGraph:UserAuthenticationMethod.ReadWrite.All' = @{
        Key = 'MSGraph:UserAuthenticationMethod.ReadWrite.All'
        Surface = 'MSGraph'
        DisplayName = 'UserAuthenticationMethod.ReadWrite.All (app)'
        Aliases = @('UserAuthenticationMethod.ReadWrite.All')
        Tier = 0
        Sensitivity = 'Critical'
        WhyPrivileged = 'Modify any user''s authentication methods, including registering new MFA methods or removing existing ones. An SP with this permission silently takes over any account by registering an attacker-controlled MFA method.'
        AttackPaths = @(
            'Register attacker-controlled FIDO2 / authenticator app',
            'Remove victim MFA methods to force fallback'
        )
        ExpectedControls = @('Tier-0 SP treatment', 'Alert on MFA-method changes', 'Rotate credentials')
        ReferenceUrl = 'https://learn.microsoft.com/en-us/graph/permissions-reference#userauthenticationmethodreadwriteall'
    }

    'MSGraph:Mail.Send' = @{
        Key = 'MSGraph:Mail.Send'
        Surface = 'MSGraph'
        DisplayName = 'Mail.Send (app)'
        Aliases = @('Mail.Send')
        Tier = 2
        Sensitivity = 'Medium'
        WhyPrivileged = 'Send mail as any user without the user''s consent. Lower blast radius than Mail.ReadWrite.All but a high-fidelity phishing-impersonation primitive — every "send as" looks legitimate.'
        AttackPaths = @(
            'Internal-phishing campaigns with high deliverability',
            'BEC with sender-identity authenticity'
        )
        ExpectedControls = @('Restrict via application access policies', 'Audit send events')
        ReferenceUrl = 'https://learn.microsoft.com/en-us/graph/permissions-reference#mailsend'
    }

    'MSGraph:DelegatedAdminRelationship.ReadWrite.All' = @{
        Key = 'MSGraph:DelegatedAdminRelationship.ReadWrite.All'
        Surface = 'MSGraph'
        DisplayName = 'DelegatedAdminRelationship.ReadWrite.All (app)'
        Aliases = @('DelegatedAdminRelationship.ReadWrite.All')
        Tier = 0
        Sensitivity = 'Critical'
        WhyPrivileged = 'Manage GDAP relationships with partner tenants. A malicious change here adds a partner-tenant SP as an admin, and partner-tenant admins can access this tenant under the relationship — Nobelium / SolarWinds-style cross-tenant pivot.'
        AttackPaths = @(
            'GDAP injection for cross-tenant admin access',
            'Persistent partner-tenant backdoor'
        )
        ExpectedControls = @('Tier-0 SP treatment', 'Audit GDAP relationships')
        ReferenceUrl = 'https://learn.microsoft.com/en-us/graph/permissions-reference#delegatedadminrelationshipreadwriteall'
    }

    #endregion
}

#endregion

#region ==================== PRIVATE HELPERS ====================

function ConvertTo-PrivilegeClone {
    <#
    .SYNOPSIS
        Returns a clone of a catalog descriptor so callers cannot mutate the
        master entry by reference.
    #>
    [OutputType([hashtable])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Descriptor
    )

    $clone = @{}
    foreach ($key in $Descriptor.Keys) {
        $value = $Descriptor[$key]
        if ($value -is [array]) {
            $clone[$key] = @($value)
        }
        else {
            $clone[$key] = $value
        }
    }
    return $clone
}

#endregion

#region ==================== PUBLIC FUNCTIONS ====================

function Get-PrivilegeCatalog {
    <#
    .SYNOPSIS
        Returns a fresh clone of the full privilege catalog.
    .DESCRIPTION
        Each call returns independent clones so callers can populate
        roster-specific runtime fields without affecting the master catalog
        or other consumers.
    #>
    [OutputType([hashtable])]
    [CmdletBinding()]
    param()

    $result = @{}
    foreach ($key in $script:PrivilegeCatalog.Keys) {
        $result[$key] = ConvertTo-PrivilegeClone -Descriptor $script:PrivilegeCatalog[$key]
    }
    return $result
}

function Get-PrivilegeDescriptor {
    <#
    .SYNOPSIS
        Returns a clone of one named privilege descriptor.
    .PARAMETER Key
        Canonical privilege key, e.g. 'AD:DomainAdmins' or 'Entra:GlobalAdministrator'.
    #>
    [OutputType([hashtable])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Key
    )

    if (-not $script:PrivilegeCatalog.ContainsKey($Key)) {
        throw "Unknown privilege key: '$Key'. Use Get-PrivilegeCatalogKeys to list valid keys."
    }
    return ConvertTo-PrivilegeClone -Descriptor $script:PrivilegeCatalog[$Key]
}

function Get-PrivilegeCatalogKeys {
    <#
    .SYNOPSIS
        Returns the sorted list of privilege catalog keys.
    .PARAMETER Surface
        Optional filter — return keys for only one surface ('AD', 'Entra', 'MSGraph').
    .PARAMETER Tier
        Optional filter — return keys at or below the given tier (0 returns Tier 0
        only; 1 returns Tier 0 and 1; 2 returns 0, 1, 2; 'Service' returns all).
    #>
    [OutputType([string[]])]
    [CmdletBinding()]
    param(
        [ValidateSet('AD', 'Entra', 'MSGraph', 'App')]
        [string]$Surface,

        [object]$Tier
    )

    $keys = $script:PrivilegeCatalog.Keys
    if ($Surface) {
        $keys = $keys | Where-Object { $script:PrivilegeCatalog[$_].Surface -eq $Surface }
    }
    if ($PSBoundParameters.ContainsKey('Tier')) {
        $keys = $keys | Where-Object {
            $entryTier = $script:PrivilegeCatalog[$_].Tier
            # Numeric tiers compare normally; 'Service' is included only when
            # explicitly asked for or when no tier filter restricts it.
            if ($Tier -is [int] -and $entryTier -is [int]) {
                $entryTier -le $Tier
            }
            elseif ($Tier -eq 'Service') {
                $entryTier -eq 'Service'
            }
            else {
                $false
            }
        }
    }
    return [string[]]@($keys | Sort-Object)
}

function Resolve-PrivilegeKey {
    <#
    .SYNOPSIS
        Maps a surface + display name (or alias) to a canonical privilege key.
    .DESCRIPTION
        Auditors and AD/Entra APIs return display names like 'Domain Admins' or
        'Global Administrator'. This resolver normalises those — including
        common aliases and case-insensitive matching — into the catalog's
        canonical key.

        Returns $null when no match is found (the caller decides whether
        unknown names are an error or get tagged 'Unknown').
    .PARAMETER Surface
        'AD' | 'Entra' | 'MSGraph'.
    .PARAMETER Name
        Display name or alias as observed at the call site.
    #>
    [OutputType([string])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('AD', 'Entra', 'MSGraph')]
        [string]$Surface,

        [Parameter(Mandatory)]
        [string]$Name
    )

    $needle = $Name.Trim()
    foreach ($key in $script:PrivilegeCatalog.Keys) {
        $entry = $script:PrivilegeCatalog[$key]
        if ($entry.Surface -ne $Surface) { continue }
        if ($entry.DisplayName -ieq $needle) { return $key }
        foreach ($alias in @($entry.Aliases)) {
            if ($alias -ieq $needle) { return $key }
        }
    }
    return $null
}

function Get-TierForPrivilege {
    <#
    .SYNOPSIS
        Convenience: return the Tier value (0/1/2/'Service') for a privilege key.
    .PARAMETER Key
        Canonical privilege key.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Key
    )

    if (-not $script:PrivilegeCatalog.ContainsKey($Key)) {
        throw "Unknown privilege key: '$Key'."
    }
    return $script:PrivilegeCatalog[$Key].Tier
}

#endregion

#region ==================== MODULE EXPORTS ====================

Export-ModuleMember -Function @(
    'Get-PrivilegeCatalog',
    'Get-PrivilegeDescriptor',
    'Get-PrivilegeCatalogKeys',
    'Resolve-PrivilegeKey',
    'Get-TierForPrivilege'
)

#endregion
