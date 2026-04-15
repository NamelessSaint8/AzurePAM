# AD CS ESC1-ESC13 Check Reference

**Module:** `EntraChecks-ADCS.psm1`
**Shipping in:** v1.7.0 (PR 3 — ESC1-8), v1.9.0 (PR 4b — ESC9/10/11/13).
**Invoked by:** `Invoke-ActiveDirectoryAssessment` when an Enterprise CA is detected (no new menu item or CLI flag).

This guide is a technical reference for the AD CS checks (ESC1-8 plus ESC9/10/11/13). For running instructions see the [AD module guide](ActiveDirectory-Guide.md).

---

## Background

The "ESC" family of AD CS misconfigurations was catalogued by SpecterOps in *Certified Pre-Owned: Abusing Active Directory Certificate Services* (2021). Each ESC represents a different way a low-privilege attacker can coerce the CA into issuing a certificate that authenticates them as a higher-privilege principal — often Domain Admin. Because AD CS certificates are accepted by every DC for Kerberos PKINIT, compromising a template or CA is effectively equivalent to compromising the domain.

EntraChecks detects the 8 original ESC classes plus 4 newer additions (ESC9, ESC10, ESC11, ESC13 — relevant in environments that have applied the KB5014754 hardening or added OID-group links). All checks are **read-only**. Results are advisory — a flagged template may have legitimate use in your environment (e.g., a smart-card enrollment agent for helpdesk staff), and the checks report the flag combination so you can decide.

---

## Check matrix

| Check | ESC | Data sources | Detection logic |
|---|---|---|---|
| `Test-ADCSEnvironment` (private) | — | AD `CN=Enrollment Services,CN=Public Key Services,CN=Services,<config NC>` | Returns `HasADCS=$true` when any `pKIEnrollmentService` object exists. |
| `Test-ADCSInventory` | — | AD | Lists CAs + template count. INFO-only. |
| `Test-ADCSEscalation1` | ESC1 | AD + ACL | Template with: client-auth EKU + `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` + no manager approval + `msPKI-RA-Signature=0` + non-admin enrollment right. |
| `Test-ADCSEscalation2` | ESC2 | AD + ACL | Template with: Any-Purpose EKU (`2.5.29.37.0`) OR empty EKU (SubCA-style) + non-admin enrollment right. |
| `Test-ADCSEscalation3` | ESC3 | AD + ACL | Template with: Certificate Request Agent EKU (`1.3.6.1.4.1.311.20.2.1`) + non-admin enrollment right. |
| `Test-ADCSEscalation4` | ESC4 | AD ACL | Template object has write-class permissions (`GenericAll`, `GenericWrite`, `WriteOwner`, `WriteDacl`, `WriteProperty`) granted to a non-admin principal. |
| `Test-ADCSEscalation5` | ESC5 | AD ACL | Any of `CN=Enrollment Services`, `CN=Certification Authorities`, `CN=AIA`, `CN=NTAuthCertificates` has write-class permissions granted to a non-admin principal. |
| `Test-ADCSEscalation6` | ESC6 | CA registry (PSRemoting) | `EditFlags` registry value (under `HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CAName>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy`) has the `EDITF_ATTRIBUTESUBJECTALTNAME2` (`0x40000`) bit set. |
| `Test-ADCSEscalation7` | ESC7 | CA security descriptor (PSRemoting) | `certutil -getreg ca\<CAName>\Security` output indicates a broad principal (Domain Users / Authenticated Users / Everyone / Users / Domain Computers) holds CA administrative rights. |
| `Test-ADCSEscalation8` | ESC8 | HTTP probe | `http://<CA>/certsrv/` is reachable over plain HTTP. |
| `Test-ADCSEscalation9` | ESC9 | AD + ACL | Template with `CT_FLAG_NO_SECURITY_EXTENSION` (`0x80000`) in `msPKI-Enrollment-Flag` + enrollable by non-admins. The issued cert omits the SID security extension added by KB5014754, enabling ESC10-style mapping abuse. |
| `Test-ADCSEscalation10` | ESC10 | DC registry (PSRemoting) | Per DC: `StrongCertificateBindingEnforcement` under `HKLM:\SYSTEM\CurrentControlSet\Services\Kdc`. `0` = disabled (pre-KB5014754 legacy), `1` = compatibility, `2` = full enforcement. Also surfaces legacy `CertificateMappingMethods` (implicit UPN/CN). |
| `Test-ADCSEscalation11` | ESC11 | CA registry (PSRemoting) | CA `EditFlags` missing `IF_ENFORCEENCRYPTICERTREQUEST` (`0x00000100`) — allows NTLM-relay to CA RPC endpoint. |
| `Test-ADCSEscalation13` | ESC13 | AD (`CN=OID,CN=Public Key Services`) | Certificate issuance policy OIDs with `msDS-OIDToGroupLink` pointing to a privileged group, used by a template enrollable by non-admins. Enrolling the cert inserts the linked group into the Kerberos PAC. |

### Authorized-principals filter

For ACL-based checks (ESC1-5), findings only fire when a **non-admin** principal holds the right. "Admin" is defined as any of:
- Domain Admins
- Enterprise Admins
- Administrators (builtin)
- SYSTEM
- Cert Publishers
- Enterprise Read-only Domain Controllers

Add more entries to `$script:AuthorizedPrincipals` in `EntraChecks-ADCS.psm1` if your environment has additional legitimate administrative groups.

---

## Severity matrix

| Check | FAIL severity | Reasoning |
|---|---|---|
| `Test-ADCSEscalation1` | **Critical** | SAN abuse grants instant impersonation of any user, including DA. |
| `Test-ADCSEscalation4` | **Critical** | Template ACL abuse lets an attacker modify the template to become ESC1. |
| `Test-ADCSEscalation6` | **Critical** | EDITF_ATTRIBUTESUBJECTALTNAME2 = every template is ESC1-vulnerable. |
| `Test-ADCSEscalation8` | **Critical** | NTLM relay from DC machine account to web enrollment = remote domain admin without credentials. |
| `Test-ADCSEscalation2` | High | Any-Purpose / SubCA templates functionally equal ESC1 when enrollable by non-admins. |
| `Test-ADCSEscalation3` | High | Enrollment agent abuse requires a cooperating victim template; not instant DA. |
| `Test-ADCSEscalation5` | High | PKI-container ACL abuse is a step toward CA compromise, not the compromise itself. |
| `Test-ADCSEscalation7` | High | Broad CA admin rights enable ESC6 and arbitrary issuance — but requires the attacker to act on the CA. |
| `Test-ADCSEscalation9` | High | SID-extension-less cert is dangerous only when combined with ESC10 or weak mapping — not a single-step path. |
| `Test-ADCSEscalation10` | **Critical** | Domain-wide — governs every Kerberos PKINIT cert-to-account binding across all DCs. |
| `Test-ADCSEscalation11` | **Critical** | NTLM relay to CA RPC endpoint = certificate issuance as the relayed account; no HTTPS needed (bypasses ESC8 mitigations). |
| `Test-ADCSEscalation13` | **Critical** | Enrolling the cert injects a privileged group SID into the PAC — direct DA without modifying the template. |

WARNING is used when a check can't complete (PSRemoting blocked, HTTP probe error). The WARNING never blocks the rest of the assessment.

---

## Common false positives

### ESC1 — "Legitimate enrollment agent template"

An organization using smart-card enrollment might configure a template with `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` intentionally — for the helpdesk enrollment workflow. If the **enrollment rights are tightly restricted** to the enrollment agent group, the check will not fire (the ACL filter catches it). If a vendor wizard ticked "allow request to supply subject information" on a template enrollable by Authenticated Users, that's a genuine finding.

### ESC3 — "Smart card enrollment is working as designed"

Smart-card enrollment legitimately uses the Enrollment Agent EKU. Mitigation: restrict the template's enrollment rights to the enrollment agent operators, and configure the CA's Enrollment Agent Restrictions (certsrv.msc → CA Properties → Enrollment Agents tab) so agents can only enroll on behalf of specific groups.

### ESC6 — "We need SAN on v1 templates"

Some legacy applications request certificates via v1 templates that don't expose SAN fields. Admins sometimes set `EDITF_ATTRIBUTESUBJECTALTNAME2` to work around that — this is a **huge** risk and is not a legitimate workaround. The correct fix is to migrate those applications to a v2/v3 template that supports SAN properly.

### ESC8 — "Web enrollment is HTTPS-only; probe misreports"

The probe tests `http://` explicitly. If a 200/401/403 is returned, the endpoint is reachable over plain HTTP. If the CA is configured to redirect HTTP → HTTPS, the probe will typically see the redirect and report based on its status code. If that's misreporting for your topology, verify manually:

```powershell
Invoke-WebRequest 'http://<CA>/certsrv/' -MaximumRedirection 0
```

---

## Remediation guide

### ESC1 / ESC6
- Remove `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` from vulnerable templates OR require manager approval (`CT_FLAG_PEND_ALL_REQUESTS`) OR restrict enrollment rights.
- For ESC6 specifically: on the CA, run `certutil -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2 && net stop certsvc && net start certsvc`. Then audit all certs issued while the flag was set.

### ESC2
- Remove Any-Purpose EKU (`2.5.29.37.0`) from the template, OR populate the EKU list explicitly.
- Restrict enrollment rights on SubCA-style templates.

### ESC3
- Restrict enrollment-agent template enrollment to a small, highly-privileged group.
- Configure Enrollment Agent Restrictions on the CA (certsrv.msc → CA Properties → Enrollment Agents).

### ESC4 / ESC5
- Audit AD ACLs on all template objects and the PKI containers. Restrict write-class permissions (`GenericAll`, `GenericWrite`, `WriteOwner`, `WriteDacl`, `WriteProperty`) to Enterprise Admins and SYSTEM only.

### ESC7
- On each CA: certsrv.msc → CA Properties → Security tab. Ensure only Enterprise Admins and specific PKI administration groups have `ManageCA` or `ManageCertificates` rights.

### ESC8
- IIS: require SSL for `/certsrv/` (uncheck "Require SSL" is wrong — check it).
- Enable Extended Protection for Authentication (EPA) / channel binding on the web enrollment site.
- Better: if you don't need web enrollment, **remove the role entirely** (Server Manager → Remove Roles).

### ESC9 / ESC10
- **ESC9:** Clear `CT_FLAG_NO_SECURITY_EXTENSION` on the flagged template (Certificate Templates MMC → Properties → Server tab → uncheck "Do not include revocation information in issued certificates" / inspect `msPKI-Enrollment-Flag`). Restrict enrollment rights.
- **ESC10:** On every DC, set `StrongCertificateBindingEnforcement=2` (full enforcement) under `HKLM\SYSTEM\CurrentControlSet\Services\Kdc`. Ensure `CertificateMappingMethods` excludes `0x4` (implicit UPN) and `0x2` (implicit CN). Microsoft's KB5014754 rollout guidance covers the full migration path and enforcement timeline.

### ESC11
- On each CA, enable the `IF_ENFORCEENCRYPTICERTREQUEST` flag via `certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST && net stop certsvc && net start certsvc`. This requires packet privacy on the RPC interface, defeating unencrypted relay.

### ESC13
- Inspect `CN=OID,CN=Public Key Services,CN=Services,<config NC>` for OID objects with `msDS-OIDToGroupLink` populated. For each link to a privileged group, confirm the business need. If legitimate (rare), restrict templates that include the OID in `msPKI-Certificate-Policy` to highly-privileged enrollment rights only. Otherwise clear the attribute.

Microsoft's guidance for CVE-2022-26923 (Certifried) covers ESC6/ESC8 mitigations in depth — it's the canonical reference.

---

## References

- [Certified Pre-Owned (SpecterOps, 2021)](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [MS-WCCE: Windows Client Certificate Enrollment Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/)
- [MS-CRTD: Certificate Template Structure](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/)
- [KB5005413 — Managing security for Active Directory Certificate Services](https://support.microsoft.com/en-us/topic/kb5005413-mitigating-ntlm-relay-attacks-on-active-directory-certificate-services-ad-cs-3612b773-4043-4aa9-b23d-b87ca6cb47fd) (covers ESC8 mitigation)
- [Certipy](https://github.com/ly4k/Certipy) — active-exploitation tool; we detect what it exploits, we don't exploit
