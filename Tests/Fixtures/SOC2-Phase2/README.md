# SOC 2 Phase 2 fixtures

Scrubbed JSON captures of real API responses used by `Tests/SOC2-Phase2.Tests.ps1`.

Every UPN / ObjectId / subscription GUID / workspace path is a stable test
value (not a real one). Fixtures shape their data for the path the test
context exercises — naming suffix explains the scenario.

- `recoveryServicesVaults-*.json` — Azure REST `/subscriptions/.../Microsoft.RecoveryServices/vaults`
- `backupProtectedItems-*.json` — Azure REST `/backupProtectedItems` under a vault
- `resourceHealth-*.json` — Azure REST `/Microsoft.ResourceHealth/availabilityStatuses`
- `aadiam-diagnosticSettings-*.json` — Azure REST `/providers/microsoft.aadiam/diagnosticSettings`
- `defenderSettings-wdatp-*.json` — Azure REST `Microsoft.Security/settings/WDATP`
- `defenderAssessments-*.json` — output shape of `Get-DefenderComplianceAssessments`
- `directoryRoles-*.json` — Graph `/directoryRoles` and `/directoryRoles/{id}/members`
- `conditionalAccess-*.json` — Graph `/identity/conditionalAccess/policies`

Each fixture captures only the fields the check actually reads. Contents are
safe for public git history.
