# AD Security Audit

A read-only PowerShell audit of Active Directory security and hygiene. It produces a single HTML report that you can email to management, with a red, amber or green status for every check and a recommended action for each problem.

It looks for the weaknesses found in almost every small and medium-sized domain: accounts nobody uses any more, leavers who still belong to groups, passwords that never expire, too many Domain Admins, dangerous Kerberos delegation, unsupported Windows versions and GPOs that apply to nobody.

> **Built with AI assistance (Claude Code).** I defined what to audit from what I see as an IT technician, reviewed the checks and tested the tool against the lab domain. The tool only reads data: it uses `Get-*` cmdlets and nothing else, and a test enforces this.

**Try it without Active Directory:** `.\Invoke-ADSecurityAudit.ps1 -Lab` builds the report for a fictional company. A pre-built copy is in [docs/sample-report.html](docs/sample-report.html) (download it and open it in a browser).

## Quick start

```powershell
# Lab mode: fictional "Demo Corp" domain, works on any Windows PC
.\Invoke-ADSecurityAudit.ps1 -Lab

# Real domain, from a domain-joined machine with RSAT
.\Invoke-ADSecurityAudit.ps1

# Stricter inactivity threshold, specific DC, custom output folder
.\Invoke-ADSecurityAudit.ps1 -InactiveDays 60 -Server dc01.example.local -OutputDirectory C:\Audits

# Collect on a DC, analyse elsewhere
.\Invoke-ADSecurityAudit.ps1 -ExportSnapshot                                     # on the DC
.\Invoke-ADSecurityAudit.ps1 -SnapshotPath .\ad-audit-CORP-...-snapshot.json      # anywhere
```

Each run writes two files to `.\reports`:

| File | Contents |
|---|---|
| `ad-audit-<DOMAIN>-<date>-results.json` | Every finding with its affected objects. Use it for automation or for comparing runs over time. |
| `ad-audit-<DOMAIN>-<date>-report.html` | The executive report. It is one self-contained file with no external fonts, scripts or images, and it works offline. |

| Parameter | Meaning |
|---|---|
| `-Lab` | Use the fictional domain in `lab/lab-sample.json`. |
| `-SnapshotPath` | Analyse a snapshot saved earlier with `-ExportSnapshot`. |
| `-Server`, `-Credential` | Domain controller and account used to read AD. Any domain user can read almost everything checked here. |
| `-InactiveDays` | Days without logon before an account counts as inactive (default 90). |
| `-MaxDomainAdmins` | Acceptable Domain Admins count. More than this is amber; more than twice this is red (default 5). |
| `-OutputDirectory` | Where the results and the report are written (default `.\reports`). |
| `-ExportSnapshot` | Also save the raw collected data as JSON. |
| `-PassThru` | Return the results object to the pipeline. |

## What it checks

| ID | Check | Red when | Amber when |
|---|---|---|---|
| **Account hygiene** ||||
| ACC-01 | Enabled users inactive for more than 90 days | more than 10% of users | any |
| ACC-02 | Ghost accounts: enabled, never logged on, created over 30 days ago | | any |
| ACC-03 | Disabled accounts still in security groups (incomplete offboarding) | one is still in a privileged group | any |
| ACC-04 | Passwords set to never expire | a privileged account has it | any |
| ACC-05 | `PasswordNotRequired` (an empty password is allowed) | any | |
| ACC-06 | Passwords older than one year | | any |
| ACC-07 | Enabled accounts that are locked out or past their expiry date | | any |
| ACC-08 | Reversible password encryption | any, or enabled in the domain policy | |
| ACC-09 | Kerberos pre-authentication disabled (AS-REP roasting) | any | |
| ACC-10 | User accounts with SPNs (Kerberoasting) | a privileged account has one | any |
| ACC-11 | Built-in Guest account enabled | enabled | |
| **Privileged access** ||||
| PRV-01 | Inventory of Domain Admins, Enterprise Admins and Administrators, including nested members | Domain Admins count is more than 2× the target | Domain Admins count is above the target |
| PRV-02 | Members in groups that should be empty (Enterprise and Schema Admins, Operators groups) | | any |
| PRV-03 | Weak privileged accounts: dormant, disabled but still members, password never expires or older than a year, can be delegated | a dormant admin | any |
| PRV-04 | krbtgt password age | more than 365 days | more than 180 days |
| PRV-05 | Built-in Administrator (RID 500) password age | | more than 365 days |
| PRV-06 | Former admins still flagged `adminCount=1` | | any |
| **Delegation** ||||
| DEL-01 | Unconstrained delegation on accounts that are not domain controllers | any | |
| DEL-02 | Constrained delegation with protocol transition | | any |
| DEL-03 | Resource-based constrained delegation | | any |
| **Computers** ||||
| CMP-01 | OS past end of support (Windows 7/8.1/10, Server 2008/2012) or ending within 12 months (Server 2016) | past end of support | ending within 12 months |
| CMP-02 | Computers inactive for more than 90 days | | any |
| **Group Policy** ||||
| GPO-01 | GPOs not linked anywhere (or only through disabled links) | | any |
| GPO-02 | GPOs with all settings disabled | | any |
| GPO-03 | Empty GPOs (never edited) | | any |
| GPO-04 | Orphaned GPOs: in AD without a SYSVOL folder, or in SYSVOL without an AD object | any | |
| **Domain** ||||
| DOM-01 | Default password policy: length, complexity, lockout, history, reversible encryption | length below 8 or reversible encryption | below the targets |
| DOM-02 | Domain functional level | | below 2016 |
| DOM-03 | AD Recycle Bin | | disabled |

The hygiene score is the share of checks that pass, with red counting twice as much as amber (all green = 100). It is meant for tracking progress between audits. It is not a benchmark.

### Design notes

- **Language-independent.** Privileged groups are found by their well-known SID, not by name, so localized domains work. For example, Spanish domains call Domain Admins *Admins. del dominio*.
- **No GroupPolicy module needed.** GPOs are read from their AD containers and `gPLink` attributes, so RSAT AD tools are enough. SYSVOL is checked with `Test-Path`.
- **LastLogonDate, not LastLogon.** `LastLogonDate` is replicated, so one DC is enough. It can lag by up to 14 days, which does not matter for a 90-day threshold.
- **Fails visibly.** If a data source cannot be read, its checks show *Not run* in grey instead of a misleading green.
- **Out of scope.** File share permissions given directly to a leaver are not checked. That needs access to each file server, and the ACC-03 recommendation points to it.

## How it works

```
Collect (Get-* only)  ->  snapshot  ->  checks (pure functions)  ->  results.json  ->  HTML report
   src/Collect.ps1         or lab/         src/Checks.ps1                          ConvertTo-ADAuditReport.ps1
                           lab-sample.json                                         (src/Report.ps1)
```

Data and presentation are separate. The checks only see a snapshot object, so the same code runs against a live domain, a saved snapshot or the lab. The report generator only reads the results JSON, so you can rebuild the HTML on any machine:

```powershell
.\ConvertTo-ADAuditReport.ps1 -InputPath .\reports\ad-audit-CORP-20261120-1000-results.json
```

## Lab mode

`lab/lab-sample.json` describes *Demo Corp* (`demo-corp.lab`), a fictional company with 64 users, 43 computers and 13 GPOs. It has the problems you find in real small businesses: an external IT supplier that is still a Domain Admin after 214 days without logging on, a leaver still in Domain Admins, service accounts with 4-year-old passwords, Windows 7 and Windows 10 PCs, a 2012 R2 server with unconstrained delegation and a test GPO nobody deleted. All names are invented.

`tools/New-LabSample.ps1` builds the file from `src/Lab.ps1` with fixed values, so every run produces the same file, and refreshes `docs/sample-report.html`.

## Tests

```powershell
powershell -ExecutionPolicy Bypass -File .\tests\Run-Tests.ps1
```

45 tests with no external dependencies (Pester is not needed). They cover:

- the expected result of every check on the lab domain
- OS lifecycle dates
- scoring and configurable thresholds
- a healthy domain coming out all green
- *Not run* handling
- HTML encoding of directory data
- the report having no external resources
- a static check that the collector contains no AD write cmdlets

## Requirements

- Windows PowerShell 5.1 or PowerShell 7.
- For live audits: the RSAT **ActiveDirectory** module (installed on DCs, or on Windows 10/11 with *Settings > Optional features > RSAT: Active Directory Domain Services*) and any domain account. To check SYSVOL for orphaned GPOs, the account also needs read access to `\\<domain>\SYSVOL`.
- Lab mode needs nothing else.

## Handling the output

The report and the snapshot contain account names, group memberships and a map of the domain's weak points. Store and send them as confidential. `reports/` and `*-snapshot.json` are git-ignored.

## License

MIT. See [LICENSE](LICENSE).
