# 2.2.0
Accuracy release. Results of earlier scans can differ noticeably from scans made with this version, mostly because much more is found.

**SharePoint and OneDrive**
- Every site collection and OneDrive is now listed through the SharePoint admin API, including Teams channel sites and the OneDrives of leavers and unlicensed users. Without an active SharePoint Administrator role the scan falls back to search and is marked incomplete.
- Subsites, lists and libraries with unique permissions are scanned.
- SharePoint group members are listed with the access they get through the group.
- Sharing links (anonymous, organization-wide, specific people) are reported with their recipients, at any depth.
- Fixed: temporary site admin elevation could remove existing secondary site admins when reading them failed. Elevation now adds and removes only the scanning account.
- Fixed: "View Only" grants were skipped, and localized role names (for example "Volledig beheer") were missed by the risk policies.
- Entra and Microsoft 365 groups on sites are linked to their Entra object, so User Lookup finds access through them.

**Entra ID, Exchange, Azure and other services**
- Role assignments now distinguish permanent, time-bound, PIM-activated and eligible assignments, including administrative unit scope. Fixed: an admin who activated a role through PIM was reported as a permanent admin.
- Members of role-assignable groups are listed as role holders. PIM for Groups eligibility is scanned (requires one new consent: PrivilegedEligibilitySchedule.Read.AzureADGroup).
- App registration and enterprise app owners are scanned; user-consented OAuth grants show the consenting user.
- Exchange trustees are resolved to their Entra object, shared, room and equipment mailboxes are told apart, Deny entries are respected and orphaned entries are reported.
- Azure: PIM eligibility per scope, conditional (ABAC) assignments marked, assignments of deleted principals reported.
- Teams: members from other tenants in shared channels, and teams a channel is shared with.
- Power BI: personal and orphaned workspaces marked, deleted workspaces skipped. Power Platform: apps shared with everyone are reported, admin endpoints used for app permissions.
- Azure DevOps and Purview: retries on throttling, project paging fixed, Entra groups in DevOps groups reported, Purview role groups shown by display name.

**Scan status and coverage**
- Scans with failed sites, mailboxes or other targets, or that fell back to a narrower source, now show "Completed with errors" with the reason in the log instead of "Completed".
- Each scan records what it saw but did not list (for example sharing link counts and users with access to individual files), shown on the dashboard, in Results and in the Excel export.
- Timeouts, throttling and gateway errors are retried more consistently.

**Risk policies**
- 50 rewritten default policies, each with remediation advice shown in the permission details.
- Existing installs now receive updated default policies automatically; policies you edited are kept and marked when a newer default exists.
- Evaluate a whole scan against the policies, and re-score an existing scan after changing policies.

**Compare, export and GUI**
- Compare only includes categories that completed in both scans and lists what was excluded. Fixed: delegates on the same mailbox were mixed up in comparisons.
- The dashboard shows new Critical and High findings since the previous scan.
- Excel export: Category column and an About sheet with scan details, per-category status and coverage.
- Fixed: scans completed with errors never finished in the progress view; scan durations were off by the timezone offset; User Lookup sorting and filters; quick filters; SharePoint group member lookup.
- Delete individual scans. Chart.js is bundled instead of loaded from a CDN.

**Cmdlets**
- New: Get-M365Scan, Get-M365RiskSummary, Remove-M365Scan, Invoke-M365PolicyEvaluation.
- Get-M365Permissions -All streams every entry to the pipeline; -RiskLevel filter.
- Export-M365Permissions and Compare-M365Scans: -Category. Set-M365Config: -DefaultTimeoutMinutes.

# 2.1.0
- fix auth issues and some other long standing minor bugs

# 2.0.7-preview
- fix button and improve publish pipeline logic

# 2.0.6
- Minor improvements to logging
- Better handling of missing SPN's (post-auth)

# 2.0.5
- Fix issue with export to excel
- Automatic gallery publish
- Continue scans after interrupts and show more progress
- Fix showing all users in groups when looking up a specific user's permissions
- Adaptive throttling
- Enhanced local security (e.g. CORS)
- **Parallel scanning**
- Fix issues with delegated auth on tenants that lack certain SPN's
- Persists logs and make them filterable by target service
- Better pagination and retry
- Fix SPO temporary site ownership for scan
- More details / better scans of Entra and Azure (incl PIM)

