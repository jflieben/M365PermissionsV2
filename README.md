# M365Permissions

A PowerShell module that scans and reports on Microsoft 365 permissions across **SharePoint**, **Entra ID**, **Exchange Online**, **OneDrive**, **Power BI**, **Power Platform**, **Azure RBAC**, and **Azure DevOps**.

Built on a compiled .NET 8 engine with embedded SQLite database and web-based GUI. Zero external PowerShell module dependencies: everything is bundled.

## Features

- **360° permission visibility** across SharePoint, Entra ID, Exchange, OneDrive, Power BI, Power Platform, Azure RBAC, and Azure DevOps
- **Web GUI**: opens automatically on module import with dashboard, scan progress, results viewer, comparison tool
- **SQLite storage**: paginated queries, cross-scan comparison, persistent scan history
- **Excel/CSV export**: styled XLSX with ClosedXML or UTF-8 CSV
- **Scan comparison**: detect added, removed, and changed permissions between scans
- **Delegated auth**: secure browser-based OAuth2 PKCE flow, no client secrets needed
- **Lightweight**: no PnP.PowerShell, no Pode, no ImportExcel dependencies
- **Cross-platform**: runs on Windows, macOS, Linux (PowerShell 7.4+)

## Installation

```powershell
Install-PSResource -Name M365Permissions -Repository PSGallery
```

## Quick Start

```powershell
# Import module; the GUI opens automatically in your browser
Import-Module M365Permissions
```

Everything happens in the browser: connect to a tenant, configure scans, view results, export reports, and compare scans. You can scan multiple tenants by disconnecting from one and connecting to another; each scan records which tenant it belongs to.

## GUI

The web GUI starts automatically at `http://localhost:8080` when you import the module.

| Page | Description |
|------|-------------|
| Dashboard | Connection status, token expiry, recent scans (with tenant), risk summary, scan comparison delta |
| Scan | Select scan types, start/cancel scans, live progress |
| Results | Paginated results with category/search filters, risk levels, column picker, quick filters |
| Compare | Side-by-side scan comparison with added/removed/changed detection |
| Trends | Permission trend chart with tenant filter for multi-tenant tracking |
| Policies | Risk policy editor with custom conditions per permission field |
| Audit | Action log (scans, exports, config changes) |
| Settings | Port, threads, output format, log level, database management |

## Multi-Tenant Support

The module can scan different tenants in sequence. Each scan stores the tenant domain so you can:
- See which tenant each scan belongs to in results, comparisons, and the dashboard
- Filter trends by tenant to track permission changes per tenant over time
- Auto-compare only compares scans from the same tenant

To switch tenants, use the disconnect button (⏏) in the navigation bar or dashboard, then connect to a different tenant.

## Configuration

Settings are managed through the GUI's Settings page and stored in `%APPDATA%/JSolveBV/M365Permissions/`:

| Setting | Default | Description |
|---------|---------|-------------|
| `GuiPort` | 8080 | Web GUI TCP port |
| `MaxThreads` | 5 | Parallel scan threads |
| `OutputFormat` | XLSX | Default export format |
| `LogLevel` | Minimal | Logging verbosity |
| `DefaultTimeoutMinutes` | 120 | Scan timeout |

## Required Roles

Scans run as the signed-in account. These categories need an active admin role for complete results:

| Category | Role (any one) |
|----------|----------------|
| SharePoint, OneDrive | Global Administrator or SharePoint Administrator |
| Exchange Online | Global Administrator or Exchange Administrator |
| Power BI | Global Administrator or Fabric Administrator |
| Power Platform | Global Administrator, Power Platform Administrator or Dynamics 365 Administrator |
| Purview | Global Administrator, Compliance Administrator or Exchange Administrator |

Each scan starts with an account check that reads the roles and permissions in the access tokens and logs anything that will limit the results. Tokens are renewed at every scan start, so a PIM role activated after connecting is used as soon as you start the scan again.

## Scan Coverage

### SharePoint
- Every site collection from the tenant admin list (falls back to search when the account is not SharePoint Administrator; the scan is then marked incomplete), including Teams private and shared channel sites
- Site collection administrators
- Permissions on sites, subsites, lists and libraries with unique permissions; localized role names are mapped to the English built-in names
- SharePoint group members expanded, Entra and Microsoft 365 group claims linked to their Entra object
- Sharing links (anonymous, organization-wide, specific people) with their recipients, from the site's sharing link groups
- App-only grants (Graph site permissions, Sites.Selected)
- Files and folders with unique permissions below library level are counted, not listed

### OneDrive for Business
- Every OneDrive from the tenant admin list, including leavers and unlicensed users
- OneDrive administrators, libraries with unique permissions, sharing links at any depth with their recipients

### Entra ID
- Directory role assignments: permanent, time-bound, PIM-activated and PIM-eligible, including administrative unit and app scopes
- Members of role-assignable groups listed as role holders; PIM for Groups eligibility on role-assignable groups
- App registrations and enterprise apps: requested and granted API permissions, owners
- OAuth2 permission grants (admin consent and per-user consent)
- Group memberships and owners (dynamic groups marked), guests flagged

### Microsoft Teams
- Team owners, members and guests; private and shared channel members, including teams a channel is shared with and members from other tenants

### Exchange Online
- Full Access, Send As (including Deny entries) and Send on Behalf, with each trustee resolved to its Entra object
- Shared, room and equipment mailboxes told apart; entries of deleted accounts reported as orphaned

### Power BI
- Workspace roles (Admin, Member, Contributor, Viewer); personal and orphaned workspaces marked

### Power Platform
- Flow owners and sharing, Power Apps owners and sharing (including apps shared with everyone), custom connectors

### Azure RBAC
- Management group (incl. root), subscription, resource group and resource role assignments, active and PIM-eligible
- Conditional (ABAC) assignments marked; assignments of deleted principals reported

### Azure DevOps
- Organizations the account belongs to, project and organization security groups with nested and Entra groups

### Purview
- Compliance role groups and their members

Each scan records per category whether it completed, and what it saw but did not itemize (for example the number of sharing links and of users with item-level access). A category whose data is incomplete is shown as completed with errors.

## Free module and Cloud Edition

This module is free for non-commercial use and covers on-demand scans and one-off audits from your workstation. The [M365Permissions Cloud Edition](https://m365permissions.com/evaluate) runs in your own Azure subscription and adds:

- Scheduled, unattended scans (continuous, daily, weekly or monthly) with managed identity, delta scans and scale-out scan nodes for large tenants
- Every file and folder with unique permissions in SharePoint, OneDrive and Teams, sharing link details (expiry, block download, dates) and mailbox folder permissions
- Automatic comparison of every run with first-seen and removed dates, a permission change timeline, email subscriptions and Microsoft Sentinel events
- A risk queue that tracks each finding to closure and re-checks fixes on the next scan, plus prebuilt oversharing, guest, admin and PIM reports
- A multi-user portal with Entra ID single sign-on, an audit trail and direct SQL access for Power BI

## License

Free for non-commercial use.

Commercial use: https://jsolve.nl/commercial-use.html
