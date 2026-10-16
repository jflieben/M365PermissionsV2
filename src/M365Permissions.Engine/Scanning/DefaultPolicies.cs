using M365Permissions.Engine.Models;

namespace M365Permissions.Engine.Scanning;

/// <summary>
/// Built-in policy rules. Each has a stable DefaultKey so installs can be upgraded in place when a
/// definition changes (see PolicyRepository.SyncDefaults). Conditions target the vocabulary the
/// scanners emit; DefaultPolicyContractTests pins that contract.
/// </summary>
public static class DefaultPolicies
{
    // Entra roles that allow tenant takeover or broad data access.
    private const string CriticalAdminRoles =
        "Global Administrator|Company Administrator|Privileged Role Administrator|Privileged Authentication Administrator|" +
        "Security Administrator|Exchange Administrator|SharePoint Administrator|Teams Administrator|User Administrator|" +
        "Application Administrator|Cloud Application Administrator|Intune Administrator|Authentication Administrator|" +
        "Conditional Access Administrator|Compliance Administrator|Hybrid Identity Administrator|Domain Name Administrator|" +
        "External Identity Provider Administrator|Partner Tier2 Support";

    // Privileged but not tenant-takeover roles.
    private const string HighAdminRoles =
        "Billing Administrator|Helpdesk Administrator|Password Administrator|Groups Administrator|Authentication Policy Administrator";

    private const string CriticalAdminRolesRegex = "^(" + CriticalAdminRoles + ")$";

    // Scoped (administrative unit / object) role assignments: TargetPath "DirectoryRole/<role> (scope: ...)".
    private const string ScopedMarker = "(scope:";
    private const string HighAdminRolesRegex = "^(" + HighAdminRoles + ")$";
    private const string OtherAdminRolesRegex = "^(?!(" + CriticalAdminRoles + "|" + HighAdminRoles + ")$).+";

    // Purview role group names: newer scans use display names with spaces, older ones the no-space names.
    private const string CriticalPurviewRolesRegex = @"(?i)^(Organization ?Management|eDiscovery ?Manager|eDiscovery ?Administrator|Compliance ?Administrator)$";
    private const string HighPurviewRoleGroupsRegex =
        @"(?i)^(Compliance ?Data ?Administrator|Compliance ?Management|Security ?Administrator|Information ?Protection( ?Admins)?|" +
        @"Data ?Loss ?Prevention|Records ?Management|Insider ?Risk ?Management|Data ?Investigator|Communication ?Compliance|" +
        @"Privacy ?Management|Quarantine ?Administrator|Attack ?Simulator ?Administrators)$";

    // Azure roles that can grant access or change everything in scope.
    private const string AzurePrivilegedRolesRegex = "^(Owner|Contributor|User Access Administrator|Role Based Access Control Administrator)$";
    private const string AzureAccessAdminRolesRegex = "^(Owner|User Access Administrator|Role Based Access Control Administrator)$";

    private const string CriticalDevOpsRolesRegex = "(?i)^(Project Collection Administrators|Project Collection Service Accounts)$";
    private const string HighDevOpsOrgRolesRegex =
        "(?i)^(Project Collection Build Administrators|Project Collection Build Service Accounts|Project Collection Proxy Service Accounts|Project Collection Test Service Accounts)$";
    private const string HighDevOpsProjectRolesRegex = "(?i)^(Project Administrators|Build Administrators|Release Administrators|Endpoint Administrators)$";

    // Application/delegated Graph and Exchange permissions that expose data or allow privilege escalation.
    private const string HighRiskAppPermsRegex =
        @"^(Mail\.(Read|ReadWrite|Send)|MailboxSettings\.ReadWrite|Calendars\.ReadWrite|Files\.(Read|ReadWrite)\.All|" +
        @"Sites\.(Read|ReadWrite|Manage|FullControl)\.All|Directory\.(ReadWrite\.All|AccessAsUser\.All)|User\.ReadWrite\.All|" +
        @"Group\.ReadWrite\.All|GroupMember\.ReadWrite\.All|Chat\.(Read|ReadWrite)\.All|ChannelMessage\.Read\.All|" +
        @"Policy\.ReadWrite\.(ConditionalAccess|AuthenticationMethod)|Domain\.ReadWrite\.All|RoleManagement\.ReadWrite\.\w+|" +
        @"PrivilegedAccess\.ReadWrite\.\w+|AppRoleAssignment\.ReadWrite\.All|Application\.ReadWrite\.All|" +
        @"UserAuthenticationMethod\.ReadWrite\.All|Exchange\.ManageAsApp|full_access_as_app)$";

    // Permissions that let an app grant itself (or anyone) any other permission or role.
    private const string CriticalAppPermsRegex =
        @"^(RoleManagement\.ReadWrite\.\w+|PrivilegedAccess\.ReadWrite\.\w+|AppRoleAssignment\.ReadWrite\.All|Application\.ReadWrite\.All|Domain\.ReadWrite\.All)$";

    // Display names / claims of broad principals, for rows whose principal_type predates the canonical "Everyone".
    private const string BroadPrincipalNamesRegex =
        @"(?i)^(Everyone|Everyone except external users|All Users|All Users \(windows\)|All Authenticated Users|" +
        @"c:0\(\.s\|true|c:0-\.f\|rolemanager\|spo-grid-all-users/.*|Everyone in the organization)$";

    private const string GuestExternalTypesRegex = "^(Guest|External User|ExternalUser|External Group)$";

    private const string WriteRolesRegex =
        "(?i)^(Full Control|Design|Edit|Contribute|Contributor|Site Collection Administrator|Owner|Admin|FullAccess|SendAs|" +
        "ChangePermission|ChangeOwner|View or Edit|CanEdit|CanEditWithShare)$";

    private const string BroadFullControlRolesRegex = "(?i)^(Full Control|Design|Site Collection Administrator|Owner|Admin)$";
    private const string BroadEditRolesRegex = "(?i)^(Edit|Contribute|Contributor|View or Edit|Review|CanEdit|CanEditWithShare|Member)$";
    private const string AnonymousEditRolesRegex = "(?i)^(Edit|View or Edit|Contribute|Full Control|Design)$";

    // Rows that can't be used by anyone (cleanup items) must not inherit the grant's severity.
    private const string NotOrphanedRegex = "^(?!(Orphaned SID|Deleted principal)$).*";

    private const string SharedMailboxTypesRegex = "^(SharedMailbox|RoomMailbox|EquipmentMailbox)$";

    /// <summary>Names the defaults had before they carried a key, mapped to their key (legacy upgrade).</summary>
    public static readonly IReadOnlyDictionary<string, string> LegacyNames = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
    {
        ["Permanent active admin role"] = "entra-permanent-critical-role",
        ["Full Control to Everyone/All Users"] = "broad-full-control",
        ["Azure subscription-level Owner/Contributor"] = "azure-privileged-subscription",
        ["Azure management-group Owner/Contributor"] = "azure-privileged-management-group",
        ["Azure DevOps Project Collection Administrator"] = "devops-collection-admin",
        ["PIM-eligible critical admin role"] = "entra-eligible-critical-role",
        ["Azure resource group Owner/Contributor"] = "azure-privileged-resource-group",
        ["Azure DevOps Project Administrator"] = "devops-project-admin",
        ["FullAccess to mailbox"] = "exo-full-access",
        ["SendAs permission"] = "exo-send-as",
        ["Anonymous sharing link"] = "sp-anonymous-link",
        ["Broad principal permission"] = "broad-principal",
        ["High-risk application permission"] = "entra-high-risk-app-permission",
        ["Admin-consented OAuth2 grant"] = "entra-admin-consent-high-risk",
        ["Guest/external user access"] = "guest-external-access",
        ["Permanent non-critical directory role"] = "entra-permanent-other-role",
        ["Organization-wide sharing link"] = "sp-organization-link",
        ["SharePoint site owner/Full Control"] = "sp-full-control",
        ["Power Platform / PowerBI owner"] = "pp-owner",
        ["Critical Purview compliance role group member"] = "purview-critical-role-group",
        ["High-privilege Purview role group member"] = "purview-high-role-group",
        ["Standard member/contributor"] = "standard-contributor",
        ["Read-only access"] = "read-only",
    };

    public static List<Policy> GetAll() => new()
    {
        // ── Entra directory roles ───────────────────────────────
        P("entra-permanent-critical-role", "Permanent critical admin role", "Critical", "Entra",
            "Standing (permanent) assignment to a critical Entra admin role.",
            "Remove the assignment in Entra admin center > Roles and administrators, or convert it to PIM eligible with approval and MFA on activation. Keep at most two permanent break-glass Global Administrators.",
            C("tenure", "equals", "Permanent"),
            C("target_path", "startsWith", "DirectoryRole/"),
            C("target_path", "notContains", ScopedMarker),
            C("principal_role", "regex", CriticalAdminRolesRegex)),
        P("entra-timebound-critical-role", "Time-bound active critical admin role", "High", "Entra",
            "Active (non-PIM-activated) time-bound assignment to a critical Entra admin role.",
            "Confirm the end date is needed. Prefer PIM eligible assignments in Entra admin center > Identity Governance > Privileged Identity Management.",
            C("tenure", "startsWith", "Active (until"),
            C("target_path", "notContains", ScopedMarker),
            C("principal_role", "regex", CriticalAdminRolesRegex)),
        P("entra-scoped-critical-role", "Scoped critical admin role", "High", "Entra",
            "Standing or time-bound critical Entra admin role limited to an administrative unit or object scope.",
            "Confirm the scope still matches the person's job. Prefer PIM eligible assignments; manage them in Entra admin center > Roles and administrators (or the administrative unit's Roles and administrators).",
            C("tenure", "regex", "^(Permanent|Active \\(until)"),
            C("target_path", "contains", ScopedMarker),
            C("principal_role", "regex", CriticalAdminRolesRegex)),
        P("entra-eligible-critical-role", "PIM-eligible critical admin role", "High", "Entra",
            "PIM-eligible assignment to a critical Entra admin role.",
            "Review whether this person still needs the role. In Privileged Identity Management, require approval, MFA and a justification for activation, and schedule an access review.",
            C("tenure", "startsWith", "Eligible"),
            C("target_path", "notContains", ScopedMarker),
            C("principal_role", "regex", CriticalAdminRolesRegex)),
        P("entra-scoped-eligible-critical-role", "Scoped PIM-eligible critical admin role", "Medium", "Entra",
            "PIM-eligible critical Entra admin role limited to an administrative unit or object scope.",
            "Include the assignment in a periodic access review in Privileged Identity Management.",
            C("tenure", "startsWith", "Eligible"),
            C("target_path", "contains", ScopedMarker),
            C("principal_role", "regex", CriticalAdminRolesRegex)),
        P("entra-activated-critical-role", "Activated critical admin role", "Medium", "Entra",
            "Critical Entra admin role currently activated through PIM.",
            "No action if the activation is expected. Check the activation reason in Privileged Identity Management > Audit history.",
            C("tenure", "startsWith", "Activated"),
            C("principal_role", "regex", CriticalAdminRolesRegex)),
        P("entra-permanent-high-role", "Permanent privileged admin role", "High", "Entra",
            "Standing assignment to a privileged Entra admin role (billing, helpdesk, password, groups).",
            "Convert the assignment to PIM eligible in Entra admin center > Roles and administrators, or remove it if no longer needed.",
            C("tenure", "equals", "Permanent"),
            C("target_path", "startsWith", "DirectoryRole/"),
            C("principal_role", "regex", HighAdminRolesRegex)),
        P("entra-eligible-high-role", "PIM-eligible privileged admin role", "Medium", "Entra",
            "PIM-eligible assignment to a privileged Entra admin role.",
            "Include the role in a periodic access review in Privileged Identity Management.",
            C("tenure", "startsWith", "Eligible"),
            C("principal_role", "regex", HighAdminRolesRegex)),
        P("entra-permanent-other-role", "Permanent directory role", "Medium", "Entra",
            "Standing assignment to a directory role that is not in the critical or privileged lists.",
            "Convert to a PIM eligible assignment in Entra admin center > Roles and administrators, or remove it if unused.",
            C("tenure", "equals", "Permanent"),
            C("target_path", "startsWith", "DirectoryRole/"),
            C("principal_role", "regex", OtherAdminRolesRegex)),

        // ── Entra applications and consent ──────────────────────
        P("entra-critical-app-permission", "Privilege-escalation application permission", "Critical", "Entra",
            "Application permission that lets the app grant itself or others any role or permission.",
            "Verify the app needs this permission. Remove it in Entra admin center > Enterprise applications > the app > Permissions, restrict who owns the app, and monitor its credentials.",
            C("through", "equals", "ApplicationPermission"),
            C("principal_role", "regex", CriticalAppPermsRegex)),
        P("entra-high-risk-app-permission", "High-risk application permission", "High", "Entra",
            "Application permission with tenant-wide access to mail, files, chats or directory data.",
            "Confirm the business need and replace tenant-wide permissions with scoped ones (for example Sites.Selected or an Exchange application access policy). Revoke unused grants in Enterprise applications > Permissions.",
            C("through", "equals", "ApplicationPermission"),
            C("principal_role", "regex", HighRiskAppPermsRegex)),
        P("entra-admin-consent-high-risk", "Admin-consented high-risk delegated permission", "High", "Entra",
            "Delegated permission with high-risk scope consented for all users of the tenant.",
            "Review the app in Entra admin center > Enterprise applications > Permissions and revoke the admin consent if it isn't needed. Restrict user consent under Consent and permissions.",
            C("through", "equals", "OAuth2Grant (AllPrincipals)"),
            C("principal_role", "regex", HighRiskAppPermsRegex)),
        P("entra-user-consent-high-risk", "User-consented high-risk delegated permission", "Medium", "Entra",
            "A single user consented a high-risk delegated permission to an app.",
            "Check whether the app is trusted. Revoke the grant in Enterprise applications > the app > Permissions > User consent, and set user consent to verified publishers only.",
            C("through", "equals", "OAuth2Grant (Principal)"),
            C("principal_role", "regex", HighRiskAppPermsRegex)),
        P("entra-app-owner", "Application owner", "Medium", "Entra",
            "Owner of an app registration or service principal: can add credentials and act as the app.",
            "Keep app owners to a small, named set of administrators. Remove owners in Entra admin center > App registrations (or Enterprise applications) > Owners.",
            C("through", "regex", "^(ApplicationOwner|ServicePrincipalOwner|AppOwner)$")),

        // ── Groups and Teams ────────────────────────────────────
        P("group-owner", "Group owner", "Medium", "Entra",
            "Owner of a security group, Microsoft 365 group or distribution list: can change membership and therefore access.",
            "Make sure each group has at least two named owners and no unexpected ones. Manage owners in Entra admin center > Groups > Owners.",
            C("target_type", "regex", "^(SecurityGroup|M365Group|DistributionList)$"),
            C("principal_role", "equals", "Owner")),
        P("teams-owner", "Team owner", "Medium", "Teams",
            "Owner of a team or channel: can add members and guests.",
            "Review team owners in Teams admin center > Teams > Manage teams, and keep at least two owners per team.",
            C("principal_role", "equals", "Owner")),

        // ── Guests and external users ───────────────────────────
        P("guest-external-write", "Guest or external user with write access", "High", "",
            "Guest or external user holding edit, owner or full-control level access.",
            "Confirm the collaboration is still needed. Reduce the role to read, remove the access, or remove the guest in Entra admin center > Users. Schedule guest access reviews.",
            C("principal_type", "regex", GuestExternalTypesRegex),
            C("principal_role", "regex", WriteRolesRegex)),
        P("guest-external-access", "Guest/external user access", "Medium", "",
            "Permission held by a guest or external user.",
            "Verify the guest still needs access and is sponsored. Use Entra access reviews for guests and remove stale guest accounts.",
            C("principal_type", "regex", GuestExternalTypesRegex)),

        // ── Broad principals (Everyone, Anonymous) ──────────────
        P("broad-full-control", "Full control for everyone", "Critical", "",
            "Owner or full-control level access granted to everyone in the organization.",
            "Remove the Everyone grant and grant the access to a named group instead (site permissions in SharePoint, sharing settings in Power Platform).",
            C("principal_type", "regex", "^(Everyone|Anonymous)$"),
            C("through", "notEquals", "SharingLink"),
            C("principal_role", "regex", BroadFullControlRolesRegex)),
        P("broad-edit", "Edit access for everyone", "High", "",
            "Edit level access granted to everyone in the organization.",
            "Replace the Everyone grant with a named group that actually needs to edit. In SharePoint use Site permissions or Advanced permissions settings.",
            C("principal_type", "regex", "^(Everyone|Anonymous)$"),
            C("through", "notEquals", "SharingLink"),
            C("principal_role", "regex", BroadEditRolesRegex)),
        P("broad-principal", "Access for everyone", "Medium", "",
            "Access granted to everyone in the organization.",
            "Check the content is meant for the whole organization. Otherwise replace the Everyone grant with a named group.",
            C("principal_type", "regex", "^(Everyone|Anonymous)$")),
        P("broad-principal-legacy", "Access for everyone (by name)", "Medium", "",
            "Access granted to a broad principal recognised by name or claim (older scans).",
            "Check the content is meant for the whole organization. Otherwise replace the grant with a named group. Re-scan to get the current classification.",
            C("principal_sys_name", "regex", BroadPrincipalNamesRegex)),

        // ── SharePoint and OneDrive ─────────────────────────────
        P("sp-anonymous-link-edit", "Anonymous edit link", "Critical", "SharePoint,OneDrive",
            "Anyone with the link can edit, without signing in.",
            "Delete the link in the item's Manage access pane, or replace it with a link for specific people. Limit or disable Anyone links in SharePoint admin center > Policies > Sharing.",
            C("principal_type", "equals", "Anonymous"),
            C("principal_role", "regex", AnonymousEditRolesRegex)),
        P("sp-anonymous-link", "Anonymous link", "High", "SharePoint,OneDrive",
            "Anyone with the link can open the content, without signing in.",
            "Delete the link in the item's Manage access pane if it isn't needed, and set an expiration for Anyone links in SharePoint admin center > Policies > Sharing.",
            C("principal_type", "equals", "Anonymous")),
        P("sp-organization-link", "Organization-wide link", "Medium", "SharePoint,OneDrive",
            "Everyone in the organization who has the link can open the content.",
            "Replace the link with one for specific people when the content is sensitive. Set the default link type to Specific people in SharePoint admin center > Policies > Sharing.",
            C("through", "equals", "SharingLink"),
            C("principal_type", "equals", "Everyone")),
        P("sp-site-admin", "Site collection administrator", "Medium", "SharePoint",
            "Site collection administrator: full control over the site and all its content, including unique permissions.",
            "Keep site admins to the site owners who need it. Manage them in SharePoint admin center > Active sites > the site > Membership.",
            C("principal_role", "equals", "Site Collection Administrator")),
        P("sp-full-control", "Full Control on SharePoint", "Medium", "SharePoint",
            "Full Control or Design permission on a SharePoint site, list or item.",
            "Confirm the principal should manage this content. Lower it to Edit in Site settings > Site permissions where full control isn't needed.",
            C("principal_role", "regex", "(?i)^(Full Control|Design)$")),

        // ── Exchange ────────────────────────────────────────────
        P("exo-full-access", "Full Access to a user mailbox", "High", "Exchange",
            "Full Access (or the right to change permissions) on another user's mailbox.",
            "Remove the permission in Exchange admin center > Recipients > Mailboxes > the mailbox > Delegation if it isn't needed. Use a shared mailbox for shared work.",
            C("target_type", "notEquals", "SharedMailbox"),
            C("target_type", "notEquals", "RoomMailbox"),
            C("target_type", "notEquals", "EquipmentMailbox"),
            C("principal_role", "regex", "^(FullAccess|ChangePermission|ChangeOwner)$"),
            C("principal_type", "regex", NotOrphanedRegex)),
        P("exo-send-as", "Send As a user mailbox", "High", "Exchange",
            "Can send mail that appears to come from another user.",
            "Remove Send As in Exchange admin center > Recipients > Mailboxes > the mailbox > Delegation, or replace it with Send on Behalf.",
            C("target_type", "notEquals", "SharedMailbox"),
            C("target_type", "notEquals", "RoomMailbox"),
            C("target_type", "notEquals", "EquipmentMailbox"),
            C("principal_role", "contains", "SendAs"),
            C("principal_type", "regex", NotOrphanedRegex)),
        P("exo-shared-mailbox-access", "Full Access or Send As on a shared mailbox", "Medium", "Exchange",
            "Full Access or Send As on a shared, room or equipment mailbox.",
            "Review the delegates of the shared mailbox in Exchange admin center > Recipients > Mailboxes > Delegation and remove people who left the team.",
            C("target_type", "regex", SharedMailboxTypesRegex),
            C("principal_role", "regex", "^(FullAccess|ChangePermission|ChangeOwner|SendAs)$"),
            C("principal_type", "regex", NotOrphanedRegex)),
        P("exo-send-on-behalf", "Send on Behalf", "Low", "Exchange",
            "Can send mail on behalf of the mailbox (the recipient sees both names).",
            "Remove stale delegates in Exchange admin center > Recipients > Mailboxes > Delegation.",
            C("through", "equals", "GrantSendOnBehalfTo")),
        P("cleanup-orphaned-principal", "Orphaned principal", "Low", "",
            "Permission assigned to a deleted or unresolvable principal (orphaned SID or deleted principal).",
            "Remove the stale entry: Remove-MailboxPermission / Remove-RecipientPermission for Exchange, or delete the role assignment in Azure portal > Access control (IAM).",
            C("principal_type", "regex", "^(Orphaned SID|Deleted principal)$")),

        // ── Azure RBAC ──────────────────────────────────────────
        P("azure-privileged-management-group", "Permanent privileged Azure role on a management group", "Critical", "Azure",
            "Standing Owner, Contributor or access-administrator role on a management group: applies to every subscription below it.",
            "Remove the assignment in Azure portal > Management groups > Access control (IAM), or make it PIM eligible in Privileged Identity Management > Azure resources.",
            C("target_type", "equals", "ManagementGroup"),
            C("tenure", "equals", "Permanent"),
            C("principal_role", "regex", AzurePrivilegedRolesRegex),
            C("principal_type", "regex", NotOrphanedRegex)),
        P("azure-privileged-subscription", "Permanent privileged Azure role on a subscription", "Critical", "Azure",
            "Standing Owner, Contributor or access-administrator role on a subscription.",
            "Remove the assignment in Azure portal > Subscriptions > Access control (IAM), or make it PIM eligible in Privileged Identity Management > Azure resources.",
            C("target_type", "equals", "Subscription"),
            C("tenure", "equals", "Permanent"),
            C("principal_role", "regex", AzurePrivilegedRolesRegex),
            C("principal_type", "regex", NotOrphanedRegex)),
        P("azure-timebound-privileged-top", "Time-bound privileged Azure role on a subscription or management group", "High", "Azure",
            "Active time-bound Owner, Contributor or access-administrator role on a subscription or management group.",
            "Confirm the end date is needed. Prefer PIM eligible assignments with approval.",
            C("target_type", "regex", "^(ManagementGroup|Subscription)$"),
            C("tenure", "startsWith", "Active (until"),
            C("principal_role", "regex", AzurePrivilegedRolesRegex),
            C("principal_type", "regex", NotOrphanedRegex)),
        P("azure-eligible-privileged-top", "Eligible privileged Azure role on a subscription or management group", "Medium", "Azure",
            "PIM-eligible or activated Owner, Contributor or access-administrator role on a subscription or management group.",
            "Require approval and MFA on activation in Privileged Identity Management > Azure resources > Settings, and include the role in an access review.",
            C("target_type", "regex", "^(ManagementGroup|Subscription)$"),
            C("tenure", "regex", "^(Eligible|Activated)"),
            C("principal_role", "regex", AzurePrivilegedRolesRegex),
            C("principal_type", "regex", NotOrphanedRegex)),
        P("azure-privileged-resource-group", "Privileged Azure role on a resource group", "High", "Azure",
            "Owner, Contributor or access-administrator role on a resource group.",
            "Grant the least privileged built-in role instead, or make the assignment PIM eligible. Manage it in Azure portal > Resource groups > Access control (IAM).",
            C("target_type", "equals", "ResourceGroup"),
            C("tenure", "regex", "^(Permanent|Active)"),
            C("principal_role", "regex", AzurePrivilegedRolesRegex),
            C("principal_type", "regex", NotOrphanedRegex)),
        P("azure-access-admin-resource", "Access-administrator Azure role on a resource", "High", "Azure",
            "Owner or access-administrator role on a single resource: can grant others access to it.",
            "Replace with a role that can't assign access (for example Contributor) unless delegation is required. Manage it in the resource's Access control (IAM).",
            C("target_type", "equals", "Resource"),
            C("tenure", "regex", "^(Permanent|Active)"),
            C("principal_role", "regex", AzureAccessAdminRolesRegex),
            C("principal_type", "regex", NotOrphanedRegex)),
        P("azure-eligible-privileged-scoped", "Eligible privileged Azure role on a resource group or resource", "Low", "Azure",
            "PIM-eligible or activated Owner, Contributor or access-administrator role on a resource group or resource.",
            "Include the assignment in a periodic access review.",
            C("target_type", "regex", "^(ResourceGroup|Resource)$"),
            C("tenure", "regex", "^(Eligible|Activated)"),
            C("principal_role", "regex", AzurePrivilegedRolesRegex),
            C("principal_type", "regex", NotOrphanedRegex)),
        P("azure-contributor-resource", "Contributor on an Azure resource", "Medium", "Azure",
            "Contributor role on a single Azure resource.",
            "Use the least privileged built-in role for the resource type where possible.",
            C("target_type", "equals", "Resource"),
            C("tenure", "regex", "^(Permanent|Active)"),
            C("principal_role", "equals", "Contributor"),
            C("principal_type", "regex", NotOrphanedRegex)),

        // ── Azure DevOps ────────────────────────────────────────
        P("devops-collection-admin", "Azure DevOps organization administrator", "Critical", "AzureDevOps",
            "Member of Project Collection Administrators or Service Accounts: full control over the whole Azure DevOps organization.",
            "Keep this group to a few named administrators. Manage it in Azure DevOps > Organization settings > Permissions.",
            C("target_type", "equals", "Organization"),
            C("principal_role", "regex", CriticalDevOpsRolesRegex)),
        P("devops-collection-build-admin", "Azure DevOps organization build or service account group", "High", "AzureDevOps",
            "Member of an organization-wide build or service account group (for example Project Collection Build Administrators).",
            "Remove people who don't manage pipelines tenant-wide in Azure DevOps > Organization settings > Permissions.",
            C("target_type", "equals", "Organization"),
            C("principal_role", "regex", HighDevOpsOrgRolesRegex)),
        P("devops-project-admin", "Azure DevOps project administrator", "High", "AzureDevOps",
            "Member of Project, Build, Release or Endpoint Administrators: elevated project-level privileges.",
            "Review the group in Azure DevOps > Project settings > Permissions and remove members who no longer administer the project.",
            C("target_type", "equals", "Project"),
            C("principal_role", "regex", HighDevOpsProjectRolesRegex)),

        // ── Purview ─────────────────────────────────────────────
        P("purview-critical-role-group", "Critical Purview role group member", "Critical", "Purview",
            "Member of a Purview role group that can search all content or manage compliance tenant-wide (Organization Management, eDiscovery Manager, Compliance Administrator).",
            "Keep membership minimal and named. Manage it in Microsoft Purview portal > Settings > Roles and scopes > Role groups.",
            C("through", "equals", "RoleGroupMember"),
            C("principal_role", "regex", CriticalPurviewRolesRegex)),
        P("purview-high-role-group", "Privileged Purview role group member", "High", "Purview",
            "Member of a privileged Purview role group (DLP, information protection, records, insider risk, investigations).",
            "Review membership in Microsoft Purview portal > Settings > Roles and scopes > Role groups.",
            C("through", "equals", "RoleGroupMember"),
            C("principal_role", "regex", HighPurviewRoleGroupsRegex)),

        // ── Power BI and Power Platform ─────────────────────────
        P("pbi-workspace-admin", "Power BI workspace admin", "Medium", "PowerBI",
            "Admin of a shared Power BI workspace: can add users and delete content.",
            "Keep two named admins per workspace. Manage access in the workspace > Manage access, or Power BI admin portal > Workspaces.",
            C("principal_role", "equals", "Admin"),
            C("target_type", "notEquals", "PersonalWorkspace")),
        P("pbi-orphaned-workspace", "Orphaned Power BI workspace", "Medium", "PowerBI",
            "Access to a Power BI workspace that has no admin, so nobody manages its access or content.",
            "Assign at least two admins in Power BI admin portal > Workspaces > the workspace > Get access, or delete the workspace if it's no longer used.",
            C("target_type", "equals", "OrphanedWorkspace")),
        P("pp-owner", "Power Platform owner", "Medium", "PowerAutomate",
            "Owner or creator of a flow, app or connector.",
            "Make sure ownership is with a current employee or a service account, and add a co-owner. Manage it in Power Platform admin center > Resources.",
            C("principal_role", "regex", "^(Owner|Creator)$")),

        // ── Generic ─────────────────────────────────────────────
        P("standard-contributor", "Standard member or contributor", "Low", "",
            "Standard member, contributor or editor access.",
            "No action needed unless the person shouldn't have edit access. Include the resource in regular access reviews.",
            C("principal_role", "regex", "(?i)^(Members?|Contribut.*|Edit|View or Edit|Review|CanEdit|CanEditWithShare)$")),
        P("read-only", "Read-only access", "Info", "",
            "Read-only, viewer or visitor access.",
            "No action needed unless the content is confidential.",
            C("principal_role", "regex", "(?i)(Read|View|Visitor)")),
    };

    private static Policy P(string key, string name, string severity, string categories, string description, string remediation,
        params PolicyCondition[] conditions) => new()
    {
        DefaultKey = key,
        Name = name,
        Severity = severity,
        CategoryFilter = categories,
        Description = description,
        Remediation = remediation,
        IsDefault = true,
        Enabled = true,
        Conditions = conditions.ToList()
    };

    private static PolicyCondition C(string field, string op, string value) => new() { Field = field, Operator = op, Value = value };
}
