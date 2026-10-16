// Cloud Edition tips and per-category coverage. One place for what the free module covers, what the
// M365Permissions Cloud Edition adds, and the wording and links used for that across the GUI.
// Claims here must stay verifiable against the Cloud Edition; keep them factual and short.
(function () {
    'use strict';

    const SITE = 'https://m365permissions.com';
    const NAME = 'Cloud Edition';
    const HIDE_ALL_KEY = 'm365_cloudTips_off';
    const HIDE_KEY_PREFIX = 'm365_cloudTip_hidden_';

    function store(key, value) {
        try { value === null ? localStorage.removeItem(key) : localStorage.setItem(key, value); } catch { /* storage blocked */ }
    }
    function read(key) {
        try { return localStorage.getItem(key); } catch { return null; }
    }
    function esc(str) {
        const d = document.createElement('div');
        d.textContent = str == null ? '' : String(str);
        return d.innerHTML;
    }

    /** Link to m365permissions.com, tagged with where in the module it was clicked. */
    function link(path, context) {
        const [p, hash] = String(path || '/').split('#');
        const sep = p.includes('?') ? '&' : '?';
        return `${SITE}${p}${sep}utm_source=m365permissions-module&utm_medium=app&utm_content=${encodeURIComponent(context || 'general')}${hash ? '#' + hash : ''}`;
    }

    // Context -> tip. Body is plain text; {n} style values are filled by the caller through data.
    const TIPS = {
        riskQueue: {
            path: '/docs/how-to-use#reports',
            text: 'Track findings to closure: the Cloud Edition keeps a risk queue (open, fixed, recurred, ignored), says where to act, and re-checks every fix on the next scan.'
        },
        changes: {
            path: '/features',
            text: 'The Cloud Edition compares every scheduled scan with the previous one automatically, keeps first-seen and removed dates per permission, and emails the changes or sends them to Microsoft Sentinel.'
        },
        compare: {
            path: '/features',
            text: 'Comparing by hand works for spot checks. The Cloud Edition does it after every scheduled scan, with a "permissions changed over time" timeline and email or Microsoft Sentinel alerts on added, removed and changed permissions.'
        },
        trends: {
            path: '/features',
            text: 'Trends here only move when you run a scan. The Cloud Edition scans on a schedule (continuous, daily, weekly or monthly) and keeps the full history.'
        },
        userLookup: {
            path: '/docs/how-to-use',
            text: 'The Cloud Edition answers this down to individual files and folders, expands groups, and flags inactive users who still hold access.'
        },
        policies: {
            path: '/docs/how-to-use#reports',
            text: 'The Cloud Edition adds a risk queue with built-in risk reasons (admins without PIM, privileged app roles, escalation from Azure to Entra, anonymous links that never expire, orphaned permissions, inactive users) and tracks each to closure.'
        },
        sharingLink: {
            path: '/use-cases/sharepoint-oversharing-report',
            text: 'The Cloud Edition records every sharing link per file and folder, including expiry, block download and creation date, and reports anonymous links that never expire.'
        },
        itemLevel: {
            path: '/use-cases/sharepoint-oversharing-report',
            text: 'Below site and library level this scan counts access but does not list it. The Cloud Edition scans every file and folder with unique permissions, using delta scans so later runs only read what changed.'
        },
        exchangeFolders: {
            path: '/features',
            text: 'Mailbox folder permissions (including calendars shared with Default or Anonymous) are scanned by the Cloud Edition, with mailbox oversharing and published calendar reports.'
        },
        schedule: {
            path: '/evaluate',
            text: 'The Cloud Edition runs this scan unattended on a schedule from your own Azure subscription, with managed identity and no workstation or sign-in needed.'
        },
        export: {
            path: '/docs/how-to-use#subscriptions',
            text: 'The Cloud Edition can email reports like this on a schedule, filtered per category or path, and gives Power BI read access to the data.'
        },
        largeExport: {
            path: '/docs/how-to-use#exporting',
            text: 'The Cloud Edition exports large datasets server-side and emails the workbook, and offers direct SQL access for Power BI.'
        }
    };

    function tipsEnabled() { return read(HIDE_ALL_KEY) !== '1'; }

    /**
     * Small dismissible tip, or '' when tips are off or this tip was hidden.
     * options.text overrides the default text; options.compact renders a single line.
     */
    function tip(key, options = {}) {
        const def = TIPS[key];
        if (!def || !tipsEnabled() || read(HIDE_KEY_PREFIX + key) === '1') return '';
        const text = options.text || def.text;
        return `<div class="cloud-tip${options.compact ? ' compact' : ''}" data-tip="${esc(key)}">
            <span class="cloud-tip-badge">${NAME}</span>
            <span class="cloud-tip-text">${esc(text)} <a href="${esc(link(def.path, key))}" target="_blank" rel="noopener">Learn more</a></span>
            <button class="cloud-tip-close" title="Hide this tip" onclick="window.M365Cloud.hideTip('${esc(key)}', this)">&#x2715;</button>
        </div>`;
    }

    function hideTip(key, button) {
        store(HIDE_KEY_PREFIX + key, '1');
        const el = button && button.closest('.cloud-tip');
        if (el) el.remove();
    }

    function setTipsEnabled(on) {
        store(HIDE_ALL_KEY, on ? null : '1');
        if (on) {
            try {
                Object.keys(localStorage).filter(k => k.startsWith(HIDE_KEY_PREFIX)).forEach(k => localStorage.removeItem(k));
            } catch { /* storage blocked */ }
        }
    }

    // What each category covers locally, and what the Cloud Edition adds on top (verified features only).
    const COVERAGE = {
        SharePoint: {
            scans: [
                'Every site collection (tenant admin list), including Teams channel sites',
                'Site collection administrators',
                'Permissions on sites, subsites, lists and libraries with unique permissions',
                'SharePoint group members expanded',
                'Sharing links (anonymous, organization, specific people) with their recipients',
                'App-only grants (Sites.Selected)'
            ],
            notCovered: ['Files and folders with unique permissions are counted, not listed'],
            cloud: ['Every file and folder with unique permissions', 'Sharing link expiry, block download and dates', 'Delta scans that only re-read changes']
        },
        Entra: {
            scans: [
                'Directory role assignments: permanent, time-bound, PIM-activated and eligible, incl. administrative unit scope',
                'Members of role-assignable groups shown as role holders',
                'PIM for Groups eligibility on role-assignable groups',
                'App registrations and enterprise apps: API permissions and owners',
                'OAuth2 permission grants (admin and user consent)',
                'Group memberships and ownership, dynamic groups marked'
            ],
            notCovered: ['Administrative unit membership'],
            cloud: ['Devices and Intune RBAC', 'Inactive users that still hold access', 'Admins not using PIM report', 'Partner (delegated admin) permissions']
        },
        Teams: {
            scans: ['Team owners, members and guests', 'Private and shared channel members, including teams a channel is shared with'],
            notCovered: ['Files in Teams below library level'],
            cloud: ['Files and folders in Teams sites with unique permissions']
        },
        Exchange: {
            scans: ['Full Access delegates', 'Send As and Send on Behalf', 'Shared, room and equipment mailboxes told apart', 'Orphaned (deleted account) entries'],
            notCovered: ['Mailbox folder permissions (calendars, inbox)'],
            cloud: ['Mailbox folder permissions, including calendars', 'Mailbox oversharing and published calendars reports']
        },
        OneDrive: {
            scans: [
                'Every OneDrive, including leavers and unlicensed users (tenant admin list)',
                'OneDrive administrators',
                'Sharing links at any depth, with their recipients',
                'Libraries with unique permissions'
            ],
            notCovered: ['Files and folders with unique permissions are counted, not listed'],
            cloud: ['Every file and folder with unique permissions', 'Unexpected OneDrive owners report', 'Non-owner access to a personal OneDrive as a risk']
        },
        PowerBI: {
            scans: ['Workspace roles (Admin, Member, Contributor, Viewer)', 'Personal and orphaned workspaces'],
            notCovered: ['Report and dataset level sharing'],
            cloud: []
        },
        PowerAutomate: {
            scans: ['Flow owners and sharing', 'Power Apps owners and sharing, including apps shared with everyone', 'Custom connectors'],
            notCovered: ['Environment role assignments (Dataverse security roles)'],
            cloud: ['Power Automate connections']
        },
        Azure: {
            scans: [
                'Management group, subscription, resource group and resource role assignments',
                'PIM-eligible assignments',
                'Orphaned assignments of deleted principals'
            ],
            notCovered: ['Deny assignments', 'Data-plane access such as Key Vault access policies'],
            cloud: ['Entra permissions reachable through Azure (escalation paths)', 'Azure external access report']
        },
        AzureDevOps: {
            scans: ['Organizations the account belongs to', 'Project and organization security groups, nested groups expanded', 'Entra groups granted access'],
            notCovered: ['Repository, pipeline and service connection permissions'],
            cloud: []
        },
        Purview: {
            scans: ['Compliance role groups and their members'],
            notCovered: ['eDiscovery case membership'],
            cloud: []
        }
    };

    /** Scan-page card body for a category: what is scanned, what is not, and what the Cloud Edition adds. */
    function coverageHtml(category) {
        const c = COVERAGE[category];
        if (!c) return '';
        const list = (items, style) => `<ul style="margin:0 0 8px 16px;padding:0;${style || ''}">${items.map(i => `<li>${esc(i)}</li>`).join('')}</ul>`;
        let html = `<div style="color:var(--text-muted);margin-bottom:6px;font-weight:600">What is scanned</div>${list(c.scans, 'color:var(--text-secondary)')}`;
        if (c.notCovered.length)
            html += `<div style="color:var(--text-muted);margin-bottom:4px;font-weight:600">Not covered here</div>${list(c.notCovered, 'color:var(--text-muted)')}`;
        if (c.cloud.length && tipsEnabled())
            html += `<div style="color:var(--text-muted);margin-bottom:4px;font-weight:600">${NAME} adds</div>${list(c.cloud, 'color:var(--text-muted);font-style:italic')}`;
        return html;
    }

    const n = v => Number(v || 0);
    const fmt = v => n(v).toLocaleString();

    /**
     * Facts a scan measured but did not itemize, from /api/scans/:id/insights, as short sentences.
     * Returns [] when there is nothing worth saying.
     */
    function coverageFacts(insights) {
        const facts = [];
        if (!insights) return facts;
        for (const cat of ['SharePoint', 'OneDrive']) {
            const i = insights[cat];
            if (!i) continue;
            if (n(i.sharingLinks) > 0) {
                const parts = [];
                if (n(i.anonymousLinks)) parts.push(`${fmt(i.anonymousLinks)} anonymous`);
                if (n(i.organizationLinks)) parts.push(`${fmt(i.organizationLinks)} organization-wide`);
                if (n(i.specificPeopleLinks)) parts.push(`${fmt(i.specificPeopleLinks)} specific people`);
                facts.push({ key: 'sharingLink', text: `${cat}: ${fmt(i.sharingLinks)} sharing links (${parts.join(', ')}).` });
            }
            if (n(i.itemLevelPrincipals) > 0)
                facts.push({ key: 'itemLevel', text: `${cat}: ${fmt(i.itemLevelPrincipals)} users or groups hold access to individual files, folders or items that this scan counts but does not list.` });
            if (n(i.lockedSites) + n(i.archivedSites) > 0)
                facts.push({ key: null, text: `${cat}: ${fmt(n(i.lockedSites) + n(i.archivedSites))} locked or archived site${n(i.lockedSites) + n(i.archivedSites) === 1 ? '' : 's'} could not be read.` });
        }
        for (const [cat, i] of Object.entries(insights))
            if (n(i.partialReasons) > 0)
                facts.push({ key: null, text: `${cat}: results are partial; see the scan log for the reason.` });
        return facts;
    }

    /** Coverage card for a scan, or '' when there is nothing to report. */
    function coverageCard(insights, scanId) {
        const facts = coverageFacts(insights);
        if (!facts.length) return '';
        const itemLevel = facts.some(f => f.key === 'itemLevel' || f.key === 'sharingLink');
        return `<div class="card coverage-card">
            <h2>Coverage of scan #${esc(scanId)}</h2>
            <ul class="coverage-facts">${facts.map(f => `<li>${esc(f.text)}</li>`).join('')}</ul>
            ${itemLevel ? tip('itemLevel') : ''}
        </div>`;
    }

    window.M365Cloud = { NAME, SITE, link, tip, hideTip, tipsEnabled, setTipsEnabled, coverageHtml, coverageFacts, coverageCard, COVERAGE };
})();
