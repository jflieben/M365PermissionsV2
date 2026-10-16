/* M365Permissions — Vanilla JS SPA */
/* Hash-based routing, no build step, no frameworks */

(function () {
    'use strict';

    // ── API Helper ──────────────────────────────────────────────
    const api = {
        async get(url) {
            const res = await fetch(`/api${url}`);
            return res.json();
        },
        async post(url, body, headers) {
            const res = await fetch(`/api${url}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', ...(headers || {}) },
                body: body ? JSON.stringify(body) : undefined
            });
            return res.json();
        },
        async put(url, body) {
            const res = await fetch(`/api${url}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body)
            });
            return res.json();
        },
        async del(url) {
            const res = await fetch(`/api${url}`, { method: 'DELETE' });
            return res.json();
        },
        async getBlob(url) {
            return fetch(`/api${url}`);
        }
    };

    // Statuses of a scan that finished and has usable results.
    const isDoneScan = s => s.status === 'Completed' || s.status === 'CompletedWithErrors';

    // Timestamps without a zone are UTC (older SQLite values); parse them as such.
    function parseDate(value) {
        if (!value) return null;
        const s = String(value);
        const hasZone = /[zZ]$|[+-]\d\d:?\d\d$/.test(s);
        const d = new Date(hasZone ? s : s.replace(' ', 'T') + 'Z');
        return isNaN(d.getTime()) ? null : d;
    }
    const fmtDate = v => { const d = parseDate(v); return d ? d.toLocaleDateString() : '-'; };
    const fmtDateTime = v => { const d = parseDate(v); return d ? d.toLocaleString() : '-'; };

    // ── Toast Notifications ─────────────────────────────────────
    function showToast(message, type = 'info', durationMs = 4000) {
        const container = document.getElementById('toast-container');
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        toast.textContent = message;
        container.appendChild(toast);
        setTimeout(() => toast.remove(), durationMs);
    }

    // ── Theme Toggle ────────────────────────────────────────────
    function initTheme() {
        const saved = localStorage.getItem('m365pv2-theme') || 'dark';
        document.documentElement.setAttribute('data-theme', saved);
        updateThemeIcon(saved);

        document.getElementById('themeToggle').addEventListener('click', () => {
            const current = document.documentElement.getAttribute('data-theme');
            const next = current === 'dark' ? 'light' : 'dark';
            document.documentElement.setAttribute('data-theme', next);
            localStorage.setItem('m365pv2-theme', next);
            updateThemeIcon(next);
        });
    }

    function updateThemeIcon(theme) {
        document.getElementById('themeToggle').textContent = theme === 'dark' ? '☀️' : '🌙';
    }

    // ── State ───────────────────────────────────────────────────
    let state = {
        connected: false,
        tenantId: '',
        tenantDomain: '',
        upn: '',
        moduleVersion: '',
        scanRunning: false,
        currentScanId: null,
        refreshTokenExpiry: null,
        sharePointAdminUrl: null
    };

    let pollInterval = null;

    // Build a query string with current tenantId for tenant-scoped API calls
    function tenantQuery(extra) {
        const tid = state.tenantId;
        const params = tid ? `tenantId=${encodeURIComponent(tid)}` : '';
        return extra ? (params ? `${extra}&${params}` : extra) : (params ? `?${params}` : '');
    }

    // ── Status Polling ──────────────────────────────────────────
    async function refreshStatus() {
        try {
            const res = await api.get('/status');
            if (res.success) {
                state.connected = res.data.connected;
                state.tenantId = res.data.tenantId || '';
                state.tenantDomain = res.data.tenantDomain || '';
                state.upn = res.data.userPrincipalName || '';
                state.moduleVersion = res.data.moduleVersion || '';
                state.scanRunning = res.data.scanning || false;
                state.currentScanId = res.data.activeScanId;
                state.refreshTokenExpiry = res.data.refreshTokenExpiry || null;
                state.sharePointAdminUrl = res.data.sharePointAdminUrl || null;
                updateNavStatus();
            }
        } catch { /* ignore polling errors */ }
    }

    function updateNavStatus() {
        const badge = document.getElementById('connectionStatus');
        const version = document.getElementById('navVersion');
        const disconnectBtn = document.getElementById('disconnectBtn');

        if (state.moduleVersion) version.textContent = `v${state.moduleVersion}`;

        if (state.scanRunning) {
            badge.textContent = 'Scanning...';
            badge.className = 'status-badge scanning';
            if (disconnectBtn) disconnectBtn.style.display = 'none';
        } else if (state.connected) {
            badge.textContent = state.tenantDomain || 'Connected';
            badge.title = state.tenantDomain || '';
            badge.className = 'status-badge connected';
            if (disconnectBtn) disconnectBtn.style.display = '';
        } else {
            badge.textContent = 'Disconnected';
            badge.className = 'status-badge disconnected';
            if (disconnectBtn) disconnectBtn.style.display = 'none';
        }
    }

    // ── Router ──────────────────────────────────────────────────
    const routes = {
        '/': renderDashboard,
        '/scan': renderScan,
        '/results': renderResults,
        '/compare': renderCompare,
        '/settings': renderSettings,
        '/user-lookup': renderUserLookup,
        '/trends': renderTrends,
        '/audit': renderAudit,
        '/policies': renderPolicies
    };

    function navigate() {
        const hash = window.location.hash.slice(1) || '/';
        const path = hash.split('?')[0];
        const render = routes[path] || renderDashboard;

        document.querySelectorAll('.nav-link').forEach(link => {
            const page = link.getAttribute('data-page');
            const isActive =
                (path === '/' && page === 'dashboard') ||
                path === `/${page}`;
            link.classList.toggle('active', isActive);
        });

        render();
    }

    // ── Modal / Overlay Helpers ─────────────────────────────────
    function showModal(title, contentHtml) {
        let overlay = document.getElementById('modalOverlay');
        if (!overlay) {
            overlay = document.createElement('div');
            overlay.id = 'modalOverlay';
            overlay.className = 'modal-overlay';
            document.body.appendChild(overlay);
        }
        overlay.innerHTML = `
            <div class="modal-content">
                <div class="modal-header">
                    <h3>${escapeHtml(title)}</h3>
                    <button class="btn-icon modal-close" onclick="document.getElementById('modalOverlay').style.display='none'">✕</button>
                </div>
                <div class="modal-body">${contentHtml}</div>
            </div>
        `;
        overlay.style.display = 'flex';
        // Attached once: showModal is called repeatedly on the same overlay.
        if (!overlay.dataset.backdropClose) {
            overlay.dataset.backdropClose = '1';
            overlay.addEventListener('click', (e) => {
                if (e.target === overlay) overlay.style.display = 'none';
            });
        }
    }

    function closeModal() {
        const overlay = document.getElementById('modalOverlay');
        if (overlay) overlay.style.display = 'none';
    }

    // ── Sign-in popup ───────────────────────────────────────────
    // Requests that may need a Microsoft sign-in send X-M365-Prompt: gui. The engine then hands the
    // sign-in URL to this page (GET /api/auth/prompt) instead of opening a browser tab, and the page
    // shows it in a popup it closes again when the request finishes. A tab the OS opened can't be
    // closed by script, which is why sign-in used to leave a tab behind.
    const SIGNIN_WINDOW = 'm365-signin';
    const SIGNIN_FEATURES = 'popup,width=520,height=720';

    function openSignInWindow(url) {
        try { return window.open(url || 'about:blank', SIGNIN_WINDOW, SIGNIN_FEATURES); } catch { return null; }
    }

    function hideSignInPrompt() {
        document.getElementById('signInOverlay')?.remove();
    }

    // Asks for a click when no popup is open yet: browsers only allow popups right after a user action.
    function showSignInPrompt(url, onOpened) {
        hideSignInPrompt();
        const overlay = document.createElement('div');
        overlay.id = 'signInOverlay';
        overlay.className = 'modal-overlay';
        overlay.innerHTML = `
            <div class="modal-content" style="max-width:460px">
                <div class="modal-header"><h3>Microsoft sign-in required</h3></div>
                <div class="modal-body">
                    <p style="margin-bottom:16px">Sign in or approve the requested permissions in a popup window. It closes by itself when you're done.</p>
                    <div class="btn-group">
                        <button class="btn btn-primary" data-action="open">Open sign-in window</button>
                        <button class="btn btn-secondary" data-action="cancel">Cancel</button>
                    </div>
                </div>
            </div>`;
        overlay.querySelector('[data-action="open"]').addEventListener('click', () => {
            const win = openSignInWindow(url);
            if (win) {
                onOpened(win);
                hideSignInPrompt();
            } else {
                showToast('The popup was blocked. Allow popups for this page and try again.', 'error', 8000);
            }
        });
        overlay.querySelector('[data-action="cancel"]').addEventListener('click', () => {
            hideSignInPrompt();
            api.post('/auth/cancel').catch(() => { });
        });
        document.body.appendChild(overlay);
    }

    // Runs a request that may need sign-in. preopen opens the popup right away, inside the click that
    // started the request, so no extra click is needed when sign-in is certain (connect, re-consent).
    async function withSignIn(request, { preopen = false } = {}) {
        let win = preopen ? openSignInWindow() : null;
        if (win) {
            try { win.document.body.innerHTML = '<p style="font-family:sans-serif;padding:16px">Opening Microsoft sign-in…</p>'; } catch { /* ignore */ }
        }
        let done = false, seq = 0, reprompted = false;

        (async () => {
            while (!done) {
                await new Promise(r => setTimeout(r, 400));
                if (done) break;
                let res;
                try { res = await api.get('/auth/prompt'); } catch { continue; }
                const p = res && res.success ? res.data : null;
                if (done || !p || !p.url) continue;

                if (p.sequence !== seq) {
                    seq = p.sequence;
                    reprompted = false;
                    if (win && !win.closed) {
                        try { win.location.href = p.url; continue; } catch { /* fall back to asking for a click */ }
                    }
                    showSignInPrompt(p.url, w => { win = w; });
                } else if (win && win.closed && !reprompted) {
                    // Closed before finishing; the engine is still waiting. Offer to reopen or cancel.
                    reprompted = true;
                    showSignInPrompt(p.url, w => { win = w; reprompted = false; });
                }
            }
        })();

        try {
            return await request({ 'X-M365-Prompt': 'gui' });
        } finally {
            done = true;
            hideSignInPrompt();
            if (win && !win.closed) { try { win.close(); } catch { /* ignore */ } }
        }
    }

    // ── Remediation Links ───────────────────────────────────────
    function getRemediationLink(entry) {
        const cat = (entry.category || '').toLowerCase();
        if (cat === 'sharepoint' || cat === 'onedrive') {
            // The engine knows the real SharePoint tenant name; the tenant domain often differs from it.
            return state.sharePointAdminUrl
                ? { label: 'SharePoint Admin Center', url: `${state.sharePointAdminUrl}/_layouts/15/online/AdminHome.aspx#/siteManagement` }
                : { label: 'Microsoft 365 Admin Center', url: 'https://admin.microsoft.com/' };
        }
        if (cat === 'teams') {
            return { label: 'Teams Admin Center', url: 'https://admin.teams.microsoft.com/teams/manage' };
        }
        if (cat === 'azuredevops') {
            const org = ((entry.targetPath || '').split('/')[1] || '').trim();
            return org
                ? { label: 'Azure DevOps Permissions', url: `https://dev.azure.com/${encodeURIComponent(org)}/_settings/groups` }
                : { label: 'Azure DevOps', url: 'https://aex.dev.azure.com/' };
        }
        if (cat === 'purview') {
            return { label: 'Purview Role Groups', url: 'https://purview.microsoft.com/settings/rolesandscopes' };
        }
        if (cat === 'entra') {
            if ((entry.principalRole || '').toLowerCase().includes('admin')) {
                return { label: 'Entra ID Roles', url: 'https://entra.microsoft.com/#view/Microsoft_AAD_IAM/RolesManagementMenuBlade/~/AllRoles' };
            }
            if ((entry.targetType || '').toLowerCase().includes('application')) {
                return { label: 'Entra App Registrations', url: 'https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps/ApplicationsListBlade/quickStartType~/null/sourceType/Microsoft_AAD_IAM' };
            }
            return { label: 'Entra Admin Center', url: 'https://entra.microsoft.com/' };
        }
        if (cat === 'exchange') {
            return { label: 'Exchange Admin Center', url: 'https://admin.exchange.microsoft.com/#/mailboxes' };
        }
        if (cat === 'powerbi') {
            return { label: 'Power BI Admin Portal', url: 'https://app.powerbi.com/admin-portal' };
        }
        if (cat === 'powerautomate') {
            return { label: 'Power Automate Admin', url: 'https://admin.powerplatform.microsoft.com/environments' };
        }
        if (cat === 'azure') {
            const scope = entry.targetId || '';
            return scope.startsWith('/')
                ? { label: 'Azure Access control (IAM)', url: `https://portal.azure.com/#@${encodeURIComponent(state.tenantDomain || '')}/resource${scope}/users` }
                : { label: 'Azure Portal', url: 'https://portal.azure.com/#view/Microsoft_Azure_PIMCommon/CommonMenuBlade/~/quickStart' };
        }
        return null;
    }

    const isSharePointGroup = e => (e.principalType || '') === 'SharePoint Group' &&
        ['sharepoint', 'onedrive'].includes((e.category || '').toLowerCase());

    // ── Detail Panel ────────────────────────────────────────────
    function showDetailPanel(entry) {
        const fields = [
            ['Risk Level', entry.riskLevel],
            ['Risk Reason', entry.riskReason],
            ['Category', entry.category],
            ['Target Path', entry.targetPath],
            ['Target Type', entry.targetType],
            ['Target ID', entry.targetId],
            ['Principal UPN', entry.principalEntraUpn],
            ['Principal Name', entry.principalSysName],
            ['Principal Entra ID', entry.principalEntraId],
            ['Principal System ID', entry.principalSysId],
            ['Principal Type', entry.principalType],
            ['Role', entry.principalRole],
            ['Through', entry.through],
            ['Access Type', entry.accessType],
            ['Tenure', entry.tenure],
            ['Parent ID', entry.parentId],
            ['Start Date', entry.startDateTime],
            ['End Date', entry.endDateTime],
            ['Created', entry.createdDateTime],
            ['Modified', entry.modifiedDateTime]
        ];

        if (entry.via) fields.splice(3, 0, ['Via Group', entry.via]);

        // Entra group rows: the group is the target (membership rows) or the principal (grants).
        const groupAsTarget = ['SecurityGroup', 'M365Group', 'DistributionList'].includes(entry.targetType);
        const groupAsPrincipal = ['SecurityGroup', 'M365Group'].includes(entry.principalType) && entry.principalEntraId;
        let groupHint = '';
        if (isSharePointGroup(entry)) {
            groupHint = `<div style="margin-top:12px">
                <button class="btn btn-secondary" style="padding:6px 14px;font-size:0.85em"
                    onclick="window.m365.showSharePointGroupMembers(${Number(entry.scanId) || 'null'}, ${jsArg(entry.principalSysName)}, ${jsArg(entry.targetPath)}, ${jsArg(entry.targetId)})">
                    👥 View Group Members
                </button>
            </div>`;
        } else if (groupAsTarget || groupAsPrincipal) {
            const gid = groupAsTarget ? entry.targetId : String(entry.principalEntraId).replace(/_o$/, '');
            const gname = groupAsTarget ? (entry.targetPath || '') : (entry.principalSysName || '');
            groupHint = `<div style="margin-top:12px">
                <button class="btn btn-secondary" style="padding:6px 14px;font-size:0.85em"
                    onclick="window.m365.showGroupMembers(${Number(entry.scanId) || 'null'}, ${jsArg(gid)}, ${jsArg(gname)})">
                    👥 View Group Members
                </button>
            </div>`;
        }

        const remediation = getRemediationLink(entry);
        const remediationHtml = remediation ? `<div style="margin-top:12px">
            <a href="${escapeAttr(remediation.url)}" target="_blank" rel="noopener" class="btn btn-secondary" style="padding:6px 14px;font-size:0.85em;text-decoration:none">
                🔧 Open in ${escapeHtml(remediation.label)}
            </a>
        </div>` : '';

        showModal('Permission Details', `
            <table class="detail-table">
                ${fields.filter(([,v]) => v).map(([k, v]) => `<tr><td class="detail-label">${escapeHtml(k)}</td><td>${escapeHtml(v)}</td></tr>`).join('')}
            </table>
            <div id="detailPolicies"></div>
            ${groupHint}
            ${remediationHtml}
            ${detailCloudTip(entry)}
        `);
        loadMatchedPolicies(entry);
    }

    /** One Cloud Edition tip that fits the row: link details, item-level depth, mailbox folders. */
    function detailCloudTip(entry) {
        const C = window.M365Cloud;
        if (entry.through === 'SharingLink') return C.tip('sharingLink', { compact: true });
        if (['File', 'Folder', 'Item', 'Library', 'List'].includes(entry.targetType)) return C.tip('itemLevel', { compact: true });
        if (entry.category === 'Exchange') return C.tip('exchangeFolders', { compact: true });
        return '';
    }

    // Matched policies with their remediation advice, evaluated against the current policies.
    async function loadMatchedPolicies(entry) {
        if (!entry.riskLevel || entry.riskLevel === 'Info') return;
        try {
            const res = await api.post('/policies/match', { ...entry, scanId: Number(entry.scanId) || 0 });
            const el = document.getElementById('detailPolicies');
            if (!el || !res.success || !res.data || res.data.length === 0) return;
            el.innerHTML = `<div class="detail-policies">
                <div class="detail-policies-title">What to do</div>
                ${res.data.map(v => `<div class="detail-policy">
                    <div><span class="risk-badge risk-${escapeAttr((v.severity || 'info').toLowerCase())}">${escapeHtml(v.severity)}</span>
                        <strong>${escapeHtml(v.policyName)}</strong></div>
                    ${v.remediation ? `<div class="detail-policy-remediation">${escapeHtml(v.remediation)}</div>` : ''}
                </div>`).join('')}
            </div>${window.M365Cloud.tip('riskQueue', { compact: true })}`;
        } catch { /* advice is optional */ }
    }

    async function showSharePointGroupMembers(scanId, groupName, targetPath, targetId) {
        if (!scanId || !groupName) { showToast('No scan data available for group lookup', 'error'); return; }
        const title = `Members of ${groupName}`;
        showModal(title, '<div class="empty-state"><p>Loading...</p></div>');
        try {
            const q = `group=${encodeURIComponent(groupName)}&targetPath=${encodeURIComponent(targetPath || '')}&targetId=${encodeURIComponent(targetId || '')}`;
            const res = await api.get(`/scans/${scanId}/sharepoint-group-members?${q}`);
            renderMemberList(title, res.success ? res.data : null);
        } catch (e) {
            showModal(title, `<p>Error loading members: ${escapeHtml(e.message)}</p>`);
        }
    }

    function renderMemberList(title, members) {
        if (!members || members.length === 0) {
            showModal(title, '<div class="empty-state"><p>No members found in scan data</p></div>');
            return;
        }
        showModal(`${title} (${members.length})`, `
            <table>
                <thead><tr><th>Name</th><th>UPN</th><th>Type</th><th>Entra ID</th></tr></thead>
                <tbody>${members.map(m => `<tr>
                    <td>${escapeHtml(m.principalSysName || '')}</td>
                    <td>${escapeHtml(m.principalEntraUpn || '')}</td>
                    <td>${escapeHtml(m.principalType || '')}</td>
                    <td style="font-size:0.8em;color:var(--text-muted)">${escapeHtml(m.principalEntraId || '')}</td>
                </tr>`).join('')}</tbody>
            </table>
        `);
    }

    // ── Group Members Popup ─────────────────────────────────────
    async function showGroupMembers(scanId, groupId, groupName) {
        if (!scanId || !groupId) { showToast('No scan data available for group lookup', 'error'); return; }
        showModal(`Members of ${groupName}`, '<div class="empty-state"><p>Loading...</p></div>');
        try {
            const res = await api.get(`/scans/${scanId}/group-members?groupId=${encodeURIComponent(groupId)}`);
            renderMemberList(`Members of ${groupName}`, res.success ? res.data : null);
        } catch (e) {
            showModal(`Members of ${groupName}`, `<p>Error loading members: ${escapeHtml(e.message)}</p>`);
        }
    }

    // ── Sortable/Filterable Table Builder ───────────────────────
    let tableState = {
        sortColumn: null,
        sortDirection: 'asc',
        columnFilters: {},
        filterOptions: {}
    };

    function resetTableState() {
        tableState = { sortColumn: null, sortDirection: 'asc', columnFilters: {}, filterOptions: {} };
    }

    const dropdownFilterColumns = new Set(['category', 'targetType', 'principalType', 'through', 'accessType', 'tenure', 'riskLevel']);
    const columnDbMap = {
        category: 'category', targetPath: 'target_path', targetType: 'target_type',
        principal: 'principal_entra_upn', principalRole: 'principal_role',
        through: 'through', accessType: 'access_type', tenure: 'tenure',
        principalType: 'principal_type', riskLevel: 'risk_level'
    };

    // st: the table's own state object (Results uses tableState, User Lookup userTableState).
    function buildSortableHeader(columns, onSort, st = tableState) {
        return `<thead><tr>${columns.map(col => {
            const isSorted = st.sortColumn === col.db;
            const arrow = isSorted ? (st.sortDirection === 'asc' ? ' ↑' : ' ↓') : '';
            const filterHtml = col.filterable ? buildFilterControl(col, st) : '';
            return `<th>
                <div class="th-content" style="cursor:pointer" data-sort="${col.db}">
                    <span class="th-label">${escapeHtml(col.label)}${arrow}</span>
                </div>
                ${filterHtml}
            </th>`;
        }).join('')}</tr></thead>`;
    }

    function buildFilterControl(col, st = tableState) {
        if (dropdownFilterColumns.has(col.key)) {
            // Keep active filter values selectable even when the option list doesn't contain them.
            const selected = (st.columnFilters[col.db] || '').split('|').filter(Boolean);
            const options = [...new Set([...(st.filterOptions[col.db] || []), ...selected])];
            const selectedSet = new Set(selected);
            if (options.length === 0) return '';
            return `<div class="th-filter">
                <select class="filter-select" data-filter-col="${col.db}" multiple size="1"
                    title="${escapeAttr(selected.length ? selected.join(', ') : 'All')}">
                    ${options.map(o => `<option value="${escapeAttr(o)}" ${selectedSet.has(o) ? 'selected' : ''}>${escapeHtml(o)}</option>`).join('')}
                </select>
            </div>`;
        }
        const val = st.columnFilters[col.db] || '';
        return `<div class="th-filter">
            <input type="text" class="filter-input" data-filter-col="${col.db}"
                placeholder="Filter..." value="${escapeAttr(val)}">
        </div>`;
    }

    function attachTableListeners(tableEl, onSort, onFilter, st) {
        // Resolve the state at event time: renderResults/resetTableState replace tableState.
        const S = () => st || tableState;
        tableEl.querySelectorAll('.th-content[data-sort]').forEach(th => {
            th.addEventListener('click', () => {
                const col = th.dataset.sort;
                if (S().sortColumn === col) {
                    S().sortDirection = S().sortDirection === 'asc' ? 'desc' : 'asc';
                } else {
                    S().sortColumn = col;
                    S().sortDirection = 'asc';
                }
                onSort();
            });
        });

        tableEl.querySelectorAll('.filter-input').forEach(input => {
            input.addEventListener('input', debounce(() => {
                const col = input.dataset.filterCol;
                S().columnFilters[col] = input.value;
                onFilter();
            }, 400));
        });

        tableEl.querySelectorAll('.filter-select').forEach(sel => {
            sel.addEventListener('change', () => {
                const col = sel.dataset.filterCol;
                const selected = Array.from(sel.selectedOptions).map(o => o.value);
                S().columnFilters[col] = selected.join('|');
                sel.title = selected.length ? selected.join(', ') : 'All';
                onFilter();
            });
        });
    }

    // ── Quick Filter Presets ────────────────────────────────────
    // Column filters per quick-filter preset (values match the scanners' vocabulary).
    const QUICK_FILTERS = {
        'critical-high': { risk_level: 'Critical|High' },
        'external': { principal_type: 'Guest|External User|ExternalUser|External Group' },
        'anonymous': { principal_type: 'Anonymous' },
        'admin-roles': { category: 'Entra', through: 'DirectoryRoleAssignment|GroupMember|PIM-Eligible' },
        'full-access': { principal_role: 'FullAccess' },
        'critical': { risk_level: 'Critical' },
        'high': { risk_level: 'High' },
        'medium': { risk_level: 'Medium' },
        'low': { risk_level: 'Low' },
        'info': { risk_level: 'Info' }
    };

    async function applyQuickFilter(preset, btn) {
        resetTableState();
        document.querySelectorAll('#quickFilters .btn-active').forEach(b => b.classList.remove('btn-active'));
        const pill = btn || document.querySelector(`#quickFilters [data-preset="${preset}"]`);
        if (pill) pill.classList.add('btn-active');

        Object.assign(tableState.columnFilters, QUICK_FILTERS[preset] || {});
        currentPage = 1;
        await loadFilterOptions();
        await loadResults();
    }

    // ── Pages ───────────────────────────────────────────────────

    // Dashboard
    async function renderDashboard() {
        const app = document.getElementById('app');
        app.innerHTML = `
            <div class="card">
                <h2>Dashboard</h2>
                <div class="stats-grid" id="dashStats">
                    <div class="stat-card">
                        <div class="stat-value" id="statTenant">—</div>
                        <div class="stat-label">Tenant</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value" id="statScans">—</div>
                        <div class="stat-label">Completed Scans</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value" id="statPerms">—</div>
                        <div class="stat-label" id="statPermsLabel">Permissions (latest scan)</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value" id="statStatus">—</div>
                        <div class="stat-label">Status</div>
                    </div>
                    <div class="stat-card" id="tokenExpiryCard" style="display:none">
                        <div class="stat-value" id="statTokenExpiry" style="font-size:1.2em">—</div>
                        <div class="stat-label">Token Expires</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value" id="statDbSize">—</div>
                        <div class="stat-label">Database Size</div>
                    </div>
                </div>
                <div class="btn-group">
                    ${state.connected
                        ? `<button class="btn btn-primary" onclick="window.m365.startQuickScan()">▶ Start Scan</button>
                           <button class="btn btn-secondary" onclick="location.hash='#/user-lookup'">🔍 User Lookup</button>
                           <button class="btn btn-secondary" onclick="window.m365.disconnect()" title="Disconnect and connect to a different tenant">⏏ Switch Tenant</button>`
                        : '<button class="btn btn-primary" onclick="window.m365.connect()">🔗 Connect</button>'
                    }
                </div>
            </div>
            <div class="card" id="painCard" style="display:none;border-left:3px solid var(--accent)">
                <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:12px">
                    <div>
                        <strong>⚡ This scan worked hard.</strong>
                        <p id="painText" style="margin:6px 0;color:var(--text-muted);font-size:0.9em"></p>
                        <a href="${window.M365Cloud.link('/evaluate', 'dashboard-long-scan')}" target="_blank" rel="noopener" class="btn btn-secondary" style="padding:6px 14px;font-size:0.85em;text-decoration:none">How the ${window.M365Cloud.NAME} works</a>
                    </div>
                    <button class="btn-icon" title="Dismiss" onclick="window.m365.dismissPain()" style="background:none;border:none;cursor:pointer;font-size:1.2em;color:var(--text-muted)">✕</button>
                </div>
            </div>
            <div class="card" id="riskSummaryCard" style="display:none">
                <h2>Risk Overview (Latest Scan)</h2>
                <div class="stats-grid" id="riskStats"></div>
                <div id="riskTip"></div>
            </div>
            <div id="coverageSlot"></div>
            <div class="card" id="deltaCard" style="display:none">
                <h2 id="deltaTitle">Changes Since Previous Scan</h2>
                <p id="deltaHeadline" class="delta-headline"></p>
                <div class="stats-grid" id="deltaStats"></div>
                <div id="deltaCoverage"></div>
                <div style="margin-top:8px">
                    <a id="deltaCompareLink" href="#/compare" class="btn btn-secondary" style="padding:6px 14px;font-size:0.85em;text-decoration:none">View Full Comparison</a>
                </div>
                <div id="deltaTip"></div>
            </div>
            <div class="card" id="recentScansCard" style="display:none">
                <h2>Recent Scans</h2>
                <div class="table-wrapper">
                    <table><thead><tr>
                        <th>ID</th><th>Tenant</th><th>Date</th><th>Types</th><th>Status</th><th>Permissions</th><th>Notes</th><th>Actions</th>
                    </tr></thead><tbody id="recentScansBody"></tbody></table>
                </div>
            </div>
        `;

        document.getElementById('statTenant').textContent = state.tenantDomain || '—';
        document.getElementById('statStatus').textContent = state.connected ? '✓ Connected' : '✗ Not connected';
        document.getElementById('statStatus').style.fontSize = '1.3em';

        if (state.refreshTokenExpiry) {
            const expiryCard = document.getElementById('tokenExpiryCard');
            const expiryVal = document.getElementById('statTokenExpiry');
            if (expiryCard && expiryVal) {
                expiryCard.style.display = '';
                const exp = new Date(state.refreshTokenExpiry);
                const now = new Date();
                const daysLeft = Math.ceil((exp - now) / (1000 * 60 * 60 * 24));
                expiryVal.textContent = daysLeft > 0 ? `${daysLeft} days` : 'Expired';
                expiryVal.style.color = daysLeft <= 7 ? 'var(--error)' : daysLeft <= 14 ? 'var(--warning)' : 'var(--success)';
            }
        }

        // Load database size for dashboard
        try {
            const dbRes = await api.get('/database');
            if (dbRes.success) {
                document.getElementById('statDbSize').textContent = dbRes.data.sizeMB + ' MB';
            }
        } catch { /* best effort */ }

        try {
            const scans = await api.get('/scans' + tenantQuery());
            if (scans.success && scans.data.length > 0) {
                const completedScans = scans.data.filter(isDoneScan);
                document.getElementById('statScans').textContent = completedScans.length;
                if (completedScans.length > 0) {
                    document.getElementById('statPerms').textContent = (completedScans[0].totalPermissions || 0).toLocaleString();
                    document.getElementById('statPermsLabel').textContent = `Permissions (scan #${completedScans[0].id})`;
                }
                document.getElementById('recentScansCard').style.display = '';

                // A scan that took long or was very large is where scheduled, unattended Cloud Edition scans pay off.
                const latest = completedScans[0];
                if (latest && window.M365Cloud.tipsEnabled() && !localStorage.getItem('m365_painDismissed_' + latest.id)) {
                    const durMs = latest.completedAt && latest.startedAt
                        ? (parseDate(latest.completedAt) - parseDate(latest.startedAt)) : 0;
                    const hours = durMs / 3600000;
                    const perms = latest.totalPermissions || 0;
                    if (hours >= 2 || perms >= 250000) {
                        const painCard = document.getElementById('painCard');
                        const painText = document.getElementById('painText');
                        if (painCard && painText) {
                            const reason = hours >= 2
                                ? `Scan #${latest.id} took ${hours.toFixed(1)} hours`
                                : `Scan #${latest.id} found ${perms.toLocaleString()} permissions`;
                            painText.textContent = `${reason} and needed this workstation and your sign-in throughout. ` +
                                `The ${window.M365Cloud.NAME} runs scans like this unattended on a schedule from your own Azure subscription, ` +
                                'with managed identity and delta scans that only re-read what changed.';
                            painCard.dataset.scanId = latest.id;
                            painCard.style.display = '';
                        }
                    }
                }

                const tbody = document.getElementById('recentScansBody');
                tbody.innerHTML = scans.data.slice(0, 10).map(s => `<tr>
                    <td>${s.id}</td>
                    <td title="${escapeAttr(s.tenantDomain || '')}" style="max-width:150px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escapeHtml(s.tenantDomain || '—')}</td>
                    <td>${fmtDateTime(s.startedAt)}</td>
                    <td>${escapeHtml(s.scanTypes || '')}</td>
                    <td><span style="color:${s.status === 'Completed' ? 'var(--success)' : s.status === 'CompletedWithErrors' ? 'var(--warning)' : s.status === 'Failed' ? 'var(--error)' : 'var(--text-muted)'}">${s.status}</span></td>
                    <td>${s.totalPermissions ? s.totalPermissions.toLocaleString() : '—'}</td>
                    <td>
                        <span class="scan-notes-text" id="scanNotes${s.id}" title="Click to edit"
                            data-notes="${escapeAttr(s.notes || '')}"
                            onclick="window.m365.editScanNotes(${s.id})"
                            style="cursor:pointer;max-width:150px;display:inline-block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--text-muted);font-size:0.85em">
                            ${escapeHtml(s.notes || s.tags || '—')}
                        </span>
                    </td>
                    <td>
                        <button class="btn btn-secondary" style="padding:4px 10px;font-size:0.8em"
                            onclick="location.hash='#/results?id=${s.id}'">View</button>
                        ${s.status === 'Running' || s.status === 'Pending' ? '' : `<button class="btn btn-secondary btn-delete-scan" title="Delete this scan and its results"
                            onclick="window.m365.deleteScan(${s.id})">🗑</button>`}
                    </td>
                </tr>`).join('');

                // Risk summary for latest completed scan
                if (completedScans.length > 0) {
                    const latestId = completedScans[0].id;
                    try {
                        const riskRes = await api.get(`/scans/${latestId}/risk-summary`);
                        if (riskRes.success && riskRes.data) {
                            const riskCard = document.getElementById('riskSummaryCard');
                            riskCard.style.display = '';
                            const riskData = riskRes.data;
                            const levels = ['Critical', 'High', 'Medium', 'Low', 'Info'];
                            const colors = { Critical: '#b71c1c', High: '#f44336', Medium: '#ff9800', Low: '#4caf50', Info: '#2196f3' };
                            if ((riskData.Critical || 0) + (riskData.High || 0) > 0)
                                document.getElementById('riskTip').innerHTML = window.M365Cloud.tip('riskQueue');
                            document.getElementById('riskStats').innerHTML = levels.map(l => {
                                const count = riskData[l] || 0;
                                return `<div class="stat-card" style="cursor:pointer" title="Show ${l} findings" onclick="location.hash='#/results?id=${latestId}&risk=${l}'">
                                    <div class="stat-value" style="color:${colors[l]}">${count.toLocaleString()}</div>
                                    <div class="stat-label">${l}</div>
                                </div>`;
                            }).join('');
                        }
                    } catch { }

                    try {
                        const insRes = await api.get(`/scans/${latestId}/insights`);
                        if (insRes.success)
                            document.getElementById('coverageSlot').innerHTML = window.M365Cloud.coverageCard(insRes.data, latestId);
                    } catch { /* best effort */ }

                    // Counts-only delta vs the previous completed scan of this tenant (server picks it).
                    if (completedScans.length >= 2) {
                        try {
                            const newId = completedScans[0].id;
                            const dRes = await api.get(`/scans/${newId}/risk-delta`);
                            const d = dRes.success ? dRes.data : null;
                            if (d && d.previousScanId) {
                                document.getElementById('deltaCard').style.display = '';
                                document.getElementById('deltaTitle').textContent = `Changes Since Scan #${d.previousScanId}`;
                                document.getElementById('deltaHeadline').innerHTML = (d.newCritical || d.newHigh)
                                    ? `<span style="color:#b71c1c;font-weight:600">${d.newCritical.toLocaleString()} new Critical</span> / <span style="color:#f44336;font-weight:600">${d.newHigh.toLocaleString()} new High</span> since scan #${d.previousScanId}`
                                    : `No new Critical or High findings since scan #${d.previousScanId}`;
                                document.getElementById('deltaStats').innerHTML = `
                                    <div class="stat-card"><div class="stat-value" style="color:var(--success)">+${d.totalAdded.toLocaleString()}</div><div class="stat-label">Added</div></div>
                                    <div class="stat-card"><div class="stat-value" style="color:var(--error)">-${d.totalRemoved.toLocaleString()}</div><div class="stat-label">Removed</div></div>
                                    <div class="stat-card"><div class="stat-value" style="color:var(--warning)">~${d.totalChanged.toLocaleString()}</div><div class="stat-label">Changed</div></div>
                                `;
                                document.getElementById('deltaCoverage').innerHTML = coverageNotice(d.excludedCategories, d.flaggedCategories);
                                document.getElementById('deltaCompareLink').href = `#/compare?old=${d.previousScanId}&new=${newId}`;
                                if (d.totalAdded + d.totalRemoved + d.totalChanged > 0)
                                    document.getElementById('deltaTip').innerHTML = window.M365Cloud.tip('changes');
                            }
                        } catch { }
                    }
                }
            }
        } catch { }
    }

    // Scan
    /** Append a Cloud Edition tip to the first card of the current page. */
    function addPageTip(key) {
        document.querySelector('#app .card')?.insertAdjacentHTML('beforeend', window.M365Cloud.tip(key));
    }

    /** Collapsed side-by-side of this module and the Cloud Edition (empty when Cloud Edition tips are off). */
    function editionComparison(context) {
        const C = window.M365Cloud;
        if (!C.tipsEnabled()) return '';
        const rows = [
            ['Scanning', 'On demand, from this workstation while you are signed in', 'Scheduled (continuous, daily, weekly, monthly) and unattended with managed identity, in your own Azure subscription'],
            ['Depth', 'Sites, subsites, lists and libraries, groups expanded, sharing links', 'Also every file and folder with unique permissions, mailbox folders, delta scans for large tenants'],
            ['Changes', 'Compare two scans yourself', 'Every run compared automatically, first-seen and removed dates, change timeline, email and Microsoft Sentinel alerts'],
            ['Risk', 'Policies with severity and remediation advice', 'Risk queue that tracks each finding to closure and re-checks fixes on the next scan'],
            ['Sharing results', 'Local database and exports', 'Multi-user portal with Entra ID single sign-on, audit trail, scheduled email reports, SQL access for Power BI']
        ];
        return `<details class="edition-details" style="margin-top:16px;padding-top:12px;border-top:1px solid var(--border);font-size:0.9em">
            <summary style="cursor:pointer;color:var(--text-muted)">This module or the ${C.NAME}?</summary>
            <table class="edition-compare">
                <thead><tr><th></th><th>This module</th><th>${C.NAME}</th></tr></thead>
                <tbody>${rows.map(r => `<tr><td><strong>${escapeHtml(r[0])}</strong></td><td>${escapeHtml(r[1])}</td><td>${escapeHtml(r[2])}</td></tr>`).join('')}</tbody>
            </table>
            <div style="margin-top:8px;color:var(--text-muted);font-size:0.9em">
                No per-user licensing: billed through your Azure invoice.
                <a href="${C.link('/evaluate', context)}" target="_blank" rel="noopener" style="color:var(--accent)">Evaluate the ${C.NAME}</a> ·
                <a href="${C.link('/pricing', context)}" target="_blank" rel="noopener" style="color:var(--accent)">Pricing</a>
            </div>
        </details>`;
    }

    async function renderScan() {
        const app = document.getElementById('app');
        const isScanning = state.scanRunning;

        const scanCategories = [
            {
                val: 'SharePoint',
                icon: '📁',
                label: 'SharePoint Online',
                checked: true,
            },
            {
                val: 'Entra',
                icon: '🔐',
                label: 'Entra ID',
                checked: true,
            },
            {
                val: 'Teams',
                icon: '👥',
                label: 'Microsoft Teams',
                checked: false,
            },
            {
                val: 'Exchange',
                icon: '📧',
                label: 'Exchange Online',
                checked: true,
            },
            {
                val: 'OneDrive',
                icon: '☁️',
                label: 'OneDrive for Business',
                checked: false,
            },
            {
                val: 'PowerBI',
                icon: '📊',
                label: 'Power BI',
                checked: false,
            },
            {
                val: 'PowerAutomate',
                icon: '⚡',
                label: 'Power Platform',
                checked: false,
            },
            {
                val: 'Azure',
                icon: '🌐',
                label: 'Azure RBAC',
                checked: false,
            },
            {
                val: 'AzureDevOps',
                icon: '🔧',
                label: 'Azure DevOps',
                checked: false,
            },
            {
                val: 'Purview',
                icon: '🛡️',
                label: 'Purview Compliance',
                checked: false,
            },
        ];

        app.innerHTML = `
            <div class="card" ${isScanning ? 'style="display:none"' : ''}>
                <h2>Permission Scan</h2>
                ${!state.connected ? `
                    <div class="empty-state">
                        <div class="emoji">🔌</div>
                        <p>Connect to Microsoft 365 first</p>
                        <button class="btn btn-primary" style="margin-top:16px" onclick="window.m365.connect()">Connect</button>
                    </div>
                ` : `
                    <div class="form-group">
                        <p style="color:var(--text-muted);margin-bottom:16px;font-size:0.9em">Select which Microsoft 365 services to scan for permissions. Hover over a category for details.</p>
                        <div class="scan-cat-grid" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:14px">
                            ${scanCategories.map(t => `
                                <label class="scan-cat-card" style="display:flex;flex-direction:column;padding:16px;background:var(--bg-input);border:2px solid ${t.checked ? 'var(--accent)' : 'var(--border)'};border-radius:12px;cursor:pointer;transition:all 0.15s;user-select:none;position:relative">
                                    <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px">
                                        <input type="checkbox" value="${t.val}" ${t.checked ? 'checked' : ''} style="width:18px;height:18px;accent-color:var(--accent);flex-shrink:0"
                                            onchange="this.closest('.scan-cat-card').style.borderColor=this.checked?'var(--accent)':'var(--border)';this.closest('.scan-cat-card').style.background=this.checked?'var(--bg-card)':'var(--bg-input)'">
                                        <span style="font-size:1.5em;flex-shrink:0">${t.icon}</span>
                                        <span style="font-weight:700;font-size:1.05em">${t.label}</span>
                                    </div>
                                    <div style="font-size:0.8em;line-height:1.5;flex:1">
                                        ${window.M365Cloud.coverageHtml(t.val)}
                                    </div>
                                </label>
                            `).join('')}
                        </div>
                        <div style="margin-top:10px;display:flex;gap:8px">
                            <button type="button" class="btn btn-secondary" style="padding:3px 10px;font-size:0.78em"
                                onclick="document.querySelectorAll('.scan-cat-card input').forEach(c=>{c.checked=true;c.dispatchEvent(new Event('change'))})">Select All</button>
                            <button type="button" class="btn btn-secondary" style="padding:3px 10px;font-size:0.78em"
                                onclick="document.querySelectorAll('.scan-cat-card input').forEach(c=>{c.checked=false;c.dispatchEvent(new Event('change'))})">Clear All</button>
                        </div>
                    </div>
                    <div id="precheckResults" style="display:none;margin-bottom:12px"></div>
                    <div class="btn-group">
                        <button class="btn btn-secondary" id="btnPrecheck" onclick="window.m365.precheckScan()">🔍 Pre-check Permissions</button>
                        <button class="btn btn-primary" id="btnStartScan" onclick="window.m365.startScan()">▶ Start Scan</button>
                    </div>
                    ${editionComparison('scan-page')}
                `}
            </div>
            <div class="card" id="progressCard" style="${isScanning ? '' : 'display:none'}">
                <h2>Scan Progress</h2>
                <div class="btn-group" style="margin-bottom:12px">
                    <button class="btn btn-danger" id="btnCancelScan2" onclick="window.m365.cancelScan()">⏹ Cancel Scan</button>
                </div>
                <div class="progress-bar"><div class="progress-fill" id="progressFill" style="width:0%"></div></div>
                <p id="progressText" style="font-size:0.9em;color:var(--text-muted);margin:8px 0">Preparing...</p>
                <div id="categoryProgress" style="margin:12px 0"></div>
                <div id="throttleStatus" style="display:none;margin:8px 0;padding:8px 12px;background:var(--bg-input);border-radius:6px;font-size:0.8em;color:var(--text-muted)"></div>
                <div style="display:flex;align-items:center;gap:8px;margin:8px 0 4px">
                    <label style="font-size:0.8em;color:var(--text-muted)">Filter log by service:</label>
                    <select id="logCategoryFilter" onchange="window.renderScanLog && window.renderScanLog()" style="padding:4px 8px;background:var(--bg-input);border:1px solid var(--border);border-radius:6px;color:var(--text);font-size:0.8em">
                        <option value="">All services</option>
                        <option value="SharePoint">SharePoint</option>
                        <option value="Entra">Entra</option>
                        <option value="Teams">Teams</option>
                        <option value="Exchange">Exchange</option>
                        <option value="OneDrive">OneDrive</option>
                        <option value="PowerBI">PowerBI</option>
                        <option value="PowerAutomate">PowerAutomate</option>
                        <option value="Azure">Azure</option>
                        <option value="AzureDevOps">AzureDevOps</option>
                        <option value="Purview">Purview</option>
                    </select>
                </div>
                <div class="log-container" id="scanLog"></div>
            </div>
        `;

        if (state.scanRunning) {
            startProgressPolling();
        }
    }

    function startProgressPolling() {
        const progressCard = document.getElementById('progressCard');
        const setupCard = progressCard?.previousElementSibling;

        if (progressCard) progressCard.style.display = '';
        if (setupCard) setupCard.style.display = 'none';

        // Render the live scan log applying the per-service filter, with "sticky bottom" so the
        // panel only auto-scrolls when the user is already at the bottom. Reused by the poll loop
        // and by the filter dropdown's onchange (so filtering works after the scan finishes too).
        window.renderScanLog = function renderScanLog() {
            const log = document.getElementById('scanLog');
            if (!log || !window.__scanLogs) return;
            const filter = document.getElementById('logCategoryFilter')?.value || '';
            const lines = filter ? window.__scanLogs.filter(l => l.includes(`[${filter}]`)) : window.__scanLogs;
            const nearBottom = (log.scrollHeight - log.scrollTop - log.clientHeight) < 40;
            log.innerHTML = lines.map(l => `<div class="log-entry">${escapeHtml(l)}</div>`).join('');
            if (nearBottom) log.scrollTop = log.scrollHeight;
        };
        const renderScanLog = window.renderScanLog;

        if (pollInterval) clearInterval(pollInterval);
        pollInterval = setInterval(async () => {
            try {
                const res = await api.get('/scan/progress');
                if (!res.success || !res.data) return;

                const p = res.data;
                const fill = document.getElementById('progressFill');
                const text = document.getElementById('progressText');
                const log = document.getElementById('scanLog');
                const catProg = document.getElementById('categoryProgress');

                const pct = Math.min(100, Math.round(p.overallPercent || 0));
                if (fill) fill.style.width = `${pct}%`;

                const statusText = p.overallStatus === 'Completed' ? '100% — Scan complete!'
                    : p.overallStatus === 'CompletedWithErrors' ? '100% — Completed with errors (some services failed/skipped)'
                    : p.overallStatus === 'Failed' ? 'Scan failed'
                    : p.overallStatus === 'Cancelled' ? 'Scan cancelled'
                    : p.estimatedTimeRemaining ? `${pct}% — ${p.estimatedTimeRemaining}`
                    : `${pct}%`;
                if (text) text.textContent = statusText;

                if (catProg && p.categories && p.categories.length > 0) {
                    catProg.innerHTML = p.categories.slice().sort((a, b) => a.category.localeCompare(b.category)).map(c => {
                        const catPct = Math.min(100, c.percentComplete || 0);
                        const st = c.status;
                        const icon = st === 'Completed' ? '✓' : st === 'Running' ? '⏳' : st === 'Pending' ? '⏸'
                            : st === 'Skipped' ? '⊘' : '✗';
                        const barColor = st === 'Completed' ? 'var(--success)'
                            : st === 'Failed' ? 'var(--danger, #e5484d)'
                            : st === 'Skipped' ? 'var(--warning, #f5a623)'
                            : 'var(--accent)';
                        const failNote = (st === 'Failed' || st === 'Skipped')
                            ? ` <span style="color:${barColor};font-size:0.9em">(${st})</span>` : '';
                        return `<div style="display:flex;align-items:center;gap:8px;margin:4px 0;font-size:0.85em">
                            <span>${icon}</span>
                            <span style="min-width:100px;font-weight:600">${escapeHtml(c.category)}${failNote}</span>
                            <div style="flex:1;height:6px;background:var(--bg-input);border-radius:3px;overflow:hidden">
                                <div style="height:100%;width:${catPct}%;background:${barColor};border-radius:3px;transition:width 0.5s"></div>
                            </div>
                            <span style="min-width:40px;text-align:right;color:var(--text-muted)">${Math.round(catPct)}%</span>
                            <span style="min-width:80px;color:var(--text-muted);font-size:0.9em">${c.permissionsFound || 0} found</span>
                        </div>`;
                    }).join('');
                }

                if (log && p.recentLogs && p.recentLogs.length > 0) {
                    window.__scanLogs = p.recentLogs;
                    renderScanLog();
                }

                // Poll throttle metrics
                try {
                    const tRes = await api.get('/scan/throttle');
                    const tDiv = document.getElementById('throttleStatus');
                    if (tRes.success && tRes.data && tDiv) {
                        const t = tRes.data;
                        tDiv.style.display = '';
                        tDiv.innerHTML = `⚡ Throttle: ${t.currentConcurrency}/${t.maxConcurrency} concurrent | ${t.totalRequests} requests | ${t.throttledRequests} throttled | ${t.requestsPerSecond?.toFixed(1) || 0}/s`;
                    }
                } catch { }

                const finished = p.overallStatus === 'Completed' || p.overallStatus === 'CompletedWithErrors';
                const done = finished || p.overallStatus === 'Failed' || p.overallStatus === 'Cancelled';
                if (done) {
                    clearInterval(pollInterval);
                    pollInterval = null;
                    state.scanRunning = false;
                    updateNavStatus();
                    const btnCancel2 = document.getElementById('btnCancelScan2');
                    if (btnCancel2) btnCancel2.style.display = 'none';
                    if (finished && fill) fill.style.width = '100%';

                    // Show completion actions in the progress card
                    const progressCard = document.getElementById('progressCard');
                    if (progressCard) {
                        const actionsDiv = document.createElement('div');
                        actionsDiv.className = 'btn-group';
                        actionsDiv.style.marginTop = '16px';
                        if (finished && p.scanId) {
                            actionsDiv.innerHTML = `
                                <a class="btn btn-primary" href="#/results?id=${p.scanId}">📋 View Results</a>
                                <button class="btn btn-secondary" onclick="location.hash='#/scan';window.m365.route()">🔄 New Scan</button>
                            `;
                            actionsDiv.insertAdjacentHTML('afterend', window.M365Cloud.tip('schedule'));
                        } else {
                            actionsDiv.innerHTML = `
                                <button class="btn btn-secondary" onclick="location.hash='#/scan';window.m365.route()">🔄 New Scan</button>
                            `;
                        }
                        progressCard.appendChild(actionsDiv);
                    }

                    const toast = {
                        Completed: ['Scan completed!', 'success'],
                        CompletedWithErrors: ['Scan completed with errors: some services failed or were skipped. Check the log above.', 'warning'],
                        Failed: ['Scan failed', 'error'],
                        Cancelled: ['Scan cancelled', 'error']
                    }[p.overallStatus];
                    showToast(toast[0], toast[1], p.overallStatus === 'CompletedWithErrors' ? 10000 : 4000);
                }
            } catch { }
        }, 2000);
    }

    // Results
    let currentPage = 1;
    const pageSize = 50;
    let currentScanIdForResults = null;
    let hiddenColumns = new Set(JSON.parse(localStorage.getItem('m365pv2-hiddenCols') || '[]'));

    async function renderResults() {
        resetTableState();
        const app = document.getElementById('app');
        const params = new URLSearchParams(window.location.hash.split('?')[1] || '');
        const scanId = params.get('id');
        // Dashboard risk tiles link here with &risk=<level>; applied before the first load.
        const riskParam = params.get('risk');
        if (riskParam && ['Critical', 'High', 'Medium', 'Low', 'Info'].includes(riskParam))
            tableState.columnFilters['risk_level'] = riskParam;

        app.innerHTML = `
            <div class="card">
                <h2>Scan Results</h2>
                <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px" id="quickFilters">
                    <button class="btn btn-secondary" style="padding:4px 10px;font-size:0.8em" data-preset="critical-high" onclick="window.m365.applyQuickFilter('critical-high', this)">🔴 Critical/High</button>
                    <button class="btn btn-secondary" style="padding:4px 10px;font-size:0.8em" data-preset="external" onclick="window.m365.applyQuickFilter('external', this)">👤 External Users</button>
                    <button class="btn btn-secondary" style="padding:4px 10px;font-size:0.8em" data-preset="anonymous" onclick="window.m365.applyQuickFilter('anonymous', this)">🔗 Anonymous Links</button>
                    <button class="btn btn-secondary" style="padding:4px 10px;font-size:0.8em" data-preset="admin-roles" onclick="window.m365.applyQuickFilter('admin-roles', this)">🛡️ Admin Roles</button>
                    <button class="btn btn-secondary" style="padding:4px 10px;font-size:0.8em" data-preset="full-access" onclick="window.m365.applyQuickFilter('full-access', this)">📬 Full Access</button>
                    <button class="btn btn-secondary" style="padding:4px 10px;font-size:0.8em" onclick="window.m365.clearFilters()">✕ Clear</button>
                </div>
                <div style="display:flex;gap:12px;flex-wrap:wrap;margin-bottom:16px;align-items:flex-end">
                    <div class="form-group" style="margin:0;min-width:250px">
                        <label>Scan</label>
                        <select id="scanSelect" style="padding:8px;background:var(--bg-input);border:1px solid var(--border);border-radius:8px;color:var(--text);width:100%"></select>
                    </div>
                    <div class="form-group" style="margin:0;min-width:150px">
                        <label>Category</label>
                        <select id="categoryFilter" style="padding:8px;background:var(--bg-input);border:1px solid var(--border);border-radius:8px;color:var(--text)">
                            <option value="">All Categories</option>
                        </select>
                    </div>
                    <div class="form-group" style="margin:0;flex:1;min-width:200px">
                        <label>Search</label>
                        <input id="searchInput" type="text" placeholder="Search targets, principals, roles..." style="padding:8px;background:var(--bg-input);border:1px solid var(--border);border-radius:8px;color:var(--text);width:100%">
                    </div>
                    <button class="btn btn-secondary" onclick="window.m365.exportResults()">📥 Export</button>
                    <button class="btn btn-secondary" onclick="window.m365.toggleColumnPicker()" title="Show/hide columns">📊 Columns</button>
                </div>
                <div id="columnPicker" style="display:none;margin-bottom:12px;padding:8px 12px;background:var(--bg-input);border-radius:8px;font-size:0.85em"></div>
                <div class="table-wrapper" id="resultsTable">
                    <div class="empty-state"><div class="emoji">📋</div><p>Select a scan to view results</p></div>
                </div>
                <div class="pagination" id="pagination"></div>
            </div>
            <div id="resultsCoverage"></div>
        `;

        try {
            const scans = await api.get('/scans' + tenantQuery());
            if (scans.success && scans.data.length > 0) {
                const sel = document.getElementById('scanSelect');
                sel.innerHTML = '<option value="">— Select a scan —</option>' + scans.data.map(s =>
                    `<option value="${s.id}" ${s.id == scanId ? 'selected' : ''}>Scan #${s.id} · ${s.tenantDomain ? escapeHtml(s.tenantDomain) + ' · ' : ''}${fmtDate(s.startedAt)} · ${escapeHtml(s.scanTypes)} (${s.status})</option>`
                ).join('');

                sel.addEventListener('change', () => { resetTableState(); loadCategories(); loadFilterOptions(); loadResults(); });
                document.getElementById('categoryFilter').addEventListener('change', () => { currentPage = 1; loadFilterOptions(); loadResults(); });
                document.getElementById('searchInput').addEventListener('input', debounce(() => { currentPage = 1; loadResults(); }, 400));

                if (scanId || sel.value) {
                    if (scanId) sel.value = scanId;
                    loadCategories();
                    loadFilterOptions();
                    loadResults();
                }
            } else {
                document.getElementById('resultsTable').innerHTML = '<div class="empty-state"><div class="emoji">📋</div><p>No scans found. Run a scan first.</p></div>';
            }
        } catch { }
    }

    async function loadCategories() {
        const scanId = document.getElementById('scanSelect')?.value;
        const catFilter = document.getElementById('categoryFilter');
        if (!scanId || !catFilter) return;

        try {
            const res = await api.get(`/scans/${scanId}/categories`);
            if (res.success && res.data) {
                catFilter.innerHTML = '<option value="">All Categories</option>' +
                    res.data.map(c => `<option value="${c}">${c}</option>`).join('');
            }
        } catch { }

        // What this scan saw but did not itemize (sharing links, item-level access, unreadable sites).
        const coverage = document.getElementById('resultsCoverage');
        if (coverage) {
            coverage.innerHTML = '';
            try {
                const ins = await api.get(`/scans/${scanId}/insights`);
                if (ins.success && document.getElementById('scanSelect')?.value === scanId)
                    coverage.innerHTML = window.M365Cloud.coverageCard(ins.data, scanId);
            } catch { /* best effort */ }
        }
    }

    async function loadFilterOptions() {
        const scanId = document.getElementById('scanSelect')?.value;
        if (!scanId) return;
        const category = document.getElementById('categoryFilter')?.value || '';
        const filterCols = ['category', 'target_type', 'principal_type', 'through', 'access_type', 'tenure', 'risk_level'];
        try {
            const results = await Promise.all(filterCols.map(col =>
                api.get(`/scans/${scanId}/filter-options?column=${col}${category ? '&category=' + encodeURIComponent(category) : ''}`)
            ));
            results.forEach((res, i) => {
                if (res.success) tableState.filterOptions[filterCols[i]] = res.data;
            });
        } catch { }
    }

    async function loadResults(page) {
        currentPage = page || 1;
        const scanId = document.getElementById('scanSelect')?.value;
        const category = document.getElementById('categoryFilter')?.value || '';
        // Require 3+ chars before searching: a 1-2 char LIKE '%x%' is a full table scan on large
        // scans and returns near-everything anyway (P4). 0 chars = no filter.
        const rawSearch = document.getElementById('searchInput')?.value || '';
        const search = rawSearch.length > 0 && rawSearch.length < 3 ? '' : rawSearch;

        if (!scanId) return;
        // Show loading state
        const tableDiv = document.getElementById('resultsTable');
        if (tableDiv) tableDiv.innerHTML = '<div class="loading-skeleton"><div class="skeleton-row"></div><div class="skeleton-row"></div><div class="skeleton-row"></div><div class="skeleton-row"></div></div>';

        currentScanIdForResults = scanId;

        let url = `/scans/${scanId}/results?category=${encodeURIComponent(category)}&search=${encodeURIComponent(search)}&page=${currentPage}&pageSize=${pageSize}`;

        if (tableState.sortColumn) {
            url += `&sortColumn=${encodeURIComponent(tableState.sortColumn)}&sortDirection=${encodeURIComponent(tableState.sortDirection)}`;
        }
        for (const [col, val] of Object.entries(tableState.columnFilters)) {
            if (val) url += `&f_${encodeURIComponent(col)}=${encodeURIComponent(val)}`;
        }

        try {
            const allColumns = [
                { key: 'riskLevel', db: 'risk_level', label: 'Risk', filterable: true },
                { key: 'category', db: 'category', label: 'Category', filterable: true },
                { key: 'targetPath', db: 'target_path', label: 'Target', filterable: false },
                { key: 'targetType', db: 'target_type', label: 'Type', filterable: true },
                { key: 'principal', db: 'principal_entra_upn', label: 'Principal', filterable: false },
                { key: 'principalType', db: 'principal_type', label: 'Identity Type', filterable: true },
                { key: 'principalRole', db: 'principal_role', label: 'Role', filterable: false },
                { key: 'through', db: 'through', label: 'Through', filterable: true },
                { key: 'accessType', db: 'access_type', label: 'Access', filterable: true }
            ];
            const columns = allColumns.filter(c => !hiddenColumns.has(c.key));
            const visibleKeys = new Set(columns.map(c => c.key));

            const res = await api.get(url);
            if (!res.success) { showToast(res.error || 'Load failed', 'error'); return; }
            const { items, totalCount } = res.data;
            const totalPages = Math.ceil(totalCount / pageSize);

            if (items.length > 0) {
                tableDiv.innerHTML = `<table id="resultsTableEl">
                    ${buildSortableHeader(columns, () => loadResults())}
                    <tbody>${items.map((p, idx) => {
                        const principal = p.principalEntraUpn || p.principalSysName || p.principalEntraId || '';
                        const isGroupType = p.principalType === 'SecurityGroup' || p.principalType === 'M365Group';
                        const principalHtml = isSharePointGroup(p)
                            ? `<span class="group-link" onclick="event.stopPropagation();window.m365.showSharePointGroupMembers(${Number(scanId) || 'null'},${jsArg(p.principalSysName || '')},${jsArg(p.targetPath || '')},${jsArg(p.targetId || '')})" title="Click to view group members">👥 ${escapeHtml(principal)}</span>`
                            : isGroupType
                            ? `<span class="group-link" onclick="event.stopPropagation();window.m365.showGroupMembers(${Number(scanId) || 'null'},${jsArg(String(p.principalEntraId || p.principalSysId || '').replace(/_o$/, ''))},${jsArg(principal)})" title="Click to view group members">👥 ${escapeHtml(principal)}</span>`
                            : escapeHtml(principal);
                        const cellMap = {
                            riskLevel: `<td><span class="risk-badge risk-${(p.riskLevel || 'low').toLowerCase()}">${escapeHtml(p.riskLevel || '')}</span></td>`,
                            category: `<td>${escapeHtml(p.category || '')}</td>`,
                            targetPath: `<td title="${escapeHtml(p.targetPath || '')}">${escapeHtml(truncate(p.targetPath, 45))}</td>`,
                            targetType: `<td>${escapeHtml(p.targetType || '')}</td>`,
                            principal: `<td>${principalHtml}</td>`,
                            principalType: `<td>${escapeHtml(p.principalType || '')}</td>`,
                            principalRole: `<td>${escapeHtml(p.principalRole || '')}</td>`,
                            through: `<td>${escapeHtml(p.through || '')}</td>`,
                            accessType: `<td>${escapeHtml(p.accessType || '')}</td>`
                        };
                        return `<tr class="clickable-row" data-idx="${idx}">
                            ${columns.map(c => cellMap[c.key] || '').join('')}
                        </tr>`;
                    }).join('')}</tbody>
                </table>`;

                const tableEl = document.getElementById('resultsTableEl');
                attachTableListeners(tableEl, () => loadResults(), () => { currentPage = 1; loadResults(); });

                tableEl.querySelectorAll('.clickable-row').forEach(row => {
                    row.addEventListener('click', () => {
                        const idx = parseInt(row.dataset.idx);
                        const entry = items[idx];
                        if (entry) {
                            entry.scanId = scanId;
                            showDetailPanel(entry);
                        }
                    });
                });
            } else {
                tableDiv.innerHTML = '<div class="empty-state"><p>No results found</p></div>';
            }

            const pagDiv = document.getElementById('pagination');
            pagDiv.innerHTML = totalPages <= 1
                ? `<span class="page-info">${totalCount.toLocaleString()} result${totalCount === 1 ? '' : 's'}</span>`
                : `
                <button ${currentPage <= 1 ? 'disabled' : ''} onclick="window.m365.loadResults(${currentPage - 1})">← Prev</button>
                <span class="page-info">Page ${currentPage} of ${totalPages} (${totalCount.toLocaleString()} results)</span>
                <button ${currentPage >= totalPages ? 'disabled' : ''} onclick="window.m365.loadResults(${currentPage + 1})">Next →</button>
            `;
        } catch (e) {
            showToast('Failed to load results', 'error');
        }
    }

    // User Permissions Lookup
    async function renderUserLookup() {
        const app = document.getElementById('app');

        app.innerHTML = `
            <div class="card">
                <h2>🔍 User Permissions Lookup</h2>
                <p style="color:var(--text-muted);margin-bottom:16px">Search for all permissions a user has — directly, through groups, or as eligible. Results are based on scan data.</p>
                ${!state.connected ? `
                    <div class="notice notice-warning" style="margin-bottom:16px">
                        <strong>Not connected.</strong> Connect to Microsoft 365 and run a scan to see results.
                    </div>
                ` : ''}
                <div style="display:flex;gap:12px;flex-wrap:wrap;align-items:flex-end">
                    <div class="form-group" style="margin:0;min-width:250px">
                        <label>Scan</label>
                        <select id="userLookupScan" style="padding:8px;background:var(--bg-input);border:1px solid var(--border);border-radius:8px;color:var(--text);width:100%"></select>
                    </div>
                    <div class="form-group" style="margin:0;flex:1;min-width:250px">
                        <label>User (UPN, name, or Entra ID)</label>
                        <input id="userLookupInput" type="text" placeholder="e.g. john@contoso.com" style="padding:8px;background:var(--bg-input);border:1px solid var(--border);border-radius:8px;color:var(--text);width:100%">
                    </div>
                    <button class="btn btn-primary" onclick="window.m365.searchUserPerms()">🔍 Search</button>
                </div>
                <div id="userLookupNotice" style="margin-top:12px"></div>
            </div>
            <div class="card" id="userResultsCard" style="display:none">
                <h2 id="userResultsTitle">Results</h2>
                <div class="table-wrapper" id="userResultsTable"></div>
                <div class="pagination" id="userPagination"></div>
            </div>
        `;
        addPageTip('userLookup');

        try {
            const scans = await api.get('/scans' + tenantQuery());
            if (scans.success && scans.data.length > 0) {
                const sel = document.getElementById('userLookupScan');
                const completedScans = scans.data.filter(isDoneScan);
                if (completedScans.length === 0) {
                    sel.innerHTML = '<option value="">No completed scans available</option>';
                    document.getElementById('userLookupNotice').innerHTML = `
                        <div class="notice notice-warning">No completed scans found. Run a full scan first to get accurate results.</div>
                    `;
                } else {
                    sel.innerHTML = completedScans.map(s =>
                        `<option value="${s.id}" data-types="${escapeAttr(s.scanTypes || '')}" data-status="${escapeAttr(s.status)}">Scan #${s.id} · ${fmtDate(s.startedAt)} · ${escapeHtml(s.scanTypes)} (${(s.totalPermissions || 0).toLocaleString()} perms${s.status === 'CompletedWithErrors' ? ', with errors' : ''})</option>`
                    ).join('');
                    sel.addEventListener('change', () => {
                        updateScanNotice();
                        userTableState = { sortColumn: null, sortDirection: 'asc', columnFilters: {}, filterOptions: {} };
                        document.getElementById('userResultsCard').style.display = 'none';
                    });
                    updateScanNotice();
                }
            } else {
                document.getElementById('userLookupScan').innerHTML = '<option value="">No scans available</option>';
                document.getElementById('userLookupNotice').innerHTML = `
                    <div class="notice notice-warning">No scans have been run yet. Run a scan to search for user permissions.</div>
                `;
            }
        } catch { }

        document.getElementById('userLookupInput')?.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') window.m365.searchUserPerms();
        });
    }

    function updateScanNotice() {
        const sel = document.getElementById('userLookupScan');
        const notice = document.getElementById('userLookupNotice');
        if (!sel || !notice) return;
        const option = sel.selectedOptions[0];
        if (!option) return;
        // Exact category match: "Azure" must not count as covered by "AzureDevOps".
        const types = new Set((option.dataset.types || '').split(',').map(t => t.trim()).filter(Boolean));
        const allTypes = ['SharePoint', 'Entra', 'Teams', 'Exchange', 'OneDrive', 'PowerBI', 'PowerAutomate', 'Azure', 'AzureDevOps', 'Purview'];
        const missing = allTypes.filter(t => !types.has(t));
        const parts = [];
        if (missing.length > 0)
            parts.push(`<div class="notice notice-info">This scan did not include: <strong>${missing.join(', ')}</strong>. Results for those services will not appear.</div>`);
        if (option.dataset.status === 'CompletedWithErrors')
            parts.push('<div class="notice notice-warning">This scan completed with errors; some services may be incomplete.</div>');
        notice.innerHTML = parts.join('');
    }

    let userLookupPage = 1;
    let userTableState = {
        sortColumn: null,
        sortDirection: 'asc',
        columnFilters: {},
        filterOptions: {}
    };

    async function searchUserPerms(page) {
        userLookupPage = page || 1;
        const scanId = document.getElementById('userLookupScan')?.value;
        const user = document.getElementById('userLookupInput')?.value?.trim();
        if (!scanId) { showToast('Select a scan first', 'error'); return; }
        if (!user) { showToast('Enter a user to search for', 'error'); return; }

        let url = `/scans/${scanId}/user-permissions?user=${encodeURIComponent(user)}&page=${userLookupPage}&pageSize=50`;
        if (userTableState.sortColumn) {
            url += `&sortColumn=${encodeURIComponent(userTableState.sortColumn)}&sortDirection=${encodeURIComponent(userTableState.sortDirection)}`;
        }
        for (const [col, val] of Object.entries(userTableState.columnFilters)) {
            if (val) url += `&f_${encodeURIComponent(col)}=${encodeURIComponent(val)}`;
        }

        try {
            // Filter dropdown values for this scan, loaded once per scan.
            if (userTableState.optionsScanId !== scanId) {
                const cols = ['category', 'target_type', 'through', 'access_type', 'tenure', 'risk_level'];
                const opts = await Promise.all(cols.map(c => api.get(`/scans/${scanId}/filter-options?column=${c}`).catch(() => null)));
                userTableState.filterOptions = {};
                opts.forEach((r, i) => { if (r && r.success) userTableState.filterOptions[cols[i]] = r.data; });
                userTableState.optionsScanId = scanId;
            }

            const res = await api.get(url);
            if (!res.success) { showToast(res.error || 'Search failed', 'error'); return; }

            const { items, totalCount } = res.data;
            const via = res.data.via || {};
            const totalPages = Math.ceil(totalCount / 50);
            const card = document.getElementById('userResultsCard');
            card.style.display = '';

            document.getElementById('userResultsTitle').textContent =
                `Results for "${user}" (${totalCount.toLocaleString()} permissions${res.data.exactMatch ? ', exact UPN match' : ''})`;

            const columns = [
                { key: 'riskLevel', db: 'risk_level', label: 'Risk', filterable: true },
                { key: 'category', db: 'category', label: 'Category', filterable: true },
                { key: 'targetPath', db: 'target_path', label: 'Target', filterable: false },
                { key: 'targetType', db: 'target_type', label: 'Type', filterable: true },
                { key: 'principalRole', db: 'principal_role', label: 'Role', filterable: false },
                { key: 'through', db: 'through', label: 'Through', filterable: true },
                { key: 'via', db: 'via', label: 'Via Group', filterable: false, sortable: false },
                { key: 'accessType', db: 'access_type', label: 'Access', filterable: true },
                { key: 'tenure', db: 'tenure', label: 'Tenure', filterable: true }
            ];

            const tableDiv = document.getElementById('userResultsTable');
            if (items.length === 0) {
                tableDiv.innerHTML = '<div class="empty-state"><p>No permissions found for this user in the selected scan.</p></div>';
            } else {
                tableDiv.innerHTML = `<table id="userResultsTableEl">
                    ${buildSortableHeader(columns, () => searchUserPerms(), userTableState)}
                    <tbody>${items.map((p, idx) => `<tr class="clickable-row" data-uidx="${idx}">
                        <td><span class="risk-badge risk-${escapeAttr((p.riskLevel || 'low').toLowerCase())}">${escapeHtml(p.riskLevel || '')}</span></td>
                        <td>${escapeHtml(p.category || '')}</td>
                        <td title="${escapeAttr(p.targetPath || '')}">${escapeHtml(truncate(p.targetPath, 45))}</td>
                        <td>${escapeHtml(p.targetType || '')}</td>
                        <td>${escapeHtml(p.principalRole || '')}</td>
                        <td>${escapeHtml(p.through || '')}</td>
                        <td>${escapeHtml(via[p.id] || '')}</td>
                        <td>${escapeHtml(p.accessType || '')}</td>
                        <td>${escapeHtml(p.tenure || '')}</td>
                    </tr>`).join('')}</tbody>
                </table>`;

                const userTableEl = document.getElementById('userResultsTableEl');
                // "via" is computed per row and can't be sorted server-side.
                userTableEl.querySelector('.th-content[data-sort="via"]')?.removeAttribute('data-sort');
                attachTableListeners(userTableEl, () => searchUserPerms(), () => { userLookupPage = 1; searchUserPerms(); }, userTableState);

                userTableEl.querySelectorAll('.clickable-row').forEach(row => {
                    row.addEventListener('click', () => {
                        const idx = parseInt(row.dataset.uidx);
                        const entry = items[idx];
                        if (entry) { entry.scanId = scanId; entry.via = via[entry.id] || ''; showDetailPanel(entry); }
                    });
                });
            }

            const pagDiv = document.getElementById('userPagination');
            pagDiv.innerHTML = totalPages > 1 ? `
                <button ${userLookupPage <= 1 ? 'disabled' : ''} onclick="window.m365.searchUserPerms(${userLookupPage - 1})">← Prev</button>
                <span class="page-info">Page ${userLookupPage} of ${totalPages}</span>
                <button ${userLookupPage >= totalPages ? 'disabled' : ''} onclick="window.m365.searchUserPerms(${userLookupPage + 1})">Next →</button>
            ` : '';
        } catch (e) {
            showToast('Search failed: ' + e.message, 'error');
        }
    }

    // Compare
    const COMPARE_LIMIT = 500; // rows per list returned by /api/compare; counts are always complete
    let lastCompare = null;

    // Value of a ChangedFields entry ("TargetPath") on a camelCase entry object.
    function changeValue(entry, field) {
        const v = entry ? entry[field.charAt(0).toLowerCase() + field.slice(1)] : '';
        return v === undefined || v === null || v === '' ? '(empty)' : v;
    }

    // Banner listing categories left out of (or only partly in) a comparison.
    function coverageNotice(excluded, flagged) {
        const parts = [];
        if (excluded && excluded.length)
            parts.push(`<div class="notice notice-warning"><strong>Not compared:</strong> ${excluded.map(n => `${escapeHtml(n.category)} (${escapeHtml(n.reason)})`).join('; ')}</div>`);
        if (flagged && flagged.length)
            parts.push(`<div class="notice notice-info"><strong>Partial:</strong> ${flagged.map(n => `${escapeHtml(n.category)} (${escapeHtml(n.reason)})`).join('; ')}</div>`);
        return parts.join('');
    }

    async function renderCompare() {
        lastCompare = null;
        const app = document.getElementById('app');
        app.innerHTML = `
            <div class="card">
                <h2>Compare Scans</h2>
                <div style="display:flex;gap:16px;flex-wrap:wrap">
                    <div class="form-group" style="flex:1;min-width:200px">
                        <label>Baseline Scan</label>
                        <select id="oldScanSelect" style="width:100%;padding:10px;background:var(--bg-input);border:1px solid var(--border);border-radius:8px;color:var(--text)"></select>
                    </div>
                    <div class="form-group" style="flex:1;min-width:200px">
                        <label>Comparison Scan</label>
                        <select id="newScanSelect" style="width:100%;padding:10px;background:var(--bg-input);border:1px solid var(--border);border-radius:8px;color:var(--text)"></select>
                    </div>
                    <div class="form-group" style="min-width:160px">
                        <label>Category</label>
                        <select id="compareCategory" style="width:100%;padding:10px;background:var(--bg-input);border:1px solid var(--border);border-radius:8px;color:var(--text)">
                            <option value="">All categories</option>
                            ${['SharePoint', 'Entra', 'Teams', 'Exchange', 'OneDrive', 'PowerBI', 'PowerAutomate', 'Azure', 'AzureDevOps', 'Purview'].map(c => `<option value="${c}">${c}</option>`).join('')}
                        </select>
                    </div>
                </div>
                <div class="btn-group">
                    <button class="btn btn-primary" onclick="window.m365.runCompare()">🔄 Compare</button>
                    <button class="btn btn-secondary" id="btnExportCompare" style="display:none" onclick="window.m365.exportCompare()">📥 Export Comparison</button>
                </div>
            </div>
            <div class="card" id="compareResults" style="display:none">
                <h2>Comparison Results</h2>
                <div id="compareCoverage"></div>
                <div class="stats-grid" id="compareStats"></div>
                <div class="btn-group compare-tabs" id="compareTabs"></div>
                <p id="compareNotice" class="compare-notice"></p>
                <div class="table-wrapper" id="compareTable"></div>
            </div>
        `;
        addPageTip('compare');

        try {
            const scans = await api.get('/scans' + tenantQuery());
            if (scans.success && scans.data.length > 0) {
                const completedScans = scans.data.filter(isDoneScan);
                if (completedScans.length >= 1) {
                    const options = completedScans.map(s =>
                        `<option value="${s.id}">Scan #${s.id} · ${s.tenantDomain ? escapeHtml(s.tenantDomain) + ' · ' : ''}${fmtDate(s.startedAt)} (${escapeHtml(s.scanTypes)}, ${(s.totalPermissions || 0).toLocaleString()} perms${s.status === 'CompletedWithErrors' ? ', with errors' : ''})</option>`
                    ).join('');
                    document.getElementById('oldScanSelect').innerHTML = options;
                    document.getElementById('newScanSelect').innerHTML = options;
                    document.getElementById('newScanSelect').selectedIndex = 0;
                    if (completedScans.length > 1)
                        document.getElementById('oldScanSelect').selectedIndex = 1;
                    // Deep link from the dashboard: #/compare?old=1&new=2 runs right away.
                    const hp = new URLSearchParams(window.location.hash.split('?')[1] || '');
                    if (hp.get('old') && hp.get('new')) {
                        document.getElementById('oldScanSelect').value = hp.get('old');
                        document.getElementById('newScanSelect').value = hp.get('new');
                        window.m365.runCompare();
                    }
                } else {
                    document.getElementById('oldScanSelect').innerHTML = '<option>No completed scans</option>';
                    document.getElementById('newScanSelect').innerHTML = '<option>No completed scans</option>';
                }
            } else {
                document.getElementById('oldScanSelect').innerHTML = '<option>No scans available</option>';
                document.getElementById('newScanSelect').innerHTML = '<option>No scans available</option>';
            }
        } catch { }
    }

    // Trends
    async function renderTrends() {
        const app = document.getElementById('app');
        app.innerHTML = `
            <div class="card">
                <h2>📈 Permission Trends</h2>
                <div style="display:flex;align-items:center;gap:12px;margin-bottom:16px">
                    <p style="color:var(--text-muted);margin:0">Track how permissions change across scans.</p>
                    <select id="trendTenantFilter" style="padding:4px 8px;border-radius:4px;border:1px solid var(--border);background:var(--card-bg);color:var(--text)">
                        <option value="">All tenants</option>
                    </select>
                </div>
                <div style="max-height:350px;position:relative"><canvas id="trendChart"></canvas></div>
            </div>
            <div class="card" id="trendTable" style="display:none">
                <h2>Trend Data</h2>
                <div class="table-wrapper" id="trendTableBody"></div>
            </div>
        `;
        addPageTip('trends');

        try {
            const trendsTenantId = state.tenantId ? `&tenantId=${encodeURIComponent(state.tenantId)}` : '';
            const res = await api.get('/trends?limit=50' + trendsTenantId);
            if (!res.success || !res.data || res.data.length === 0) {
                document.getElementById('trendChart').parentElement.innerHTML += '<div class="empty-state"><p>No trend data yet. Complete at least 2 scans.</p></div>';
                return;
            }
            const allData = res.data;

            // Populate tenant filter dropdown
            const tenants = [...new Set(allData.map(d => d.tenantDomain || 'Unknown').filter(t => t))];
            const filterEl = document.getElementById('trendTenantFilter');
            if (tenants.length <= 1) {
                filterEl.style.display = 'none';
            } else {
                tenants.forEach(t => {
                    const opt = document.createElement('option');
                    opt.value = t;
                    opt.textContent = t;
                    filterEl.appendChild(opt);
                });
                // Default to current tenant if connected
                const currentDomain = state.tenantDomain || '';
                if (currentDomain && tenants.includes(currentDomain)) {
                    filterEl.value = currentDomain;
                }
            }

            const showMultipleTenants = tenants.length > 1;

            function applyTrendFilter(selectedTenant) {
                const data = selectedTenant ? allData.filter(d => (d.tenantDomain || 'Unknown') === selectedTenant) : allData;
                if (data.length === 0) {
                    document.getElementById('trendTable').style.display = 'none';
                    return;
                }

                const trendCard = document.getElementById('trendTable');
                trendCard.style.display = '';
                document.getElementById('trendTableBody').innerHTML = `<table>
                    <thead><tr>${showMultipleTenants ? '<th>Tenant</th>' : ''}<th>Scan</th><th>Date</th><th>Total</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Info</th></tr></thead>
                    <tbody>${data.map(d => `<tr>
                        ${showMultipleTenants ? `<td title="${escapeAttr(d.tenantDomain || '')}">${escapeHtml(truncate(d.tenantDomain || 'Unknown', 30))}</td>` : ''}
                        <td>#${d.scanId}</td>
                        <td>${fmtDate(d.startedAt)}</td>
                        <td>${d.totalPermissions.toLocaleString()}</td>
                        <td style="color:#b71c1c">${d.critical}</td>
                        <td style="color:#f44336">${d.high}</td>
                        <td style="color:#ff9800">${d.medium}</td>
                        <td style="color:#4caf50">${d.low}</td>
                        <td style="color:#2196f3">${d.info}</td>
                    </tr>`).join('')}</tbody>
                </table>`;

                // Destroy existing chart if any
                const canvas = document.getElementById('trendChart');
                if (canvas._chartInstance) { canvas._chartInstance.destroy(); }

                if (typeof Chart !== 'undefined') {
                    const ctx = canvas.getContext('2d');
                    const chartLabels = data.map(d => showMultipleTenants ? `#${d.scanId} (${truncate(d.tenantDomain || '?', 15)})` : `#${d.scanId}`);
                    const chart = new Chart(ctx, {
                        type: 'line',
                        data: {
                            labels: chartLabels,
                            datasets: [
                                { label: 'Critical', data: data.map(d => d.critical), borderColor: '#b71c1c', backgroundColor: 'rgba(183,28,28,0.1)', tension: 0.3 },
                                { label: 'High', data: data.map(d => d.high), borderColor: '#f44336', backgroundColor: 'rgba(244,67,54,0.1)', tension: 0.3 },
                                { label: 'Medium', data: data.map(d => d.medium), borderColor: '#ff9800', backgroundColor: 'rgba(255,152,0,0.1)', tension: 0.3 },
                                { label: 'Low', data: data.map(d => d.low), borderColor: '#4caf50', backgroundColor: 'rgba(76,175,80,0.1)', tension: 0.3 },
                                { label: 'Info', data: data.map(d => d.info), borderColor: '#2196f3', backgroundColor: 'rgba(33,150,243,0.1)', tension: 0.3 }
                            ]
                        },
                        options: {
                            responsive: true,
                            maintainAspectRatio: false,
                            interaction: { intersect: false, mode: 'index' },
                            scales: { y: { beginAtZero: true } },
                            plugins: { legend: { position: 'bottom' } }
                        }
                    });
                    canvas._chartInstance = chart;
                } else {
                    canvas.style.display = 'none';
                }
            }

            filterEl.addEventListener('change', () => applyTrendFilter(filterEl.value));
            applyTrendFilter(filterEl.value);
        } catch (e) {
            showToast('Failed to load trends', 'error');
        }
    }

    // Audit Log
    async function renderAudit() {
        const app = document.getElementById('app');
        app.innerHTML = `
            <div class="card">
                <h2>📋 Audit Log</h2>
                <p style="color:var(--text-muted);margin-bottom:16px">Track all actions performed in the application.</p>
                <div class="table-wrapper" id="auditTableBody">
                    <div class="empty-state"><p>Loading...</p></div>
                </div>
            </div>
        `;

        try {
            const res = await api.get('/audit' + tenantQuery('?limit=200'));
            if (!res.success || !res.data || res.data.length === 0) {
                document.getElementById('auditTableBody').innerHTML = '<div class="empty-state"><p>No audit entries yet.</p></div>';
                return;
            }
            document.getElementById('auditTableBody').innerHTML = `<table>
                <thead><tr><th>Timestamp</th><th>Action</th><th>User</th><th>Details</th><th>Scan</th></tr></thead>
                <tbody>${res.data.map(a => `<tr>
                    <td style="white-space:nowrap">${new Date(a.timestamp + 'Z').toLocaleString()}</td>
                    <td><span class="audit-action">${escapeHtml(a.action)}</span></td>
                    <td>${escapeHtml(a.userName || '—')}</td>
                    <td style="max-width:400px;overflow:hidden;text-overflow:ellipsis" title="${escapeAttr(a.details)}">${escapeHtml(truncate(a.details, 60))}</td>
                    <td>${a.scanId ? `<a href="#/results?id=${a.scanId}">#${a.scanId}</a>` : '—'}</td>
                </tr>`).join('')}</tbody>
            </table>`;
        } catch (e) {
            showToast('Failed to load audit log', 'error');
        }
    }

    // Policies
    let policyConditions = [];
    let lastEvalRows = [];
    let policyCache = [];

    const POLICY_FIELDS = [
        { value: 'category', label: 'Category' },
        { value: 'principal_type', label: 'Principal Type' },
        { value: 'principal_role', label: 'Role' },
        { value: 'principal_entra_upn', label: 'Principal UPN' },
        { value: 'principal_entra_id', label: 'Principal Entra ID' },
        { value: 'principal_sys_id', label: 'Principal Sys ID' },
        { value: 'principal_sys_name', label: 'Principal Sys Name' },
        { value: 'through', label: 'Through' },
        { value: 'access_type', label: 'Access Type' },
        { value: 'tenure', label: 'Tenure' },
        { value: 'target_type', label: 'Target Type' },
        { value: 'target_path', label: 'Target Path' },
        { value: 'target_id', label: 'Target ID' },
    ];

    const POLICY_OPERATORS = [
        { value: 'equals', label: 'Equals' },
        { value: 'notEquals', label: 'Not equals' },
        { value: 'contains', label: 'Contains' },
        { value: 'notContains', label: 'Not contains' },
        { value: 'startsWith', label: 'Starts with' },
        { value: 'regex', label: 'Regex' },
    ];

    function renderConditionRow(cond, idx) {
        return `<div style="display:flex;gap:8px;align-items:center;margin-bottom:6px" data-cond-idx="${idx}">
            <select data-role="field" style="flex:1;min-width:120px">
                ${POLICY_FIELDS.map(f => `<option value="${f.value}" ${cond.field === f.value ? 'selected' : ''}>${f.label}</option>`).join('')}
            </select>
            <select data-role="operator" style="flex:1;min-width:100px">
                ${POLICY_OPERATORS.map(o => `<option value="${o.value}" ${cond.operator === o.value ? 'selected' : ''}>${o.label}</option>`).join('')}
            </select>
            <input data-role="value" type="text" value="${escapeAttr(cond.value || '')}" placeholder="Value" style="flex:2;min-width:160px">
            <button type="button" class="btn btn-secondary" style="padding:2px 8px;font-size:0.85em;color:var(--error);flex-shrink:0" onclick="window.m365.removeCondition(${idx})">✕</button>
        </div>`;
    }

    function renderConditionsEditor() {
        const container = document.getElementById('conditionsEditor');
        if (!container) return;
        container.innerHTML = policyConditions.map((c, i) => renderConditionRow(c, i)).join('')
            + `<button type="button" class="btn btn-secondary" style="padding:3px 10px;font-size:0.8em;margin-top:4px" onclick="window.m365.addCondition()">+ Add Condition</button>`;
    }

    function collectConditions() {
        const rows = document.querySelectorAll('[data-cond-idx]');
        return Array.from(rows).map(row => ({
            field: row.querySelector('[data-role="field"]').value,
            operator: row.querySelector('[data-role="operator"]').value,
            value: row.querySelector('[data-role="value"]').value,
        }));
    }

    async function renderPolicies() {
        const app = document.getElementById('app');
        app.innerHTML = `
            <div class="card">
                <h2>📜 Policy Rules</h2>
                <p style="color:var(--text-muted);margin-bottom:16px">Policies define risk scoring rules. Each policy contains one or more conditions (all must match). During scans, permissions are scored by the highest-severity matching policy.</p>
                <div class="btn-group" style="margin-bottom:16px;align-items:center;flex-wrap:wrap">
                    <button class="btn btn-primary" onclick="window.m365.showPolicyForm()">+ New Policy</button>
                    <select id="evalScanSelect" title="Scan to evaluate or re-score" style="padding:8px;background:var(--bg-input);border:1px solid var(--border);border-radius:8px;color:var(--text);max-width:320px"></select>
                    <button class="btn btn-secondary" id="evalPoliciesBtn" onclick="window.m365.evaluatePolicies()" title="Count matches of the current policies over every row of the selected scan">▶ Evaluate Scan</button>
                    <button class="btn btn-secondary" id="rescoreBtn" onclick="window.m365.rescoreScan()" title="Re-apply the current policies to the stored risk levels of the selected scan">♻ Re-score this scan</button>
                    <button class="btn btn-secondary" onclick="window.m365.resetDefaultPolicies()" title="Delete all default policies and re-create them from built-in definitions">🔄 Reset Defaults</button>
                </div>
                <div class="table-wrapper" id="policiesTable">
                    <div class="empty-state"><p>Loading...</p></div>
                </div>
            </div>
            <div class="card" id="violationsCard" style="display:none">
                <h2 id="violationsTitle">Policy Violations</h2>
                <div id="violationsSummary"></div>
                <div class="table-wrapper" id="violationsTable"></div>
            </div>
        `;
        addPageTip('policies');

        try {
            const scans = await api.get('/scans' + tenantQuery());
            const sel = document.getElementById('evalScanSelect');
            const done = scans.success ? scans.data.filter(isDoneScan) : [];
            sel.innerHTML = done.length === 0
                ? '<option value="">No completed scans</option>'
                : done.map(s => `<option value="${s.id}">Scan #${s.id} · ${fmtDate(s.startedAt)} · ${escapeHtml(s.scanTypes)}${s.status === 'CompletedWithErrors' ? ' (with errors)' : ''}</option>`).join('');
        } catch { /* evaluation buttons report the missing scan */ }

        await loadPolicies();
    }

    async function loadPolicies() {
        try {
            const res = await api.get('/policies');
            if (!res.success || !res.data) return;

            const policies = res.data;
            policyCache = policies;
            const tableDiv = document.getElementById('policiesTable');
            if (policies.length === 0) {
                tableDiv.innerHTML = '<div class="empty-state"><p>No policies defined yet. Create your first rule or click "Reset Defaults" to load built-in policies.</p></div>';
                return;
            }

            tableDiv.innerHTML = `<table>
                <thead><tr><th>Enabled</th><th>Name</th><th>Severity</th><th>Conditions</th><th>Category</th><th>Actions</th></tr></thead>
                <tbody>${policies.map(p => {
                    const conds = (p.conditions || []);
                    const condSummary = conds.length === 0 ? '<em>none</em>'
                        : conds.map(c => `<span style="white-space:nowrap">${escapeHtml(c.field)} ${escapeHtml(c.operator)} <code>${escapeHtml(c.value?.length > 40 ? c.value.substring(0,37)+'...' : c.value)}</code></span>`).join(' <strong>AND</strong> ');
                    const defaultBadge = (p.isDefault ? ' <span class="policy-badge">default</span>' : '')
                        + (p.isOutdatedDefault ? ' <span class="policy-badge policy-badge-warn" title="You edited this built-in policy and a newer built-in version is available. Reset Defaults loads it (and discards your edits).">update available</span>'
                            : p.isModifiedDefault ? ' <span class="policy-badge" title="You edited this built-in policy; it won\'t be upgraded automatically.">edited</span>' : '');
                    const tip = [p.description, p.remediation ? 'What to do: ' + p.remediation : ''].filter(Boolean).join('\n\n');
                    return `<tr>
                    <td><span style="color:${p.enabled ? 'var(--success)' : 'var(--text-muted)'};cursor:pointer" onclick="window.m365.togglePolicy(${p.id},${!p.enabled})" title="Click to ${p.enabled ? 'disable' : 'enable'}">${p.enabled ? '●' : '○'}</span></td>
                    <td title="${escapeAttr(tip)}">${escapeHtml(p.name)}${defaultBadge}</td>
                    <td><span class="risk-badge risk-${(p.severity || 'high').toLowerCase()}">${escapeHtml(p.severity)}</span></td>
                    <td style="font-size:0.8em;line-height:1.5;max-width:400px">${condSummary}</td>
                    <td>${escapeHtml(p.categoryFilter || 'All')}</td>
                    <td style="white-space:nowrap">
                        <button class="btn btn-secondary" style="padding:2px 8px;font-size:0.8em" onclick="window.m365.editPolicy(${p.id})">Edit</button>
                        <button class="btn btn-secondary" style="padding:2px 8px;font-size:0.8em;color:var(--error)" onclick="window.m365.deletePolicy(${p.id})">Delete</button>
                    </td>
                </tr>`;
                }).join('')}</tbody>
            </table>`;
        } catch (e) {
            showToast('Failed to load policies', 'error');
        }
    }

    // Settings
    async function renderSettings() {
        const app = document.getElementById('app');
        app.innerHTML = `
            <div class="card">
                <h2>Settings</h2>
                <div id="settingsForm">Loading...</div>
            </div>
            <div class="card" style="margin-top:16px">
                <h2>Database</h2>
                <div id="dbInfo">Loading...</div>
            </div>
        `;

        try {
            const res = await api.get('/config');
            if (!res.success) return;
            const cfg = res.data;

            document.getElementById('settingsForm').innerHTML = `
                <div class="form-group">
                    <label>GUI Port</label>
                    <input id="cfgGuiPort" type="number" value="${cfg.guiPort || 8080}" min="1024" max="65535">
                </div>
                <div class="form-group">
                    <label>Max Parallel Threads</label>
                    <input id="cfgMaxThreads" type="number" value="${cfg.maxThreads || 5}" min="1" max="20">
                </div>
                <div class="form-group">
                    <label>Default Output Format</label>
                    <select id="cfgOutputFormat">
                        <option value="XLSX" ${cfg.outputFormat === 'XLSX' ? 'selected' : ''}>XLSX (Excel)</option>
                        <option value="CSV" ${cfg.outputFormat === 'CSV' ? 'selected' : ''}>CSV</option>
                    </select>
                </div>
                <div class="form-group">
                    <label>Log Level</label>
                    <select id="cfgLogLevel">
                        <option value="Minimal" ${cfg.logLevel === 'Minimal' ? 'selected' : ''}>Minimal</option>
                        <option value="Normal" ${cfg.logLevel === 'Normal' ? 'selected' : ''}>Normal</option>
                        <option value="Verbose" ${cfg.logLevel === 'Verbose' ? 'selected' : ''}>Verbose</option>
                    </select>
                </div>
                <div class="form-group">
                    <label>Default Timeout (minutes)</label>
                    <input id="cfgTimeout" type="number" value="${cfg.defaultTimeoutMinutes || 120}" min="1" max="1440">
                </div>
                <div class="form-group">
                    <label style="display:flex;align-items:center;gap:8px;cursor:pointer">
                        <input id="cfgCloudTips" type="checkbox" ${window.M365Cloud.tipsEnabled() ? 'checked' : ''} style="width:auto"
                            onchange="window.M365Cloud.setTipsEnabled(this.checked)">
                        Show ${window.M365Cloud.NAME} tips (stored in this browser; re-enabling also shows tips you hid)
                    </label>
                </div>
                <div class="btn-group">
                    <button class="btn btn-primary" onclick="window.m365.saveSettings()">💾 Save</button>
                </div>
            `;
        } catch {
            document.getElementById('settingsForm').innerHTML = '<p>Failed to load settings.</p>';
        }

        // Load database info
        try {
            const dbRes = await api.get('/database');
            if (!dbRes.success) { document.getElementById('dbInfo').innerHTML = '<p>Failed to load database info.</p>'; return; }
            const db = dbRes.data;
            const totalRows = Object.values(db.tableCounts).reduce((a, b) => a + b, 0);

            document.getElementById('dbInfo').innerHTML = `
                <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:16px">
                    <div style="background:var(--bg-secondary);padding:12px;border-radius:8px">
                        <div style="color:var(--text-muted);font-size:0.8em">Database Size</div>
                        <div style="font-size:1.4em;font-weight:600">${db.sizeMB} MB</div>
                    </div>
                    <div style="background:var(--bg-secondary);padding:12px;border-radius:8px">
                        <div style="color:var(--text-muted);font-size:0.8em">Total Records</div>
                        <div style="font-size:1.4em;font-weight:600">${totalRows.toLocaleString()}</div>
                    </div>
                </div>
                <details style="margin-bottom:16px">
                    <summary style="cursor:pointer;color:var(--text-muted);font-size:0.85em">Table Details</summary>
                    <table class="data-table" style="margin-top:8px;font-size:0.85em">
                        <thead><tr><th>Table</th><th style="text-align:right">Rows</th></tr></thead>
                        <tbody>
                            ${Object.entries(db.tableCounts).map(([t, c]) =>
                                `<tr><td>${escapeHtml(t)}</td><td style="text-align:right">${c.toLocaleString()}</td></tr>`
                            ).join('')}
                        </tbody>
                    </table>
                </details>
                <div style="padding:12px;background:var(--bg-secondary);border-radius:8px;margin-bottom:16px">
                    <div style="color:var(--text-muted);font-size:0.8em;word-break:break-all">Path: ${escapeHtml(db.path)}</div>
                </div>
                <div class="btn-group">
                    <button class="btn btn-danger" onclick="window.m365.resetDatabase()">🗑️ Reset Database</button>
                </div>
                <p style="color:var(--text-muted);font-size:0.8em;margin-top:8px">Deletes all scans, permissions, and logs. Settings and policies are preserved.</p>
            `;
        } catch {
            document.getElementById('dbInfo').innerHTML = '<p>Failed to load database info.</p>';
        }
    }

    // ── Actions ─────────────────────────────────────────────────
    window.m365 = {
        dismissPain() {
            const card = document.getElementById('painCard');
            if (card) {
                if (card.dataset.scanId) localStorage.setItem('m365_painDismissed_' + card.dataset.scanId, '1');
                card.style.display = 'none';
            }
        },
        async connect() {
            try {
                showToast('Sign in with your Microsoft account in the popup window.', 'info');
                const res = await withSignIn(h => api.post('/connect', undefined, h), { preopen: true });
                if (res.success) {
                    await refreshStatus();
                    showToast(`Connected to ${state.tenantDomain}`, 'success');
                    // Larger tenants: explain once per tenant what scheduled Cloud Edition scans would change.
                    const sizeKey = 'm365_sizeNotice_' + (state.tenantId || state.tenantDomain || '');
                    if (window.M365Cloud.tipsEnabled() && !localStorage.getItem(sizeKey)) {
                        try {
                            const countRes = await api.get('/user-count');
                            if (countRes.success && countRes.data && countRes.data.recommendation) {
                                localStorage.setItem(sizeKey, '1');
                                showModal('Scanning a larger tenant', `
                                    <p style="margin-bottom:12px"><strong>${countRes.data.userCount.toLocaleString()}</strong> enabled member accounts in this tenant. This module scans it fine; it just runs on demand from this workstation.</p>
                                    <p style="color:var(--text-muted)">${escapeHtml(countRes.data.recommendation)}</p>
                                    <div style="margin-top:16px">
                                        <a href="${window.M365Cloud.link('/evaluate', 'tenant-size')}" target="_blank" rel="noopener" class="btn btn-secondary" style="text-decoration:none">Evaluate the ${window.M365Cloud.NAME}</a>
                                        <button class="btn btn-primary" style="margin-left:8px" onclick="document.getElementById('modalOverlay').style.display='none'">Continue</button>
                                    </div>
                                `);
                            }
                        } catch { /* best effort */ }
                    }
                    navigate();
                } else {
                    showToast(res.error || 'Connection failed', 'error');
                }
            } catch (e) {
                showToast('Connection failed: ' + e.message, 'error');
            }
        },

        async disconnect() {
            try {
                const res = await api.post('/disconnect');
                if (res.success) {
                    state.connected = false;
                    state.tenantId = '';
                    state.tenantDomain = '';
                    updateNavStatus();
                    showToast('Disconnected', 'info');
                    navigate();
                } else {
                    showToast(res.error || 'Disconnect failed', 'error');
                }
            } catch (e) {
                showToast('Disconnect failed: ' + e.message, 'error');
            }
        },

        async precheckScan() {
            const checkboxes = document.querySelectorAll('.scan-cat-card input:checked');
            const types = Array.from(checkboxes).map(c => c.value);
            if (types.length === 0) { showToast('Select at least one scan type', 'error'); return; }

            const precheckDiv = document.getElementById('precheckResults');
            precheckDiv.style.display = '';
            precheckDiv.innerHTML = '<div style="color:var(--text-muted);font-size:0.85em">Checking permissions...</div>';

            try {
                const res = await withSignIn(h => api.post('/scan/precheck', { scanTypes: types }, h));
                if (!res.success) { precheckDiv.innerHTML = `<div class="notice notice-warning">${escapeHtml(res.error || 'Pre-check failed')}</div>`; return; }

                const issues = res.data;
                const entries = Object.entries(issues).filter(([, v]) => v && v.length > 0);
                if (entries.length === 0) {
                    precheckDiv.innerHTML = '<div class="notice notice-info">✓ All permission and role checks passed</div>';
                } else {
                    const hasPermIssues = entries.some(([, warnings]) => warnings.some(w => !w.startsWith('Missing role:')));
                    let html = entries.map(([scanType, warnings]) => {
                        const roleWarnings = warnings.filter(w => w.startsWith('Missing role:'));
                        const permIssues = warnings.filter(w => !w.startsWith('Missing role:'));
                        let inner = `<div style="margin-bottom:8px"><strong>${escapeHtml(scanType)}:</strong>`;
                        if (permIssues.length > 0) {
                            inner += `<div class="notice notice-warning" style="margin:4px 0 6px 0">
                                <strong>API Permissions</strong>
                                <ul style="margin:4px 0 0 16px;padding:0">${permIssues.map(w => `<li>${escapeHtml(w)}</li>`).join('')}</ul>
                            </div>`;
                        }
                        if (roleWarnings.length > 0) {
                            inner += `<div class="notice notice-info" style="margin:4px 0 6px 0">
                                <strong>Entra Directory Roles</strong>
                                <ul style="margin:4px 0 0 16px;padding:0">${roleWarnings.map(w => `<li>${escapeHtml(w)}</li>`).join('')}</ul>
                            </div>`;
                        }
                        inner += '</div>';
                        return inner;
                    }).join('');
                    if (hasPermIssues) {
                        html += `<div style="margin-top:8px;padding:10px;border-radius:6px;background:var(--bg)">
                            <p style="margin:0 0 8px 0;font-size:0.85em;color:var(--text-muted)">API permission issues can often be resolved by re-consenting the app registration. An admin can grant the missing permissions:</p>
                            <button class="btn btn-primary" onclick="window.m365.reconsentPermissions()" style="font-size:0.85em">🔑 Re-consent App Permissions</button>
                        </div>`;
                    }
                    precheckDiv.innerHTML = html;
                }
            } catch (e) {
                precheckDiv.innerHTML = `<div class="notice notice-warning">Pre-check failed: ${escapeHtml(e.message)}</div>`;
            }
        },

        async reconsentPermissions() {
            const checkboxes = document.querySelectorAll('.scan-cat-card input:checked');
            const types = Array.from(checkboxes).map(c => c.value);
            const payload = types.length > 0
                ? { scanTypes: types, includeGraph: false }
                : { includeGraph: true };

            const consentTarget = types.length > 0 ? `selected targets (${types.join(', ')})` : 'all configured targets';
            showToast(`Approve the permissions for ${consentTarget} in the popup window.`, 'info');
            try {
                const res = await withSignIn(h => api.post('/reconsent', payload, h), { preopen: true });
                if (res.success) {
                    showToast('Permissions re-consented successfully! Run the pre-check again to verify.', 'success');
                    await refreshStatus();
                } else {
                    showToast(res.error || 'Consent failed', 'error');
                }
            } catch (e) {
                showToast('Consent failed: ' + e.message, 'error');
            }
        },

        async startScan() {
            const checkboxes = document.querySelectorAll('.scan-cat-card input:checked');
            const types = Array.from(checkboxes).map(c => c.value);
            if (types.length === 0) { showToast('Select at least one scan type', 'error'); return; }

            // Busy state: starting can wait on a sign-in/consent popup for a first-time category.
            const btn = document.getElementById('btnStartScan');
            const originalLabel = btn ? btn.innerHTML : null;
            if (btn) { btn.disabled = true; btn.innerHTML = '⏳ Starting…'; }

            try {
                showToast('Starting scan. If a category needs new permissions you will be asked to sign in.', 'info');
                const res = await withSignIn(h => api.post('/scan/start', { scanTypes: types }, h));
                if (res.success) {
                    state.scanRunning = true;
                    state.currentScanId = res.data?.scanId;
                    updateNavStatus();
                    startProgressPolling();
                    const warnings = res.data?.warnings || [];
                    if (warnings.length > 0) {
                        showToast(`Scan started, but results will be incomplete (details in the scan log): ${warnings.join(' ')}`, 'error', 20000);
                    } else {
                        showToast('Scan started', 'success');
                    }
                } else {
                    // Surface the server's explanation (missing consent, timeout, etc.) rather than a
                    // generic message, and restore the button so the user can retry.
                    showToast(res.error || 'Failed to start scan', 'error');
                    if (btn) { btn.disabled = false; btn.innerHTML = originalLabel; }
                }
            } catch (e) {
                showToast('Could not start scan: ' + e.message, 'error');
                if (btn) { btn.disabled = false; btn.innerHTML = originalLabel; }
            }
        },

        startQuickScan() { window.location.hash = '#/scan'; },

        async cancelScan() {
            try {
                await api.post('/scan/cancel');
                state.scanRunning = false;
                updateNavStatus();
                if (pollInterval) { clearInterval(pollInterval); pollInterval = null; }
                showToast('Scan cancelled', 'info');
                navigate();
            } catch (e) {
                showToast('Error: ' + e.message, 'error');
            }
        },

        async exportResults() {
            const scanId = document.getElementById('scanSelect')?.value;
            if (!scanId) { showToast('Select a scan first', 'error'); return; }

            try {
                // Use configured output format
                const cfgRes = await api.get('/config');
                const format = (cfgRes.success && cfgRes.data?.outputFormat) ? cfgRes.data.outputFormat.toLowerCase() : 'xlsx';
                const category = document.getElementById('categoryFilter')?.value || '';
                showToast(`Preparing ${format.toUpperCase()} export${category ? ` of ${category}` : ''}…`, 'info');
                const res = await api.getBlob(`/scans/${scanId}/export?format=${format}${category ? '&category=' + encodeURIComponent(category) : ''}`);
                if (!res.ok) {
                    let msg = 'Export failed';
                    try { const j = await res.json(); if (j.error) msg = j.error; } catch { /* not JSON */ }
                    if (/too large for an XLSX export/i.test(msg) && window.M365Cloud.tipsEnabled())
                        showModal('Export too large for Excel', `<p>${escapeHtml(msg)}</p>${window.M365Cloud.tip('largeExport')}`);
                    else
                        showToast(msg, 'error', 10000);
                    return;
                }
                const blob = await res.blob();
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `M365Permissions_${category || 'All'}_${scanId}.${format}`;
                document.body.appendChild(a);
                a.click();
                a.remove();
                URL.revokeObjectURL(url);
                showToast('Export downloaded', 'success');
                // Once per browser: scheduled email reports are the Cloud Edition's answer to repeated exports.
                if (!localStorage.getItem('m365_exportTipShown') && window.M365Cloud.tipsEnabled()) {
                    localStorage.setItem('m365_exportTipShown', '1');
                    document.getElementById('resultsCoverage')?.insertAdjacentHTML('afterbegin', window.M365Cloud.tip('export'));
                }
            } catch (e) {
                showToast('Export failed: ' + e.message, 'error');
            }
        },

        async exportCompare() {
            const oldId = document.getElementById('oldScanSelect')?.value;
            const newId = document.getElementById('newScanSelect')?.value;
            if (!oldId || !newId) { showToast('Select two scans first', 'error'); return; }
            try {
                const category = document.getElementById('compareCategory')?.value || '';
                const res = await fetch('/api/compare/export', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ oldScanId: parseInt(oldId), newScanId: parseInt(newId), category: category || null })
                });
                if (!res.ok) {
                    let msg = 'Export failed';
                    try { const j = await res.json(); if (j.error) msg = j.error; } catch { /* not JSON */ }
                    showToast(msg, 'error', 10000);
                    return;
                }
                const blob = await res.blob();
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `M365Permissions_Compare_${oldId}_vs_${newId}.xlsx`;
                document.body.appendChild(a);
                a.click();
                a.remove();
                URL.revokeObjectURL(url);
                showToast('Comparison export downloaded', 'success');
            } catch (e) {
                showToast('Export failed: ' + e.message, 'error');
            }
        },

        async runCompare() {
            const oldId = document.getElementById('oldScanSelect')?.value;
            const newId = document.getElementById('newScanSelect')?.value;
            if (!oldId || !newId) { showToast('Select two scans', 'error'); return; }
            if (oldId === newId) { showToast('Select two different scans', 'error'); return; }

            const category = document.getElementById('compareCategory')?.value || '';
            try {
                const res = await api.post('/compare', { oldScanId: parseInt(oldId), newScanId: parseInt(newId), category: category || null, limit: COMPARE_LIMIT });
                if (!res.success) { showToast(res.error || 'Compare failed', 'error', 10000); return; }

                const r = res.data;
                lastCompare = { r, newScanId: parseInt(newId), oldScanId: parseInt(oldId) };
                document.getElementById('compareResults').style.display = '';
                document.getElementById('btnExportCompare').style.display = '';
                document.getElementById('compareCoverage').innerHTML = coverageNotice(r.excludedCategories, r.flaggedCategories);
                document.getElementById('compareStats').innerHTML = `
                    <div class="stat-card"><div class="stat-value" style="color:var(--success)">${r.addedCount.toLocaleString()}</div><div class="stat-label">Added</div></div>
                    <div class="stat-card"><div class="stat-value" style="color:var(--error)">${r.removedCount.toLocaleString()}</div><div class="stat-label">Removed</div></div>
                    <div class="stat-card"><div class="stat-value" style="color:var(--warning)">${r.changedCount.toLocaleString()}</div><div class="stat-label">Changed</div></div>
                    <div class="stat-card"><div class="stat-value" style="color:#b71c1c">${r.newCriticalCount.toLocaleString()}</div><div class="stat-label">New/escalated Critical</div></div>
                    <div class="stat-card"><div class="stat-value" style="color:#f44336">${r.newHighCount.toLocaleString()}</div><div class="stat-label">New/escalated High</div></div>
                `;
                const firstTab = r.addedCount ? 'added' : r.removedCount ? 'removed' : r.changedCount ? 'changed' : 'added';
                window.m365.showCompareTab(firstTab);
            } catch (e) {
                showToast('Compare failed: ' + e.message, 'error');
            }
        },

        showCompareTab(tab) {
            if (!lastCompare) return;
            const r = lastCompare.r;
            const counts = { added: r.addedCount, removed: r.removedCount, changed: r.changedCount };
            document.getElementById('compareTabs').innerHTML = ['added', 'removed', 'changed'].map(t =>
                `<button class="btn btn-secondary${t === tab ? ' btn-active' : ''}" onclick="window.m365.showCompareTab('${t}')">${t[0].toUpperCase() + t.slice(1)} (${counts[t].toLocaleString()})</button>`
            ).join('');

            const rows = tab === 'changed'
                ? (r.changed || []).map(c => ({ ...(c.new || c.old || {}), changeType: 'Changed', details: (c.changedFields || []).map(f => `${f}: ${changeValue(c.old, f)} → ${changeValue(c.new, f)}`).join('; ') }))
                : (r[tab] || []).map(p => ({ ...p, changeType: tab === 'added' ? 'Added' : 'Removed', details: p.through || '' }));
            lastCompare.rows = rows;
            document.getElementById('compareNotice').textContent = rows.length < counts[tab]
                ? `Showing the first ${rows.length.toLocaleString()} of ${counts[tab].toLocaleString()}. Export the comparison for the full list.`
                : '';

            document.getElementById('compareTable').innerHTML = rows.length === 0
                ? '<div class="empty-state"><p>No differences found</p></div>'
                : `<table>
                    <thead><tr><th>Risk</th><th>Category</th><th>Target</th><th>Principal</th><th>Role</th><th>${tab === 'changed' ? 'Changes' : 'Through'}</th></tr></thead>
                    <tbody>${rows.map((c, i) => `<tr class="clickable-row" onclick="window.m365.showCompareDetail(${i})">
                        <td><span class="risk-badge risk-${escapeAttr((c.riskLevel || 'low').toLowerCase())}">${escapeHtml(c.riskLevel || '')}</span></td>
                        <td>${escapeHtml(c.category || '')}</td>
                        <td title="${escapeAttr(c.targetPath || '')}">${escapeHtml(truncate(c.targetPath, 40))}</td>
                        <td>${escapeHtml(c.principalEntraUpn || c.principalSysName || c.principalSysId || c.principalEntraId || '')}</td>
                        <td>${escapeHtml(c.principalRole || '')}</td>
                        <td title="${escapeAttr(c.details || '')}">${escapeHtml(truncate(c.details || '', 80))}</td>
                    </tr>`).join('')}</tbody>
                </table>`;
        },

        showCompareDetail(idx) {
            const entry = lastCompare && lastCompare.rows ? lastCompare.rows[idx] : null;
            if (!entry) return;
            showDetailPanel({ ...entry, scanId: entry.scanId || lastCompare.newScanId });
        },

        async saveSettings() {
            try {
                const config = {
                    guiPort: parseInt(document.getElementById('cfgGuiPort').value),
                    maxThreads: parseInt(document.getElementById('cfgMaxThreads').value),
                    outputFormat: document.getElementById('cfgOutputFormat').value,
                    logLevel: document.getElementById('cfgLogLevel').value,
                    defaultTimeoutMinutes: parseInt(document.getElementById('cfgTimeout').value)
                };
                const res = await api.put('/config', config);
                if (res.success) showToast('Settings saved', 'success');
                else showToast(res.error || 'Save failed', 'error');
            } catch (e) {
                showToast('Error: ' + e.message, 'error');
            }
        },

        async resetDatabase() {
            showModal('Reset Database', `
                <p style="margin-bottom:12px">This will <strong>permanently delete</strong> all scans, permissions, logs, and audit entries.</p>
                <p style="margin-bottom:16px;color:var(--text-muted)">Settings and policies will be preserved.</p>
                <div style="display:flex;gap:8px;justify-content:flex-end">
                    <button class="btn btn-secondary" onclick="document.getElementById('modalOverlay').style.display='none'">Cancel</button>
                    <button class="btn btn-danger" id="confirmResetBtn" onclick="window.m365._confirmResetDatabase()">🗑️ Confirm Reset</button>
                </div>
            `);
        },

        async _confirmResetDatabase() {
            const btn = document.getElementById('confirmResetBtn');
            if (btn) { btn.disabled = true; btn.textContent = 'Resetting...'; }
            try {
                const res = await api.post('/database/reset');
                closeModal();
                if (res.success) {
                    showToast('Database reset successfully', 'success');
                    renderSettings(); // Refresh to show new sizes
                } else {
                    showToast(res.error || 'Reset failed', 'error');
                }
            } catch (e) {
                closeModal();
                showToast('Error: ' + e.message, 'error');
            }
        },

        applyQuickFilter,

        async clearFilters() {
            resetTableState();
            // Remove active state from quick filter pills
            document.querySelectorAll('#quickFilters .btn-active').forEach(b => b.classList.remove('btn-active'));
            currentPage = 1;
            await loadFilterOptions();
            await loadResults();
        },

        async editScanNotes(scanId) {
            const el = document.getElementById(`scanNotes${scanId}`);
            const notes = prompt('Edit scan notes:', el?.dataset.notes || '');
            if (notes === null) return;
            try {
                // Only notes: omitting tags leaves them unchanged.
                const res = await api.put(`/scans/${scanId}`, { notes: notes });
                if (res.success) {
                    if (el) { el.textContent = notes || '-'; el.dataset.notes = notes; }
                    showToast('Scan notes updated', 'success');
                } else {
                    showToast(res.error || 'Failed to update notes', 'error');
                }
            } catch (e) {
                showToast('Failed to update notes: ' + e.message, 'error');
            }
        },

        showPolicyForm(policy) {
            const isEdit = !!policy;
            const title = isEdit ? 'Edit Policy' : 'New Policy';
            const formHtml = `
                <input type="hidden" id="policyId" value="">
                <div class="form-group">
                    <label>Name</label>
                    <input id="policyName" type="text" placeholder="e.g. Full Control anonymous access">
                </div>
                <div class="form-group">
                    <label>Description</label>
                    <input id="policyDesc" type="text" placeholder="Describe what this rule flags">
                </div>
                <div style="display:flex;gap:12px;flex-wrap:wrap">
                    <div class="form-group" style="flex:1;min-width:120px">
                        <label>Severity</label>
                        <select id="policySeverity">
                            <option value="Critical">Critical</option>
                            <option value="High" selected>High</option>
                            <option value="Medium">Medium</option>
                            <option value="Low">Low</option>
                            <option value="Info">Info</option>
                        </select>
                    </div>
                    <div class="form-group" style="flex:1;min-width:120px">
                        <label>Category filter (empty = all)</label>
                        <input id="policyCat" type="text" placeholder="e.g. SharePoint,Entra">
                    </div>
                </div>
                <div class="form-group">
                    <label>Conditions <span style="color:var(--text-muted);font-weight:400">(all conditions must match)</span></label>
                    <div id="conditionsEditor"></div>
                </div>
                <div class="form-group">
                    <label>Remediation <span style="color:var(--text-muted);font-weight:400">(what to do about a match, and where)</span></label>
                    <textarea id="policyRemediation" rows="3" placeholder="e.g. Remove the assignment in Entra admin center > Roles and administrators." style="width:100%;resize:vertical"></textarea>
                </div>
                <div id="policyFormError" class="notice notice-warning" style="display:none"></div>
                <div class="btn-group">
                    <button class="btn btn-primary" onclick="window.m365.savePolicy()">💾 Save</button>
                    <button class="btn btn-secondary" onclick="document.getElementById('modalOverlay').style.display='none'">Cancel</button>
                </div>
            `;
            showModal(title, formHtml);
            if (isEdit) {
                document.getElementById('policyId').value = policy.id;
                document.getElementById('policyName').value = policy.name;
                document.getElementById('policyDesc').value = policy.description || '';
                document.getElementById('policySeverity').value = policy.severity;
                document.getElementById('policyCat').value = policy.categoryFilter || '';
                document.getElementById('policyRemediation').value = policy.remediation || '';
                policyConditions = (policy.conditions || []).map(c => ({...c}));
                if (policyConditions.length === 0) policyConditions.push({ field: 'principal_type', operator: 'equals', value: '' });
            } else {
                policyConditions = [{ field: 'principal_type', operator: 'equals', value: '' }];
            }
            renderConditionsEditor();
        },

        addCondition() {
            policyConditions = collectConditions();
            policyConditions.push({ field: 'principal_type', operator: 'equals', value: '' });
            renderConditionsEditor();
        },

        removeCondition(idx) {
            policyConditions = collectConditions();
            policyConditions.splice(idx, 1);
            if (policyConditions.length === 0) policyConditions.push({ field: 'principal_type', operator: 'equals', value: '' });
            renderConditionsEditor();
        },

        async editPolicy(id) {
            try {
                const res = await api.get('/policies');
                if (res.success) {
                    const policy = res.data.find(p => p.id === id);
                    if (policy) window.m365.showPolicyForm(policy);
                }
            } catch { }
        },

        async togglePolicy(id, enabled) {
            try {
                // Send the full definition (the server also merges missing properties).
                const current = policyCache.find(p => p.id === id);
                const body = current
                    ? { name: current.name, description: current.description, severity: current.severity, categoryFilter: current.categoryFilter,
                        conditions: current.conditions, remediation: current.remediation, enabled }
                    : { enabled };
                const res = await api.put(`/policies/${id}`, body);
                if (res.success) await loadPolicies();
                else showToast(res.error || 'Toggle failed', 'error');
            } catch (e) { showToast('Error: ' + e.message, 'error'); }
        },

        async savePolicy() {
            const id = document.getElementById('policyId').value;
            const existing = id ? policyCache.find(p => p.id === Number(id)) : null;
            const conditions = collectConditions().filter(c => c.value.trim() !== '' || /^not/i.test(c.operator));
            const policy = {
                name: document.getElementById('policyName').value,
                description: document.getElementById('policyDesc').value,
                // Keep the current state when editing; new policies start enabled. isDefault is server-owned.
                enabled: existing ? existing.enabled : true,
                severity: document.getElementById('policySeverity').value,
                categoryFilter: document.getElementById('policyCat').value,
                remediation: document.getElementById('policyRemediation').value,
                conditions: conditions
            };
            if (!policy.name) { showToast('Policy name is required', 'error'); return; }
            if (conditions.length === 0) { showToast('At least one condition with a value is required', 'error'); return; }

            try {
                let res;
                if (id) {
                    res = await api.put(`/policies/${id}`, policy);
                } else {
                    res = await api.post('/policies', policy);
                }
                if (res.success) {
                    showToast(id ? 'Policy updated. Re-score a scan to apply it to stored results.' : 'Policy created. Re-score a scan to apply it to stored results.', 'success', 6000);
                    closeModal();
                    await loadPolicies();
                } else {
                    // Validation errors (unknown field, bad regex, severity) are shown in the form.
                    const errEl = document.getElementById('policyFormError');
                    if (errEl) { errEl.textContent = res.error || 'Save failed'; errEl.style.display = ''; }
                    else showToast(res.error || 'Save failed', 'error');
                }
            } catch (e) {
                showToast('Error: ' + e.message, 'error');
            }
        },

        async deletePolicy(id) {
            if (!confirm('Delete this policy?')) return;
            try {
                const res = await fetch(`/api/policies/${id}`, { method: 'DELETE' });
                const data = await res.json();
                if (data.success) {
                    showToast('Policy deleted', 'success');
                    await loadPolicies();
                } else {
                    showToast(data.error || 'Delete failed', 'error');
                }
            } catch (e) {
                showToast('Error: ' + e.message, 'error');
            }
        },

        async resetDefaultPolicies() {
            if (!confirm('This will delete all default policies and re-create them from built-in definitions. Custom policies will not be affected. Continue?')) return;
            try {
                const res = await api.post('/policies/reset-defaults', {});
                if (res.success) {
                    showToast('Default policies have been reset', 'success');
                    await loadPolicies();
                } else {
                    showToast(res.error || 'Reset failed', 'error');
                }
            } catch (e) {
                showToast('Error: ' + e.message, 'error');
            }
        },

        async evaluatePolicies() {
            const scanId = document.getElementById('evalScanSelect')?.value;
            if (!scanId) { showToast('No completed scan to evaluate', 'error'); return; }
            const btn = document.getElementById('evalPoliciesBtn');
            if (btn) {
                btn.disabled = true;
                btn.innerHTML = '<span class="btn-spinner"></span> Evaluating...';
            }
            try {
                const res = await api.post('/policies/evaluate', { scanId: Number(scanId), maxViolations: 500 });
                if (!res.success) { showToast(res.error || 'Evaluation failed', 'error'); return; }

                const r = res.data;
                lastEvalRows = r.violations || [];
                const card = document.getElementById('violationsCard');
                const table = document.getElementById('violationsTable');
                card.style.display = '';
                document.getElementById('violationsTitle').textContent = `Policy Violations in Scan #${r.scanId}`;

                const warnings = (r.warnings || []).length
                    ? `<div class="notice notice-warning">These policies can't match anything: ${r.warnings.map(escapeHtml).join('; ')}</div>` : '';
                document.getElementById('violationsSummary').innerHTML = `${warnings}
                    <p style="color:var(--text-muted);font-size:0.9em">${r.entriesWithViolations.toLocaleString()} of ${r.entriesEvaluated.toLocaleString()} rows match at least one policy.</p>
                    ${(r.perPolicy || []).length ? `<table class="data-table" style="margin-bottom:16px">
                        <thead><tr><th>Severity</th><th>Policy</th><th style="text-align:right">Matches</th></tr></thead>
                        <tbody>${r.perPolicy.map(c => `<tr>
                            <td><span class="risk-badge risk-${escapeAttr((c.severity || 'high').toLowerCase())}">${escapeHtml(c.severity)}</span></td>
                            <td>${escapeHtml(c.policyName)}</td>
                            <td style="text-align:right">${c.count.toLocaleString()}</td>
                        </tr>`).join('')}</tbody>
                    </table>` : ''}`;

                if (lastEvalRows.length === 0) {
                    table.innerHTML = '<div class="empty-state"><p>✅ No policy violations found in this scan</p></div>';
                    showToast('Evaluation complete: no violations', 'success');
                    return;
                }

                table.innerHTML = `<table>
                    <thead><tr><th>Severity</th><th>Policy</th><th>Target</th><th>Principal</th><th>Role</th></tr></thead>
                    <tbody>${lastEvalRows.map((row, idx) => {
                        const e = row.entry || {};
                        const top = (row.violations || [])[0] || {};
                        const more = (row.violations || []).length > 1 ? ` <span style="color:var(--text-muted)">+${row.violations.length - 1}</span>` : '';
                        const principal = e.principalEntraUpn || e.principalSysName || '';
                        return `<tr class="clickable-row" onclick="window.m365.showViolationDetail(${idx})">
                            <td><span class="risk-badge risk-${escapeAttr((top.severity || 'high').toLowerCase())}">${escapeHtml(top.severity || '')}</span></td>
                            <td>${escapeHtml(top.policyName || '')}${more}</td>
                            <td style="max-width:250px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${escapeAttr(e.targetPath || '')}">${escapeHtml(e.targetPath || '')}</td>
                            <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${escapeAttr(principal)}">${escapeHtml(principal)}</td>
                            <td>${escapeHtml(e.principalRole || '')}</td>
                        </tr>`;
                    }).join('')}</tbody>
                </table>
                <p style="margin-top:8px;font-size:0.85em;color:var(--text-muted)">${r.truncated
                    ? `Showing the ${lastEvalRows.length.toLocaleString()} most severe of ${r.entriesWithViolations.toLocaleString()} rows with violations.`
                    : `${lastEvalRows.length.toLocaleString()} rows with violations.`}</p>`;
                showToast(`Evaluation complete: ${r.entriesWithViolations.toLocaleString()} rows with violations`, 'success');
            } catch (e) {
                showToast('Evaluation failed: ' + e.message, 'error');
            } finally {
                if (btn) {
                    btn.disabled = false;
                    btn.innerHTML = '▶ Evaluate Scan';
                }
            }
        },

        async rescoreScan() {
            const scanId = document.getElementById('evalScanSelect')?.value;
            if (!scanId) { showToast('No completed scan to re-score', 'error'); return; }
            if (!confirm(`Re-apply the current enabled policies to every row of scan #${scanId}? This replaces the stored risk levels of that scan.`)) return;
            const btn = document.getElementById('rescoreBtn');
            if (btn) { btn.disabled = true; btn.innerHTML = '<span class="btn-spinner"></span> Re-scoring...'; }
            try {
                const res = await api.post(`/scans/${scanId}/rescore`, {});
                if (!res.success) { showToast(res.error || 'Re-score failed', 'error'); return; }
                const r = res.data;
                const summary = ['Critical', 'High', 'Medium', 'Low', 'Info'].map(l => `${l} ${(r.riskSummary[l] || 0).toLocaleString()}`).join(', ');
                showToast(`Scan #${r.scanId} re-scored: ${r.entriesChanged.toLocaleString()} of ${r.entriesScored.toLocaleString()} rows changed. ${summary}`, 'success', 10000);
            } catch (e) {
                showToast('Re-score failed: ' + e.message, 'error');
            } finally {
                if (btn) { btn.disabled = false; btn.innerHTML = '♻ Re-score this scan'; }
            }
        },

        showViolationDetail(idx) {
            const row = lastEvalRows[idx];
            if (!row || !row.entry) { showToast('Entry details not available', 'error'); return; }
            showDetailPanel(row.entry);
        },

        toggleColumnPicker() {
            const picker = document.getElementById('columnPicker');
            if (!picker) return;
            if (picker.style.display !== 'none') { picker.style.display = 'none'; return; }
            const allCols = [
                { key: 'riskLevel', label: 'Risk' },
                { key: 'category', label: 'Category' },
                { key: 'targetPath', label: 'Target' },
                { key: 'targetType', label: 'Type' },
                { key: 'principal', label: 'Principal' },
                { key: 'principalType', label: 'Identity Type' },
                { key: 'principalRole', label: 'Role' },
                { key: 'through', label: 'Through' },
                { key: 'accessType', label: 'Access' }
            ];
            picker.innerHTML = allCols.map(c => `
                <label style="display:inline-flex;align-items:center;gap:4px;margin-right:12px;cursor:pointer">
                    <input type="checkbox" ${!hiddenColumns.has(c.key) ? 'checked' : ''} data-col-key="${c.key}">
                    ${escapeHtml(c.label)}
                </label>
            `).join('');
            picker.style.display = '';
            picker.querySelectorAll('input[type=checkbox]').forEach(cb => {
                cb.addEventListener('change', () => {
                    if (cb.checked) hiddenColumns.delete(cb.dataset.colKey);
                    else hiddenColumns.add(cb.dataset.colKey);
                    localStorage.setItem('m365pv2-hiddenCols', JSON.stringify([...hiddenColumns]));
                    loadResults();
                });
            });
        },

        async deleteScan(scanId) {
            if (!confirm(`Delete scan #${scanId} and all its results? This can't be undone.`)) return;
            try {
                const res = await api.del(`/scans/${scanId}`);
                if (res.success) {
                    showToast(`Scan #${scanId} deleted`, 'success');
                    navigate();
                } else {
                    showToast(res.error || 'Delete failed', 'error');
                }
            } catch (e) {
                showToast('Delete failed: ' + e.message, 'error');
            }
        },

        loadResults,
        showGroupMembers,
        showSharePointGroupMembers,
        searchUserPerms
    };

    // ── Keyboard Shortcuts ──────────────────────────────────────
    document.addEventListener('keydown', (e) => {
        // Ignore if typing in an input/textarea/select
        if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA' || e.target.tagName === 'SELECT') {
            if (e.key === 'Escape') e.target.blur();
            return;
        }

        // Esc closes modals
        if (e.key === 'Escape') {
            closeModal();
            return;
        }

        // Ctrl+E or Cmd+E to export (Results page only)
        if ((e.ctrlKey || e.metaKey) && e.key === 'e' && document.getElementById('scanSelect')) {
            e.preventDefault();
            window.m365.exportResults();
            return;
        }

        // Ctrl+K or Cmd+K to focus search
        if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
            e.preventDefault();
            const searchInput = document.getElementById('searchInput');
            if (searchInput) searchInput.focus();
            return;
        }
    });

    // ── Utilities ───────────────────────────────────────────────
    function escapeHtml(str) {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    function escapeAttr(str) {
        return (str || '').replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/'/g, '&#39;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    }

    // A JS string literal for use inside an inline handler attribute: onclick="fn(${jsArg(x)})".
    // escapeAttr alone is not enough there: the browser decodes &#39; back to ' before running the JS,
    // so a tenant-controlled name like x');alert(1);// would break out of the string.
    function jsArg(str) {
        return escapeAttr(JSON.stringify(String(str ?? '')));
    }

    function truncate(str, max) {
        if (!str) return '';
        return str.length > max ? str.slice(0, max) + '…' : str;
    }

    function debounce(fn, ms) {
        let timer;
        return function (...args) {
            clearTimeout(timer);
            timer = setTimeout(() => fn.apply(this, args), ms);
        };
    }

    // ── Init ────────────────────────────────────────────────────
    // Footer copyright year: rewrite only the year text node, leaving the footer markup as is.
    function updateFooterYear() {
        const span = document.querySelector('.site-footer span');
        const node = span && Array.from(span.childNodes).find(n => n.nodeType === Node.TEXT_NODE && /\d{4}/.test(n.textContent));
        if (node) node.textContent = node.textContent.replace(/\d{4}/, String(new Date().getFullYear()));
        const cloudLink = document.getElementById('footerCloudLink');
        if (cloudLink) cloudLink.href = window.M365Cloud.link('/', 'footer');
    }

    async function init() {
        initTheme();
        updateFooterYear();
        await refreshStatus();
        window.addEventListener('hashchange', navigate);
        navigate();
        setInterval(refreshStatus, 10000);
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();